import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { after, before, describe, it } from "node:test";
import { createConnection } from "node:net";
import {
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { Reader, Writer, frame } from "../src/wire.mjs";
import {
  importSshEd25519Public,
  parseEd25519SignatureBlob,
} from "../src/keys.mjs";

const keyDir = fileURLToPath(new URL("../keys/", import.meta.url));
const read = (name) => readFileSync(join(keyDir, name));
const userKeyBlob = read("user_ed25519.pub.ssh");
const jumpHostBlob = read("jump_host_ed25519.pub.ssh");
const targetHostBlob = read("target_host_ed25519.pub.ssh");
const jumpPrivate = read("jump_host_ed25519");
const targetPrivate = read("target_host_ed25519");
const userPrivate = read("user_ed25519");
const authorizedUser = "deploy";

let socketPath;
let server;
let serverOutput;

function sshBlob(buffer) {
  return importSshEd25519Public(buffer).blob;
}

function hostSignature(privateKey, sessionId) {
  const raw = cryptoSign(null, sessionId, privateKey);
  return new Writer().string("ssh-ed25519").bytes(raw).toBuffer();
}

function sessionBind(hostBlob, sessionId, privateKey, forwarding) {
  const message = new Writer()
    .u8(27)
    .string("session-bind@openssh.com")
    .bytes(hostBlob)
    .bytes(sessionId)
    .bytes(hostSignature(privateKey, sessionId))
    .bool(forwarding)
    .toBuffer();
  return frame(message);
}

function hostboundUserauth({
  sessionId,
  user = authorizedUser,
  service = "ssh-connection",
  method = "publickey-hostbound-v00@openssh.com",
  signatureFollows = true,
  algorithm = "ssh-ed25519",
  userKey = userKeyBlob,
  hostKey = targetHostBlob,
  trailing = 0,
} = {}) {
  const writer = new Writer()
    .bytes(sessionId)
    .u8(50)
    .string(user)
    .string(service)
    .string(method)
    .bool(signatureFollows)
    .string(algorithm)
    .bytes(userKey)
    .bytes(hostKey);
  for (let i = 0; i < trailing; i += 1) writer.u8(0);
  return writer.toBuffer();
}

function signRequest(keyBlob = userKeyBlob, data = randomBytes(64), flags = 0) {
  return frame(
    new Writer().u8(13).bytes(keyBlob).bytes(data).u32(flags).toBuffer(),
  );
}

function identitiesRequest() {
  return frame(Buffer.from([11]));
}

function unsupportedAddRequest() {
  // A deliberately malformed add request must still be refused, not processed.
  return frame(Buffer.from([17]));
}

function connectAgent() {
  const socket = createConnection(socketPath);
  socket.buffer = Buffer.alloc(0);
  socket.waiters = [];
  socket.on("data", (chunk) => {
    socket.buffer =
      socket.buffer.length === 0
        ? chunk
        : Buffer.concat([socket.buffer, chunk]);
    while (socket.waiters.length > 0 && socket.buffer.length >= 4) {
      const length = socket.buffer.readUInt32BE(0);
      if (socket.buffer.length < 4 + length) break;
      const message = Buffer.from(socket.buffer.subarray(4, 4 + length));
      socket.buffer = Buffer.from(socket.buffer.subarray(4 + length));
      socket.waiters.shift().resolve(message);
    }
  });
  return socket;
}

function readOneMessage(socket, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("timed out waiting for message")),
      timeout,
    );
    const waiter = {
      resolve(message) {
        clearTimeout(timer);
        resolve(message);
      },
    };
    socket.waiters.push(waiter);
    socket.emit("data", Buffer.alloc(0));
  });
}

async function request(socket, data) {
  await new Promise((resolve, reject) => {
    socket.write(data, (error) => (error ? reject(error) : resolve()));
  });
  return readOneMessage(socket);
}

async function bindPath(socket, jumpSession, targetSession = jumpSession) {
  assert.equal(
    (
      await request(
        socket,
        sessionBind(jumpHostBlob, jumpSession, jumpPrivate, true),
      )
    )[0],
    6,
  );
  assert.equal(
    (
      await request(
        socket,
        sessionBind(targetHostBlob, targetSession, targetPrivate, false),
      )
    )[0],
    6,
  );
}

function isFailure(message) {
  return message.length === 1 && message[0] === 5;
}

async function closed(socket) {
  await new Promise((resolve) => socket.end(resolve));
}

describe("restricted SSH agent", () => {
  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-"));
    socketPath = join(dir, "agent.sock");
    serverOutput = "";
    server = spawn(process.execPath, ["src/server.mjs"], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      env: {
        ...process.env,
        KEY_DIR: keyDir,
        SSH_AUTH_SOCK: socketPath,
        AUTHORIZED_USER: authorizedUser,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    server.stdout.on("data", (chunk) => {
      serverOutput += chunk;
    });
    server.stderr.on("data", (chunk) => {
      serverOutput += chunk;
    });

    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 5000;
      const attempt = () => {
        const probe = createConnection(socketPath);
        probe.once("connect", () => probe.end(resolve));
        probe.once("error", () => {
          if (Date.now() > deadline)
            reject(new Error(`server did not start: ${serverOutput}`));
          else setTimeout(attempt, 20);
        });
      };
      attempt();
    });
  });

  after(async () => {
    if (server) server.kill("SIGTERM");
  });

  it("answers an identity query with the single demo Ed25519 key", async () => {
    const socket = connectAgent();
    const answer = await request(socket, identitiesRequest());
    const reader = new Reader(answer);
    assert.equal(reader.u8(), 12);
    assert.equal(reader.u32(), 1);
    assert.deepEqual(reader.bytes(), sshBlob(userKeyBlob));
    assert.equal(reader.string(), "restricted-demo-ed25519");
    reader.end();
    await closed(socket);
  });

  it("signs only the fully bound authorized hostbound userauth request", async () => {
    const socket = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);
    await bindPath(socket, jumpSession, targetSession);

    const authData = hostboundUserauth({ sessionId: targetSession });
    const answer = await request(socket, signRequest(userKeyBlob, authData, 0));
    assert.equal(answer[0], 14);

    const answerReader = new Reader(answer);
    assert.equal(answerReader.u8(), 14);
    const signatureBlob = answerReader.bytes();
    answerReader.end();
    const rawSignature = parseEd25519SignatureBlob(signatureBlob);
    assert.ok(rawSignature);
    assert.equal(rawSignature.length, 64);
    assert.ok(cryptoVerify(null, authData, userPrivate, rawSignature));
    await closed(socket);
  });

  it("refuses signing before forwarding and target bindings are complete", async () => {
    const sessionId = randomBytes(32);

    const unbound = connectAgent();
    assert.ok(
      isFailure(
        await request(
          unbound,
          signRequest(userKeyBlob, hostboundUserauth({ sessionId })),
        ),
      ),
    );
    await closed(unbound);

    const jumpOnly = connectAgent();
    assert.equal(
      (
        await request(
          jumpOnly,
          sessionBind(jumpHostBlob, sessionId, jumpPrivate, true),
        )
      )[0],
      6,
    );
    assert.ok(
      isFailure(
        await request(
          jumpOnly,
          signRequest(userKeyBlob, hostboundUserauth({ sessionId })),
        ),
      ),
    );
    await closed(jumpOnly);
  });

  it("rejects wrong binding order without changing the socket state", async () => {
    const socket = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);

    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(targetHostBlob, targetSession, targetPrivate, false),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(jumpHostBlob, jumpSession, jumpPrivate, false),
        ),
      ),
    );

    // The failed order must not have installed either hop.
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        ),
      ),
    );

    await bindPath(socket, jumpSession, targetSession);
    const answer = await request(
      socket,
      signRequest(userKeyBlob, hostboundUserauth({ sessionId: targetSession })),
    );
    assert.equal(answer[0], 14);
    await closed(socket);
  });

  it("rejects a bad second binding without losing the valid forwarding binding", async () => {
    const socket = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);

    assert.equal(
      (
        await request(
          socket,
          sessionBind(jumpHostBlob, jumpSession, jumpPrivate, true),
        )
      )[0],
      6,
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(targetHostBlob, targetSession, jumpPrivate, false),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(jumpHostBlob, targetSession, jumpPrivate, false),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        ),
      ),
    );

    const validTargetSession = randomBytes(32);
    assert.equal(
      (
        await request(
          socket,
          sessionBind(targetHostBlob, validTargetSession, targetPrivate, false),
        )
      )[0],
      6,
    );
    assert.equal(
      (
        await request(
          socket,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: validTargetSession }),
          ),
        )
      )[0],
      14,
    );
    await closed(socket);
  });

  it("rejects duplicate session IDs and bindings after the authentication binding", async () => {
    const socket = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);
    await bindPath(socket, jumpSession, targetSession);

    const laterJumpSession = randomBytes(32);
    const laterTargetSession = randomBytes(32);
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(jumpHostBlob, laterJumpSession, jumpPrivate, true),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(targetHostBlob, laterTargetSession, targetPrivate, false),
        ),
      ),
    );

    // Reusing either recorded session ID is rejected as well.
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(jumpHostBlob, jumpSession, jumpPrivate, true),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(targetHostBlob, targetSession, targetPrivate, false),
        ),
      ),
    );

    const answer = await request(
      socket,
      signRequest(userKeyBlob, hostboundUserauth({ sessionId: targetSession })),
    );
    assert.equal(answer[0], 14);
    await closed(socket);
  });

  it("verifies each host signature over the corresponding session ID", async () => {
    const socket = connectAgent();
    const sessionId = randomBytes(32);
    const badBind = new Writer()
      .u8(27)
      .string("session-bind@openssh.com")
      .bytes(jumpHostBlob)
      .bytes(sessionId)
      .bytes(hostSignature(jumpPrivate, randomBytes(32)))
      .bool(true)
      .toBuffer();

    assert.ok(isFailure(await request(socket, frame(badBind))));
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(userKeyBlob, hostboundUserauth({ sessionId })),
        ),
      ),
    );
    await closed(socket);
  });

  it("rejects swapped hosts, host roles, sessions, and users", async () => {
    const valid = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);
    await bindPath(valid, jumpSession, targetSession);

    const swappedHost = await request(
      valid,
      signRequest(
        userKeyBlob,
        hostboundUserauth({ sessionId: targetSession, hostKey: jumpHostBlob }),
      ),
    );
    assert.ok(isFailure(swappedHost));

    const swappedUser = await request(
      valid,
      signRequest(
        userKeyBlob,
        hostboundUserauth({ sessionId: targetSession, user: "root" }),
      ),
    );
    assert.ok(isFailure(swappedUser));

    const swappedSession = await request(
      valid,
      signRequest(
        userKeyBlob,
        hostboundUserauth({ sessionId: randomBytes(32) }),
      ),
    );
    assert.ok(isFailure(swappedSession));

    // Using the target as the first forwarding hop is a host/path mismatch.
    const roleSocket = connectAgent();
    assert.ok(
      isFailure(
        await request(
          roleSocket,
          sessionBind(targetHostBlob, jumpSession, targetPrivate, true),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          roleSocket,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        ),
      ),
    );
    await closed(roleSocket);

    // The original authorized request still works.
    assert.equal(
      (
        await request(
          valid,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        )
      )[0],
      14,
    );
    await closed(valid);
  });

  it("checks every hostbound userauth field rather than a digest or a single field", async () => {
    const socket = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);
    await bindPath(socket, jumpSession, targetSession);

    const variants = [
      { sessionId: randomBytes(32) },
      { sessionId: jumpSession },
      { user: "other-user" },
      { service: "other-service" },
      { method: "publickey" },
      { signatureFollows: false },
      { algorithm: "ssh-ed25519-cert-v01@openssh.com" },
      { userKey: jumpHostBlob },
      { hostKey: jumpHostBlob },
      { trailing: 1 },
    ];

    for (const variant of variants) {
      assert.ok(
        isFailure(
          await request(
            socket,
            signRequest(
              userKeyBlob,
              hostboundUserauth({ sessionId: targetSession, ...variant }),
            ),
          ),
        ),
      );
    }
    assert.equal(
      (
        await request(
          socket,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
            1,
          ),
        )
      )[0],
      5,
    );
    assert.equal(
      (await request(socket, signRequest(userKeyBlob, randomBytes(128), 0)))[0],
      5,
    );
    await closed(socket);
  });

  it("keeps bindings private to each socket and destroys them on close", async () => {
    const bound = connectAgent();
    const unbound = connectAgent();
    const jumpSession = randomBytes(32);
    const targetSession = randomBytes(32);
    await bindPath(bound, jumpSession, targetSession);

    assert.ok(
      isFailure(
        await request(
          unbound,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        ),
      ),
    );
    await closed(bound);
    await closed(unbound);

    // A new socket starts with no bindings; the same sessions need both hops again.
    const reopened = connectAgent();
    assert.ok(
      isFailure(
        await request(
          reopened,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          reopened,
          sessionBind(targetHostBlob, targetSession, targetPrivate, false),
        ),
      ),
    );
    await bindPath(reopened, jumpSession, targetSession);
    assert.equal(
      (
        await request(
          reopened,
          signRequest(
            userKeyBlob,
            hostboundUserauth({ sessionId: targetSession }),
          ),
        )
      )[0],
      14,
    );
    await closed(reopened);
  });

  it("does not support add-key or non-session-bind extension paths", async () => {
    const socket = connectAgent();
    assert.ok(isFailure(await request(socket, unsupportedAddRequest())));

    const extension = frame(
      new Writer().u8(27).string("query-certs@openssh.com").toBuffer(),
    );
    assert.ok(isFailure(await request(socket, extension)));

    assert.equal((await request(socket, identitiesRequest()))[0], 12);
    await closed(socket);
  });
});
