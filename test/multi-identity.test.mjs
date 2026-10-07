import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { after, before, describe, it } from "node:test";
import { createConnection } from "node:net";
import {
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { Reader, Writer, frame } from "../src/wire.mjs";
import { parseEd25519SignatureBlob } from "../src/keys.mjs";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const keyDir = join(repoRoot, "keys");
const read = (name) => readFileSync(join(keyDir, name));

const adminPrivate = read("multi-admin.pem");
const auditorPrivate = read("multi-auditor.pem");
const adminBlob = read("multi-admin.pub.ssh");
const auditorBlob = read("multi-auditor.pub.ssh");

const hosts = {
  edge: { blob: read("multi-edge.pub.ssh"), private: read("multi-edge.pem") },
  relay: {
    blob: read("multi-relay.pub.ssh"),
    private: read("multi-relay.pem"),
  },
  prod: { blob: read("multi-prod.pub.ssh"), private: read("multi-prod.pem") },
  test: { blob: read("multi-test.pub.ssh"), private: read("multi-test.pem") },
};

let socketPath;
let server;
let serverOutput;

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

function bind(socket, label, sessionId, forwarding) {
  const host = hosts[label];
  return request(
    socket,
    sessionBind(host.blob, sessionId, host.private, forwarding),
  );
}

function hostboundUserauth({
  sessionId,
  user,
  service = "ssh-connection",
  method = "publickey-hostbound-v00@openssh.com",
  signatureFollows = true,
  algorithm = "ssh-ed25519",
  userKey,
  hostKey,
  trailing = 0,
}) {
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

function signRequest(keyBlob, data, flags = 0) {
  return frame(
    new Writer().u8(13).bytes(keyBlob).bytes(data).u32(flags).toBuffer(),
  );
}

function identitiesRequest() {
  return frame(Buffer.from([11]));
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

function isFailure(message) {
  return message.length === 1 && message[0] === 5;
}

async function closed(socket) {
  await new Promise((resolve) => socket.end(resolve));
}

async function listedIdentities(socket) {
  const answer = await request(socket, identitiesRequest());
  const reader = new Reader(answer);
  assert.equal(reader.u8(), 12);
  const count = reader.u32();
  const entries = [];
  for (let i = 0; i < count; i += 1)
    entries.push({ blob: reader.bytes(), comment: reader.string() });
  reader.end();
  return entries;
}

// Binds the full hop sequence on one socket, asserting every bind succeeds,
// and returns the session ID of each hop.
async function bindRoute(socket, labels) {
  const sessions = labels.map(() => randomBytes(32));
  for (let i = 0; i < labels.length; i += 1) {
    const forwarding = i < labels.length - 1;
    const answer = await bind(socket, labels[i], sessions[i], forwarding);
    assert.equal(answer[0], 6, `bind of hop ${labels[i]} failed`);
  }
  return sessions;
}

async function expectSignature(socket, keyBlob, keyPrivate, data) {
  const answer = await request(socket, signRequest(keyBlob, data));
  assert.equal(answer[0], 14);
  const reader = new Reader(answer);
  assert.equal(reader.u8(), 14);
  const raw = parseEd25519SignatureBlob(reader.bytes());
  reader.end();
  assert.ok(raw);
  assert.ok(cryptoVerify(null, data, keyPrivate, raw));
}

describe("multi-identity policy agent", () => {
  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "multi-agent-"));
    socketPath = join(dir, "agent.sock");
    serverOutput = "";
    server = spawn(process.execPath, ["src/server.mjs"], {
      cwd: repoRoot,
      env: {
        ...process.env,
        AGENT_POLICY: join(repoRoot, "demo-routes.json"),
        SSH_AUTH_SOCK: socketPath,
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

  it("lists identities only for the identity whose route this socket completed", async () => {
    const socket = connectAgent();
    assert.deepEqual(await listedIdentities(socket), []);

    const edgeSession = randomBytes(32);
    assert.equal((await bind(socket, "edge", edgeSession, true))[0], 6);
    // A lone prefix is not a completed route: still no identities.
    assert.deepEqual(await listedIdentities(socket), []);

    const relaySession = randomBytes(32);
    assert.equal((await bind(socket, "relay", relaySession, true))[0], 6);
    // edge->relay is a shared prefix of two routes, neither complete.
    assert.deepEqual(await listedIdentities(socket), []);

    const prodSession = randomBytes(32);
    assert.equal((await bind(socket, "prod", prodSession, false))[0], 6);
    const adminOnly = await listedIdentities(socket);
    assert.equal(adminOnly.length, 1);
    assert.deepEqual(adminOnly[0].blob, adminBlob);
    assert.equal(adminOnly[0].comment, "demo-admin");
    await closed(socket);

    // A different completed path lists only that path's identity.
    const auditorSocket = connectAgent();
    await bindRoute(auditorSocket, ["edge", "test"]);
    const auditorOnly = await listedIdentities(auditorSocket);
    assert.equal(auditorOnly.length, 1);
    assert.deepEqual(auditorOnly[0].blob, auditorBlob);
    assert.equal(auditorOnly[0].comment, "demo-auditor");
    await closed(auditorSocket);

    // The other route sharing the edge->relay prefix maps to the admin key.
    const backupSocket = connectAgent();
    await bindRoute(backupSocket, ["edge", "relay", "test"]);
    const backupOnly = await listedIdentities(backupSocket);
    assert.equal(backupOnly.length, 1);
    assert.deepEqual(backupOnly[0].blob, adminBlob);
    await closed(backupSocket);
  });

  it("keeps every route choice open on a shared prefix", async () => {
    const viaProd = connectAgent();
    const prodSessions = await bindRoute(viaProd, ["edge", "relay", "prod"]);
    await expectSignature(
      viaProd,
      adminBlob,
      adminPrivate,
      hostboundUserauth({
        sessionId: prodSessions[2],
        user: "deploy",
        userKey: adminBlob,
        hostKey: hosts.prod.blob,
      }),
    );
    await closed(viaProd);

    const viaTest = connectAgent();
    const testSessions = await bindRoute(viaTest, ["edge", "relay", "test"]);
    await expectSignature(
      viaTest,
      adminBlob,
      adminPrivate,
      hostboundUserauth({
        sessionId: testSessions[2],
        user: "backup",
        userKey: adminBlob,
        hostKey: hosts.test.blob,
      }),
    );
    await closed(viaTest);
  });

  it("rejects binds that extend no allowed route and keeps prior bindings", async () => {
    const socket = connectAgent();

    // No route starts with relay or with a non-forwarding first hop.
    assert.ok(isFailure(await bind(socket, "relay", randomBytes(32), true)));
    assert.ok(isFailure(await bind(socket, "edge", randomBytes(32), false)));

    const edgeSession = randomBytes(32);
    assert.equal((await bind(socket, "edge", edgeSession, true))[0], 6);

    // After edge, only relay or test may follow; prod extends no route.
    assert.ok(isFailure(await bind(socket, "prod", randomBytes(32), true)));
    // relay is an intermediate hop on its routes: it must be forwarding.
    assert.ok(isFailure(await bind(socket, "relay", randomBytes(32), false)));

    // The failed attempts must not have disturbed the valid edge binding.
    const relaySession = randomBytes(32);
    assert.equal((await bind(socket, "relay", relaySession, true))[0], 6);

    // prod is the final hop of its route: it must not be forwarding.
    assert.ok(isFailure(await bind(socket, "prod", randomBytes(32), true)));
    const prodSession = randomBytes(32);
    assert.equal((await bind(socket, "prod", prodSession, false))[0], 6);

    await expectSignature(
      socket,
      adminBlob,
      adminPrivate,
      hostboundUserauth({
        sessionId: prodSession,
        user: "deploy",
        userKey: adminBlob,
        hostKey: hosts.prod.blob,
      }),
    );
    await closed(socket);
  });

  it("rejects any further bind once the final hop completed", async () => {
    const socket = connectAgent();
    const sessions = await bindRoute(socket, ["edge", "test"]);

    assert.ok(isFailure(await bind(socket, "prod", randomBytes(32), true)));
    assert.ok(isFailure(await bind(socket, "relay", randomBytes(32), true)));
    assert.ok(isFailure(await bind(socket, "test", randomBytes(32), false)));

    // The completed path is untouched and still authorizes its identity.
    await expectSignature(
      socket,
      auditorBlob,
      auditorPrivate,
      hostboundUserauth({
        sessionId: sessions[1],
        user: "audit",
        userKey: auditorBlob,
        hostKey: hosts.test.blob,
      }),
    );
    await closed(socket);
  });

  it("rejects duplicate session IDs without losing the valid path", async () => {
    const socket = connectAgent();
    const edgeSession = randomBytes(32);
    assert.equal((await bind(socket, "edge", edgeSession, true))[0], 6);

    // Reusing the recorded session ID is rejected.
    assert.ok(isFailure(await bind(socket, "relay", edgeSession, true)));

    const relaySession = randomBytes(32);
    assert.equal((await bind(socket, "relay", relaySession, true))[0], 6);
    assert.ok(isFailure(await bind(socket, "prod", relaySession, false)));

    const prodSession = randomBytes(32);
    assert.equal((await bind(socket, "prod", prodSession, false))[0], 6);
    await expectSignature(
      socket,
      adminBlob,
      adminPrivate,
      hostboundUserauth({
        sessionId: prodSession,
        user: "deploy",
        userKey: adminBlob,
        hostKey: hosts.prod.blob,
      }),
    );
    await closed(socket);
  });

  it("verifies each hop signature against the announced host key", async () => {
    const socket = connectAgent();
    const sessionId = randomBytes(32);
    // The edge host key is announced but relay's private key signed.
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(hosts.edge.blob, sessionId, hosts.relay.private, true),
        ),
      ),
    );
    assert.deepEqual(await listedIdentities(socket), []);
    assert.equal((await bind(socket, "edge", sessionId, true))[0], 6);
    await closed(socket);
  });

  it("does not let an identity borrow another identity's route or user", async () => {
    const adminSocket = connectAgent();
    const sessions = await bindRoute(adminSocket, ["edge", "relay", "prod"]);

    // The auditor key is not listed on this path and cannot sign as deploy.
    assert.ok(
      isFailure(
        await request(
          adminSocket,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: sessions[2],
              user: "deploy",
              userKey: auditorBlob,
              hostKey: hosts.prod.blob,
            }),
          ),
        ),
      ),
    );
    // The admin identity cannot use the auditor identity's user...
    assert.ok(
      isFailure(
        await request(
          adminSocket,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: sessions[2],
              user: "audit",
              userKey: adminBlob,
              hostKey: hosts.prod.blob,
            }),
          ),
        ),
      ),
    );
    // ...nor its own user from a different route of the same identity.
    assert.ok(
      isFailure(
        await request(
          adminSocket,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: sessions[2],
              user: "backup",
              userKey: adminBlob,
              hostKey: hosts.prod.blob,
            }),
          ),
        ),
      ),
    );
    await closed(adminSocket);

    // On the auditor path the admin key gains nothing from the auditor user.
    const auditorSocket = connectAgent();
    const auditSessions = await bindRoute(auditorSocket, ["edge", "test"]);
    assert.ok(
      isFailure(
        await request(
          auditorSocket,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: auditSessions[1],
              user: "audit",
              userKey: adminBlob,
              hostKey: hosts.test.blob,
            }),
          ),
        ),
      ),
    );
    assert.ok(
      isFailure(
        await request(
          auditorSocket,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: auditSessions[1],
              user: "deploy",
              userKey: auditorBlob,
              hostKey: hosts.test.blob,
            }),
          ),
        ),
      ),
    );
    await expectSignature(
      auditorSocket,
      auditorBlob,
      auditorPrivate,
      hostboundUserauth({
        sessionId: auditSessions[1],
        user: "audit",
        userKey: auditorBlob,
        hostKey: hosts.test.blob,
      }),
    );
    await closed(auditorSocket);
  });

  it("checks the full hostbound payload against the socket's own last hop", async () => {
    const socket = connectAgent();
    const sessions = await bindRoute(socket, ["edge", "relay", "prod"]);
    const base = {
      sessionId: sessions[2],
      user: "deploy",
      userKey: adminBlob,
      hostKey: hosts.prod.blob,
    };

    const variants = [
      { sessionId: sessions[1] },
      { sessionId: randomBytes(32) },
      { user: "root" },
      { service: "other-service" },
      { method: "publickey" },
      { signatureFollows: false },
      { algorithm: "ssh-ed25519-cert-v01@openssh.com" },
      { userKey: auditorBlob },
      { hostKey: hosts.relay.blob },
      { hostKey: hosts.test.blob },
      { trailing: 1 },
    ];
    for (const variant of variants) {
      assert.ok(
        isFailure(
          await request(
            socket,
            signRequest(
              adminBlob,
              hostboundUserauth({ ...base, ...variant }),
            ),
          ),
        ),
        `variant ${JSON.stringify(Object.keys(variant))} must fail`,
      );
    }
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(adminBlob, hostboundUserauth(base), 1),
        ),
      ),
    );
    assert.ok(
      isFailure(await request(socket, signRequest(adminBlob, randomBytes(64)))),
    );

    await expectSignature(
      socket,
      adminBlob,
      adminPrivate,
      hostboundUserauth(base),
    );
    await closed(socket);
  });

  it("keeps bindings per socket and destroys them on close", async () => {
    const bound = connectAgent();
    const sessions = await bindRoute(bound, ["edge", "relay", "prod"]);

    const other = connectAgent();
    assert.deepEqual(await listedIdentities(other), []);
    assert.ok(
      isFailure(
        await request(
          other,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: sessions[2],
              user: "deploy",
              userKey: adminBlob,
              hostKey: hosts.prod.blob,
            }),
          ),
        ),
      ),
    );
    await closed(other);
    await closed(bound);

    // A new socket starts empty; the same sessions must be bound again.
    const reopened = connectAgent();
    assert.deepEqual(await listedIdentities(reopened), []);
    assert.ok(
      isFailure(
        await request(
          reopened,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: sessions[2],
              user: "deploy",
              userKey: adminBlob,
              hostKey: hosts.prod.blob,
            }),
          ),
        ),
      ),
    );
    for (let i = 0; i < 3; i += 1) {
      const label = ["edge", "relay", "prod"][i];
      assert.equal(
        (await bind(reopened, label, sessions[i], i < 2))[0],
        6,
        `rebind of ${label} after close must succeed`,
      );
    }
    await expectSignature(
      reopened,
      adminBlob,
      adminPrivate,
      hostboundUserauth({
        sessionId: sessions[2],
        user: "deploy",
        userKey: adminBlob,
        hostKey: hosts.prod.blob,
      }),
    );
    await closed(reopened);
  });

  it("rejects unknown host keys and unsupported messages", async () => {
    const socket = connectAgent();
    // Identity keys are not host keys.
    assert.ok(
      isFailure(
        await request(
          socket,
          sessionBind(adminBlob, randomBytes(32), adminPrivate, true),
        ),
      ),
    );
    assert.ok(isFailure(await request(socket, frame(Buffer.from([17])))));
    assert.ok(
      isFailure(
        await request(
          socket,
          frame(new Writer().u8(27).string("query-certs@openssh.com").toBuffer()),
        ),
      ),
    );
    // The socket is still usable afterwards.
    assert.equal((await bind(socket, "edge", randomBytes(32), true))[0], 6);
    await closed(socket);
  });
});

describe("policy validation", () => {
  const keyPath = (name) => join(keyDir, name);
  const validHosts = () => ({
    edge: keyPath("multi-edge.pub.ssh"),
    relay: keyPath("multi-relay.pub.ssh"),
    prod: keyPath("multi-prod.pub.ssh"),
    test: keyPath("multi-test.pub.ssh"),
  });
  const adminIdentity = () => ({
    privateKey: keyPath("multi-admin.pem"),
    comment: "admin",
    routes: [{ hosts: ["edge", "relay", "prod"], user: "deploy" }],
  });
  function writeTempKeys(dir, prefix, count) {    const paths = [];
    for (let i = 0; i < count; i += 1) {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const der = publicKey.export({ type: "spki", format: "der" });
      const blob = new Writer()
        .string("ssh-ed25519")
        .bytes(der.subarray(der.length - 32))
        .toBuffer();
      const pubPath = join(dir, `${prefix}-${i}.pub.ssh`);
      const pemPath = join(dir, `${prefix}-${i}.pem`);
      writeFileSync(pubPath, blob);
      writeFileSync(pemPath, privateKey.export({ type: "pkcs8", format: "pem" }));
      paths.push({ pubPath, pemPath });
    }
    return paths;
  }

  async function expectPolicyRejected(policy, note) {
    const dir = mkdtempSync(join(tmpdir(), "bad-policy-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify(policy));
    const child = spawn(process.execPath, ["src/server.mjs"], {
      cwd: repoRoot,
      env: {
        ...process.env,
        AGENT_POLICY: policyPath,
        SSH_AUTH_SOCK: join(dir, "agent.sock"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    const code = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`server kept running on ${note}: ${output}`));
      }, 5000);
      child.on("exit", (exitCode) => {
        clearTimeout(timer);
        resolve(exitCode);
      });
    });
    assert.notEqual(code, 0, `policy must be rejected (${note}): ${output}`);
  }

  it("rejects duplicate host public keys", async () => {
    const hostsSpec = validHosts();
    hostsSpec.edgeAlias = hostsSpec.edge;
    await expectPolicyRejected(
      { hosts: hostsSpec, identities: [adminIdentity()] },
      "duplicate host key",
    );
  });

  it("rejects duplicate identity keys", async () => {
    const second = adminIdentity();
    second.comment = "admin-copy";
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [adminIdentity(), second] },
      "duplicate identity key",
    );
  });

  it("rejects unknown host labels in routes", async () => {
    const identity = adminIdentity();
    identity.routes = [{ hosts: ["edge", "ghost"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "unknown host label",
    );
  });

  it("rejects routes with too few or too many hops", async () => {
    const short = adminIdentity();
    short.routes = [{ hosts: ["edge"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [short] },
      "single-hop route",
    );

    const long = adminIdentity();
    long.routes = [
      { hosts: ["edge", "relay", "prod", "test", "edge2"], user: "deploy" },
    ];
    const hostsSpec = validHosts();
    hostsSpec.edge2 = keyPath("user_ed25519.pub.ssh");
    await expectPolicyRejected(
      { hosts: hostsSpec, identities: [long] },
      "five-hop route",
    );
  });

  it("rejects routes that revisit a host or repeat within an identity", async () => {
    const loop = adminIdentity();
    loop.routes = [{ hosts: ["edge", "relay", "edge"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [loop] },
      "route revisiting a host",
    );

    const repeated = adminIdentity();
    repeated.routes = [
      { hosts: ["edge", "relay", "prod"], user: "deploy" },
      { hosts: ["edge", "relay", "prod"], user: "backup" },
    ];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [repeated] },
      "duplicate route",
    );
  });

  it("rejects policies beyond the host, identity, and route limits", async () => {
    const dir = mkdtempSync(join(tmpdir(), "policy-keys-"));
    const hostKeys = writeTempKeys(dir, "host", 13);
    const hostsSpec = {};
    for (const [index, { pubPath }] of hostKeys.entries())
      hostsSpec[`h${index}`] = pubPath;
    await expectPolicyRejected(
      {
        hosts: hostsSpec,
        identities: [
          {
            privateKey: keyPath("multi-admin.pem"),
            comment: "admin",
            routes: [{ hosts: ["h0", "h1"], user: "deploy" }],
          },
        ],
      },
      "more than 12 hosts",
    );

    const identityKeys = writeTempKeys(dir, "identity", 9);
    await expectPolicyRejected(
      {
        hosts: validHosts(),
        identities: identityKeys.map(({ pemPath }, index) => ({
          privateKey: pemPath,
          comment: `i${index}`,
          routes: [{ hosts: ["edge", "test"], user: "deploy" }],
        })),
      },
      "more than 8 identities",
    );

    const manyRoutes = adminIdentity();
    manyRoutes.routes = [
      ["edge", "relay"],
      ["edge", "prod"],
      ["edge", "test"],
      ["relay", "edge"],
      ["relay", "prod"],
      ["relay", "test"],
      ["prod", "edge"],
      ["prod", "relay"],
      ["prod", "test"],
    ].map((hostsList) => ({ hosts: hostsList, user: "deploy" }));
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [manyRoutes] },
      "more than 8 routes",
    );
  });

  it("rejects malformed policies as a whole", async () => {
    await expectPolicyRejected({ identities: [adminIdentity()] }, "no hosts");
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [] },
      "no identities",
    );
    const noUser = adminIdentity();
    noUser.routes = [{ hosts: ["edge", "prod"] }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [noUser] },
      "route without user",
    );
    const badKey = { privateKey: 7, comment: "x", routes: [{ hosts: ["edge", "prod"], user: "u" }] };
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [badKey] },
      "non-string privateKey",
    );
  });
});
