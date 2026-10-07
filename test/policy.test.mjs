import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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
import {
  encodeEd25519Public,
  parseEd25519SignatureBlob,
} from "../src/keys.mjs";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const keyDir = join(repoRoot, "keys");
const read = (name) => readFileSync(join(keyDir, name));

const edgeBlob = read("multi-edge.pub.ssh");
const relayBlob = read("multi-relay.pub.ssh");
const prodBlob = read("multi-prod.pub.ssh");
const testBlob = read("multi-test.pub.ssh");
const edgePrivate = read("multi-edge.pem");
const relayPrivate = read("multi-relay.pem");
const prodPrivate = read("multi-prod.pem");
const testPrivate = read("multi-test.pem");
const adminBlob = read("multi-admin.pub.ssh");
const auditorBlob = read("multi-auditor.pub.ssh");
const adminPrivate = read("multi-admin.pem");
const auditorPrivate = read("multi-auditor.pem");

const HOPS = {
  edge: { blob: edgeBlob, privateKey: edgePrivate },
  relay: { blob: relayBlob, privateKey: relayPrivate },
  prod: { blob: prodBlob, privateKey: prodPrivate },
  test: { blob: testBlob, privateKey: testPrivate },
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

function hostboundUserauth({
  sessionId,
  user,
  userKey,
  hostKey,
  service = "ssh-connection",
  method = "publickey-hostbound-v00@openssh.com",
  signatureFollows = true,
  algorithm = "ssh-ed25519",
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
    socket.waiters.push({
      resolve(message) {
        clearTimeout(timer);
        resolve(message);
      },
    });
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

async function bind(socket, hop, sessionId, forwarding) {
  const answer = await request(
    socket,
    sessionBind(hop.blob, sessionId, hop.privateKey, forwarding),
  );
  return answer[0];
}

// Binds a full route and returns the per-hop session IDs.
async function bindRoute(socket, hops) {
  const sessions = [];
  hops.forEach((hop, index) => {
    sessions[index] = randomBytes(32);
  });
  for (let index = 0; index < hops.length; index += 1) {
    const forwarding = index < hops.length - 1;
    assert.equal(await bind(socket, HOPS[hops[index]], sessions[index], forwarding), 6);
  }
  return sessions;
}

async function identities(socket) {
  const answer = await request(socket, identitiesRequest());
  const reader = new Reader(answer);
  assert.equal(reader.u8(), 12);
  const count = reader.u32();
  const items = [];
  for (let i = 0; i < count; i += 1)
    items.push({ blob: reader.bytes(), comment: reader.string() });
  reader.end();
  return items;
}

async function expectSignature(socket, keyBlob, data, privateKey) {
  const answer = await request(socket, signRequest(keyBlob, data));
  assert.equal(answer[0], 14);
  const reader = new Reader(answer);
  assert.equal(reader.u8(), 14);
  const rawSignature = parseEd25519SignatureBlob(reader.bytes());
  reader.end();
  assert.ok(rawSignature);
  assert.ok(cryptoVerify(null, data, privateKey, rawSignature));
}

describe("multi-identity policy mode", () => {
  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-policy-"));
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

  it("lists no identity before a route completes on this socket", async () => {
    const socket = connectAgent();
    assert.deepEqual(await identities(socket), []);

    assert.equal(await bind(socket, HOPS.edge, randomBytes(32), true), 6);
    assert.deepEqual(await identities(socket), []);

    // A shared prefix of two routes is still not a completed route.
    assert.equal(await bind(socket, HOPS.relay, randomBytes(32), true), 6);
    assert.deepEqual(await identities(socket), []);
    await closed(socket);
  });

  it("keeps every route choice open while bindings follow a shared prefix", async () => {
    // edge -> relay is a prefix of both admin routes; either final hop works.
    const viaProd = connectAgent();
    const prodSessions = await bindRoute(viaProd, ["edge", "relay", "prod"]);
    assert.deepEqual(await identities(viaProd), [
      { blob: adminBlob, comment: "demo-admin" },
    ]);
    await expectSignature(
      viaProd,
      adminBlob,
      hostboundUserauth({
        sessionId: prodSessions[2],
        user: "deploy",
        userKey: adminBlob,
        hostKey: prodBlob,
      }),
      adminPrivate,
    );
    // The sibling route's user is not authorized on this completed route.
    assert.ok(
      isFailure(
        await request(
          viaProd,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: prodSessions[2],
              user: "backup",
              userKey: adminBlob,
              hostKey: prodBlob,
            }),
          ),
        ),
      ),
    );
    await closed(viaProd);

    const viaTest = connectAgent();
    const testSessions = await bindRoute(viaTest, ["edge", "relay", "test"]);
    assert.deepEqual(await identities(viaTest), [
      { blob: adminBlob, comment: "demo-admin" },
    ]);
    await expectSignature(
      viaTest,
      adminBlob,
      hostboundUserauth({
        sessionId: testSessions[2],
        user: "backup",
        userKey: adminBlob,
        hostKey: testBlob,
      }),
      adminPrivate,
    );
    assert.ok(
      isFailure(
        await request(
          viaTest,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: testSessions[2],
              user: "deploy",
              userKey: adminBlob,
              hostKey: testBlob,
            }),
          ),
        ),
      ),
    );
    await closed(viaTest);
  });

  it("authorizes each identity only on its own routes and users", async () => {
    // The auditor route edge -> test belongs to the auditor alone.
    const socket = connectAgent();
    const sessions = await bindRoute(socket, ["edge", "test"]);
    assert.deepEqual(await identities(socket), [
      { blob: auditorBlob, comment: "demo-auditor" },
    ]);

    const auditorAuth = hostboundUserauth({
      sessionId: sessions[1],
      user: "audit",
      userKey: auditorBlob,
      hostKey: testBlob,
    });
    await expectSignature(socket, auditorBlob, auditorAuth, auditorPrivate);

    // The admin key cannot borrow the auditor's path and user.
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(
            adminBlob,
            hostboundUserauth({
              sessionId: sessions[1],
              user: "audit",
              userKey: adminBlob,
              hostKey: testBlob,
            }),
          ),
        ),
      ),
    );
    // The auditor cannot use another identity's user on its own path.
    assert.ok(
      isFailure(
        await request(
          socket,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: sessions[1],
              user: "deploy",
              userKey: auditorBlob,
              hostKey: testBlob,
            }),
          ),
        ),
      ),
    );
    await closed(socket);

    // And the auditor key gains nothing from the admin's completed route.
    const adminSocket = connectAgent();
    const adminSessions = await bindRoute(adminSocket, ["edge", "relay", "prod"]);
    assert.ok(
      isFailure(
        await request(
          adminSocket,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: adminSessions[2],
              user: "deploy",
              userKey: auditorBlob,
              hostKey: prodBlob,
            }),
          ),
        ),
      ),
    );
    await closed(adminSocket);
  });

  it("rejects failed bindings without disturbing the valid prefix", async () => {
    const socket = connectAgent();
    const edgeSession = randomBytes(32);
    assert.equal(await bind(socket, HOPS.edge, edgeSession, true), 6);

    // edge -> prod is no route prefix.
    assert.equal(await bind(socket, HOPS.prod, randomBytes(32), true), 5);
    // relay is an intermediate hop and may not carry the final-hop flag.
    assert.equal(await bind(socket, HOPS.relay, randomBytes(32), false), 5);
    // A forged host signature is rejected.
    const forged = new Writer()
      .u8(27)
      .string("session-bind@openssh.com")
      .bytes(relayBlob)
      .bytes(randomBytes(32))
      .bytes(hostSignature(relayPrivate, randomBytes(32)))
      .bool(true)
      .toBuffer();
    assert.ok(isFailure(await request(socket, frame(forged))));
    // Repeating the first hop is not a prefix of any route either.
    assert.equal(await bind(socket, HOPS.edge, randomBytes(32), true), 5);

    // The earlier valid hop survived every failed attempt.
    assert.deepEqual(await identities(socket), []);
    const relaySession = randomBytes(32);
    const prodSession = randomBytes(32);
    assert.equal(await bind(socket, HOPS.relay, relaySession, true), 6);
    assert.equal(await bind(socket, HOPS.prod, prodSession, false), 6);
    await expectSignature(
      socket,
      adminBlob,
      hostboundUserauth({
        sessionId: prodSession,
        user: "deploy",
        userKey: adminBlob,
        hostKey: prodBlob,
      }),
      adminPrivate,
    );
    await closed(socket);
  });

  it("rejects out-of-order first hops and wrong forwarding flags", async () => {
    const socket = connectAgent();
    // No route starts with relay, test, or prod.
    assert.equal(await bind(socket, HOPS.relay, randomBytes(32), true), 5);
    assert.equal(await bind(socket, HOPS.test, randomBytes(32), true), 5);
    // The first hop of every route is a forwarding hop.
    assert.equal(await bind(socket, HOPS.edge, randomBytes(32), false), 5);

    // The socket is still usable after the rejected attempts.
    const sessions = await bindRoute(socket, ["edge", "relay", "test"]);
    await expectSignature(
      socket,
      adminBlob,
      hostboundUserauth({
        sessionId: sessions[2],
        user: "backup",
        userKey: adminBlob,
        hostKey: testBlob,
      }),
      adminPrivate,
    );
    await closed(socket);
  });

  it("refuses to extend the path after the final hop", async () => {
    const socket = connectAgent();
    const sessions = await bindRoute(socket, ["edge", "test"]);

    // The route is complete: no further hop may follow, in either flag form.
    assert.equal(await bind(socket, HOPS.prod, randomBytes(32), false), 5);
    assert.equal(await bind(socket, HOPS.relay, randomBytes(32), true), 5);

    // The completed route still authorizes its own identity.
    assert.deepEqual(await identities(socket), [
      { blob: auditorBlob, comment: "demo-auditor" },
    ]);
    await expectSignature(
      socket,
      auditorBlob,
      hostboundUserauth({
        sessionId: sessions[1],
        user: "audit",
        userKey: auditorBlob,
        hostKey: testBlob,
      }),
      auditorPrivate,
    );
    await closed(socket);
  });

  it("rejects duplicate session IDs across hops", async () => {
    const socket = connectAgent();
    const shared = randomBytes(32);
    assert.equal(await bind(socket, HOPS.edge, shared, true), 6);
    assert.equal(await bind(socket, HOPS.relay, shared, true), 5);
    assert.equal(await bind(socket, HOPS.relay, randomBytes(32), true), 6);
    assert.equal(await bind(socket, HOPS.prod, randomBytes(32), false), 6);
    await closed(socket);
  });

  it("checks the full hostbound payload against the bound route", async () => {
    const socket = connectAgent();
    const sessions = await bindRoute(socket, ["edge", "relay", "prod"]);
    const base = {
      sessionId: sessions[2],
      user: "deploy",
      userKey: adminBlob,
      hostKey: prodBlob,
    };

    const variants = [
      { sessionId: sessions[1] },
      { sessionId: randomBytes(32) },
      { user: "root" },
      { user: "backup" },
      { service: "other-service" },
      { method: "publickey" },
      { signatureFollows: false },
      { algorithm: "ssh-ed25519-cert-v01@openssh.com" },
      { userKey: auditorBlob },
      { hostKey: testBlob },
      { hostKey: relayBlob },
      { trailing: 1 },
    ];
    for (const variant of variants) {
      assert.ok(
        isFailure(
          await request(
            socket,
            signRequest(adminBlob, hostboundUserauth({ ...base, ...variant })),
          ),
        ),
        `variant should fail: ${JSON.stringify(Object.keys(variant))}`,
      );
    }
    assert.ok(
      isFailure(
        await request(socket, signRequest(adminBlob, hostboundUserauth(base), 1)),
      ),
    );
    assert.ok(
      isFailure(
        await request(socket, signRequest(adminBlob, randomBytes(128))),
      ),
    );

    await expectSignature(socket, adminBlob, hostboundUserauth(base), adminPrivate);
    await closed(socket);
  });

  it("keeps bindings per socket and destroys them on close", async () => {
    const bound = connectAgent();
    const sessions = await bindRoute(bound, ["edge", "test"]);

    const other = connectAgent();
    assert.deepEqual(await identities(other), []);
    assert.ok(
      isFailure(
        await request(
          other,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: sessions[1],
              user: "audit",
              userKey: auditorBlob,
              hostKey: testBlob,
            }),
          ),
        ),
      ),
    );
    await closed(bound);
    await closed(other);

    // A fresh socket starts empty even for previously used session IDs.
    const reopened = connectAgent();
    assert.deepEqual(await identities(reopened), []);
    assert.ok(
      isFailure(
        await request(
          reopened,
          signRequest(
            auditorBlob,
            hostboundUserauth({
              sessionId: sessions[1],
              user: "audit",
              userKey: auditorBlob,
              hostKey: testBlob,
            }),
          ),
        ),
      ),
    );
    const rebound = await bindRoute(reopened, ["edge", "test"]);
    await expectSignature(
      reopened,
      auditorBlob,
      hostboundUserauth({
        sessionId: rebound[1],
        user: "audit",
        userKey: auditorBlob,
        hostKey: testBlob,
      }),
      auditorPrivate,
    );
    await closed(reopened);
  });
});

describe("policy startup validation", () => {
  const validHosts = () => ({
    edge: join(keyDir, "multi-edge.pub.ssh"),
    relay: join(keyDir, "multi-relay.pub.ssh"),
    prod: join(keyDir, "multi-prod.pub.ssh"),
    test: join(keyDir, "multi-test.pub.ssh"),
  });
  const validRoute = () => ({ hosts: ["edge", "prod"], user: "deploy" });
  const validIdentity = () => ({
    privateKey: join(keyDir, "multi-admin.pem"),
    comment: "demo-admin",
    routes: [validRoute()],
  });

  function writeKeyPair(dir, name) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pem = join(dir, `${name}.pem`);
    writeFileSync(pem, privateKey.export({ format: "pem", type: "pkcs8" }), {
      mode: 0o600,
    });
    const pub = join(dir, `${name}.pub.ssh`);
    writeFileSync(pub, encodeEd25519Public(publicKey));
    return { pem, pub };
  }

  async function expectPolicyRejected(policy, note) {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-invalid-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify(policy));
    const sock = join(dir, "agent.sock");
    const child = spawn(process.execPath, ["src/server.mjs"], {
      cwd: repoRoot,
      env: { ...process.env, AGENT_POLICY: policyPath, SSH_AUTH_SOCK: sock },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    const exitCode = await new Promise((resolve) =>
      child.on("exit", resolve),
    );
    assert.notEqual(
      exitCode,
      0,
      `${note}: server must exit non-zero (output: ${output.trim()})`,
    );
    assert.ok(!existsSync(sock), `${note}: no socket may be created`);
  }

  it("rejects a duplicate host public key", async () => {
    await expectPolicyRejected(
      {
        hosts: {
          edge: join(keyDir, "multi-edge.pub.ssh"),
          edgeAlias: join(keyDir, "multi-edge.pub.ssh"),
        },
        identities: [validIdentity()],
      },
      "duplicate host key",
    );
  });

  it("rejects a duplicate identity public key", async () => {
    const second = validIdentity();
    second.comment = "demo-admin-copy";
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [validIdentity(), second] },
      "duplicate identity key",
    );
  });

  it("rejects an unknown host label in a route", async () => {
    const identity = validIdentity();
    identity.routes = [{ hosts: ["edge", "ghost"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "unknown host label",
    );
  });

  it("rejects routes with too few or too many hops", async () => {
    const shortRoute = validIdentity();
    shortRoute.routes = [{ hosts: ["edge"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [shortRoute] },
      "single-hop route",
    );

    const longRoute = validIdentity();
    longRoute.routes = [
      { hosts: ["edge", "relay", "prod", "test", "edge"], user: "deploy" },
    ];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [longRoute] },
      "five-hop route",
    );
  });

  it("rejects a route that repeats a host", async () => {
    const identity = validIdentity();
    identity.routes = [{ hosts: ["edge", "relay", "relay"], user: "deploy" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "repeated host in route",
    );
  });

  it("rejects duplicate routes within one identity", async () => {
    const identity = validIdentity();
    identity.routes = [validRoute(), validRoute()];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "duplicate route",
    );
  });

  it("rejects a route without a target user", async () => {
    const identity = validIdentity();
    identity.routes = [{ hosts: ["edge", "prod"], user: "" }];
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "empty route user",
    );
  });

  it("rejects more than eight routes for one identity", async () => {
    const identity = validIdentity();
    identity.routes = Array.from({ length: 9 }, (_, index) => ({
      hosts: ["edge", "prod"],
      user: `user-${index}`,
    }));
    await expectPolicyRejected(
      { hosts: validHosts(), identities: [identity] },
      "nine routes",
    );
  });

  it("rejects more than twelve hosts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-keys-"));
    const hosts = {};
    for (let index = 0; index < 13; index += 1) {
      hosts[`host-${index}`] = writeKeyPair(dir, `host-${index}`).pub;
    }
    const identity = validIdentity();
    identity.privateKey = writeKeyPair(dir, "identity").pem;
    identity.routes = [{ hosts: ["host-0", "host-1"], user: "deploy" }];
    await expectPolicyRejected({ hosts, identities: [identity] }, "13 hosts");
  });

  it("rejects more than eight identities", async () => {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-keys-"));
    const identities = Array.from({ length: 9 }, (_, index) => ({
      privateKey: writeKeyPair(dir, `identity-${index}`).pem,
      comment: `identity-${index}`,
      routes: [validRoute()],
    }));
    await expectPolicyRejected(
      { hosts: validHosts(), identities },
      "nine identities",
    );
  });

  it("rejects a policy that is not valid JSON", async () => {
    const dir = mkdtempSync(join(tmpdir(), "restricted-agent-invalid-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, "{ not json");
    const sock = join(dir, "agent.sock");
    const child = spawn(process.execPath, ["src/server.mjs"], {
      cwd: repoRoot,
      env: { ...process.env, AGENT_POLICY: policyPath, SSH_AUTH_SOCK: sock },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const exitCode = await new Promise((resolve) =>
      child.on("exit", resolve),
    );
    assert.notEqual(exitCode, 0);
    assert.ok(!existsSync(sock));
  });
});
