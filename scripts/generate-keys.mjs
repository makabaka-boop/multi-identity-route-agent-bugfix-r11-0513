#!/usr/bin/env node
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { Writer } from "../src/wire.mjs";

const outDir = process.argv[2] || join(process.cwd(), "keys");
mkdirSync(outDir, { recursive: true });

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function seed(label) {
  return createHash("sha256")
    .update(`restricted-ssh-agent-demo:${label}`)
    .digest();
}

function keyPair(label) {
  const der = Buffer.concat([PKCS8_PREFIX, seed(label)]);
  const privateKey = createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const rawPublic = publicDer.subarray(publicDer.length - 32);
  if (!Buffer.concat([SPKI_PREFIX, rawPublic]).equals(publicDer)) {
    throw new Error("unexpected Ed25519 SPKI encoding");
  }
  const sshBlob = new Writer()
    .string("ssh-ed25519")
    .bytes(rawPublic)
    .toBuffer();
  return { privateKey, publicKey, sshBlob, rawPublic };
}

function writePem(name, key, type) {
  const path = join(outDir, name);
  writeFileSync(path, key.export({ format: "pem", type }), { mode: 0o600 });
  chmodSync(path, 0o600);
}

function writeSshBlob(name, blob) {
  const path = join(outDir, name);
  writeFileSync(path, blob, { mode: 0o644 });
  chmodSync(path, 0o644);
}

const pairs = {
  user: keyPair("demo-user-key"),
  jump: keyPair("fixed-jump-host-key"),
  target: keyPair("fixed-target-host-key"),
};

writePem("user_ed25519", pairs.user.privateKey, "pkcs8");
writePem("user_ed25519.pub.pem", pairs.user.publicKey, "spki");
writeSshBlob("user_ed25519.pub.ssh", pairs.user.sshBlob);

writePem("jump_host_ed25519", pairs.jump.privateKey, "pkcs8");
writePem("jump_host_ed25519.pub.pem", pairs.jump.publicKey, "spki");
writeSshBlob("jump_host_ed25519.pub.ssh", pairs.jump.sshBlob);

writePem("target_host_ed25519", pairs.target.privateKey, "pkcs8");
writePem("target_host_ed25519.pub.pem", pairs.target.publicKey, "spki");
writeSshBlob("target_host_ed25519.pub.ssh", pairs.target.sshBlob);

console.log(`Generated deterministic demo Ed25519 keys in ${outDir}`);
