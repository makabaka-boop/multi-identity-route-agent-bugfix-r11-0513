import { loadPolicy } from "./policy.mjs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadPrivateKey, loadSshPublicKey } from "./keys.mjs";

export function loadConfig(env = process.env) {
  if (env.AGENT_POLICY) return loadPolicy(env.AGENT_POLICY);
  const keyDir = env.KEY_DIR || "/keys";
  const authorizedUser = env.AUTHORIZED_USER || "deploy";
  const jumpHostname = env.JUMP_HOSTNAME || "bastion.example";
  const targetHostname = env.TARGET_HOSTNAME || "target.example";
  const keyComment = env.KEY_COMMENT || "restricted-demo-ed25519";

  const readKey = (name) => readFileSync(join(keyDir, name));
  const userKey = loadPrivateKey(readKey("user_ed25519"));
  const jumpHost = loadSshPublicKey(readKey("jump_host_ed25519.pub.ssh"));
  const targetHost = loadSshPublicKey(readKey("target_host_ed25519.pub.ssh"));

  const hostByBlob = new Map();
  hostByBlob.set(jumpHost.blob.toString("binary"), jumpHost);
  hostByBlob.set(targetHost.blob.toString("binary"), targetHost);

  return {
    userKey,
    jumpHost,
    targetHost,
    hostByBlob,
    authorizedUser,
    jumpHostname,
    targetHostname,
    keyComment,
  };
}
