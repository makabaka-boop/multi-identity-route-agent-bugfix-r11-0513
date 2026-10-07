import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { Reader, Writer } from "./wire.mjs";

const ED25519_NAME = "ssh-ed25519";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export { ED25519_NAME };

export function encodeEd25519Public(keyObject) {
  const der = keyObject.export({ type: "spki", format: "der" });
  const raw = der.subarray(der.length - 32);
  return new Writer().string(ED25519_NAME).bytes(raw).toBuffer();
}

export function importSshEd25519Public(blob) {
  let reader;
  try {
    reader = new Reader(blob);
    const name = reader.string();
    const raw = reader.bytes();
    reader.end();
    if (name !== ED25519_NAME || raw.length !== 32) return null;
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
    return { key, blob: Buffer.from(blob), raw, name };
  } catch {
    return null;
  }
}

export function loadPrivateKey(pem) {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("only Ed25519 keys are supported");
  const publicKey = createPublicKey(key);
  const blob = encodeEd25519Public(publicKey);
  const raw = importSshEd25519Public(blob).raw;
  return {
    key,
    publicKey,
    blob,
    raw,
    type: ED25519_NAME,
  };
}

export function loadSshPublicKey(blob) {
  const parsed = importSshEd25519Public(blob);
  if (!parsed) throw new Error("unsupported host public key");
  return parsed;
}

export function makeEd25519SignatureBlob(rawSignature) {
  if (rawSignature.length !== 64)
    throw new Error("invalid Ed25519 signature length");
  return new Writer().string(ED25519_NAME).bytes(rawSignature).toBuffer();
}

export function parseEd25519SignatureBlob(blob) {
  try {
    const reader = new Reader(blob);
    const name = reader.string();
    const raw = reader.bytes();
    reader.end();
    if (name !== ED25519_NAME || raw.length !== 64) return null;
    return raw;
  } catch {
    return null;
  }
}

export function signRaw(privateKey, data) {
  return cryptoSign(null, data, privateKey);
}

export function verifyRaw(publicKey, data, signature) {
  try {
    return cryptoVerify(null, data, publicKey, signature);
  } catch {
    return false;
  }
}

export function verifyHostBinding(host, sessionId, signatureBlob) {
  const rawSignature = parseEd25519SignatureBlob(signatureBlob);
  if (!rawSignature) return false;
  return verifyRaw(host.key, sessionId, rawSignature);
}
