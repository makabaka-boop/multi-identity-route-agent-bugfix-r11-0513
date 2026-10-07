import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadPrivateKey, loadSshPublicKey } from "./keys.mjs";
export function loadPolicy(file) {
  const bytes = readFileSync(file);
  if (bytes.length > 32768) throw Error("policy too large");
  const spec = JSON.parse(bytes),
    base = dirname(resolve(file));
  if (
    !spec.hosts ||
    !Array.isArray(spec.identities) ||
    spec.identities.length < 1 ||
    spec.identities.length > 8
  )
    throw Error("invalid policy");
  const hosts = new Map(),
    hostByBlob = new Map();
  for (const [label, path] of Object.entries(spec.hosts)) {
    const host = loadSshPublicKey(readFileSync(resolve(base, path)));
    hosts.set(label, host);
    hostByBlob.set(host.blob.toString("binary"), host);
  }
  const identities = [];
  const users = new Set();
  for (const source of spec.identities) {
    if (
      typeof source.privateKey !== "string" ||
      typeof source.comment !== "string" ||
      !Array.isArray(source.routes) ||
      !source.routes.length
    )
      throw Error("invalid identity");
    const allowedHosts = [];
    for (const route of source.routes) {
      if (
        !Array.isArray(route.hosts) ||
        route.hosts.length < 2 ||
        route.hosts.length > 4 ||
        typeof route.user !== "string"
      )
        throw Error("invalid route");
      for (const label of route.hosts) {
        const host = hosts.get(label);
        if (!host) throw Error("unknown host");
        if (!allowedHosts.includes(host)) allowedHosts.push(host);
      }
      users.add(route.user);
    }
    identities.push({
      key: loadPrivateKey(readFileSync(resolve(base, source.privateKey))),
      comment: source.comment,
      allowedHosts,
    });
  }
  return { identities, hostByBlob, users };
}
