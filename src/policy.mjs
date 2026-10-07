import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadPrivateKey, loadSshPublicKey } from "./keys.mjs";

const MAX_POLICY_BYTES = 32768;
const MAX_HOSTS = 12;
const MAX_IDENTITIES = 8;
const MAX_ROUTES_PER_IDENTITY = 8;
const MIN_ROUTE_HOPS = 2;
const MAX_ROUTE_HOPS = 4;

export function loadPolicy(file) {
  const bytes = readFileSync(file);
  if (bytes.length > MAX_POLICY_BYTES) throw new Error("policy too large");
  let spec;
  try {
    spec = JSON.parse(bytes);
  } catch {
    throw new Error("invalid policy");
  }
  const base = dirname(resolve(file));
  if (!spec || typeof spec !== "object" || Array.isArray(spec))
    throw new Error("invalid policy");
  if (
    !spec.hosts ||
    typeof spec.hosts !== "object" ||
    Array.isArray(spec.hosts)
  )
    throw new Error("invalid policy");
  const hostEntries = Object.entries(spec.hosts);
  if (hostEntries.length < 1 || hostEntries.length > MAX_HOSTS)
    throw new Error("invalid policy");
  if (
    !Array.isArray(spec.identities) ||
    spec.identities.length < 1 ||
    spec.identities.length > MAX_IDENTITIES
  )
    throw new Error("invalid policy");

  const hosts = new Map();
  const hostByBlob = new Map();
  for (const [label, path] of hostEntries) {
    if (typeof path !== "string") throw new Error("invalid host");
    const host = loadSshPublicKey(readFileSync(resolve(base, path)));
    const blobId = host.blob.toString("binary");
    // Two labels for the same host key would make hop matching ambiguous.
    if (hostByBlob.has(blobId)) throw new Error("duplicate host public key");
    hosts.set(label, host);
    hostByBlob.set(blobId, host);
  }

  const identities = [];
  const identityKeys = new Set();
  for (const source of spec.identities) {
    if (
      !source ||
      typeof source !== "object" ||
      typeof source.privateKey !== "string" ||
      typeof source.comment !== "string" ||
      !Array.isArray(source.routes) ||
      source.routes.length < 1 ||
      source.routes.length > MAX_ROUTES_PER_IDENTITY
    )
      throw new Error("invalid identity");
    const key = loadPrivateKey(readFileSync(resolve(base, source.privateKey)));
    const keyId = key.blob.toString("binary");
    // Two identities with the same key would make authorization ambiguous.
    if (identityKeys.has(keyId)) throw new Error("duplicate identity key");
    identityKeys.add(keyId);

    const routes = [];
    const routePaths = new Set();
    for (const route of source.routes) {
      if (
        !route ||
        typeof route !== "object" ||
        !Array.isArray(route.hosts) ||
        route.hosts.length < MIN_ROUTE_HOPS ||
        route.hosts.length > MAX_ROUTE_HOPS ||
        typeof route.user !== "string" ||
        route.user.length === 0
      )
        throw new Error("invalid route");
      const hops = route.hosts.map((label) => {
        if (typeof label !== "string") throw new Error("invalid route");
        const host = hosts.get(label);
        if (!host) throw new Error("unknown host");
        return host;
      });
      // A route that visits a host twice cannot be matched deterministically.
      if (new Set(hops).size !== hops.length) throw new Error("invalid route");
      const pathId = hops
        .map((host) => host.blob.toString("binary"))
        .join("\0");
      // Duplicate routes within one identity are ambiguous; reject them.
      if (routePaths.has(pathId)) throw new Error("duplicate route");
      routePaths.add(pathId);
      routes.push({ hosts: hops, user: route.user });
    }
    identities.push({ key, comment: source.comment, routes });
  }
  return { identities, hostByBlob };
}
