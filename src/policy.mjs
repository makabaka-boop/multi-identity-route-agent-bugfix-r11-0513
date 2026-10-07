import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadPrivateKey, loadSshPublicKey } from "./keys.mjs";

const MAX_POLICY_BYTES = 32768;
const MAX_HOSTS = 12;
const MAX_IDENTITIES = 8;
const MAX_ROUTES_PER_IDENTITY = 8;
const MIN_ROUTE_HOPS = 2;
const MAX_ROUTE_HOPS = 4;

// Any violation rejects the whole policy before the service starts; a
// partially loaded policy is never returned.
export function loadPolicy(file) {
  const bytes = readFileSync(file);
  if (bytes.length > MAX_POLICY_BYTES) throw new Error("policy too large");
  let spec;
  try {
    spec = JSON.parse(bytes);
  } catch {
    throw new Error("policy is not valid JSON");
  }
  const base = dirname(resolve(file));

  if (!spec.hosts || typeof spec.hosts !== "object" || Array.isArray(spec.hosts))
    throw new Error("invalid policy: hosts must be an object");
  const hostEntries = Object.entries(spec.hosts);
  if (hostEntries.length < 1 || hostEntries.length > MAX_HOSTS)
    throw new Error(`invalid policy: expected 1..${MAX_HOSTS} hosts`);

  const hosts = new Map();
  const hostByBlob = new Map();
  for (const [label, path] of hostEntries) {
    if (typeof path !== "string" || path.length === 0)
      throw new Error(`invalid policy: host "${label}" needs a key path`);
    const host = loadSshPublicKey(readFileSync(resolve(base, path)));
    const id = host.blob.toString("binary");
    if (hostByBlob.has(id))
      throw new Error(`invalid policy: duplicate host public key ("${label}")`);
    hosts.set(label, host);
    hostByBlob.set(id, host);
  }

  if (
    !Array.isArray(spec.identities) ||
    spec.identities.length < 1 ||
    spec.identities.length > MAX_IDENTITIES
  )
    throw new Error(`invalid policy: expected 1..${MAX_IDENTITIES} identities`);

  const identities = [];
  const identityKeys = new Set();
  const users = new Set();
  for (const source of spec.identities) {
    if (
      !source ||
      typeof source.privateKey !== "string" ||
      typeof source.comment !== "string" ||
      !Array.isArray(source.routes) ||
      source.routes.length < 1 ||
      source.routes.length > MAX_ROUTES_PER_IDENTITY
    )
      throw new Error(
        `invalid policy: identity needs privateKey, comment and 1..${MAX_ROUTES_PER_IDENTITY} routes`,
      );

    const key = loadPrivateKey(readFileSync(resolve(base, source.privateKey)));
    const keyId = key.blob.toString("binary");
    if (identityKeys.has(keyId))
      throw new Error("invalid policy: duplicate identity public key");
    identityKeys.add(keyId);

    const routes = [];
    const seenRoutes = new Set();
    for (const route of source.routes) {
      if (
        !route ||
        !Array.isArray(route.hosts) ||
        route.hosts.length < MIN_ROUTE_HOPS ||
        route.hosts.length > MAX_ROUTE_HOPS ||
        route.hosts.some((label) => typeof label !== "string") ||
        typeof route.user !== "string" ||
        route.user.length === 0
      )
        throw new Error(
          `invalid policy: routes need ${MIN_ROUTE_HOPS}..${MAX_ROUTE_HOPS} host labels and a user`,
        );
      if (new Set(route.hosts).size !== route.hosts.length)
        throw new Error("invalid policy: route repeats a host");
      const routeId = JSON.stringify([route.hosts, route.user]);
      if (seenRoutes.has(routeId))
        throw new Error("invalid policy: duplicate route in identity");
      seenRoutes.add(routeId);

      const routeHosts = route.hosts.map((label) => {
        const host = hosts.get(label);
        if (!host)
          throw new Error(`invalid policy: unknown host label "${label}"`);
        return host;
      });
      users.add(route.user);
      routes.push({ hosts: routeHosts, user: route.user });
    }

    identities.push({ key, comment: source.comment, routes });
  }

  return { identities, hostByBlob, users };
}
