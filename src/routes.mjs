import { timingSafeEqual } from "./wire.mjs";

// A hop matches a route position only when the host is the route's host at
// that position and the forwarding flag says whether the hop is intermediate
// (forwarding) or the route's final hop (not forwarding).
function hopMatches(binding, host, intermediate) {
  return (
    binding.forwarding === intermediate &&
    timingSafeEqual(binding.host.blob, host.blob)
  );
}

function matchesPrefix(route, bindings) {
  if (bindings.length > route.hosts.length) return false;
  return bindings.every((binding, index) =>
    hopMatches(binding, route.hosts[index], index < route.hosts.length - 1),
  );
}

function matchesRoute(route, bindings) {
  return (
    bindings.length === route.hosts.length && matchesPrefix(route, bindings)
  );
}

// A socket's bindings are acceptable only while they remain a prefix of at
// least one allowed route of one identity. A shared prefix between routes
// keeps every still-matching route open instead of locking one in early.
export function allowsPrefix(config, bindings) {
  return config.identities.some((identity) =>
    identity.routes.some((route) => matchesPrefix(route, bindings)),
  );
}

// Identities are listed only once the socket's own bindings fully match one
// of the identity's own routes; incomplete or different paths list nothing.
export function availableIdentities(config, bindings) {
  return config.identities.filter((identity) =>
    identity.routes.some((route) => matchesRoute(route, bindings)),
  );
}

// A signature is authorized only for the identity named by the requested
// key, only when the socket's bindings fully match one of that identity's
// own routes, and only for the target user of that exact route.
export function authorizedIdentity(config, bindings, keyBlob, user) {
  const identity = config.identities.find((item) =>
    timingSafeEqual(item.key.blob, keyBlob),
  );
  if (!identity) return null;
  const granted = identity.routes.some(
    (route) => route.user === user && matchesRoute(route, bindings),
  );
  return granted ? identity : null;
}
