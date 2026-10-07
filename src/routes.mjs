// Route matching for the multi-identity policy mode. A socket's bindings are
// authorized only while they form an exact hop-by-hop prefix of at least one
// configured route: intermediate hops must be marked forwarding and only the
// route's final hop may be non-forwarding. Routes that share a prefix stay
// open until a hop selects one of them.

function routeAllows(route, bindings) {
  if (bindings.length > route.hosts.length) return false;
  return bindings.every((binding, index) => {
    const finalHop = index === route.hosts.length - 1;
    return (
      binding.forwarding !== finalHop &&
      binding.host.blob.equals(route.hosts[index].blob)
    );
  });
}

function completesRoute(route, bindings) {
  return bindings.length === route.hosts.length && routeAllows(route, bindings);
}

export function allowsPrefix(config, bindings) {
  return config.identities.some((identity) =>
    identity.routes.some((route) => routeAllows(route, bindings)),
  );
}

export function availableIdentities(config, bindings) {
  return config.identities.filter((identity) =>
    identity.routes.some((route) => completesRoute(route, bindings)),
  );
}

export function authorizedIdentity(config, bindings, keyBlob, user) {
  const identity = config.identities.find((item) =>
    item.key.blob.equals(keyBlob),
  );
  if (!identity) return null;
  const authorized = identity.routes.some(
    (route) => route.user === user && completesRoute(route, bindings),
  );
  return authorized ? identity : null;
}
