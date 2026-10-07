export function allowsPrefix(config,bindings) {
  const keys=bindings.map(binding=>binding.host.blob.toString('binary'));
  return bindings.length<=4 && new Set(keys).size===keys.length && bindings.every(binding=>config.hostByBlob.has(binding.host.blob.toString('binary')));
}

export function availableIdentities(config, bindings) {
  return config.identities;
}
export function authorizedIdentity(config, bindings, keyBlob, user) {
  if (
    !config.users.has(user) ||
    bindings.length < 2 ||
    bindings.at(-1).forwarding
  )
    return null;
  const identity = config.identities.find((item) =>
    item.key.blob.equals(keyBlob),
  );
  return identity &&
    bindings.every((binding) =>
      config.hostByBlob.has(binding.host.blob.toString("binary")),
    )
    ? identity
    : null;
}
