import {
  allowsPrefix,
  availableIdentities,
  authorizedIdentity,
} from "./routes.mjs";
import { randomUUID } from "node:crypto";
import { Reader, Writer, timingSafeEqual } from "./wire.mjs";
import {
  ED25519_NAME,
  makeEd25519SignatureBlob,
  signRaw,
  verifyHostBinding,
} from "./keys.mjs";

export const SSH_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH2_AGENT_IDENTITIES_ANSWER = 12;
export const SSH_AGENTC_SIGN_REQUEST = 13;
export const SSH2_AGENT_SIGN_RESPONSE = 14;
export const SSH_AGENTC_EXTENSION = 27;
export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SUCCESS = 6;

const SESSION_BIND_EXTENSION = "session-bind@openssh.com";
const SSH2_MSG_USERAUTH_REQUEST = 50;
const HOSTBOUND_METHOD = "publickey-hostbound-v00@openssh.com";
const SSH_CONNECTION_SERVICE = "ssh-connection";
const MAX_SESSION_ID = 256;

function failure() {
  return Buffer.from([SSH_AGENT_FAILURE]);
}

function success() {
  return Buffer.from([SSH_AGENT_SUCCESS]);
}

function equalString(a, b) {
  return a === b;
}

class Binding {
  constructor(host, sessionId, forwarding) {
    this.host = host;
    this.sessionId = sessionId;
    this.forwarding = forwarding;
  }
}

export class SocketState {
  constructor(id, config) {
    this.id = id;
    this.config = config;
    this.bindings = [];
    this.destroyed = false;
  }

  addSessionBind(host, sessionId, signatureBlob, forwarding) {
    // Validate before mutation. Invalid attempts must never pollute a good path.
    if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID)
      return false;
    if (!verifyHostBinding(host, sessionId, signatureBlob)) return false;

    if (
      this.bindings.some((binding) =>
        timingSafeEqual(binding.sessionId, sessionId),
      )
    ) {
      return false;
    }
    if (this.config.identities) {
      if (
        this.destroyed ||
        (this.bindings.length && !this.bindings.at(-1).forwarding)
      )
        return false;
      const binding = new Binding(host, Buffer.from(sessionId), forwarding);
      this.bindings.push(binding);
      if (!allowsPrefix(this.config, this.bindings)) return false;
      return true;
    }
    if (this.bindings.length === 1 && !this.bindings[0].forwarding)
      return false;
    if (this.bindings.length >= 2) return false;

    if (this.bindings.length === 0) {
      if (!forwarding) return false;
      if (!timingSafeEqual(host.blob, this.config.jumpHost.blob)) return false;
    } else {
      if (forwarding) return false;
      if (!timingSafeEqual(host.blob, this.config.targetHost.blob))
        return false;
    }

    this.bindings.push(new Binding(host, Buffer.from(sessionId), forwarding));
    return true;
  }

  isCompletePath() {
    return (
      this.bindings.length === 2 &&
      this.bindings[0].forwarding &&
      !this.bindings[1].forwarding &&
      timingSafeEqual(this.bindings[0].host.blob, this.config.jumpHost.blob) &&
      timingSafeEqual(this.bindings[1].host.blob, this.config.targetHost.blob)
    );
  }

  signAuthorized(userKeyBlob, data, flags) {
    if (this.config.identities) {
      if (flags !== 0 || this.destroyed) return null;
      const parsed = parseHostboundUserauth(data, userKeyBlob);
      if (!parsed) return null;
      const identity = authorizedIdentity(
        this.config,
        this.bindings,
        userKeyBlob,
        parsed.user,
      );
      const target = this.bindings.at(-1);
      if (
        !identity ||
        !target ||
        !timingSafeEqual(parsed.sessionId, target.sessionId) ||
        !timingSafeEqual(parsed.hostKeyBlob, target.host.blob)
      )
        return null;
      return makeEd25519SignatureBlob(signRaw(identity.key.key, data));
    }

    if (!this.isCompletePath()) return null;
    if (!timingSafeEqual(userKeyBlob, this.config.userKey.blob)) return null;
    if (flags !== 0) return null;

    const parsed = parseHostboundUserauth(data, userKeyBlob);
    if (!parsed) return null;
    const targetBinding = this.bindings[1];

    // Every item in the authorization decision is checked explicitly. Checking
    // only a digest or one embedded field would permit swapped connection
    // metadata to be paired with a valid signature payload.
    if (!timingSafeEqual(parsed.sessionId, targetBinding.sessionId))
      return null;
    if (!equalString(parsed.user, this.config.authorizedUser)) return null;
    if (!equalString(parsed.service, SSH_CONNECTION_SERVICE)) return null;
    if (!equalString(parsed.method, HOSTBOUND_METHOD)) return null;
    if (!equalString(parsed.algorithm, ED25519_NAME)) return null;
    if (!timingSafeEqual(parsed.userKeyBlob, this.config.userKey.blob))
      return null;
    if (!timingSafeEqual(parsed.hostKeyBlob, targetBinding.host.blob))
      return null;

    return makeEd25519SignatureBlob(signRaw(this.config.userKey.key, data));
  }
}

function parseHostboundUserauth(data, expectedUserKeyBlob) {
  try {
    const outer = new Reader(data);
    const sessionId = outer.bytes();
    const type = outer.u8();
    const user = outer.string();
    const service = outer.string();
    const method = outer.string();
    const signatureFollows = outer.bool();
    const algorithm = outer.string();
    const userKeyBlob = outer.bytes();
    const hostKeyBlob = outer.bytes();
    outer.end();

    if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID)
      return null;
    if (type !== SSH2_MSG_USERAUTH_REQUEST) return null;
    if (!signatureFollows) return null;
    if (service !== SSH_CONNECTION_SERVICE) return null;
    if (method !== HOSTBOUND_METHOD) return null;
    if (algorithm !== ED25519_NAME) return null;
    if (!timingSafeEqual(userKeyBlob, expectedUserKeyBlob)) return null;
    if (hostKeyBlob.length === 0) return null;

    return {
      sessionId,
      user,
      service,
      method,
      algorithm,
      userKeyBlob,
      hostKeyBlob,
    };
  } catch {
    return null;
  }
}

export class RestrictedAgent {
  constructor(config) {
    this.config = config;
  }

  createSocketState() {
    return new SocketState(randomUUID(), this.config);
  }

  handleMessage(message, state) {
    if (state.destroyed) return failure();
    if (message.length < 1) return failure();

    try {
      switch (message[0]) {
        case SSH_AGENTC_REQUEST_IDENTITIES: {
          const reader = new Reader(message);
          reader.u8();
          reader.end();
          return this.#identitiesAnswer(state);
        }
        case SSH_AGENTC_SIGN_REQUEST: {
          const reader = new Reader(message);
          if (reader.u8() !== SSH_AGENTC_SIGN_REQUEST) return failure();
          const keyBlob = reader.bytes();
          const data = reader.bytes();
          const flags = reader.u32();
          reader.end();
          const signature = state.signAuthorized(keyBlob, data, flags);
          if (!signature) return failure();
          return Buffer.concat([
            Buffer.from([SSH2_AGENT_SIGN_RESPONSE]),
            new Writer().bytes(signature).toBuffer(),
          ]);
        }
        case SSH_AGENTC_EXTENSION: {
          const reader = new Reader(message);
          reader.u8();
          const name = reader.string();
          if (name !== SESSION_BIND_EXTENSION) return failure();
          const hostKeyBlob = reader.bytes();
          const sessionId = reader.bytes();
          const signature = reader.bytes();
          const forwarding = reader.bool();
          reader.end();

          const host = this.config.hostByBlob.get(
            hostKeyBlob.toString("binary"),
          );
          if (!host) return failure();
          return state.addSessionBind(host, sessionId, signature, forwarding)
            ? success()
            : failure();
        }
        default:
          // No add-key, lock, removal, smartcard, certificate, or other paths.
          return failure();
      }
    } catch {
      return failure();
    }
  }

  #identitiesAnswer(state) {
    if (this.config.identities) {
      const selected = availableIdentities(this.config, state.bindings);
      const body = new Writer()
        .u8(SSH2_AGENT_IDENTITIES_ANSWER)
        .u32(selected.length);
      for (const identity of selected)
        body.bytes(identity.key.blob).string(identity.comment);
      return body.toBuffer();
    }
    const body = new Writer();
    body.u8(SSH2_AGENT_IDENTITIES_ANSWER);
    body.u32(1);
    body.bytes(this.config.userKey.blob);
    body.string(this.config.keyComment);
    return body.toBuffer();
  }
}
