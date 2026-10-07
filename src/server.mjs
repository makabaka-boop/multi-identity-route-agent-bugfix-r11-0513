import { chmodSync, mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { createServer } from "node:net";
import { loadConfig } from "./config.mjs";
import { RestrictedAgent } from "./agent.mjs";
import { frame } from "./wire.mjs";

const MAX_MESSAGE_SIZE = 256 * 1024;
const SOCKET_PATH = process.env.SSH_AUTH_SOCK || "/run/agent/ssh-agent.sock";

function start() {
  // The whole configuration is validated before the socket is opened; any
  // invalid policy aborts startup instead of serving ambiguous state.
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    console.error(`invalid configuration: ${error.message}`);
    process.exit(1);
  }
  const agent = new RestrictedAgent(config);

  mkdirSync(dirname(SOCKET_PATH), { recursive: true });
  rmSync(SOCKET_PATH, { force: true });

  const server = createServer((socket) => {
    // State is owned by exactly this socket and is discarded on close.
    const state = agent.createSocketState();
    let input = Buffer.alloc(0);

    const fail = () => socket.write(frame(Buffer.from([5])));

    socket.on("data", (chunk) => {
      input = input.length === 0 ? chunk : Buffer.concat([input, chunk]);

      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        if (length === 0 || length > MAX_MESSAGE_SIZE) {
          socket.destroy();
          return;
        }
        if (input.length < 4 + length) return;

        const message = Buffer.from(input.subarray(4, 4 + length));
        input =
          input.length === 4 + length
            ? Buffer.alloc(0)
            : Buffer.from(input.subarray(4 + length));

        socket.write(frame(agent.handleMessage(message, state)));
      }
    });

    socket.on("error", fail);
    socket.on("close", () => {
      state.destroyed = true;
      state.bindings.length = 0;
    });
  });

  server.on("error", (error) => {
    console.error(error.message);
    process.exit(1);
  });

  server.listen(SOCKET_PATH, () => {
    chmodSync(SOCKET_PATH, 0o660);
    console.log(`restricted SSH agent listening at ${SOCKET_PATH}`);
  });

  const stop = () => {
    server.close(() => {
      rmSync(SOCKET_PATH, { force: true });
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 250).unref();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

start();
