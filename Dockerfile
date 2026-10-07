FROM node:20-alpine

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY --chown=node:node --chmod=600 keys/user_ed25519 /keys/user_ed25519
COPY --chown=node:node --chmod=644 keys/jump_host_ed25519.pub.ssh /keys/jump_host_ed25519.pub.ssh
COPY --chown=node:node --chmod=644 keys/target_host_ed25519.pub.ssh /keys/target_host_ed25519.pub.ssh

RUN mkdir -p /run/agent && chown node:node /run/agent
USER node

ENV KEY_DIR=/keys \
    SSH_AUTH_SOCK=/run/agent/ssh-agent.sock \
    AUTHORIZED_USER=deploy \
    JUMP_HOSTNAME=bastion.example \
    TARGET_HOSTNAME=target.example

ENTRYPOINT ["node", "src/server.mjs"]
