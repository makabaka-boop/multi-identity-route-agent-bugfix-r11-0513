# 受限 SSH Agent 演示

这是一个只暴露 Unix socket 的受限 SSH agent。它启动时载入一把固定的演示 Ed25519 用户私钥，以及固定的跳板机和目标机主机公钥。代理不会连接真实 SSH 主机；主机身份来自 `session-bind@openssh.com` 中经过主机私钥验证的会话绑定。

## 唯一允许的认证路径

每个 socket 连接必须按顺序完成两条绑定：

1. `is_forwarding=true`，主机钥等于固定跳板机主机钥；
2. `is_forwarding=false`，主机钥等于固定目标机主机钥。

只有完成上述路径后，代理才会签名。签名数据还必须是完整的 host-bound SSH 用户认证请求，并逐项满足：

- 最末会话标识等于目标机绑定的会话标识；
- 用户名为配置中的 `AUTHORIZED_USER`（默认 `deploy`）；
- 服务为 `ssh-connection`；
- 方法为 `publickey-hostbound-v00@openssh.com`；
- `sig-follows` 为 true；
- 公钥算法为 `ssh-ed25519`；
- 请求中的用户公钥等于启动时载入的演示用户钥；
- 请求中的目标主机公钥等于固定目标机主机钥；
- 载荷无多余字节，签名 flags 必须为 0。

代理不会只比对某个摘要或其中一个字段。任意字节、普通 `publickey` 请求、证书算法、交换后的会话/主机/用户名等都会返回 `SSH_AGENT_FAILURE`。

## 绑定安全规则

- 每次绑定先使用主机钥验证该主机钥对会话标识的 SSH Ed25519 签名。
- 第一跳必须是 forwarding 跳板，第二跳必须是非 forwarding 目标。
- 重复会话标识拒绝。
- 认证绑定之后再次绑定拒绝。
- 错序绑定拒绝。
- 所有失败绑定只做验证和裁决，不修改该 socket 已有的绑定状态。
- 每个 Unix socket 的绑定状态独立；socket 关闭即销毁。

## 支持的 agent 消息

- `SSH_AGENTC_REQUEST_IDENTITIES` (11)
- `SSH_AGENTC_SIGN_REQUEST` (13)
- `SSH_AGENTC_EXTENSION` (27)，扩展名仅接受 `session-bind@openssh.com`

其他消息一律失败，包括加钥、删钥、锁定、智能卡和证书相关路径。

## 本地测试

```bash
npm test
```

测试会生成真实 Ed25519 密钥并使用真实私钥创建：

- 合法跳板/目标会话绑定；
- 合法 host-bound 用户认证载荷；
- 交换连接、会话、主机和用户名后的非法请求；
- 任意字节和逐字段变异载荷；
- 重复绑定、认证后绑定、错序绑定和多 socket 隔离场景。

## Compose 运行

```bash
docker compose build
docker compose up -d
```

容器内 socket 位于：

```text
/run/agent/ssh-agent.sock
```

容器不发布网络端口。Compose 声明了 `agent-run` 命名卷；需要访问代理的同一 Compose 服务可以把该卷挂到自己的 `/run/agent`，再设置 `SSH_AUTH_SOCK=/run/agent/ssh-agent.sock`。Compose 仅运行代理；示例主机私钥保存在 `keys/` 中，是由固定标签确定性生成的演示密钥，不能用于真实环境。

可调整的环境变量：

- `KEY_DIR`
- `SSH_AUTH_SOCK`
- `AUTHORIZED_USER`
- `JUMP_HOSTNAME`
- `TARGET_HOSTNAME`
- `KEY_COMMENT`

## 重新生成演示密钥

```bash
npm run keys:generate
```

脚本使用 Node Crypto 从固定标签确定性生成密钥，以保证测试可重复。生产部署应改为通过受控密钥注入启动密钥，并确保用户私钥和主机私钥的文件权限正确。


## 多身份路径配置
以 `AGENT_POLICY=demo-routes.json node src/server.mjs` 启动多身份模式（示例私钥仅作公开本地演示）。JSON 包含 hosts 的标签到 Ed25519 SSH 公钥文件映射，以及 identities 的 privateKey、comment、routes；每条 route 指定 2..4 个有序主机标签和目标 user。最多 12 台主机、8 个不同身份、每身份 8 条不同路径，文件路径相对于配置文件。只接受完整匹配某条允许路径的逐跳 session-bind：中间跳为 forwarding，末跳为非 forwarding；共享前缀不能提前锁定某一条路径。无效绑定保持原状态，重复会话 ID 和末跳后的再绑定均拒绝。身份查询仅返回已完成当前路径对应的身份，签名还须由该身份自己的路径、目标用户名、最后会话 ID 及完整 host-bound 用户认证载荷共同授权。不同 socket 独立，关闭后清除绑定。重复身份公钥、重复主机公钥、未知标签及无效路径在启动前整体拒绝。没有 AGENT_POLICY 时保留原来的单身份模式。
