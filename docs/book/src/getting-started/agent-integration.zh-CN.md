# Agent 接入与测试指南

> 🌐 English: [Agent Integration & Test Guide](./agent-integration.md)

把 **Vigils** 插在你的 AI agent 与它调用的工具之间，让 agent 的每一次工具调用都经过
**防火墙**（默认拒绝）、**审计**（防篡改哈希链）、**脱敏**（密钥 / PII），高危调用还会进入
**人工审批**。全部本地运行，数据不外传。

支持任何兼容 MCP 的 agent：**Claude Code**、**Codex**、**Cursor**、**Zed**、OpenCode、Continue 等。

## 工作原理

Vigils 作为 MCP **网关**运行：你的 agent 通过 stdio 连接 `vigil-hub`，由 `vigil-hub` 代理你真正的
MCP 工具服务器（"upstream"），对每次调用进行管控。

```
┌──────────────────┐   stdio JSON-RPC   ┌────────────────────┐      ┌──────────────────┐
│  你的 agent      │◄──────────────────►│  vigil-hub serve   │─────►│ 上游 MCP server   │
│  Claude Code /   │                    │   --stdio          │      │ （filesystem、    │
│  Codex / Cursor /│                    │  ┌──────────────┐  │      │  github、db…）     │
│  Zed / ...       │                    │  │ 防火墙        │  │      └──────────────────┘
└──────────────────┘                    │  │ 审计账本      │  │
                                        │  │ 脱敏          │  │
                                        │  │ 审批          │  │
                                        │  └──────────────┘  │
                                        └────────────────────┘
```

每个 upstream 的工具会用 `__`（双下划线）分隔符做命名空间化 —— `<server>__<tool>`，例如
`fs__read_file`、`github__create_issue` —— 聚合进 agent 看到的 `tools/list`。agent 调用某个工具时，Vigils 会在**转发之前**用防火墙评估它、在审计账本记一条决策，
然后放行、拒绝、或排进审批队列等你确认。

## 前置条件

安装 CLI 网关 `vigil-hub`：

- **预编译**：从[最新 release](https://github.com/duncatzat/vigils/releases/latest) 下载
  `vigils-cli-<target>.tar.gz`（Windows 为 `.zip`），内含 `vigil-hub` 与 `vigil-native-host`。把
  `vigil-hub` 放进 `PATH`。
- **从源码**：`cargo install --path apps/vigil-hub-cli`

验证：`vigil-hub --help`

## 最快路径 —— Claude Code，一条命令（`setup --all`）

如果你用 **Claude Code**,完全不必手写配置。一条命令检测你的环境并全面保护 —— 既有配置会被备份,只新增
Vigils 自己的条目(完全可逆):

```bash
vigil-hub setup --all
```

`setup --all` 同时接入**两层**:

1. **原生工具输入侧守门** —— `PreToolUse` hook,于是每次工具调用(Bash、Edit、Write、Read、MCP
   工具……)执行前都先被检查:真实凭据流*入*工具会被 fail-closed 拦截并审计。
2. **MCP 网关** —— 把你每个 stdio MCP server 改写为经 Vigils 路由,工具**结果**里的 secret 在模型看到
   之前被脱敏,每次调用都被审计。默认 **monitor** 姿态(你的 server 保持可用;裸 secret 拦截、结果脱敏、
   审计照常)。加 `--enforce` 升级 default-deny 硬拦。

```bash
vigil-hub setup --mcp --doctor    # 接入前预检:每个被包裹的 MCP server 真能启动吗?(只读 PATH 检查)
vigil-hub verify                  # 用过 agent 后:确认防篡改审计链完整(桌面应用可看拦了什么)
vigil-hub setup --all --uninstall # 移除全部(配置逐字节还原)
```

重启 Claude Code 即受保护。本指南余下部分是**手动路径** —— 用于非 Claude agent(Codex / Cursor /
Zed / …)或你想显式控制 `serve` 网关及其 `upstreams.json` 时。

## 第 1 步 —— 冒烟测试 `vigil-hub`（30 秒，不用 agent）

接任何 agent 之前，先确认网关能说 MCP。给它喂一个 `initialize` + `tools/list`（MCP stdio 是逐行
JSON-RPC）：

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | vigil-hub serve --stdio --ledger ./vigil.db
```

预期 stdout（两条 JSON-RPC 响应）：

```json
{"id":1,"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":false}},"protocolVersion":"2025-06-18","serverInfo":{"name":"vigil-hub","version":"0.1.7"}}}
{"id":2,"jsonrpc":"2.0","result":{"tools":[]}}
```

`tools/list` 为空是因为还没配 upstream（下一步配）。启动提示走 **stderr**（stdout 留给协议）。

## 第 2 步 —— 声明你的工具服务器（`upstreams.json`）

列出你要 Vigils 代理的 MCP server。裸命令会自动经 `PATH` 解析。

```json
{
  "upstreams": [
    { "name": "fs",     "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] },
    { "name": "github", "argv": ["npx", "-y", "@modelcontextprotocol/server-github"] }
  ]
}
```

传给 `serve`：

```bash
vigil-hub serve --stdio --ledger ./vigil.db --upstream-config ./upstreams.json
```

对每个条目，Vigils 会注册该 server、固定其启动命令，并在启动子进程**之前**做一次
**gate-before-spawn** 校验（argv + resolved-program 双 drift），然后把它的工具命名空间化
（`fs__…`、`github__…`）聚合进 `tools/list`。

> **HTTP / 远程 MCP server** 改走 OAuth onboarding：
> `vigil-hub add-remote-mcp --url https://mcp.example.com/ --client-id <id> --scopes mcp:tools.read`

## 第 3 步 —— 把 agent 指向 `vigil-hub`

用**同一个 ledger 路径**，让桌面应用和 CLI 看到同一份审计。桌面应用读
`data_local_dir()/Vigil/ledger.sqlite3`：

- Windows：`%LOCALAPPDATA%\Vigil\ledger.sqlite3`
- Linux：`~/.local/share/Vigil/ledger.sqlite3`
- macOS：`~/Library/Application Support/Vigil/ledger.sqlite3`

文件名必须**恰好是 `ledger.sqlite3`**（带 `3`）、目录是 `data_local_dir()` —— 路径不一致桌面就读到
*另一个*文件，Activity Feed 一直空。最省心:跑 `vigil-hub setup --mcp` / `setup --all`，自动指向这个
共享账本。手动 `serve --stdio` **切勿省略 `--ledger`** —— 省略 = 内存账本，桌面看不到。`serve`/`wrap`
启动时会打印解析后的账本路径,可与桌面读的路径比对。

下面的片段里，替换 `--ledger` / `--upstream-config` 路径和 `vigil-hub` 路径（Windows 用绝对
`.exe` 路径，如 `C:\\Vigil\\vigil-hub.exe`）。

### Claude Code

项目根 `.mcp.json`（或用户级 `~/.claude.json` 的 `mcpServers`）：

```json
{
  "mcpServers": {
    "vigil": {
      "command": "vigil-hub",
      "args": ["serve", "--stdio", "--ledger", "~/.local/share/Vigil/ledger.sqlite3", "--upstream-config", "./upstreams.json"]
    }
  }
}
```

在 Claude Code 里运行 `/mcp` —— `vigil` 应显示**已连接**，其下挂着你的 upstream 工具。

### Codex（OpenAI Codex CLI）

`~/.codex/config.toml`（或项目级 `.codex/config.toml`）：

```toml
[mcp_servers.vigil]
command = "vigil-hub"
args = ["serve", "--stdio", "--ledger", "~/.local/share/Vigil/ledger.sqlite3", "--upstream-config", "./upstreams.json"]
```

### Cursor

`~/.cursor/mcp.json`（或项目级 `.cursor/mcp.json`）：

```json
{ "mcpServers": { "vigil": { "command": "vigil-hub", "args": ["serve", "--stdio", "--upstream-config", "./upstreams.json"] } } }
```

### Zed

`~/.config/zed/settings.json`：

```json
{ "context_servers": { "vigil": { "command": { "path": "vigil-hub", "args": ["serve", "--stdio", "--upstream-config", "./upstreams.json"] } } } }
```

### OpenCode

项目根 `opencode.json`：

```json
{ "mcp": { "vigil": { "type": "local", "command": ["vigil-hub", "serve", "--stdio", "--upstream-config", "./upstreams.json"], "enabled": true } } }
```

### Continue（VS Code / JetBrains）

`~/.continue/config.yaml`：

```yaml
mcpServers:
  - name: vigil
    command: vigil-hub
    args: ["serve", "--stdio", "--upstream-config", "./upstreams.json"]
```

## 第 4 步 —— 验证它真的在管控

等 agent 跑一次工具调用（或你自己触发一次）后，查本地账本。`inspect` 输出单行 JSON，可接 `jq`：

```bash
vigil-hub inspect --db-path ./vigil.db protection            # 一眼看清:裸 secret 拦截、泄漏脱敏、链完整
vigil-hub inspect --db-path ./vigil.db activity --limit 20   # 最近事件 / 决策
vigil-hub inspect --db-path ./vigil.db search "read_file"     # 全文搜索审计链
vigil-hub inspect --db-path ./vigil.db approvals list         # 待你处理的高危调用
vigil-hub inspect --db-path ./vigil.db verify-chain           # 防篡改链校验
# → {"kind":"ChainVerification","data":{"ok":true,"broken_at_event_id":null,"message":null}}
```

或打开 **Vigils 桌面应用**实时看：**Activity Feed**、**Approval Queue**（批准 / 拒绝）、
**Server Registry**、**Session Replay**、**Privacy Findings**。

**"管控"长什么样**：默认防火墙是 deny-by-default，一次高危工具调用要么被直接拒绝，要么进 Approval
Queue —— 在你批准之前，agent 的这次调用一直阻塞。决策会记进 `activity`。

## 可选 —— 开启 ML 隐私过滤

Vigils 默认用快速硬指纹规则（无 ML）。要加 ONNX PII 扫描器，用 `ort` feature 编译 CLI 并传
`--enable-privacy-filter`：

```bash
cargo install --path apps/vigil-hub-cli --features ort
vigil-hub serve --stdio --upstream-config ./upstreams.json --enable-privacy-filter
```

如果传了 flag 但二进制没用 `--features ort` 编译，启动会 **fail-closed**（绝不静默地在你以为开了过滤
的情况下不开就跑）。

## 故障排查

- **`command not found` / agent 起不了 vigil-hub** —— 配置里用 `vigil-hub` 的绝对路径（Windows 为
  `vigil-hub.exe`）；`vigil-hub --version` 验证可执行。
- **连上了但没工具** —— 你没传 `--upstream-config`，或文件里没列 upstream。补上 `upstreams.json`。
- **某个 upstream 起不来** —— 确认它的 `argv` 能独立跑，且 `npx`/`node`（或它需要的东西）在 `PATH`。
- **桌面应用不显示事件** —— 把 `--ledger` 指向桌面应用用的同一路径（第 3 步），且 agent 子进程可写。
- **agent 日志里有乱字节** —— stdout 只能有 JSON-RPC；`vigil-hub` 所有 banner 都走 stderr。

## 参考

- [架构](../concepts/architecture.md) · [MCP Hub](../concepts/mcp-hub.md) ·
  [Action Firewall](../concepts/firewall.md)
- `apps/vigil-hub-cli/src/serve.rs` —— `serve` 实现
