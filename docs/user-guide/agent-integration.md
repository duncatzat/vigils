# CLI Agent 集成指南

把 Vigil 作为 MCP 代理插在你的 AI agent 工具(Claude Code / Codex / OpenCode / Cursor / Zed / 任何支持 MCP 的工具)和底层 MCP server 之间,审批 + 审计 + 脱敏 + 沙箱全套策略生效。

## 架构(一眼懂)

```
┌──────────────────┐   stdio JSON-RPC   ┌─────────────────┐
│  Agent 工具       │◄──────────────────►│   vigil-hub     │
│  Claude Code /    │                    │   serve --stdio │
│  Codex / Cursor / │                    └───┬──────┬──────┘
│  Zed / ...        │                        │      │
└──────────────────┘                         │      │
                                             ▼      ▼
                                        Firewall  Upstream MCP
                                        Audit     (stdio/http;Stage 2)
                                        Lease
                                        Sandbox
```

**现状(v0.3 Stage 1)**:agent 能**连上** vigil-hub 并完成 MCP 协议握手(initialize / ping / tools/list);`tools/list` 返空数组(零 upstream attach)。**实际 tool 调用转发到上游 MCP server 的能力留 Stage 2**。

## 通用配置模板

所有支持 MCP 的 agent 都遵循同一套配置形式:`command` + `args` 指向 `vigil-hub serve --stdio`。以下命令在三平台(Windows / Linux / macOS)用对应的 binary 路径替换。

**Windows**:
```json
{"command": "C:\\Vigil\\vigil-hub.exe", "args": ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]}
```

**Linux / macOS**:
```json
{"command": "/usr/local/bin/vigil-hub", "args": ["serve", "--stdio", "--ledger", "~/.local/share/Vigil/ledger.sqlite"]}
```

### 可选参数

| 参数 | 作用 |
|---|---|
| `--stdio` | **必需**。当前 Stage 1 唯一支持的 transport。 |
| `--ledger <path>` | 审计链 SQLite 路径;省略 = 内存(重启丢失) |
| `--upstream-config <path>` | 上游 MCP 配置 JSON(Stage 2 启用,目前声明会报 `UpstreamNotImplemented`) |
| `--auto-approve-first-seen` | 开发模式:首次见到的工具自动批准(生产务必 **false**) |

---

## Claude Code(Anthropic 官方 CLI)

配置文件:项目根 `.mcp.json` 或用户级 `~/.claude/mcp.json`。

```json
{
  "mcpServers": {
    "vigil": {
      "command": "C:\\Vigil\\vigil-hub.exe",
      "args": ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]
    }
  }
}
```

启动 Claude Code 后,`/mcp` 命令应显示 `vigil` 为已连接。因为 Stage 1 无 upstream,`/mcp list-tools` 会返空。

## Codex(OpenAI Codex CLI)

配置:`~/.codex/config.toml`(或项目级 `.codex/config.toml`)。

```toml
[mcp_servers.vigil]
command = "C:\\Vigil\\vigil-hub.exe"
args = ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]
```

## OpenCode(opencode.ai / sst/opencode)

项目根 `opencode.json`:

```json
{
  "mcp": {
    "vigil": {
      "type": "local",
      "command": ["C:\\Vigil\\vigil-hub.exe", "serve", "--stdio"],
      "enabled": true
    }
  }
}
```

## Cursor

`~/.cursor/mcp.json` 或 `<project>/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "C:\\Vigil\\vigil-hub.exe",
      "args": ["serve", "--stdio"]
    }
  }
}
```

## Zed

`~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "vigil": {
      "command": {
        "path": "/usr/local/bin/vigil-hub",
        "args": ["serve", "--stdio"]
      }
    }
  }
}
```

## Continue(VS Code / JetBrains)

`~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: vigil
    command: /usr/local/bin/vigil-hub
    args:
      - serve
      - --stdio
```

---

## 验证 agent 已连上 vigil-hub(无论哪个工具)

启动 agent 后:

1. **查进程**:任务管理器 / `ps aux | grep vigil-hub`,应看到 agent 作为父进程派生的 `vigil-hub serve --stdio` 子进程
2. **stderr 日志**:agent 通常会在日志/控制台显示 `vigil-hub serve: started stdio MCP server (PID ...)`(来自 vigil-hub 启动 banner)
3. **查工具列表**:agent 的"tools / MCP server"面板应显示 `vigil` 已连接,工具列表(Stage 1 为空)
4. **查审计**:打开 **Vigils** 桌面应用(`vigils.exe`)→ Activity Feed 应看到 `session.started` event(source = `vigil-hub-serve`)

## 故障排查

### "connection refused" / "command not found"

- 确认 `vigil-hub.exe`(Windows)或 `vigil-hub`(Linux/macOS)在 PATH 或配置中路径绝对正确
- 跑 `vigil-hub --version` 验证可执行

### agent 连上但 tools 空

**预期**(Stage 1)。Stage 2 加 upstream 配置后会有工具。

### `"upstream onboarding not implemented in Stage 1 (upstream '<name>')"`

配置里用了 `--upstream-config` + 真实 upstream 条目。Stage 1 只校验 JSON 格式,不实际 attach。移除 `--upstream-config` 或空列表 `{"upstreams":[]}`。

### Desktop Activity Feed 不显示 session.started

确认 `--ledger` 路径 agent 子进程可写。Windows:`%APPDATA%\Vigil\ledger.sqlite`;Linux:`~/.local/share/Vigil/ledger.sqlite`;macOS:`~/Library/Application Support/Vigil/ledger.sqlite`。Desktop GUI 默认也读这个路径(`dirs::data_local_dir`)。

### agent 日志里有乱字节

**不得向 stdout 打印任何非 JSON-RPC 内容** — vigil-hub serve 严格遵守这一点(所有启动 banner 走 stderr)。如果你看到 stdout 被污染,排查是不是 shell 配置(如 zsh 加 echo)插入了字符。

## Stage 2 预告(非本轮交付)

Stage 2 将:
1. 实装 `--upstream-config` 的真实 attach(register_server + approve_server + command hash drift 检查全自动)
2. 支持 HTTP upstream(复用 I10b-β 的 `add-remote-mcp` 流程)
3. 提供 `vigil-hub add-local-mcp` 子命令,把一个 stdio server 加到本地 upstream 白名单
4. Desktop UI 的 Server Registry 页面能显示 serve 子进程当前挂载的 upstream

这样 agent 就能**透过 vigil** 调真实工具,而不仅仅是连上 vigil。

---

**参考**:
- `docs/adr/0004-mcp-hub-and-outbox.md` — Hub 架构
- `docs/adr/0005-descriptor-pinning-and-drift.md` — upstream drift 检查
- `docs/adr/0010-http-mcp-auth.md` — HTTP MCP OAuth
- `apps/vigil-hub-cli/src/serve.rs` — serve 实现
