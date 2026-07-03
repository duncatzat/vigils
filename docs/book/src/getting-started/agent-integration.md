# Agent Integration & Test Guide

> 🌐 中文版：[Agent 接入与测试指南](./agent-integration.zh-CN.md)

Put **Vigils** in front of your AI agent's tools, so every tool call your agent makes is
**firewalled** (default-deny), **audited** (tamper-evident hash chain), **redacted** (secrets /
PII), and — when risky — sent to **approval**. Everything runs locally; nothing leaves your
machine.

Works with any MCP-capable agent: **Claude Code**, **Codex**, **Cursor**, **Zed**, OpenCode,
Continue, and more.

## How it works

Vigils runs as an MCP **gateway**: your agent connects to `vigil-hub` over stdio, and `vigil-hub`
proxies your real MCP tool servers ("upstreams"), gating every call.

```
┌──────────────────┐   stdio JSON-RPC   ┌────────────────────┐      ┌──────────────────┐
│  Your agent      │◄──────────────────►│  vigil-hub serve   │─────►│ Upstream MCP      │
│  Claude Code /   │                    │   --stdio          │      │ servers           │
│  Codex / Cursor /│                    │  ┌──────────────┐  │      │ (filesystem,      │
│  Zed / ...       │                    │  │ Firewall     │  │      │  github, db, ...) │
└──────────────────┘                    │  │ Audit ledger │  │      └──────────────────┘
                                        │  │ Redaction    │  │
                                        │  │ Approval     │  │
                                        │  └──────────────┘  │
                                        └────────────────────┘
```

Each upstream's tools are namespaced with a `__` (double-underscore) separator — `<server>__<tool>`,
e.g. `fs__read_file`, `github__create_issue` — and aggregated into the `tools/list` your agent sees. When the agent calls one, Vigils evaluates it against the
firewall **before** forwarding, records a decision in the audit ledger, and either allows it,
denies it, or queues it for your approval.

## Prerequisites

Install the CLI gateway, `vigil-hub`:

- **Prebuilt**: download `vigils-cli-<target>.tar.gz` (`.zip` on Windows) from the
  [latest release](https://github.com/duncatzat/vigils/releases/latest) — it contains `vigil-hub`
  and `vigil-native-host`. Put `vigil-hub` on your `PATH`.
- **From source**: `cargo install --path apps/vigil-hub-cli`

Verify: `vigil-hub --help`

## Fastest path — Claude Code, one command (`setup --all`)

If you use **Claude Code**, you don't need to hand-write configs at all. One command detects your
setup and protects everything — your existing config is backed up and only Vigils' own entries are
added (fully reversible):

```bash
vigil-hub setup --all
```

`setup --all` wires up **both** layers:

1. **Native-tool input guard** — a `PreToolUse` hook so every tool call (Bash, Edit, Write, Read,
   MCP tools, …) is checked before it runs; a real credential heading *into* a tool is blocked
   fail-closed and audited.
2. **MCP gateway** — rewrites each of your stdio MCP servers to run through Vigils, so secrets in
   tool **results** are scrubbed before the model sees them and every call is audited. Defaults to
   **monitor** posture (your servers stay usable; raw-secret block, result redaction, and audit
   stay on). Add `--enforce` for default-deny gating.

```bash
vigil-hub setup --mcp --doctor    # pre-flight: will each wrapped MCP server actually start? (read-only PATH check)
vigil-hub verify                  # after using your agent: confirm the tamper-evident audit chain is intact (the desktop app shows what was caught)
vigil-hub setup --all --uninstall # remove everything (config restored byte-for-byte)
```

Restart Claude Code and you're protected. The rest of this guide is the **manual path** — use it
for non-Claude agents (Codex / Cursor / Zed / …) or when you want explicit control over the
`serve` gateway and its `upstreams.json`.

## Step 1 — Smoke-test `vigil-hub` (30s, no agent needed)

Confirm the gateway speaks MCP before wiring any agent. Pipe an `initialize` + `tools/list` into
it (MCP stdio is newline-delimited JSON-RPC):

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | vigil-hub serve --stdio --ledger ./vigil.db
```

Expected stdout (two JSON-RPC responses):

```json
{"id":1,"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":false}},"protocolVersion":"2025-06-18","serverInfo":{"name":"vigil-hub","version":"0.1.7"}}}
{"id":2,"jsonrpc":"2.0","result":{"tools":[]}}
```

`tools/list` is empty because no upstreams are configured yet (next step). Startup banners go to
**stderr** (stdout is reserved for the protocol).

## Step 2 — Declare your tool servers (`upstreams.json`)

List the MCP servers you want Vigils to proxy. Bare commands resolve via `PATH`.

```json
{
  "upstreams": [
    { "name": "fs",     "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] },
    { "name": "github", "argv": ["npx", "-y", "@modelcontextprotocol/server-github"] }
  ]
}
```

Pass it to `serve`:

```bash
vigil-hub serve --stdio --ledger ./vigil.db --upstream-config ./upstreams.json
```

For each entry Vigils registers the server, pins its launch command, and runs a
**gate-before-spawn** check (argv + resolved-program drift) *before* starting the child process —
then namespaces its tools (`fs__…`, `github__…`) into `tools/list`.

> **HTTP / remote MCP servers** use OAuth onboarding instead:
> `vigil-hub add-remote-mcp --url https://mcp.example.com/ --client-id <id> --scopes mcp:tools.read`

## Step 3 — Point your agent at `vigil-hub`

Use a shared **ledger path** so the desktop app and CLI see the same audit trail. The desktop app
reads `data_local_dir()/Vigil/ledger.sqlite3`:

- Windows: `%LOCALAPPDATA%\Vigil\ledger.sqlite3`
- Linux: `~/.local/share/Vigil/ledger.sqlite3`
- macOS: `~/Library/Application Support/Vigil/ledger.sqlite3`

The filename must be exactly `ledger.sqlite3` (with the `3`) and the directory must be
`data_local_dir()` — a path mismatch means the desktop reads a *different* file and the
Activity Feed stays empty. Easiest path: run `vigil-hub setup --mcp` / `setup --all`, which
auto-targets this shared ledger. Do **not** omit `--ledger` on a manual `serve --stdio` — that
uses an in-memory ledger the desktop can't see. `serve`/`wrap` print the resolved ledger path
on startup, so you can compare it with the desktop's.

In the snippets below, replace the `--ledger` / `--upstream-config` paths and the `vigil-hub` path
(use the absolute `.exe` path on Windows, e.g. `C:\\Vigil\\vigil-hub.exe`).

### Claude Code

Project `.mcp.json` (or user-level `~/.claude.json` → `mcpServers`):

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

Run `/mcp` in Claude Code — `vigil` should show **connected**, with your upstream tools under it.

### Codex (OpenAI Codex CLI)

`~/.codex/config.toml` (or project `.codex/config.toml`):

```toml
[mcp_servers.vigil]
command = "vigil-hub"
args = ["serve", "--stdio", "--ledger", "~/.local/share/Vigil/ledger.sqlite3", "--upstream-config", "./upstreams.json"]
```

### Cursor

`~/.cursor/mcp.json` (or project `.cursor/mcp.json`):

```json
{ "mcpServers": { "vigil": { "command": "vigil-hub", "args": ["serve", "--stdio", "--upstream-config", "./upstreams.json"] } } }
```

### Zed

`~/.config/zed/settings.json`:

```json
{ "context_servers": { "vigil": { "command": { "path": "vigil-hub", "args": ["serve", "--stdio", "--upstream-config", "./upstreams.json"] } } } }
```

### OpenCode

Project `opencode.json`:

```json
{ "mcp": { "vigil": { "type": "local", "command": ["vigil-hub", "serve", "--stdio", "--upstream-config", "./upstreams.json"], "enabled": true } } }
```

### Continue (VS Code / JetBrains)

`~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: vigil
    command: vigil-hub
    args: ["serve", "--stdio", "--upstream-config", "./upstreams.json"]
```

## Step 4 — Verify it's actually gating

After your agent runs a tool call (or trigger one yourself), inspect the local ledger. `inspect`
prints single-line JSON — pipe to `jq`:

```bash
vigil-hub inspect --db-path ./vigil.db protection            # at-a-glance: secrets blocked, leaks redacted, chain intact
vigil-hub inspect --db-path ./vigil.db activity --limit 20   # recent events / decisions
vigil-hub inspect --db-path ./vigil.db search "read_file"     # full-text search the trail
vigil-hub inspect --db-path ./vigil.db approvals list         # risky calls awaiting you
vigil-hub inspect --db-path ./vigil.db verify-chain           # tamper-evident chain check
# → {"kind":"ChainVerification","data":{"ok":true,"broken_at_event_id":null,"message":null}}
```

Or open the **Vigils desktop app** for a live view: **Activity Feed**, **Approval Queue** (approve
/ deny), **Server Registry**, **Session Replay**, and **Privacy Findings**.

**What "gating" looks like:** with the default firewall (deny-by-default), a risky tool call is
either denied outright or surfaced in the Approval Queue — your agent's call blocks until you
approve. The decision is recorded in `activity`.

## Optional — turn on the ML privacy filter

By default Vigils uses fast hard-fingerprint rules (no ML). To add the ONNX PII scanner, build the
CLI with the `ort` feature and pass `--enable-privacy-filter`:

```bash
cargo install --path apps/vigil-hub-cli --features ort
vigil-hub serve --stdio --upstream-config ./upstreams.json --enable-privacy-filter
```

If the flag is set but the binary wasn't built with `--features ort`, startup **fails closed** (it
never silently runs without the filter you asked for).

## Troubleshooting

- **`command not found` / agent can't start vigil-hub** — use the absolute path to `vigil-hub`
  (`vigil-hub.exe` on Windows) in the config; verify with `vigil-hub --version`.
- **Agent connects but no tools** — you haven't passed `--upstream-config`, or the file lists no
  upstreams. Add your `upstreams.json`.
- **An upstream fails to start** — make sure its `argv` runs standalone and that `npx`/`node` (or
  whatever it needs) is on `PATH`.
- **Desktop app doesn't show events** — point `--ledger` at the same path the desktop app uses
  (Step 3), writable by the agent's child process.
- **Garbled bytes in the agent log** — nothing but JSON-RPC may go to stdout; `vigil-hub` keeps all
  banners on stderr.

## References

- [Architecture](../concepts/architecture.md) · [MCP Hub](../concepts/mcp-hub.md) ·
  [Action Firewall](../concepts/firewall.md)
- `apps/vigil-hub-cli/src/serve.rs` — the `serve` implementation
