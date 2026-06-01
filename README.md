<div align="center">

# Vigils

### A local-first control plane for AI agents — see what they do, approve what matters, keep secrets out.

**面向 AI Agent 的本地优先控制平面 —— 看见行为、审批高危、隔离凭据。**

[![CI](https://github.com/duncatzat/vigils/actions/workflows/ci.yml/badge.svg)](https://github.com/duncatzat/vigils/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](./rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation)

[Website](https://vigils.ai) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Security Model](#security-model) · [中文](#中文)

</div>

---

AI agents (Claude Code, Cursor, Zed, MCP clients, browser assistants) call tools, read
files, hit APIs, and paste into web UIs on your behalf. That power is useful — and risky.
**Vigils sits between your agents and the tools/data they touch**, and it is *local-first*:
your prompts, secrets, and audit trail never leave your machine.

```
   AI agent ──▶  ┌─────────────────── Vigils ───────────────────┐  ──▶  tools / data
 (MCP client)    │  redact → firewall → approve → sandbox → audit │       (MCP servers,
                 └───────────────────────────────────────────────┘        files, APIs, web)
```

## Why Vigils

Four guarantees, enforced locally:

| Guarantee | How |
|---|---|
| **See what the agent did** | Every tool call is recorded in a tamper-evident **SHA-256 hash-chained ledger** with full-text search. |
| **Approve risky actions first** | Destructive / sensitive calls pause for human review in an **Approval Queue**, with per-agent policy and scoped grants. |
| **Keep credentials out of prompts / logs / UI** | A **redaction engine** strips secrets and PII (hard-fingerprint rules + an optional ML ensemble) *before* text reaches a model, a log, or the screen. |
| **Contain & roll back** | The ledger is traceable end-to-end and the **sandbox runner is fail-closed by default** (Wasm + native + Linux Landlock). |

## Features

- **🔒 Tamper-evident audit ledger** — SQLite + SHA-256 hash chain; every event links to the
  previous one, so tampering is detectable. FTS5 full-text search over the redacted trail.
- **🛡️ Default-deny firewall** — tool calls are gated by a Rust policy DSL; per-agent rules;
  OAuth scope allow-lists for remote MCP. Nothing runs unless allowed.
- **✅ Human-in-the-loop approval** — risky effects (file writes, network, destructive ops)
  pause for review. Grants can be scoped (once / this-session).
- **🙈 Secret & PII redaction** — hard-fingerprint detection for 13+ credential classes
  (GitHub PAT, Stripe keys, Google/GitLab tokens, DB URLs, …) plus an optional multilingual
  ML ensemble; a fail-closed merge layer decides what to mask.
- **🎟️ Secret lease broker** — short-lived credential leases injected only into the child
  process that needs them; plaintext is never persisted.
- **📦 Sandbox runner** — one-shot tool execution in Wasm (Wasmtime) or native processes,
  with **Linux Landlock LSM** filesystem isolation and `env_clear` so children don't inherit
  your environment. Fail-closed by default.
- **🔌 MCP gateway** — sits in front of MCP servers over **stdio and HTTP**; descriptor
  pinning with drift detection (alerts when a tool's definition changes); bare-command stdio
  upstreams (`npx`/`node`/`python`) resolve via host PATH before sandboxing.
- **🖥️ Desktop app** (Tauri 2 + Vue 3) — Approval Queue, Activity Feed, Server Registry,
  Session Replay, Privacy Findings; keyboard shortcuts, light/dark/system theme, real-time
  updates, bilingual (zh / en) UI.
- **🌐 Browser extension** (Chrome MV3) — redacts secrets/PII *before* paste or submit on AI
  sites (ChatGPT, Claude, Gemini, Perplexity).

## Architecture

Vigils is a Rust workspace of focused crates plus three apps. Each layer is independently
testable and composed by the **Hub** (the MCP gateway).

| Layer | Crate | Responsibility |
|---|---|---|
| **Audit** | `vigil-audit` | SQLite ledger, SHA-256 hash chain, FTS5 search, redaction-scan records |
| **Policy** | `vigil-policy` | Rust policy DSL + rule engine (default-deny) |
| **Firewall** | `vigil-firewall` | Tool gating, per-agent rules, OAuth scope allow-lists |
| **Approval** | `vigil-mcp` (broker) | Human-in-the-loop, scoped grants, cross-process resolution |
| **Redaction** | `vigil-redaction` | Secret/PII detection (hard fingerprints + ML ensemble), fail-closed merge |
| **Leases** | `vigil-lease` | Short-lived credential leases, prepared child env (RAII revoke) |
| **Runner** | `vigil-runner` / `vigil-runner-types` | Native + Wasm execution, env policy, fail-closed |
| **Sandbox** | `vigil-sandbox-linux` | Linux Landlock LSM filesystem isolation |
| **Gateway** | `vigil-mcp` | MCP Hub: stdio + HTTP upstreams, descriptor pinning + drift |
| **Remote auth** | `vigil-http-auth` / `vigil-http-transport` | OAuth (JWT + opaque), token refresh (singleflight), real TLS |
| **UI protocol** | `vigil-ui-protocol` | Typed command/response contract for the desktop UI |
| **Browser** | `vigil-browser` | Redaction classifier + audit for the extension bridge |
| **SDK** | `vigil-sdk` | Thin, SemVer-stable facade over the engine |

**Apps & binaries:**

| Binary | Crate | What it is |
|---|---|---|
| `vigil-hub` | `vigil-hub-cli` | CLI MCP gateway: `vigil-hub serve --stdio`, `add-remote-mcp`, … |
| `gui` | `apps/desktop` | Tauri 2 desktop app (embeds the Vue 3 UI + an in-process Hub) |
| `vigil-native-host` | `apps/native-host` | Native-messaging bridge for the Chrome extension |
| — | `extensions/chrome-mv3` | Chrome MV3 extension (vanilla JS, zero npm deps) |

## Installation

Pre-built installers and binaries for **Windows, macOS, and Linux** are attached to each
[GitHub Release](https://github.com/duncatzat/vigils/releases):

| Platform | Desktop app | CLI |
|---|---|---|
| **Windows** | `.exe` (NSIS) / `.msi` | `vigil-hub.exe` (in `vigils-cli-…-windows-msvc.zip`) |
| **macOS** | `.dmg` | `vigil-hub` (in `vigils-cli-…-apple-darwin.tar.gz`) |
| **Linux** | `.AppImage` / `.deb` / `.rpm` | `vigil-hub` (in `vigils-cli-…-linux-gnu.tar.gz`) |

> Early releases are unsigned; your OS may show a Gatekeeper / SmartScreen prompt on first run.

The **Chrome extension** lives in `extensions/chrome-mv3/` — load it unpacked via
`chrome://extensions` → *Developer mode* → *Load unpacked* (it talks to `vigil-native-host`).

## Quick Start

### As an MCP gateway (CLI)

Put Vigils in front of your MCP servers so every tool call is firewalled, approved, and audited:

```bash
# Serve as an MCP endpoint your agent connects to (stdio)
vigil-hub serve --stdio --upstreams ./upstreams.json

# upstreams.json — bare commands resolve via PATH automatically
# { "upstreams": [ { "name": "fs", "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] } ] }

# Register a remote (HTTP) MCP server with OAuth onboarding
vigil-hub add-remote-mcp https://mcp.example.com/
```

Point your agent (Claude Code / Cursor / Zed) at `vigil-hub` instead of the raw MCP server.

### Desktop app

Launch the desktop app to watch and control agents in real time: **Approval Queue** (approve /
deny / bulk), **Activity Feed** (live audit stream), **Server Registry**, **Session Replay**,
and **Privacy Findings**.

## Build from source

Requirements: a recent **stable Rust** toolchain (see `rust-toolchain.toml`) and **Node.js 20+**
for the desktop UI. On Linux, Tauri needs GTK/WebKit dev packages.

```bash
# Workspace tests / lints (no GPU or model deps by default)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# CLI gateway
cargo build --release -p vigil-hub-cli --bin vigil-hub

# Desktop UI + app (the `gui` feature embeds the built UI)
cd apps/desktop/ui && npm ci && npm run build && cd -
cargo build --release -p vigil-desktop --features gui --bin gui
```

> Crate names use the historical `vigil-*` prefix; the product and project are **Vigils**.

## Security model

- **Local-first** — prompts, secrets, and the audit ledger stay on your machine.
- **Default-deny** — the firewall blocks tool calls unless a policy explicitly allows them.
- **Fail-closed** — when a guarantee can't be enforced (e.g. Landlock unsupported, redaction
  engine unavailable but requested), Vigils refuses rather than silently degrading.
- **Tamper-evident** — the audit ledger is a SHA-256 hash chain; the desktop app can verify
  the whole chain.
- **No raw secrets at rest** — redaction stores only label / count / fingerprint metadata;
  plaintext credentials are never written to the ledger.
- **Least privilege spawning** — child processes get a cleared environment plus only the
  approved env and short-lived secret leases; Linux runs add Landlock filesystem isolation.

Found a vulnerability? Please report privately via the repository's security advisories.

## Project structure

```
crates/          # 15 library crates (audit, policy, firewall, mcp, redaction, runner,
                 #   lease, sandbox-linux, http-auth/transport, ui-protocol, browser, sdk, types)
apps/
  desktop/       # Tauri 2 + Vue 3 desktop app (bin: gui)
  native-host/   # Chrome native-messaging bridge (bin: vigil-native-host)
  vigil-hub-cli/ # CLI MCP gateway (bin: vigil-hub)
extensions/
  chrome-mv3/    # Chrome MV3 extension (vanilla JS)
docs/
  adr/           # Architecture Decision Records
  book/          # User guide (mdBook)
  threat-model/  # Security threat model
```

## Documentation

- **User guide** (mdBook): [`docs/book/`](./docs/book)
- **Architecture Decision Records**: [`docs/adr/`](./docs/adr)
- **Threat model**: [`docs/threat-model/`](./docs/threat-model)
- **SDK surface**: [`docs/sdk-shallow-api.md`](./docs/sdk-shallow-api.md)

## Contributing

Issues and pull requests are welcome. Before submitting, please ensure:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same gates on Linux and the UI build on every PR.

## License

[Apache-2.0](./LICENSE) © Vigils Authors.

---

<a name="中文"></a>

## 中文

**Vigils** 位于你的 AI Agent(Claude Code、Cursor、Zed、MCP 客户端、浏览器助手)与它们所触及
的工具/数据之间。**本地优先** —— prompt、凭据与审计记录永不离开本机。

### 四项保证

| 保证 | 实现 |
|---|---|
| **看见 Agent 做了什么** | 每次工具调用写入防篡改的 **SHA-256 哈希链账本**,支持 FTS5 全文检索 |
| **高危动作先审批** | 破坏性/敏感调用在 **Approval Queue** 暂停,人工审核 + 按 Agent 策略 + 范围化授权 |
| **凭据不进入 prompt / 日志 / UI** | **脱敏引擎**在文本抵达模型/日志/屏幕前剥离密钥与 PII(硬指纹 + 可选 ML 集成)|
| **隔离与回滚** | 账本端到端可追溯;**沙箱 runner 默认 fail-closed**(Wasm + native + Linux Landlock)|

### 特性

- **审计账本** —— SQLite + SHA-256 哈希链 + FTS5 检索 + 逐事件完整性
- **默认拒绝防火墙** —— Rust 策略 DSL 门禁 + 按 Agent 规则 + OAuth scope 白名单
- **人在回路审批** —— 高风险副作用暂停审核,范围化授权(once / this-session)
- **密钥/PII 脱敏** —— 13+ 类凭据硬指纹(GitHub/Stripe/Google/GitLab/DB URL …)+ 可选多语
  ML 集成 + fail-closed 合并
- **凭据租约** —— 短时租约只注入需要的子进程,明文不落盘
- **沙箱 runner** —— Wasm(Wasmtime)/ native 一次性执行,Linux Landlock 文件隔离 + env_clear
- **MCP 网关** —— stdio + HTTP 双传输,descriptor pinning + 漂移检测,裸命令经宿主 PATH 解析
- **桌面应用**(Tauri 2 + Vue 3)—— 审批队列 / 活动流 / 服务器注册 / 会话回放 / 隐私发现,
  快捷键 + 主题切换 + 实时更新 + 中英双语
- **浏览器扩展**(Chrome MV3)—— 在 AI 站点粘贴/提交前脱敏

### 安装

各 [GitHub Release](https://github.com/duncatzat/vigils/releases) 附带 **Windows / macOS /
Linux** 安装包与 CLI 二进制(Win: `.msi`/`.exe`;macOS: `.dmg`;Linux: `.AppImage`/`.deb`/`.rpm`;
CLI: `vigil-hub`)。早期版本未签名,首次运行系统可能提示。Chrome 扩展在 `extensions/chrome-mv3/`,
经 `chrome://extensions` 开发者模式"加载已解压"载入。

### 从源码构建

需近期 **stable Rust**(见 `rust-toolchain.toml`)+ **Node.js 20+**(Linux 还需 GTK/WebKit dev 包):

```bash
cargo test --workspace
cargo build --release -p vigil-hub-cli --bin vigil-hub          # CLI
cd apps/desktop/ui && npm ci && npm run build && cd -            # 桌面 UI
cargo build --release -p vigil-desktop --features gui --bin gui # 桌面 app
```

> crate 名沿用历史 `vigil-*` 前缀;产品与项目名为 **Vigils**。

### 安全模型

本地优先 · 默认拒绝 · fail-closed(不静默降级)· 哈希链防篡改 · 原文不落盘(仅存 label/count/
fingerprint)· 最小权限派生(env_clear + 短时租约 + Linux Landlock)。

### 许可证

[Apache-2.0](./LICENSE) © Vigils Authors · [vigils.ai](https://vigils.ai)
