<div align="center">

# Vigils

### A local-first control plane for AI agents — see what they do, approve what matters, keep secrets out.

[![CI](https://github.com/duncatzat/vigils/actions/workflows/ci.yml/badge.svg)](https://github.com/duncatzat/vigils/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/duncatzat/vigils?sort=semver&color=blue)](https://github.com/duncatzat/vigils/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation)

[Website](https://vigils.ai) · [▶ Watch the 20s demo](https://duncatzat.github.io/vigils/demo.html) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Security Model](#security-model) · [Documentation](#documentation)

**English** | [简体中文](./README.zh-CN.md)

</div>

---

AI agents (Claude Code, Codex, Cursor, Zed, Kimi CLI, ZCode, pi, browser assistants) call tools, read
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
- **🖥️ Desktop app — protection in a few clicks** (Tauri 2 + Vue 3). Open the **Aegis
  command deck** and click **Deploy Guardian**: Vigils finds every AI agent on the machine,
  backs up their configs, wires hook + MCP-gateway protection into all of them, and lights up
  per-agent status — no terminal, no hand-edited files, fully reversible. Engine missing?
  One more click downloads it securely (signed manifest + SHA-pin, fail-closed). Close the
  window and it keeps guarding from the tray (single-instance). Engine mode / posture /
  resident daemon / ML install are switches on the Settings page — the GUI drives the same
  `vigil-hub` engine as the CLI. Bilingual (zh / en), real-time.
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
| **SDK** | `vigil-sdk` | Thin, SemVer-stable facade over the engine. Published on crates.io alongside stable releases (`cargo add vigil-sdk`) |

**Apps & binaries:**

| Binary | Crate | What it is |
|---|---|---|
| `vigil-hub` | `vigil-hub-cli` | CLI MCP gateway: `vigil-hub serve --stdio`, `add-remote-mcp`, `inspect`, … |
| `vigils` | `apps/desktop` | Tauri 2 desktop app (embeds the Vue 3 UI + an in-process Hub) |
| `vigil-native-host` | `apps/native-host` | Native-messaging bridge for the Chrome extension |
| — | `extensions/chrome-mv3` | Chrome MV3 extension (vanilla JS, zero npm deps) |

## Installation

> **New here? → [Install guide: which file to download + first-run steps](https://duncatzat.github.io/vigils/getting-started/installation.html)** ([中文](https://duncatzat.github.io/vigils/getting-started/installation.zh-CN.html)) — a 1-minute, pick-your-OS walkthrough (incl. the unsigned-app prompt on Windows/macOS).

**Quickest** — install the CLI in one line, then jump to [Quick Start](#quick-start):

```bash
curl -fsSL https://vigils.ai/install.sh | sh         # macOS / Linux
```

```powershell
irm https://vigils.ai/install.ps1 | iex              # Windows (PowerShell)
```

Or grab a pre-built installer / binary for **Windows, macOS, or Linux** from any
[GitHub Release](https://github.com/duncatzat/vigils/releases):

| Platform | Desktop app | CLI |
|---|---|---|
| **Windows** | `.exe` (NSIS) / `.msi` | `vigil-hub.exe` (in `vigils-cli-windows-x64.zip`) |
| **macOS** (Apple Silicon) | `Vigils_<ver>_aarch64.dmg` | `vigil-hub` (in `vigils-cli-macos-arm64.tar.gz`) |
| **macOS** (Intel) | `Vigils_<ver>_x64.dmg` | `vigil-hub` (in `vigils-cli-macos-x64.tar.gz`) |
| **Linux** | `.AppImage` / `.deb` / `.rpm` | `vigil-hub` (in `vigils-cli-linux-x64.tar.gz`) |

### Two redaction engines: hard-fingerprint (default) or ML

Both CLI builds run the identical firewall / audit / approval core — they differ only in the **redaction engine** that strips secrets and PII before text reaches a model, a log, or the screen:

| Build | Release asset | Redaction | First-run cost |
|---|---|---|---|
| **Default** — hard-fingerprint | `vigils-cli-<plat>` | 13+ structured credential & PII classes via fixed-pattern rules — deterministic, instant, no model | none |
| **ML** | `vigils-cli-ml-<plat>` | The above **plus** an OpenAI PII NER model + a DeBERTa prompt-injection classifier — broader, semantic PII (names, addresses, dates) and soft injection signals | bundles the ONNX Runtime dylib; fetches ~0.8–1.5 GB of models on first `--engine ml` run |

The two **coexist** — the engine is chosen per launch, so a single ML build serves any mode:

```bash
vigil-hub serve --engine hardfp   # fingerprint rules only (what the default build does)
vigil-hub serve --engine ml       # strict ML: fetches models on first run, fails closed if unavailable
vigil-hub serve --engine auto     # ML only if models are already cached and the dylib is present; otherwise degrades to hardfp and never downloads
```

Models are fetched from Hugging Face (primary) with a [vigils.ai](https://vigils.ai) mirror fallback, each verified by SHA-256 (fail-closed). The ML build bundles [ONNX Runtime](https://onnxruntime.ai) 1.24 next to `vigil-hub`. Platform floors for the **ML** build: **Linux glibc ≥ 2.28**, **macOS ≥ 14 (Apple Silicon only** — upstream onnxruntime no longer publishes x86_64 macOS builds, so Intel macs use the default hard-fingerprint engine**)** — the default hard-fingerprint build has neither. _(ML builds ship with every release since v0.4.0 — look for the `vigils-cli-ml-*` assets.)_

> Early releases aren't OS-code-signed yet; your OS may show a Gatekeeper / SmartScreen prompt
> on first run — they're still independently verifiable (see below, or the full
> [Verifying your download](https://duncatzat.github.io/vigils/getting-started/verifying-downloads.html) guide).

**Verify what you downloaded** (optional). Every release asset carries a SHA-256 checksum
(`<file>.sha256`, also checked automatically by the one-line installer) and a cryptographic
**build-provenance attestation**. With the [GitHub CLI](https://cli.github.com):

```bash
gh attestation verify vigils-cli-linux-x64.tar.gz --repo duncatzat/vigils
```

This confirms the artifact was built by Vigils' official CI from this repository (SLSA provenance
via Sigstore) — i.e. not swapped or tampered with after the build. The CLI archives, desktop
installers, and the extension zip are all attested. Full guide (per-OS steps + the unsigned-app
prompt): [**Verifying your download**](https://duncatzat.github.io/vigils/getting-started/verifying-downloads.html)
([中文](https://duncatzat.github.io/vigils/getting-started/verifying-downloads.zh-CN.html)).

The **Chrome extension** ([**Vigils Browser Guard**](https://chromewebstore.google.com/detail/vigils-browser-guard/ffmgaglmcimapacgmoejaobfjdpmopch))
installs in one click from the Chrome Web Store — consumer mode scans in-browser and works out of
the box; pairing with `vigil-native-host` unlocks deep redaction. Source lives in
`extensions/chrome-mv3/` (dev builds: `chrome://extensions` → *Developer mode* → *Load unpacked*).

## Quick Start

### Install (one line)

```bash
curl -fsSL https://vigils.ai/install.sh | sh         # macOS / Linux
```

```powershell
irm https://vigils.ai/install.ps1 | iex              # Windows (PowerShell)
```

Installs the `vigil-hub` CLI (to `~/.local/bin` on macOS/Linux, `%LOCALAPPDATA%\Vigils\bin` on
Windows). It only puts the binaries on disk — **no shell/PATH edits, no `setup`, no agent-config
changes** — and prints what to do next, so you stay in control. The download is verified against the
release's published SHA-256 before unpacking (fail-closed). Want to read them first? They're
[`install.sh`](./install.sh) / [`install.ps1`](./install.ps1). Prefer a manual download? See
[Installation](#installation).

### See it in 60 seconds (zero setup)

One command shows Vigils' core value — **default-deny protection + reversible secret redaction +
tamper-evident audit** — running through the real runtime code, contacting no LLM, needing no account,
key, or network:

```bash
vigil-hub demo            # default-deny → placeholder round-trip → real value only at the local tool → audit with no plaintext
vigil-hub demo --tamper   # also: alter the audit ledger and watch verify-chain DETECT it (falsifiable)
```

What you'll see (real output, trimmed):

```text
  A demo secret — freshly generated locally for this run (never leaves this process):
    github_pat = ghp_c7da264c45f58cd89aaa12cde5b8c69883e6

  [1] default-deny: agent puts the RAW secret in the tool call
    tool=github.create_issue  ->  Vigil firewall: DENY  (rule=github_token)

  [2] the Vigil way: the agent passes a PLACEHOLDER instead
    What the REMOTE MODEL saw:    {"token":"secret://github_pat"}              plaintext secret? NO
    What the LOCAL TOOL received: {"token":"ghp_c7da264c45f58cd89aaa12c..."}   contains real value? YES
    The tool's result LEAKED a credential; Vigil re-redacted it:
      {"debug_trace":"authenticated with [REDACTED github_token] ...","ok":true}    secret back to model? NO

  [3] tamper-evident audit ledger (no plaintext secrets stored)
      0002 sha256:947ce1fe0d30  raw_secret_attempt_detected
      0008 sha256:17e875d2e47e  secret.leak_detected
    hash chain valid: YES        plaintext secret in audit: NO
```

> **The aha:** the agent did useful work with a real secret — while the model, logs, and audit never
> received the real value. It's a planted scenario with a freshly-generated local fixture; the
> firewall, redaction, and audit are Vigils' real code, only the model/tool provider is simulated.

### Protect your agents in one command (turnkey)

Download the release, then run **one command** to get fully protected. No manual config editing —
your existing settings are backed up and only Vigils' own entries are added (fully reversible):

```bash
vigil-hub setup --all       # protect everything, in one step
```

`setup --all` wires up **both** layers of protection:

1. **Native-tool input guard** — pre-tool-use hooks for **Claude Code, Codex CLI, Gemini CLI
   and Cursor**, so **every tool call** (Bash, Edit, Write, Read, MCP tools, …) is checked before
   it runs; a real credential heading *into* a tool is **blocked fail-closed** and recorded in
   your tamper-evident audit ledger.
2. **MCP gateway** — rewrites the stdio MCP servers of every detected agent — **Claude Code,
   Codex, Gemini CLI, Cursor, Windsurf, Kimi CLI, ZCode, pi, Grok CLI, OpenCode, CodeBuddy and
   Cline** — to run through Vigils, so secrets in tool
   **results** are scrubbed before the model ever sees them, and every call is audited. It defaults
   to **monitor** posture — your servers stay fully usable while every hard protection stays on
   (raw-secret block, result redaction, tamper-evident audit). Add `--enforce` for default-deny gating.
   The full per-agent coverage matrix lives in the
   [Agent Integration guide](https://duncatzat.github.io/vigils/getting-started/agent-integration.html).

```bash
vigil-hub setup --mcp --doctor    # pre-flight: will each wrapped MCP server actually start? (PATH check, read-only)
vigil-hub inspect protection      # after using your agent: see what Vigils caught (secrets blocked, leaks redacted, chain intact)
vigil-hub setup --all --uninstall # cleanly remove everything (only Vigils' own entries; your settings restored faithfully)
```

Restart your agent (or start a new session) and you're protected. This is the fastest path from a
GitHub download to real protection.

### As an MCP gateway (CLI)

Put Vigils in front of your MCP servers so every tool call is firewalled, approved, and audited:

```bash
# Serve as an MCP endpoint your agent connects to (stdio)
vigil-hub serve --stdio --upstream-config ./upstreams.json

# upstreams.json — bare commands resolve via PATH automatically
# { "upstreams": [ { "name": "fs", "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] } ] }

# Register a remote (HTTP) MCP server with OAuth onboarding
vigil-hub add-remote-mcp https://mcp.example.com/

# See what Vigils has protected at a glance (secrets blocked, leaks redacted, audit chain intact)
vigil-hub inspect protection

# Inspect the local audit ledger from the command line (one-line JSON, pipe to jq)
vigil-hub inspect --db-path ./vigil.db activity --limit 20
```

Point any MCP-capable agent (Claude Code / Codex / Cursor / Zed / Kimi CLI / …) at `vigil-hub`
instead of the raw MCP server. See
the **[Agent Integration & Test guide](https://duncatzat.github.io/vigils/getting-started/agent-integration.html)**
for per-agent config and how to verify it's gating.

### Desktop app — no terminal needed

Prefer clicking to typing? The desktop app gets you to the same protection in three clicks:

1. **Open Vigils** — the Protection Overview shows an honest status: which agents are
   protected, which aren't.
2. *(first run)* Click **Download engine** if prompted — the `vigil-hub` engine is fetched
   over HTTPS, pinned to the release's signed manifest, and run-verified before use
   (fail-closed).
3. Click **Deploy Guardian** — Vigils detects your installed agents, backs up their configs,
   registers the hooks, rewrites their MCP servers through the gateway, and lights up
   per-agent status. Same effect as `setup --all`, zero typing.

From then on it's a **resident guardian**: closing the window hides to the system tray and
protection keeps running (a second launch just focuses the existing window). Watch and
control everything live — **Approval Queue** (approve / deny / bulk), **Activity Feed**
(live audit stream), **Server Registry**, **Session Replay**, **Privacy Findings**, and
**Settings** (engine mode, posture, resident daemon, ML model install, audit checkpoint
anchor). Changed your mind? One click (or `vigil-hub setup --all --uninstall`) restores
every config faithfully.

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
cargo build --release -p vigil-desktop --features gui --bin vigils
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

Found a vulnerability? Please report it privately — see [SECURITY.md](./SECURITY.md). Please
don't open a public issue for security reports.

## Project structure

```
crates/          # 16 library crates (audit, policy, firewall, mcp, redaction, runner,
                 #   lease, sandbox-linux, daemon-ipc, http-auth/transport, ui-protocol,
                 #   browser, sdk, types)
apps/
  desktop/       # Tauri 2 + Vue 3 desktop app (bin: vigils)
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

- **User guide** (mdBook): **<https://duncatzat.github.io/vigils/>** — or build [`docs/book/`](./docs/book) locally
- **Security audit**: [`docs/security/SECURITY-AUDIT-2026-06-03.md`](./docs/security/SECURITY-AUDIT-2026-06-03.md) — comprehensive baseline (OWASP + STRIDE + supply chain), 9.9/10, 0 critical / high
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

### Documentation (bilingual)

Vigils serves both the Chinese and international communities, so **user-facing docs are
bilingual**. When you add or change a guide / how-to / explanatory doc, evaluate whether it needs
both languages — if so, write an English page **plus a separate Chinese page** (never
sentence-by-sentence interleaving), e.g. `foo.md` + `foo.zh-CN.md`, cross-linked at the top.
Reference / ADR / internal docs may stay English-only.

## License

[Apache-2.0](./LICENSE) © Vigils Authors.
