# Introduction

**Vigils** is a local-first control plane for AI agents:

- **Action firewall** (`Firewall::evaluate`) — fail-closed effect gating
- **Audit ledger** (SHA-256 hash chain) — tamper-evident decision history
- **Privacy filter** — hard-fingerprint rules (always on) + *optional* ONNX PII/injection model (opt-in via `--engine ml|auto`; **not in default release builds** — see [Privacy Filter](./concepts/privacy-filter.md))
- **MCP hub** (Model Context Protocol server registry + descriptor pinning)
- **Approval queue** (human-in-the-loop for risky effects)
- **Sandbox runner** (Wasm + native, Linux Landlock LSM)

Vigils sits between AI agents and the effectful tools / APIs they touch, gating each action
through redaction + policy + audit + approval — and everything stays on your machine.

## What it protects against — and what it doesn't

Vigils is **defense in depth**, not an airtight barrier. Being honest about the boundary lets you rely on it correctly.

**Reliably catches**

- **Plaintext credential leaks** — 13 hard-fingerprint classes (AWS keys, GitHub / GitLab tokens, Google API keys, Slack webhooks, Stripe keys, private-key PEM blocks, credential-bearing DB URLs, …) appearing verbatim in tool calls, browser pastes, or tool results.
- **Reversible redaction round-trip** — the model / logs / audit see only `secret://<alias>` placeholders; the real value is injected only at the local execution boundary.
- **Tamper-evident audit** (SHA-256 chain, falsifiable via `vigil-hub verify`), **approval gating**, and **sandbox isolation**.

**Does not stop (deliberate evasion)**

Input-side fingerprint detection is fundamentally evadable by a model that is *trying* to exfiltrate: it can encode / transform a secret (base64, hex, `String.fromCharCode`, chunking) or route it through a channel Vigils doesn't mediate (e.g. a Playwright-driven browser typing character-by-character). Vigils **raises the bar and leaves an audit trail**, but is **not** a guarantee against an adversarial agent. Don't treat "Vigils is installed" as license to let an untrusted agent handle real credentials.

**The complete fix (roadmap)**

An **egress proxy** that mediates *all* outbound data is the full answer — it catches encoded / chunked exfiltration before the value leaves the machine. That's future work; until then, treat Vigils as audit + accidental-leak prevention + reversible redaction, not a sealed exfiltration barrier.

## Project status

| Dimension | State |
|---|---|
| Releases | 3-platform signed installers + auto-update (OTA) — [latest release](https://github.com/duncatzat/vigils/releases/latest) |
| Rust SDK | [`vigil-sdk`](https://crates.io/crates/vigil-sdk) published to crates.io |
| Security | Comprehensive audit (OWASP + STRIDE + supply chain) — **9.9 / 10, 0 critical / high** |
| Maturity | Core safety claims proven-safe with code + test evidence; all sandbox / SDK / audit changes reviewed |

## Distribution

- **Desktop installers** — Linux deb / rpm / AppImage + macOS dmg + Windows nsis / msi (Ed25519-signed, auto-update).
- **Rust SDK** — `cargo add vigil-sdk` ([crates.io](https://crates.io/crates/vigil-sdk) / [docs.rs](https://docs.rs/vigil-sdk)).
- **Browser extension** — Chrome MV3 (redacts before paste / submit on AI sites).
- **CLI agent gateway** — `vigil-hub serve --stdio` (Claude Code / Codex / Cursor / Zed).

## License

Apache-2.0 © Vigils Project Contributors

## Quick links

- [Installation](./getting-started/installation.md)
- [Quickstart — Embedding the SDK](./getting-started/sdk-quickstart.md)
- [Architecture Overview](./concepts/architecture.md)
