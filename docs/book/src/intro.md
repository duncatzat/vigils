# Introduction

**Vigils** is a local-first control plane for AI agents:

- **Action firewall** (`Firewall::evaluate`) — fail-closed effect gating
- **Audit ledger** (SHA-256 hash chain) — tamper-evident decision history
- **Privacy filter** (hard-fingerprint rules + optional ONNX-backed PII detection)
- **MCP hub** (Model Context Protocol server registry + descriptor pinning)
- **Approval queue** (human-in-the-loop for risky effects)
- **Sandbox runner** (Wasm + native, Linux Landlock LSM)

Vigils sits between AI agents and the effectful tools / APIs they touch, gating each action
through redaction + policy + audit + approval — and everything stays on your machine.

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
