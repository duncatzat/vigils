# vigil-sdk

[![crates.io](https://img.shields.io/crates/v/vigil-sdk.svg)](https://crates.io/crates/vigil-sdk)
[![docs.rs](https://docs.rs/vigil-sdk/badge.svg)](https://docs.rs/vigil-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Stable public SDK facade for embedding [Vigil](https://vigils.ai)'s local AI safety runtime into 3rd-party tools** — typed decisions/audit + firewall execution + redaction scanning.

## What is Vigil?

Vigil is a local-first AI Agent control plane:

- **Action firewall** (`Firewall::evaluate`) — fail-closed effect gating
- **Audit ledger** (SHA256 hash chain) — tamper-evident decision history
- **Privacy filter** (hard fingerprint rules + ONNX-backed PII detection)
- **MCP hub** (Model Context Protocol server registry + descriptor pinning)
- **Approval queue** (human-in-the-loop for risky effects)

This crate is the **minimal stable SDK** for 3rd-party tools to embed Vigil's safety runtime.

## Quickstart

```toml
[dependencies]
vigil-sdk = "0.1"
```

```rust
use vigil_sdk::prelude::*;

// Hard-fingerprint redaction (default-safe path, no model deps)
let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz12";
let result: RedactionResult = scan_text(token).unwrap();
assert!(result.findings.iter().any(|f| f.kind == "github_token"));
```

> Verified against the published `vigil-sdk = "0.1.0"` from crates.io by a standalone
> downstream consumer (see the crate-level rustdoc Quickstart, which is a compile-checked doctest).

## Invariants (SDK consumer 必守)

1. **Fail-closed** — Any `ScanError` / `FirewallError` MUST be treated as DENY. Never default to ALLOW on error path.
2. **No-plaintext audit** — SDK never persists raw input text. All audit goes through `DecisionRecord` / `AuditEvent` (no-plaintext invariant enforced).
3. **DecisionRecord mandatory** — Any effect trigger (tool invocation / approval / etc) MUST emit `DecisionRecord` first. No SDK API allows skipping.
4. **API stability** — In 0.x: minor signature tweaks allowed (must pass codex review + ADR). Post-1.0: items can only be added, never removed.

## What's in / out

**In SDK Phase 1** (public stable):
- `vigil_types::*` — `DecisionRecord`, `AuditEvent`, `EffectVector`, `ApprovalRequest`, `ToolInvocation`, etc.
- `vigil_firewall::{Firewall, FirewallConfig, FirewallOutcome, PiiScanner, ...}`
- `vigil_redaction::{scan_text, RedactionResult, ...}`

**Out of SDK Phase 1** (internal, may break):
- Server runtime (Hub / oracle internals)
- Backend implementations (`NoopEngine` / `MockEngine` / `OrtEngine`)
- Ops infra (bootstrap, model distribution)
- MCP routing internals / Lease broker internals / Policy engine internals

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `ort` | off | Enable ONNX-Runtime backed PII scanner (3-engine multilang ensemble) |

Default (no feature) uses **hard fingerprint rules + NoopEngine** — zero model deps, instant cold start.

## Status

**Alpha** (2026-05) — Vigil project at v0.11.1, SDK boundary locked per ADR 0015. Codex collaborative review session 019e0e02 reviewed 11+ iterations.

- ✅ 743+ tests / 0 clippy errors / 17 ADRs
- ✅ Multi-platform installer (Linux deb/rpm/AppImage + macOS dmg + Windows msi/nsis)
- ✅ Tauri auto-updater (Ed25519 signed)
- ⏸ External security pen test (planned v0.12)

## License

Apache-2.0 © Vigil Project Contributors

## Links

- 🏠 Homepage: <https://vigils.ai>
- 📦 Crate: <https://crates.io/crates/vigil-sdk>
- 📖 Docs: <https://docs.rs/vigil-sdk>
