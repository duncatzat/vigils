# Changelog

All notable changes to Vigils are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (0.x allows interface evolution).

> 简体中文版本：[CHANGELOG.zh-CN.md](./CHANGELOG.zh-CN.md)

---

## [v0.1.4] — 2026-06-02

First crate-line release. Earlier 0.1.x releases were desktop packaging fixes; this one
publishes the embeddable SDK (`vigil-sdk`) to crates.io, adds a second drift dimension to the
MCP gateway, and brings every crate, the desktop app, and the published SDK onto a single
0.1.4 version.

### Added

- **`vigil-sdk` embedding facade.** `FirewallBuilder` assembles a working firewall (audit
  ledger + policy engine + default rule set) in a single call and is fail-closed by default —
  an unconfigured tool is never blanket-allowed. `SdkFirewall::decide` / `decide_call` provide
  a one-call decision API for embedding Vigil's safety runtime in a host application. The SDK
  and its dependency crates are published on crates.io.
- **Resolved-program drift detection for stdio MCP servers.** A pinned server's *resolved
  executable path* is now a tracked dimension, orthogonal to argument drift: if it changes,
  the gateway refuses to spawn the server until the change is reviewed and approved. The check
  runs before spawn (fail-closed), is serialized against concurrent attaches, and is recorded
  in the audit ledger as a reviewable drift event.

### Changed

- The privacy-filter model now downloads from the public Hugging Face endpoint
  (`huggingface.co/openai/privacy-filter`, Apache-2.0); set `VIGIL_MODEL_MIRROR` to point at
  your own mirror. File sizes and SHA-256 digests are unchanged (byte-identical to the
  previous source).
- Workspace, desktop app, and published SDK versions aligned to `0.1.4`. The desktop build
  picks up the MCP drift hardening through its backend crates; there are no desktop-UI changes
  in this release.

### Security

- Wasmtime updated `44.0.1` → `44.0.2`, clearing sandbox advisory RUSTSEC-2026-0149.

---

## [v0.1.3] — 2026-06-01

Desktop GUI rendering fix. The desktop app now actually renders its UI. v0.1.2 fixed the
installer to bundle the GUI (not the CLI), but the GUI then opened a blank/black window:
vue-i18n compiled locale messages at runtime with `new Function`, which the app's strict
Content Security Policy (`script-src 'self'`, no `'unsafe-eval'`) blocks, aborting the
render.

### Fixed

- The desktop GUI no longer opens a blank/black window. vue-i18n is given a CSP-safe custom
  `messageCompiler` (plain `{named}` interpolation, no `eval` / `new Function`), so the UI
  renders under the strict production CSP without weakening it. The bug only affected
  built/installed apps — `tauri dev` runs under a relaxed CSP, so it went unnoticed until
  v0.1.2 first made the GUI installable.

### Changed

- Workspace and desktop app version `0.1.2` → `0.1.3`.

---

## [v0.1.2] — 2026-06-01

Desktop bundle fix. The Windows / macOS / Linux desktop installers now contain the actual
GUI application. The v0.1.0 and v0.1.1 desktop installers mistakenly bundled the headless
CLI binary in its place — double-clicking the installed app flashed a console and exited
instead of opening the window. The CLI binaries themselves were fine; only the desktop
installers were affected.

### Fixed

- Desktop installers now ship the GUI, not the CLI. `apps/desktop` exposed a second
  `[[bin]]` (the `vigil-desktop` debug CLI); `cargo tauri build` builds every binary
  (`cargo build --bins`) and bundled the wrong one as the app executable. The desktop crate
  now has a single `gui` binary, so the bundlers can only package the GUI.

### Changed

- The `vigil-desktop` debug CLI is removed; its ledger-inspection capability is now part of
  the main `vigil-hub` CLI as `vigil-hub inspect` (`activity` / `search` / `approvals` /
  `session` / `servers` / `sandbox` / `verify-chain`; one-line JSON output for scripting).
- Workspace and desktop app version `0.1.1` → `0.1.2`.

---

## [v0.1.1] — 2026-06-01

Packaging-completeness release. Adds Windows MSI and Linux RPM installers alongside the
existing NSIS / DMG / DEB / AppImage bundles, and aligns the workspace and desktop app
version with the public release line. No library or runtime behavior changes.

### Added

- Windows MSI installer and Linux RPM package are now produced and attached to the release.

### Changed

- Workspace and desktop app version `0.0.1` → `0.1.1`, aligning the crate/app version with
  the public release tag.
- The README installation table now lists the complete installer set per platform.

---

## [v0.1.0] — 2026-06-01

First public release of Vigils — a local-first control plane for AI agents.

### Added

- **Audit ledger** — SQLite, SHA-256 hash chain, FTS5 full-text search, per-event integrity.
- **Firewall & approval** — default-deny tool gating, per-agent policy, human-in-the-loop
  Approval Queue with scoped grants.
- **Redaction engine** — secret/PII detection via hard-fingerprint rules and an optional ML
  ensemble, with a fail-closed merge layer.
- **Secret lease broker** — short-lived credential leases; plaintext never persisted.
- **Sandbox runner** — Wasm (Wasmtime) and native execution, Linux Landlock LSM filesystem
  isolation, fail-closed by default.
- **MCP gateway** — stdio and HTTP transports, descriptor pinning with drift detection,
  OAuth scope allow-lists.
- **Desktop app** (Tauri 2 + Vue 3) — Approval Queue, Activity Feed, Server Registry,
  Session Replay, Privacy Findings; keyboard shortcuts, theme toggle, real-time updates,
  bilingual (zh / en) UI.
- **Browser extension** (Chrome MV3) — redacts secrets/PII before paste or submit on AI
  sites.

Licensed under Apache-2.0.
