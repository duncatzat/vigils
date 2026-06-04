# Changelog

All notable changes to Vigils are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (0.x allows interface evolution).

> 简体中文版本：[CHANGELOG.zh-CN.md](./CHANGELOG.zh-CN.md)

---

## [v0.1.8] — 2026-06-04

MCP gateway fixes — connecting `npx` / `uvx`-based upstream MCP servers (filesystem, GitHub, …)
now works end-to-end. Previously the gateway could aggregate **zero** tools from such servers, so
an agent saw Vigils as a 0-tool server. Validated on Linux against the real
`@modelcontextprotocol/server-filesystem` (14 tools surface, the firewall gates the call, the audit
chain verifies). No public API or SDK surface change; existing installs auto-update.

### Fixed

- **stdio upstream env policy** — user-configured upstream launchers (`npx` / `uvx` / `node`) were
  spawned with the sandbox runner's full `env_clear`, which strips `PATH` / `HOME`, so the launcher
  could not find its interpreter or package-manager cache and never started — the Hub then
  aggregated zero tools. Upstreams now use a dedicated env policy: `env_clear` plus a curated
  allowlist of **non-secret** runtime variables (`PATH` / `HOME` / `APPDATA` / locale / …), then
  approved per-tool secrets. The allowlist deliberately excludes secret-class and code-injection
  variables, so the parent process's API keys and tokens still never reach an upstream; the sandbox
  runner is unchanged. ([ADR 0007](docs/adr/0007-sandbox-runner.md) amendment)
- **MCP initialize handshake** — the Hub now performs the MCP client lifecycle handshake
  (`initialize` → `notifications/initialized`) before listing an upstream's tools, as the protocol
  requires, so strict MCP SDK servers that reject `tools/list` before initialization are supported.
  The negotiated protocol version is validated (fail-closed on an unsupported version). A
  broken/slow upstream is non-fatal — logged, its tools simply unavailable, rather than taking down
  the gateway.

### Docs

- Agent integration guide: corrected the tool-namespacing notation to the actual `__`
  (double-underscore) separator — `fs__read_file`, not `fs/read_file`.

---

## [v0.1.7] — 2026-06-03

Security hardening. Ports the fixes from the project's first comprehensive security audit
(OWASP Top 10 + STRIDE + supply-chain; score **9.9/10, 0 critical / 0 high**) into the public
release. No public API or SDK surface change; existing installs auto-update.

### Security

- **Audit-ledger hash chain v2** (VIGIL-SEC-001) — the tamper-evident SHA-256 chain now also
  binds `session_id`, `event_type`, and `redacted_text`, closing a gap where a local actor
  with database write access could rewrite those columns undetected. Versioned and
  backward-compatible: historical v1 events stay verifiable, new events use v2, and
  `verify_chain` enforces version monotonicity (a v2→v1 downgrade is rejected). See
  [ADR 0002](docs/adr/0002-audit-ledger.md).
- **Descriptor-hash validation** (VIGIL-SEC-004) — the MCP descriptor oracle fail-closes a
  malformed incoming hash to `FirstSeen` (approval-required) instead of trusting it.
- **Reserved allowlist-key guard** (VIGIL-SEC-005) — the firewall protects a *set* of reserved
  policy keys rather than a single literal.
- **Browser-extension sender check** (VIGIL-SEC-006) — the background service worker validates
  `sender.id === chrome.runtime.id` on inbound messages.

Full report: [docs/security/SECURITY-AUDIT-2026-06-03.md](docs/security/SECURITY-AUDIT-2026-06-03.md).

---

## [v0.1.6] — 2026-06-03

In-app branding consistency. The desktop UI showed "Vigil" (singular) in its title, sidebar
header, and a couple of descriptions, while the product is "Vigils". Those user-visible
strings now read "Vigils".

### Changed

- Desktop UI text uses the product name "Vigils" consistently — window / document title,
  sidebar header ("Vigils Desktop" / "Vigils 桌面"), and the privacy-findings descriptions. No
  functional change; CLI binaries (`vigil-hub`, `vigil-native-host`) and code identifiers are
  unaffected.

---

## [v0.1.5] — 2026-06-03

Desktop executable naming fix. The installed desktop program is now `vigils` instead of the
opaque `gui` — the process and on-disk executable were named `gui.exe` / `gui`, which gave no
hint of what the program was. The window, install folder, and macOS app bundle were already
"Vigils"; only the binary lagged.

### Changed

- The desktop binary is renamed `gui` → `vigils` (`mainBinaryName`, Cargo bin, and source
  file). Installed layout is now `Vigils/vigils.exe` on Windows, `vigils` on Linux, and
  `Vigils.app/Contents/MacOS/vigils` on macOS; the process shows as `vigils`. The product name
  ("Vigils"), installer filenames, and updater flow are unchanged — existing installs
  auto-update to the renamed binary.

### Fixed

- User-guide docs referenced a `vigil-desktop-gui.exe` binary that has not existed since the
  v0.1.2 single-binary fix; they now point at `vigils.exe`.

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
