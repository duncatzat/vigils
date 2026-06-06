# Changelog

All notable changes to Vigils are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (0.x allows interface evolution).

> 简体中文版本：[CHANGELOG.zh-CN.md](./CHANGELOG.zh-CN.md)

---

## [v0.1.22] — 2026-06-06

Fixes the very first protected run on a fresh machine — the audit ledger now creates its own
data directory instead of failing to open.

### Fixed

- **First run on a clean machine no longer fails to open the audit ledger.** On a machine where
  Vigil had never written its data directory yet (`~/.local/share/Vigil/` on Linux,
  `%LOCALAPPDATA%\Vigil\` on Windows), the very first protected tool call tried to open the audit
  ledger at a path whose parent directory didn't exist and failed with
  `unable to open database file`. The ledger now creates any missing parent directories before
  opening, so the turnkey flow works on a brand-new install with no manual `mkdir`. (Found by
  running the full `setup --all` → wrapped MCP server → audit loop end-to-end on a fresh machine —
  the directory always already existed on developer machines, so no prior test surfaced it.)

## [v0.1.21] — 2026-06-06

Fixes the Linux CLI so it actually runs on Ubuntu 22.04 LTS, Debian 12, and most current
distributions — the previous Linux build silently required a glibc version newer than they ship.

### Fixed

- **Linux CLI now runs on glibc 2.35+ (Ubuntu 22.04 LTS, Debian 12, …).** The `vigils-cli-linux-x64`
  binary was built on the latest CI runner (Ubuntu 24.04), so it required `GLIBC_2.39` and failed at
  startup on anything older with `version 'GLIBC_2.39' not found` — including Ubuntu 22.04 LTS, the
  single most common Linux for developers. The Linux CLI is now built on Ubuntu 22.04 (glibc 2.35),
  which runs on 22.04, 24.04, Debian 12, and most current distros. (Found by running the published
  binary end-to-end on a real machine — exactly the kind of packaging issue tests on the build host
  never surface.) A fully static (musl) "runs on any Linux" build is tracked for a later release.

## [v0.1.20] — 2026-06-06

`vigil-hub setup --all` protects everything in one command — closing the last "download → directly
protected" gap where full protection used to take two separate commands.

### Added

- **`vigil-hub setup --all` — one command for full protection.** Until now, full protection meant
  running two commands: `setup` (the native-tool PreToolUse hook that blocks raw secrets in tool
  *inputs*) **and** `setup --mcp --apply` (route each MCP server through Vigil's gateway for result
  redaction + audit). `--all` does both at once. `--all --uninstall` removes both; `--all --dry-run`
  previews both without writing. The two steps write different files and are each atomic, backed up,
  and reversible. After it's done: `vigil-hub inspect protection` shows what Vigil has caught.
- **Honest partial-failure reporting.** If the hook step succeeds but the MCP step fails (or vice
  versa), the CLI tells you exactly which step applied and how to undo just that one — never a vague
  "failed" that hides a half-applied state. `--all` is rejected at parse time when combined with the
  read-only `--status` / `--doctor` / `--mcp` flags, so it can never silently turn a read-only check
  into a write.

## [v0.1.19] — 2026-06-06

A new `vigil-hub setup --mcp --doctor` pre-flight tells you, before you even run your agent, whether
each wrapped MCP server can actually start — so a silently-broken server no longer looks like "Vigil
broke my setup".

### Added

- **`vigil-hub setup --mcp --doctor` — launchability pre-flight for your MCP servers.** For each MCP
  server in your config (including ones already wrapped by Vigil), it checks whether the underlying
  program can be resolved in your `PATH`, using the exact same resolution the gateway does at spawn
  time. You get a per-server `[OK]` / `[FAIL] program not found` / `[skip]` (for remote servers), with
  an actionable hint (e.g. "install Node.js" for a missing `npx`). This answers the most common
  turnkey failure — "which server won't start, and why?" — which previously showed up only as silently
  missing tools in your agent. Static and read-only: it resolves programs, it does **not** start any
  server. Exit code is non-zero if any server won't launch, so you can use it in scripts. For an
  already-wrapped entry it checks the **real** server program, not `vigil-hub` itself.

## [v0.1.18] — 2026-06-06

A new `vigil-hub inspect protection` command shows, at a glance, what Vigil has actually protected —
so the "monitor mode still protects you" guarantee is visible, not just claimed.

### Added

- **`vigil-hub inspect protection` — a protection-summary view over your audit ledger.** It counts
  secrets blocked at input, tool-result secret leaks detected (and redacted, when result redaction
  is on — the default for `setup --mcp`/`wrap`), `secret://` aliases withheld, total events audited
  across sessions, and whether the tamper-evident hash chain still verifies — plus the most recent
  protection events (redacted summaries only). This makes the reversible-redaction value legible:
  after running your MCP tools through Vigil, you can see exactly what it caught. Read-only;
  `--json` for scripts. The wording is deliberately honest — it reports *observed* protection, not
  inflated "threats stopped".
- The summary **fails closed**: if the audit chain does not verify, the recent-event detail is
  withheld (a tampered ledger's stored summaries can't be trusted), while the integer counts and a
  clear "chain failed verification" warning are still shown.

## [v0.1.17] — 2026-06-06

`vigil-hub setup --mcp` now defaults to **monitor** posture, so wrapping your existing MCP servers
no longer breaks them — the turnkey "download → protected" path is usable out of the box, while
keeping every hard protection on.

### Changed

- **`setup --mcp` default posture is now monitor, not enforce.** The servers this wraps are your
  own third-party MCP servers (filesystem, git, etc.). Vigil's firewall can only classify the
  effects of tools it recognizes, so a third-party tool produces no effects and — under the old
  `enforce` default — hit the default-deny floor and was **blocked**. In practice that meant the
  one-command setup could make your existing servers stop working. Monitor posture keeps the
  servers usable while still enforcing every **hard floor**: raw-secret input is still blocked,
  tool results are still redacted (reversible round-trip — the model sees placeholders), explicit
  deny rules still deny, a changed/drifted tool descriptor is still not auto-approved, and every
  call is still written to the tamper-evident audit ledger. Research backs this: ~93% of approval
  prompts are approved unread, so deterministic redaction protects you more than a blocking gate
  that gets click-through-approved anyway.
- **New `--enforce` flag for the hardened, default-deny posture.** If you want strict gating —
  e.g. for a known/fixed tool set, a server you built yourself, or a high-assurance environment —
  run `vigil-hub setup --mcp --apply --enforce`. The preview (`vigil-hub setup --mcp`) and apply
  output now state the exact posture that will be written, so there's no ambiguity about whether
  you're in monitor or enforce.

This is reversible the same way as before: `vigil-hub setup --mcp --uninstall` restores your
original config byte-for-byte.

## [v0.1.16] — 2026-06-06

Makes wrapped MCP servers actually usable in monitor mode, plus security hardening — found by
end-to-end testing the gateway against a real third-party MCP server.

### Fixed

- **Wrapped MCP servers now work in monitor mode.** Previously, a server wrapped with
  `vigil-hub wrap --monitor` (the recommended posture when you have no desktop approver running)
  would have most of its tools **denied** — third-party tools the firewall can't classify hit the
  default-deny floor, and monitor only auto-allowed approval-required calls, not the floor. Now
  monitor downgrades the **default-deny floor** to observe-allow (with full audit), so a wrapped
  filesystem/git/etc. server is usable out of the box. This affects **only** the unclassified
  floor: explicit deny rules, raw-secret blocking, and result redaction are all still enforced,
  and the default `enforce` posture is unchanged (still secure-by-default).
- **Monitor mode no longer auto-approves a changed (drifted) tool descriptor.** Descriptor drift
  is a tamper / supply-chain signal; in monitor mode a drifted descriptor now falls through to the
  approval path (and is denied in turnkey-without-GUI) instead of being silently allowed, keeping
  the descriptor-pinning trust anchor intact.
- **`vigil-hub setup --mcp` skips servers whose name can't be a valid gateway id.** A server name
  with uppercase letters, spaces, dots, or slashes would previously be rewritten successfully but
  then fail when the wrapped gateway started. It's now skipped with a clear message to rename it.
- **The `vigil-hub` startup banner shows the real release version** (e.g. `vigil-hub v0.1.16`)
  instead of an internal build marker.

## [v0.1.15] — 2026-06-06

`vigil-hub setup --mcp` now protects **local-scope** (per-project) MCP servers too — closing the
common case where `claude mcp add` (which defaults to local/project scope) left servers unguarded.

### Changed

- **`setup --mcp` protects both user-scope and local-scope MCP servers by default.** Previously it
  only wrapped user-scope servers (`~/.claude.json` top-level `mcpServers`) and refused when
  local-scope servers (`projects.*.mcpServers`) were present. Since `claude mcp add` writes
  **local scope by default**, the typical setup was left unprotected. Now `--apply` wraps both;
  `--user-scope-only` opts out of local scope and honestly reports how many servers it left
  unprotected; `--uninstall` restores both scopes. Your repo's committed `.mcp.json` (shared with
  teammates) is still never touched.
- **Local-scope servers get a project-scoped, collision-resistant gateway identity.** A server
  named `filesystem` can exist in many projects; wrapping them all under one identity would let one
  project's approval silently authorize another's. Each local-scope server is now wrapped with a
  namespace-disjoint id (`local-<project-hash>-<name>`, distinct from user-scope `user-<name>`), so
  same-named servers across projects keep independent audit/approval state in the shared ledger.

### Added

- **`setup --mcp` preview now lists both scopes**, showing exactly what would be wrapped in your
  user-scope and per-project configurations before you run `--apply`.

## [v0.1.14] — 2026-06-05

Turnkey protection for **MCP servers**: put Vigils' firewall, redaction, approval, and audit
between your AI agent and any MCP tool server — by changing one line of config, or letting
`vigil-hub setup --mcp` do it for you.

### Added

- **`vigil-hub wrap` — transparent MCP gateway shim.** Wrap any stdio MCP server command so every
  `tools/list` and `tools/call` flows through Vigils' gateway (default-deny firewall,
  hard-fingerprint secret redaction, approval, and tamper-evident audit) before reaching the real
  server. Your agent connects to `wrap` exactly as if it were the original server. Usage:
  `vigil-hub wrap --server-id <name> -- npx -y @modelcontextprotocol/server-filesystem /data`
  (in your agent's MCP config, set `command` to `vigil-hub` and prefix the args with
  `["wrap", "--server-id", "<name>", "--", ...original command]`). Secrets are handled safely: the
  child process only receives the env keys you explicitly pass with `--env-key` (nothing else is
  forwarded by default), and secrets in tool results are redacted before they reach the model.
- **`vigil-hub setup --mcp` — auto-wrap your Claude Code MCP servers.** Enumerates the stdio MCP
  servers in your Claude Code config (`~/.claude.json`, user scope) and rewrites each to go through
  `vigil-hub wrap`. `--mcp` alone is a **read-only preview**; `--mcp --apply` writes the change
  (atomic write + backup, fully reversible); `--mcp --uninstall` restores the originals. The rewrite
  is self-describing and byte-faithful — your original command, args, and env are preserved verbatim,
  so uninstall reconstructs them exactly. If a project/local-scope server would be left unprotected,
  `--apply` refuses (fail-closed) unless you pass `--user-scope-only`.
- **Monitor posture (`vigil-hub wrap --monitor`).** Opt-in, non-blocking: risky tool calls are
  auto-allowed *and* fully audited (instead of pausing for approval), which fits turnkey use with no
  desktop approver running. Raw secrets are still blocked and tool results are still redacted; only
  the human-approval gate is downgraded to observe-and-record. The default stays **enforce**.

### Security

- **Call-time descriptor oracle is now ledger-backed.** The MCP gateway consults a
  `RegistryDescriptorOracle` at `tools/call` time, so a tool's first-seen / drift state is re-checked
  against the audit ledger at the enforcement point. A tool reaching the call path without a matching
  approved descriptor pin degrades to first-seen / drifted (requiring approval) instead of being
  silently allowed — defense-in-depth on top of the `tools/list` exposure gate.
- **No raw secrets or untrusted input in logs/audit.** Upstream stderr, MCP handshake errors, and
  approval records are scrubbed through hard-fingerprint redaction before being written or surfaced;
  upstream error messages are fingerprinted (SHA-256) rather than echoed verbatim.

## [v0.1.13] — 2026-06-05

A small but completing patch: after `vigil-hub setup`, you can now *see* your protection working
with zero extra configuration.

### Changed

- **`vigil-hub inspect` defaults to the shared audit ledger.** When you omit `--db-path`, `inspect`
  now opens the **same** ledger that `vigil-hub setup` / the hook write to
  (`VIGIL_LEDGER_PATH` → `<local-data>/Vigil/ledger.sqlite3`) instead of an empty in-memory database.
  So right after `vigil-hub setup`, `vigil-hub inspect activity` shows what Vigil has actually
  blocked — no flags needed. The setup output now points you to it.

## [v0.1.12] — 2026-06-05

Turnkey protection: download the release, run one command, and your Claude Code tool calls are
guarded. This is the fastest path from a GitHub download to real protection.

### Added

- **`vigil-hub setup` — one-command turnkey protection for Claude Code.** Detects Claude Code and
  registers Vigils as a `PreToolUse` hook (covering all tools, including `mcp__*`) in
  `~/.claude/settings.json`, with no manual config editing. Safe by construction: it reads → parses
  → idempotently merges → atomically writes with a backup; it aborts rather than touch a malformed
  or unexpectedly-shaped config; it only manages its own entry (detected by a dedicated
  `--vigil-managed` marker), so your other hooks/settings are untouched. `--status` reports honest
  protection state (active / stale / not-installed) and runs a built-in self-test; `--uninstall`
  cleanly removes only Vigils' entry; `--dry-run` previews without writing. Shell-metacharacter and
  unexpected-shape paths are rejected to avoid command injection.
- **`vigil-hub hook` — Claude Code PreToolUse adapter (native-tool secret guard).** Blocks raw
  credentials and unresolved `secret://` / `vigil://` placeholders from Claude Code's native tool
  calls (Bash/Edit/Write/Read/Grep) and audits every block, fail-closed by construction (a deny is
  a hard block; any read/parse/internal error denies). Raw secrets are blocked in MCP tools too
  (defense in depth); placeholders in MCP tools defer to the MCP gateway. Never echoes a secret
  into an error or the audit log.

### Fixed

- **`vigil-hub inspect` restored.** The command-line audit-ledger query (`activity`, `search`,
  `approvals`, `verify-chain`, …) — referenced throughout the docs — had been dropped from the CLI
  binary in v0.1.10 and is now wired back in (it had become an orphaned source file). Pulls in the
  desktop dispatch/render logic without the GUI/Tauri dependency.

### Changed

- `serde_json` now preserves object key order (`preserve_order`) so `vigil-hub setup` does not
  reorder the keys of your `settings.json`. Audit hashing is unaffected (it uses JCS canonicalization).
- README now leads with a **"Protect Claude Code in one command"** section.

## [v0.1.11] — 2026-06-05

A quality patch: the desktop app no longer re-prompts to update, and `vigil-hub demo` renders
cleanly on every terminal. No functional change to the firewall, redaction, or audit core.

### Fixed

- **Desktop auto-updater no longer loops.** The bundled app version had drifted behind the
  published release, so an installed desktop saw the update manifest as "newer than itself" on
  every poll and re-downloaded the same version indefinitely. The app version is now pinned to the
  release version, so the updater settles once the install is current.
- **`vigil-hub demo` renders on every terminal.** The demo's framing and status glyphs used
  box-drawing / arrow / dash / cross characters that garble on non-UTF-8 consoles (e.g.
  Chinese-Windows cp936, legacy cp437). They are now ASCII, so the first-run experience is clean
  everywhere. Display-only change — the demo still drives the real runtime code and its invariant
  self-check is unchanged (both smoke tests still pass).

## [v0.1.10] — 2026-06-05

A zero-setup `vigil-hub demo` first-run experience, plus reversible secret redaction at the
tool boundary. Existing installs auto-update.

### Added

- **`vigil-hub demo` — see the value in 60 seconds, zero setup.** One command runs a planted
  scenario through Vigils' real runtime code (firewall · reversible redaction · tamper-evident
  audit), contacting no LLM and needing no account/key/network: an agent's raw secret is denied,
  a `secret://alias` placeholder round-trips so the remote model only ever sees the placeholder
  while the local tool receives the real value, a leaked tool result is re-redacted, and the audit
  ledger is shown to hold no plaintext. `--tamper` alters a ledger row and the real verify-chain
  detects it — falsifiable tamper-evidence you run yourself.
- **Reversible redaction — `secret://alias` detokenization at the tool boundary.** Declare secret
  aliases (`env:`/`keyring:`, server-scoped) in your upstreams config; the agent passes
  `secret://<alias>` (the remote model never sees the real value), and Vigils substitutes the real
  value only at the local tool-execution boundary. Unknown / cross-server / raw-secret-in-alias
  references fail closed (deny). Tool results that leak a secret are re-redacted before returning
  to the model (opt-in `--redact-tool-results`). Untrusted alias text is never echoed into errors.

### Changed

- README now leads with a **"See it in 60 seconds"** section.

## [v0.1.9] — 2026-06-04

Chrome extension gains a manual-input redaction guard, plus release-download improvements.
Existing installs auto-update.

### Added

- **Chrome extension: manual-input redaction guard** — a debounced `input` listener now checks
  manually-typed field text (not just paste/submit) against the classifier and redacts secrets in
  place. Best-effort cleanup; paste (pre-insert preventDefault) and submit remain the hard guards.
  No new extension permissions.
- **Release: the Chrome extension is now a downloadable asset** — `vigils-chrome-extension.zip`
  (unzip, then load unpacked at `chrome://extensions`).

### Fixed

- **Redaction false positive** — the `env_assignment` rule's bare-key form now requires `=` (not
  `:`), so URI schemes like `token://…` and YAML `token:` contexts are no longer misredacted.
  `token=secret` still redacts. (This restored a leak-guard regression.)

### Changed

- **Release filenames + download guide** — CLI archives use friendly platform names
  (`vigils-cli-linux-x64` / `-macos-arm64` / `-windows-x64`) instead of Rust target triples, and the
  release notes now include a short "which file do I want?" guide (desktop app vs CLI gateway vs
  browser extension).

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
