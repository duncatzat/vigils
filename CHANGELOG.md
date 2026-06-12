# Changelog

All notable changes to Vigils are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (0.x allows interface evolution).

> 简体中文版本：[CHANGELOG.zh-CN.md](./CHANGELOG.zh-CN.md)

---

## [v0.2.0-beta.3] — 2026-06-12 — DeBERTa injection classifier (serve path)

### Added — DeBERTa prompt-injection classifier (opt-in, serve path)

The heuristic injection defense (beta.2) now has an optional **second detector**: a fine-tuned
DeBERTa sequence classifier (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0) that
catches natural-language jailbreaks the 5 regex rules miss (measured recall **+0.28** over the
heuristic alone). It runs as a **warm-session soft signal on the MCP gateway serve path**, never
in the short-lived hook (the 738 MB model can't reload per hook spawn).

- **Opt-in, zero default footprint**: requires building with `--features ort` *and*
  `vigil-hub serve --enable-injection-classifier`. Default builds carry zero ORT dependencies.
  The model (738 MB FP32) is fetched once on first start (16-chunk parallel + sha256 verify).
- **Two scan points**: tool descriptors (at descriptor pin) and tool results, each fused with the
  heuristic detector. On hit it bumps session risk (heuristic + DeBERTa delta taken as **max, not
  summed**) and writes a zero-echo audit event. **Still a pure soft signal — it never denies and
  never rewrites the result** (rewrite belongs only to the secret-redaction path).
- **Fail-closed plumbing**: `--enable-injection-classifier` without `--features ort` aborts startup
  (never silently degrades), mirroring the privacy-filter contract.

### Fixed

- **`check_existing` re-download bug**: the model-cache readiness check only recognized the OpenAI
  `model_q4f16.onnx` filename, so the DeBERTa `model.onnx` cache always missed → every `serve`
  start re-downloaded 738 MB. Fixed via a shared `is_onnx_artifact` SSOT (download assign +
  readiness check use one matcher) with end-to-end + unit regression guards.

> **Deployment note (ORT)**: the `ort` feature uses `load-dynamic` — it needs the correct
> `onnxruntime.dll` (ORT 1.24) reachable by the executable (same directory / PATH). A wrong-version
> DLL elsewhere on the system path can hang initialization. This is an existing ORT requirement
> (shared with the privacy filter), not specific to the classifier.

## [v0.2.0-beta.2] — 2026-06-12 — Prompt-injection defense

### Added — prompt-injection defense (P0)

Vigil now detects and contains malicious *instruction injection* in tool outputs and MCP tool
descriptors — the complementary half of secret-exfiltration defense.

- **Meta-instruction detection (soft signal)**: a heuristic scan for prompt-injection phrasing
  ("ignore previous instructions", role-reset, exfiltration imperatives) in tool results.
  Deliberately a **soft signal — it never denies** (semantic, high false-positive); it raises a
  per-session risk score and is strictly separated from the hard-secret deny path.
- **Datamarking (Claude)**: a tool result flagged for injection is wrapped in nonce-tagged
  untrusted-data markers (`updatedToolOutput`) so the model treats it as data, never as
  instructions. Codex / Gemini / Cursor degrade to audit-only (no output-rewrite capability).
- **Session-risk escalation**: meta-instruction hits accumulate per session; past a threshold the
  effective posture auto-escalates (Low → Medium → High), tightening subsequent tool calls.
  Escalation **only ever tightens** — the base posture and the decision table are untouched.
- **MCP tool-poisoning scan**: a tool's description and schema are scanned for meta-instructions
  at the descriptor approval gate, making poisoning visible at approval time (soft, non-blocking).

Security: zero plaintext echo (audit / reasons carry only sha256 + counts), fail-safe
throughout, adversarially reviewed.

## [v0.2.0-beta.1] — 2026-06-11 — Hook-first data-flow control plane (public beta)

> **First public beta.** Vigil grows from "MCP gateway only" into a local **data-flow control
> plane**: `vigil-hub hook` extends secret protection to an agent CLI's **native** tool calls
> (Bash / Edit / …), covering Claude Code + Codex + Gemini + Cursor — not just MCP servers.
> We're shipping it as a beta to gather real-world feedback: run `vigil-hub setup`, try the
> postures, and tell us anything surprising. Bug reports welcome.

### ⚠️ Behavior change (BREAKING for defaults)

- **Default install surface is now the hook.** `vigil-hub setup` (no flags) registers the
  agent-CLI hook by default (Claude as the primary surface, plus any detected Codex / Gemini /
  Cursor) instead of MCP wrapping. **MCP wrap is demoted to the explicit `setup --mcp`** (its
  code and behavior are fully preserved — use it when you only want to protect an MCP tool
  flow). `setup --all` still does both in one step.
- **Default posture is Low.** A `secret://` placeholder reaching a native tool is **allowed**
  at Low (α1 used to always deny). Three tiers: **Low** (deny only the highest risk — bare
  hard-fingerprint secrets — plus a reserved ledger-tamper tier whose detection isn't wired
  yet) / **Medium** (+ placeholder *ask*) / **High**
  (= the old enforce, deny everything). A **bare real credential is denied in every tier** (a
  non-negotiable floor). Switch with `vigil-hub posture set|show`.
- **A hook `ask` is now co-approval.** At Medium, a placeholder's *ask* enters Vigil's approval
  queue with a bounded wait; **both** Vigil (desktop / CLI) **and** the tool chain's own UI can
  approve — first approver wins (atomic state-machine arbitration), and it falls back to the
  tool-chain prompt on timeout. The MCP-wrap approval-queue behavior is unchanged.

### Added

- **Multi-agent hook adapter** (`hook.rs`): a normalization layer that maps event and field
  names across Claude / Codex / Gemini / Cursor, then routes the response per CLI (Claude
  `deny` = exit 2 + stderr; Codex / Gemini / Cursor = exit 0 + each one's JSON contract). A
  bare secret is denied on **any** tool (including `mcp__*`) — the single defense-in-depth line.
- **Multi-agent hook registration** (`setup_hooks.rs`): Codex (`$CODEX_HOME/hooks.json`),
  Gemini (`~/.gemini/settings.json`), and Cursor surfaces, each idempotent, with `--uninstall`
  removing only Vigil's own entries. If Codex `config.toml` has `[features] hooks = false`,
  setup **warns and never rewrites it**. The Claude surface is completed (PreToolUse +
  **PostToolUse** + timeout).
- **`vigil-hub posture show|set <low|medium|high>`**: a turnkey entry to the three tiers
  (atomic config write + an audit event for every change).
- **Execution-boundary injection (α2)**: on PreToolUse, a `secret://<alias>` placeholder inside
  a boundary tool (Bash / shell) is resolved to its real value via a lease and rewritten
  **inline** into `updatedInput` for the host to execute — **the model transcript only ever
  sees the placeholder**. Claude only (the CLI proven to honor `updatedInput`). Real values
  never reach audit / stderr / notes (sha256 fingerprints only).
- **PostToolUse result re-redaction**: before a boundary tool's result returns to the LLM, the
  real values of declared secrets are reverse-substituted back to `secret://<alias>` (plus a
  hard-fingerprint scrub as defense-in-depth), via Claude's `updatedToolOutput`. A declared
  secret that can't be resolved, or any residue found on self-check, triggers a **fail-closed
  truncation**.

### Security invariants

- **Fail-closed by construction**: the hook never returns an error or panics; a parse failure,
  an injection failure, a re-redaction failure, or a missing ledger all converge to
  deny-or-truncate (`deny` is exit 2 — exit 1 is fail-open and is never used to block).
- **Zero plaintext**: a real value is exposed at a single point and flows straight to its
  injection target / re-redaction substitution; audit, reasons, notes, and stderr only ever
  carry the alias name + a sha256. Byte-level E2E confirms real values never hit disk.

### Known scope limitations (this beta)

- Re-redaction covers only a boundary tool's **direct** result; it does not track a secret's
  **second-order** propagation (a boundary command writes to disk → a non-boundary tool reads
  it back). Full coverage needs egress-side (model-API proxy) interception.
- inject / re-redact use the OS keyring as the value backend, but **keyring population has no
  turnkey CLI entry yet** (the next increment); injection currently requires registering the
  hook command with `--inject --secrets` by hand.
- A full real-machine **dual-CLI** (Claude Code + Codex live) inject / re-redact round-trip is
  still pending a controlled environment; the binary layer and unit tests already cover every
  decision and protocol shape.

### Also in this release — bug fixes

- **DEF-004: the firewall's project boundary now actually binds — `--project-root` flag,
  defaulting to the gateway's working directory.** Found in real-machine testing.
  - **The bug**: every production entrypoint (`serve` / `wrap` / demo / desktop embed) started
    the firewall with an *empty* set of project roots, and the policy engine's `Outside`
    condition is vacuously true on an empty set — so the built-in `deny-outside-project` rule
    (priority 150) treated the **entire filesystem** as "outside the project", while its
    counterpart `approve-repo-write` (priority 80) could never match. The Inside/Outside
    boundary semantics were inverted wholesale: any call recognized as a filesystem write was
    hard-denied in **every** posture (monitor only downgrades the default-deny *floor*, not
    explicit Deny rules), with an audit reason that falsely claimed "writes OUTSIDE project".
    It went unnoticed for so long because most wrapped third-party tool names aren't in the
    effect-extraction vocabulary — no FsWrite extracted, rule never fired, calls fell to the
    floor and were observe-allowed under monitor.
  - **Fail-safe guard in the policy engine**: with empty roots, `Outside` no longer asserts
    "outside the project" (it doesn't match), so writes fall to the default-deny floor —
    still fail-closed, and the audit reason is now the honest "no rule matched" instead of a
    fabricated boundary violation. The risk scorer follows the same semantics (no more +30
    "outside-project write" score on empty roots), and its root matching is now
    case-insensitive on Windows, aligned with the policy engine.
  - **`serve` / `wrap` accept a repeatable `--project-root <DIR>`**; omitted, the boundary
    defaults to the process working directory (agents launch the gateway inside the project,
    matching git/cargo directory semantics). Roots are normalized to the same POSIX form the
    path extractor emits (canonicalized, `\` → `/`, `\\?\` prefix stripped) — without this,
    prefix comparison on Windows silently never matches and the boundary is inert.
  - **Visible change under enforce**: writes *inside* the boundary now route to the
    `approve-repo-write` approval queue (previously hard-denied); writes *outside* are still
    blocked by `deny-outside-project`, with the reason pointing at a real boundary violation.
  - **The startup banner prints the bound boundary** (`project boundary -> <roots>` / `NONE`),
    so a gateway spawned from the wrong directory is visible at a glance.
  - SDK `FirewallBuilder::project_roots` normalizes roots in `build()` the same way, so
    native-form paths (`C:\proj`) from consumers compare correctly.
  - demo / desktop embed intentionally keep empty roots (self-contained simulation / no
    meaningful CWD for a GUI); the engine guard covers them. Adversarially reviewed.

## [v0.1.34] — 2026-06-09

Bug fixes from real-machine testing of the Claude Code / Codex integration.

- **Desktop Activity Feed now reflects CLI-written events** (DEF-001). Root cause was a
  ledger-path mismatch: the integration guide pointed at `ledger.sqlite` while the desktop
  reads `ledger.sqlite3`, so the CLI and the desktop used two different files and the feed
  stayed empty (the live watcher itself was fine). Fixed the bilingual integration guide;
  `serve`/`wrap` now print the resolved ledger absolute path at startup and warn loudly when
  an in-memory ledger is used (which the desktop cannot see).
- **`setup --mcp` no longer nests-wraps Vigil's own server** (DEF-002). The documented
  `vigil-hub serve` self-entry was mis-classified as wrappable, producing a wrap-around-serve
  nested gateway. `setup` now skips Vigil's own serve/wrap entries, and already-wrapped
  detection no longer depends on the binary's filename, so a renamed/versioned binary's wrap
  isn't double-wrapped. Reversible via `--uninstall`. Adversarially reviewed.

No changes to the production protection paths (firewall / redaction / audit). Build
provenance + checksums on every artifact as usual.

## [v0.1.33] — 2026-06-08

A guided first-run: `vigil-hub quickstart`.

### Added

- **`vigil-hub quickstart` — one screen that tells a new user exactly what to do.** After
  installing, it's not obvious what to run first. `quickstart` answers it, **read-only** (it
  changes nothing): it detects the AI agents on your machine (Claude Code, Codex, Cursor,
  Windsurf), counts their MCP servers, and shows how many are already behind Vigil vs. still
  unprotected — then points you at the three next steps: see it work (`vigil-hub demo`), protect
  everything with one reversible command (`vigil-hub setup --all`, or `setup --mcp` to preview
  first), and watch/verify (`setup --mcp --doctor`, `vigil-hub verify`, or the desktop app).
  Detection reuses the same read-only preview that `setup --mcp` uses, so it never edits a
  config — actually protecting your agents still requires an explicit `setup --all`.

## [v0.1.32] — 2026-06-08

The audit checkpoint anchor (v0.1.31) now activates automatically.

### Changed

- **The gateway auto-anchors the audit chain on shutdown.** v0.1.31 added `vigil-hub checkpoint`
  to anchor the tamper-evident ledger against a full-chain rewrite, but a turnkey user (who runs
  `setup --all` / `setup --mcp` and never invokes it by hand) would never have an anchor — leaving
  that protection inert for them. Now `vigil-hub serve` and `vigil-hub wrap` emit a checkpoint
  automatically when the gateway shuts down, so every agent session leaves an anchor without any
  manual step. It's best-effort and never blocks shutdown (the write runs on a separate thread with
  a 5-second bound, so a wedged or network filesystem can't stall exit), writes only when there are
  new events, and prints to stderr (never the MCP channel). Run `vigil-hub verify` any time to check
  both chain-internal consistency and the anchors. (To fully close the threat, keep the
  `<ledger>.checkpoints` file append-only or synced offsite — see ADR 0020.)

## [v0.1.31] — 2026-06-08

Audit checkpoint anchoring — detect a full-chain rewrite of the tamper-evident ledger.

### Added

- **`vigil-hub checkpoint` and `vigil-hub verify` — external anchoring against full-chain rewrite.**
  The audit ledger's SHA-256 hash chain makes *partial* tampering evident, but an attacker with full
  write access to the database could rewrite the *entire* chain consistently and still pass internal
  verification (audit threat #7). `vigil-hub checkpoint` now records the current chain head into an
  append-only sidecar (`<ledger>.checkpoints`) kept **separate** from the database; `vigil-hub verify`
  checks chain-internal consistency **and** that every anchored head still matches — so a DB-only
  full-chain rewrite is detected (while the checkpoint file is intact), exiting non-zero on any tamper.
  Honest scope: this is **not** a tamper-proof guarantee against an attacker with full filesystem write
  access — for that, keep the `.checkpoints` file append-only (`chattr +a`) or synced offsite;
  verification reports `Unanchored` (never "verified") when no checkpoints exist. The embeddable
  `vigil-audit` gains the `CheckpointLog` API. The existing hash-chain digest and `verify_chain` are
  unchanged (purely additive). See
  [ADR 0020](https://github.com/duncatzat/vigils/blob/main/docs/adr/0020-audit-checkpoint-anchor.md).

## [v0.1.30] — 2026-06-07

`--doctor` now health-checks every agent, not just Claude.

### Added

- **`setup --mcp --doctor` now covers all four agent surfaces.** The read-only launch-health preflight —
  which answers "after wrapping, can each MCP server's underlying program still start in this
  environment?" — previously checked only Claude Code's servers. It now checks Claude (user +
  per-project), Codex, Cursor, and Windsurf in one pass, each row tagged by agent. `--doctor --probe`
  likewise runs a real MCP-handshake test for servers across all four. It sees through Vigil's wrapping —
  it checks the underlying program (e.g. `npx` / `uvx` / `python`), not `vigil-hub` itself. This directly
  answers the most common worry after `setup --all`: "did wrapping break any of my tools?"

### Fixed / Security

- A broken (malformed or unreadable) config for a non-Claude agent is now reported as a counted doctor
  failure with an accurate cause (parse failure vs permission/IO error), instead of being silently
  skipped — so `--doctor` can no longer claim "all servers resolve" while an entire agent surface went
  unchecked. All diagnostic output (including config paths) is scrubbed before printing.

## [v0.1.29] — 2026-06-07

Cursor and Windsurf are protected now too — four agent surfaces from one command.

### Added

- **`setup --mcp` now protects Cursor and Windsurf, not just Claude Code and Codex.** `vigil-hub setup
  --mcp` (preview / `--apply` / `--uninstall`) and the all-in-one `setup --all` now also detect and wrap
  the stdio MCP servers in Cursor's `~/.cursor/mcp.json` and Windsurf's
  `~/.codeium/windsurf/mcp_config.json`. One command now protects all four agent surfaces you might
  have. Both reuse the exact same gateway wrap (result redaction + raw-secret block + tamper-evident
  audit, default monitor posture), reversibly — `--uninstall` restores the originals. Each server gets a
  `cursor-<name>` / `windsurf-<name>` gateway id, namespace-disjoint from the Claude `user-`/`local-`
  and Codex `codex-` ids so the same server name across agents never collides in the shared audit ledger.

### Security

- Cursor and Windsurf use the very same JSON `mcpServers` shape as Claude's user scope, so the new code
  reuses the **same** classifier and safe-edit machinery (sentinel exact-match, dangerous-character
  rejection, non-stdio skip, server-id validation, atomic write + backup). Two hardenings to the shared
  path: a remote server declared with Windsurf's `serverUrl` field (not just `url`) is now correctly
  skipped instead of mistaken for stdio; and a config file that exists but can't be read (e.g. a
  permission error) is now reported as a real error instead of being silently treated as "not
  configured" — so an inaccessible config is never silently left unprotected. Reviewed adversarially.

## [v0.1.28] — 2026-06-07

One command now protects Codex too — not just Claude Code.

### Added

- **`setup --mcp` now protects Codex CLI's MCP servers, not only Claude Code's.** `vigil-hub setup
  --mcp` (preview / `--apply` / `--uninstall`) and the all-in-one `setup --all` now also detect and
  wrap the stdio MCP servers in Codex's `~/.codex/config.toml` (the `[mcp_servers.*]` tables), in
  addition to Claude Code's `~/.claude.json`. One command protects every agent surface you have. Each
  Codex server is rewritten to launch through the Vigil gateway (result redaction + raw-secret block +
  tamper-evident audit, default monitor posture), reversibly — `--uninstall` restores the originals.
  Edits are **format-preserving**: only the wrapped entry's `command`/`args` change; your comments,
  key order, `env` tables, and other settings (model, approval policy, …) are left exactly as they
  were. Codex servers get a `codex-<name>` gateway id, namespace-disjoint from the Claude
  `user-`/`local-` ids so the same server name across agents never collides in the shared audit ledger.

### Security

- The Codex path reuses the **same** classifier and safety machinery as the Claude path (sentinel
  exact-match for idempotency, dangerous-character rejection, non-stdio skip, server-id validation,
  abort-on-malformed-config with atomic write + backup) — one source of truth, no drift. `env` values
  are never copied into the rewritten command line (key names only) and never printed. Reviewed
  adversarially (two rounds): uninstall refuses a lossy restore of any hand-edited entry, and a failing
  Codex step after the Claude side already applied is reported honestly with recovery guidance.

## [v0.1.27] — 2026-06-07

Verifiable supply chain, and a firewall that finally classifies risk on real MCP servers.

### Added

- **Build-provenance attestation for every release artifact.** The CLI archives, desktop
  installers, and the extension zip now carry a cryptographic SLSA build-provenance attestation
  (via GitHub OIDC + Sigstore — no key to manage). Verify any download with
  `gh attestation verify <file> --repo duncatzat/vigils`: it confirms the artifact was built by the
  official CI from this repository, closing the "swapped/tampered release" gap that a checksum alone
  can't. See [Installation](./README.md#installation).
- **Effect catalog — the tool-call firewall now classifies risk on real MCP servers.** Until now the
  firewall inferred effects only from call *arguments*, so for third-party servers whose risk is
  implied by tool *identity* (a `github` `create_issue`, a `fetch`) it saw "no effects" and the heavy
  policy machinery idled. A built-in catalog now seeds baseline effects by identity for common servers
  (filesystem, github, fetch, git, brave-search, slack, postgres) — so what each tool actually does
  (file read/write, network, secret use, outbound message) is now visible in the audit ledger, and
  `--enforce` can gate on it. It's **fail-safe by construction**: the catalog only ever *raises*
  visibility/severity (never suppresses a real effect), and it does **not** change the default
  monitor posture — no new approval prompts.

## [v0.1.26] — 2026-06-07

The Linux CLI now runs on virtually any glibc Linux from the last decade — not just recent releases.

### Changed

- **Linux CLI binaries now target a glibc 2.17 floor (any-distro reach).** Until now the published
  Linux CLI was built on Ubuntu 22.04 and required `GLIBC_2.34`, so it failed to start with
  `version 'GLIBC_2.xx' not found` on older-but-common distros — Ubuntu ≤20.04, Debian ≤11,
  RHEL/CentOS 7–8, Amazon Linux 2. The release now builds the Linux CLI with
  [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) targeting
  `x86_64-unknown-linux-gnu.2.17`, lowering the required glibc symbols to 2.17 (the manylinux2014
  floor, covering essentially every glibc Linux from the last decade). **No behavior change** — the
  binary is functionally identical; it just links against older glibc symbols. The release pipeline
  also gained an `objdump` guard that fails the build if the glibc floor ever regresses above 2.17.
  macOS and Windows builds are unchanged. (Verified in real CI: both `vigil-hub` and
  `vigil-native-host` now top out at `GLIBC_2.17`, down from `GLIBC_2.34`.)

## [v0.1.25] — 2026-06-07

The desktop app now opens on a **Protection Overview** — see what Vigil has caught for you at a
glance, the same information the CLI's `vigil-hub inspect protection` shows.

### Added

- **Desktop "Protection Overview" page (the new default landing page).** Until now, only the CLI
  could show "what Vigil has caught" (`vigil-hub inspect protection`). The desktop app now opens
  directly on a Protection Overview that shows, from the local audit ledger: secrets blocked at
  input, tool-result leaks detected, secret:// aliases withheld, how many events were audited across
  how many sessions, whether the tamper-evident audit chain still verifies, and a list of recent
  (already-redacted) protection events. It's read-only and refreshes live as Vigil records activity.
  If the audit chain ever fails verification, the recent-event details are hidden (only the counts
  remain) — a tampered log could otherwise show injected text.

## [v0.1.24] — 2026-06-07

Adds a deep health check that actually starts each MCP server to confirm it works — not just
that its program is installed.

### Added

- **`vigil-hub setup --mcp --doctor --probe` — verify each MCP server really starts.** The existing
  `--doctor` is static: it only checks that each server's program (e.g. `npx`, `uvx`) resolves on
  your `PATH`. But the most common silent failure is a program that *is* installed yet fails at
  runtime — the package won't download, the server crashes on startup, or it doesn't speak MCP — and
  your agent just silently sees zero tools from it. `--probe` goes further: for each server that
  passes the static check, it briefly **starts the server and completes a real MCP `initialize`
  handshake**, then stops it, and reports `[OK]` / `FAILED to initialize` per server. It's opt-in
  because it runs each server's startup code; plain `--doctor` stays static with no side effects.
  (First run of an `npx`/`uvx` server may time out while it downloads packages — re-run once warm.)

### Security

- The probe never forwards a started server's stderr (so a server that echoes a configured secret on
  startup can't leak it through the doctor), redacts the exact configured env values out of any
  failure message, and fingerprints untrusted protocol-version strings instead of printing them raw.

## [v0.1.23] — 2026-06-06

Fixes a cosmetic-but-real corruption in the secret redaction placeholder when a secret is
written as `KEY=value` — the redacted output could come out malformed. The secret itself was
always fully removed; only the `[REDACTED …]` marker was broken.

### Fixed

- **Redaction placeholders are now well-formed when a secret is assigned to a variable.** For the
  most common shape — a secret on the right of `=`, e.g. `api_token=ghp_…` in a tool result — two
  detection rules overlap (one matches the whole `key=value`, one matches the token inside). The
  gateway's redactor applied rules one after another over already-redacted text, so the second rule
  matched *into* the first rule's `[REDACTED …]` marker and shattered it into
  `[REDACTED env_assignment] github_token]` (unbalanced brackets). The raw secret was already gone
  in every case — this was never a leak — but the marker looked broken. The redactor now scans the
  original text once, merges overlapping matches into a single covered span, and emits one clean
  `[REDACTED …]` marker. (Found by the full end-to-end turnkey run on a real machine; reviewed for
  leak-safety — merging overlapping spans by their *union* guarantees no secret byte is ever left
  behind.)

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
