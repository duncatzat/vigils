# Vigils release-acceptance suite

Downloads the **published** release artifacts and tests them **as a real user** across
Linux / macOS / Windows, to catch packaging & distribution defects that local builds and
CI cannot see (wrong-arch binaries, un-bundled/un-loadable ORT dylib, broken signatures,
platform-specific daemon failures, turnkey model-download failures, …).

Foundation for future end-to-end functional testing — parameterized, isolated, idempotent.

## Quick start

```bash
cd tests/acceptance
cp config.env.example config.env      # fill in REPO + your test-machine SSH targets
./run.sh v0.4.0
```

Passwordless SSH to each test machine must be configured. Platforms with a blank SSH
target in `config.env` are skipped. The gate is **fail-closed**: any sub-script that
detects a defect propagates its exit code, and `run.sh` exits non-zero (earlier `|| true`
+ a trailing `rm` swallowed failures — the gate always "passed" and didn't block release).

## What it does

| Phase | Script | Needs | Checks |
|-------|--------|-------|--------|
| 1 Local audit | `local-audit.sh` | `gh`, `file`, `python3`+`pynacl` | all CLI `sha256` (+CRLF lint), per-platform binary **architecture** (flat-collision regression), **`vigil-native-host` bundled** in CLI archives (browser native-messaging), ML **dylib bundling** exe-adjacent + arch + ORT version, desktop **minisign** signatures (crypto verify), **OTA** manifest version/url |
| 2 Runtime e2e (Linux/macOS) | `ml-e2e.sh` | test machine | ML binary runs; dylib loads; turnkey `model install`→`daemon start`→`engine set ml`→hook; **R1** daemon reachability; **ML scrubs semantic PII** (person/address) beyond hard-fingerprints; **fail-closed** (no leak, exit 0); then runs `functional-sweep.sh` against the same published binary |
| 2 Functional sweep | `functional-sweep.sh` (+ `mcp_probe.py`) | any `vigil-hub` (`HUB=…`) | core protection scenarios: `demo` audit-chain + redaction roundtrip, `demo --tamper` chain-break **falsifiability**, hook PreToolUse **deny** (exit 2, no raw echo), hook PostToolUse **redact** + overlap well-formed (no leak), posture/engine persistence, `inspect`/`verify` chain, `serve --stdio` **MCP handshake** (initialize+tools/list), read-only `quickstart` |
| 2 Runtime e2e (Linux/macOS) | `daemon-regression.sh` | test machine | **R1** peer-credential reachability + **stale-socket** rebind after `kill -9` (regresses the two macOS daemon bugs; model-less, fast) |
| 2 Runtime e2e (Windows) | `win-acceptance.ps1` | test machine | ML binary runs; `onnxruntime.dll` LoadLibrary (PE + VC++ deps); turnkey model install; named-pipe **R1** daemon reachability |

## Regression coverage (v0.4.0 findings)

- **Linux `model install` timeout** — `ml-e2e.sh` fails if the turnkey download fails. Root
  cause was a fixed 30 s per-chunk timeout < the ~65 s a 48 MB chunk needs on a
  bandwidth-shared link (16 concurrent chunks). Fixed in `vigil-redaction` `download.rs`.
- **macOS daemon R1 broken** — `daemon-regression.sh` / `ml-e2e.sh` fail if `daemon status`
  is not "running" (peer_creds().pid() is None on macOS). Fixed in `vigil-hub-cli`
  `transport.rs` (euid-based R1 + `GenericFilePath`).
- **macOS stale-socket** — `daemon-regression.sh` fails if `daemon start` can't rebind after
  `kill -9` (filesystem socket not reclaimed). Fixed in the same change.
- **macOS socket-path too long (`sun_path`)** — on a deep `$HOME` (the acceptance sandbox under
  macOS's long `$TMPDIR`, or enterprise network homes like `/Network/Servers/...`), the default
  `~/Library/Application Support/Vigil/vigil-daemon.sock` (≈123 B) exceeds `sockaddr_un.sun_path`
  (104) → `daemon start` bind fails → ML protection silently degrades to hard-fingerprints. Fixed
  in `transport.rs`: a `VIGIL_DAEMON_SOCKET` env override (short, user-private escape hatch; the
  acceptance scripts set `$SBX/d.sock`) **plus** an actionable bind-time guard that rejects
  over-length paths and names the env var (instead of a cryptic libc error). Touches none of the
  R1 / single-instance / stale-reclaim invariants (the env only supplies a string they already
  consume). Regression: `explicit_socket_override_is_honored`,
  `macos_overlong_socket_path_rejected_with_actionable_error`.
- **Windows `.sha256` CRLF** — `local-audit.sh` flags CRLF line endings in checksum files.
- **Overlapping-span PII leak (found during macOS daemon hook-ML)** — two independent
  span-replacement sites (`vigil-redaction` `build_redacted_text`, `vigil-hub-cli`
  `apply_wire_spans`) used right-to-left replace + skip-on-overlap; nested model spans
  (outer prefix is PII) leaked the outer's plaintext prefix and produced broken nested
  placeholders. Both rewritten to **union-merge** (like the gateway `redact_string`).
  Regression: `model_overlap_no_leak`, `apply_wire_spans_{overlap_union_merged,nested}_no_leak`;
  `functional-sweep.sh` S3b asserts well-formed placeholders on the shipped binary.
  - **`VIGIL-SEC-OVERLAP-PH` (FIXED)** — on the daemon hook-ML path, a daemon ML span could
    over-capture into a hard-fingerprint placeholder inserted by the prior scrub, producing a
    *broken nested placeholder* in the model-facing output (e.g. `[[REDACTED address]DACTED email]`).
    No raw PII leaked (the cut bytes were placeholder; the real value was already scrubbed). **Fix**:
    `vigil-redaction::scrub_text_with_spans` returns the byte ranges of the placeholders it inserts;
    the hook fuses redact+ML into one pass (`redact_and_augment_value`) and plumbs the *genuine*
    placeholder ranges (hard-fingerprint + `secret://`) into `apply_wire_spans`, which subtracts them
    from each merged ML span (`subtract_ranges`) and replaces only the bytes outside placeholders.
    Ranges come solely from the pipeline's own output, never regex-detection of `[REDACTED …]` shape
    (a tool result can forge fake placeholders; forged ones aren't in `protected`, so the real PII
    they wrap is still replaced). Regression: `apply_wire_spans_{subtracts_protected_no_split,
    span_fully_in_protected_dropped,span_spanning_protected_splits,forged_placeholder_not_protected}`,
    `subtract_ranges_cases`, `scrub_preserving_placeholders_reports_real_placeholder_spans`,
    `vigil-redaction::scrub_with_spans_marks_placeholder_ranges`.
  - **Known P2 (no leak, `VIGIL-SEC-ML-SKIP`)** — `MlScrub::augment` skips ML for an *entire* string
    leaf when it contains the literal `secret://` or `vigil://redact/`. Tool output is attacker-influenced,
    so embedding a literal `secret://x` beside soft-PII (email/person/address — not hard-fingerprints)
    suppresses ML redaction for that leaf (the hard-fingerprint base still applies; only ML-class
    semantic PII is affected; requires engine=ml/auto). The `VIGIL-SEC-OVERLAP-PH` `protected`-subtraction
    now makes it safe to scan the whole leaf and protect only genuine placeholder bytes — but a correct
    fix must first decide how to treat `vigil://redact/` tokens (unlike `secret://<alias>`, they aren't
    recorded as pipeline-produced, so they can't be trusted as genuine). Tracked for a follow-up.

## Safety

Every test isolates state into a throwaway sandbox (`HOME`/`XDG_*` redirect on Unix) and
cleans up on exit. Windows `dirs` ignores env overrides, so `win-acceptance.ps1`
snapshots/restores `daemon.json` and removes **only** artifacts the run created — never
the shared `%LOCALAPPDATA%\Vigil` dir (NTFS is case-insensitive: `Vigil` == `vigil`).
`config.env` (with internal SSH targets) is gitignored; only `config.env.example` is committed.
