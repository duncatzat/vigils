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
target in `config.env` are skipped.

## What it does

| Phase | Script | Needs | Checks |
|-------|--------|-------|--------|
| 1 Local audit | `local-audit.sh` | `gh`, `file`, `python3`+`pynacl` | all CLI `sha256` (+CRLF lint), per-platform binary **architecture** (flat-collision regression), ML **dylib bundling** exe-adjacent + arch + ORT version, desktop **minisign** signatures (crypto verify), **OTA** manifest version/url |
| 2 Runtime e2e (Linux/macOS) | `ml-e2e.sh` | test machine | ML binary runs; dylib loads; turnkey `model install`→`daemon start`→`engine set ml`→hook; **R1** daemon reachability; **ML scrubs semantic PII** (person/address) beyond hard-fingerprints; **fail-closed** (no leak, exit 0) |
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
- **Windows `.sha256` CRLF** — `local-audit.sh` flags CRLF line endings in checksum files.

## Safety

Every test isolates state into a throwaway sandbox (`HOME`/`XDG_*` redirect on Unix) and
cleans up on exit. Windows `dirs` ignores env overrides, so `win-acceptance.ps1`
snapshots/restores `daemon.json` and removes **only** artifacts the run created — never
the shared `%LOCALAPPDATA%\Vigil` dir (NTFS is case-insensitive: `Vigil` == `vigil`).
`config.env` (with internal SSH targets) is gitignored; only `config.env.example` is committed.
