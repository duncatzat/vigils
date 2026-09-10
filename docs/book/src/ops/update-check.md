# Daily update check (version ping)

> In one sentence: `vigil-hub serve` and `vigil-hub daemon start` make at most **one** `GET` per day to
> `vigils.ai`, carrying only your **platform** and the **running version**, to tell you when a newer release
> exists. The server counts those requests per day — that count is the project's only adoption metric.
> No identifiers are sent, one command turns it off, and the `hook` path never makes network calls.

## Why it exists

- **Update notice.** The CLI has no auto-updater; you should learn about new releases, especially security fixes.
- **Adoption count.** Vigils has no product telemetry (no usage events, no crash reports). To decide whether the
  project is worth continuing we need exactly one number: how many installs run on a given day. Counting real
  update checks per day gives *Active Daily Installs* (ADI, the model Firefox used 2008–2020). This is the
  "update-check poll" the project FAQ has always described as its only outbound traffic.
- This is **not** the telemetry that Vigils' opt-in principle covers (crash reporting with stack traces, never
  shipped). An update check is a different thing.

## Exactly what is sent

One request, nothing else:

```http
GET /desktop-updates/windows-x86_64/0.7.1.json HTTP/1.1
Host: vigils.ai
User-Agent: vigil-hub/0.7.1
```

- `windows-x86_64` is the platform (`darwin-aarch64`, `linux-x86_64`, …); `0.7.1` is your vigil-hub version.
- `User-Agent` is product name + version (the desktop app will use `vigils-desktop/<version>`).
- **Not sent:** device id, random id, weekly bucket, salt, hostname, username, paths, ledger contents, any
  configuration, any query string, any body.
- No redirects are followed; the manifest is read up to 64 KB; only its `version` field is used, and only after
  it passes a strict SemVer check.

The integration test `apps/vigil-hub-cli/tests/update_check.rs` captures the request with a local one-shot HTTP
server and asserts every point above (one request, only those two fields, no extra headers, zero traffic under
each kill switch).

## When it runs

| Entry point | Behaviour |
|---|---|
| `vigil-hub serve --stdio` | decided at start-up, sent from a background thread; stdout is never touched (it is the MCP channel), only a stderr line |
| `vigil-hub daemon start` | same, after model warm-up |
| `vigil-hub hook` (every tool call) | **never**. Short-lived process with a latency budget; a source-level test asserts `hook.rs` / `command_guard.rs` / `posture.rs` do not reference the update check |
| any other subcommand | never |

- **At most once per 24 hours** per install: the only local state is a throttle file
  `<data_local>/Vigil/update-check.last` (the Unix time of the last attempt). It is written **before** the
  request, so an offline or failed attempt is not retried within 24 hours.
- **Notice up front:** `vigil-hub setup` (apply-style runs) prints one stderr line before changing anything;
  `serve` / `daemon` print one line before their very first attempt. Nothing is repeated after that.
- No local data directory (nothing to throttle with) → no request. Better to under-count than over-send.

When a newer release exists, stderr gets one more line:

```
vigil-hub 0.7.1: a newer release 0.8.0 is available -> https://github.com/duncatzat/vigils/releases/latest
```

## Turning it off

Any one of these is enough and **overrides everything else**:

| Switch | Notes |
|---|---|
| `vigil-hub version-ping off` | writes `<data_local>/Vigil/version-ping.off`; `on` removes it |
| `VIGIL_NO_VERSION_PING=1` | product-specific environment variable (any non-empty value other than `0` / `false` / `off` / `no`) |
| `DO_NOT_TRACK=1` | the industry convention (<https://consoledonottrack.com>) |

Check once by hand and see the outcome, including failure reasons (refused while disabled — no exceptions):
`vigil-hub version-ping check`.

Status:

```
$ vigil-hub version-ping status
version ping: enabled
  what:     one GET per day from `serve` / `daemon start`, to notice a newer release
  sends:    platform + version only, no identifiers
  request:  GET https://vigils.ai/desktop-updates/windows-x86_64/0.7.1.json
  last try: 3h ago
  turn off: vigil-hub version-ping off   (or VIGIL_NO_VERSION_PING=1 / DO_NOT_TRACK=1)
```

`vigil-hub version-ping status --json` prints a stable, language-independent schema: `enabled`, `disabled_by`
(`env:VIGIL_NO_VERSION_PING` / `env:DO_NOT_TRACK` / `marker` / `no-state-dir` / `null`), `endpoint`,
`user_agent`, `sends`, `last_attempt_unix`, `min_interval_secs`.

Self-hosting or an internal mirror: `VIGIL_UPDATE_ENDPOINT=https://mirror.example.com` (base URL; the path
rule is unchanged).

## What the server keeps

- The origin is `vigils.ai` (nginx behind Cloudflare). `/desktop-updates/*` is `no-cache`, so every request
  reaches the origin.
- nginx keeps its default `combined` access log: time, request line, status, User-Agent, and the **connecting
  IP — which, behind Cloudflare, is a Cloudflare edge node, not you** (the origin does not restore the real
  client IP and does not log `CF-Connecting-IP`). Logs rotate daily and are kept for 14 days.
- The aggregation script only outputs **counts**: requests per `(day, platform, version)`, the 7-day ADI mean,
  and platform / version breakdowns. The stored report and history contain no IPs and no raw User-Agents.
- The aggregate is public at <https://vigils.ai/stats/adoption.json> (as Homebrew and Fedora do: the people
  being counted can see the number).

## Legal framing (GDPR / ePrivacy)

- The client stores exactly one throttle timestamp, strictly necessary for the user-facing "update check"
  function; no salt, id or bucket (EDPB Guidelines 2/2023 treat *any* information written to terminal
  equipment as ePrivacy 5(3) territory, so the design narrows "storage" to that single file).
- The connecting IP the server sees transiently is processed under GDPR Art. 6(1)(f) legitimate interest.
  LIA summary — **purpose:** update notice and install counting; **necessity:** the data is already minimal
  (platform + version); **balance:** no identifiers, off switch, notice up front, public aggregate, logs
  deleted after 14 days.
- Public wording is: "**no usage telemetry; only one counting-style update check that you can turn off**" —
  not shorthand like "zero network requests".

## Scope

- Ships in the first release *after* the one whose release notes announce it.
- CLI only for now (`serve` / `daemon`); the desktop app follows once it has a Settings toggle (its User-Agent
  will be `vigils-desktop/<version>`).
- Code: policy crate `crates/vigil-update-check` (pure logic, no networking, tested offline); wiring in
  `apps/vigil-hub-cli/src/update_check.rs`; tests in `apps/vigil-hub-cli/tests/update_check.rs`.

> 简体中文版本：[update-check.zh-CN.md](./update-check.zh-CN.md)
