# Outbound Gate

**Opt-in.** A loopback HTTP proxy for the model API itself. Agents are pointed at it; every request
body is scanned for hard-secret fingerprints and hits are replaced before the request leaves the
machine. Responses stream through untouched.

```console
$ vigil-hub outbound on      # writes the agent configs, persists the switch
$ vigil-hub daemon start     # the gate runs inside the daemon
$ vigil-hub outbound off     # restores the agent configs (only keys Vigil wrote)
```

## Why

The hook and the MCP gateway both sit at the *entrance* — tool inputs and tool results. Neither sees
`@file` inlining, memory files (`CLAUDE.md` / `AGENTS.md`), compaction summaries, or a credential the
model itself repeats back. And because the context is append-only, a secret that got in is re-sent on
every subsequent model call for the life of the session. The outbound gate is the only layer that
sees the bytes actually leaving the machine.

## Wiring

| Agent | File | Keys written |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `env.ANTHROPIC_BASE_URL`, `env.ENABLE_TOOL_SEARCH` |
| Codex CLI | `<CODEX_HOME>/config.toml` | `model_provider`, `[model_providers.vigil]` |

Backed up, atomically replaced, TOCTOU-guarded; no other key is touched and TOML comments survive.
An existing `ANTHROPIC_BASE_URL` pointing at your own gateway is remembered and chained behind the
gate, then restored on `off`. Subscription OAuth keeps working — `Authorization` / `x-api-key` /
`ChatGPT-Account-ID` are forwarded byte-for-byte and never logged.

## Request handling

1. Read the full body (413 above the limit).
2. Refuse what cannot be inspected: non-JSON bodies (415) and compressed bodies. Read-only methods
   pass straight through.
3. Rewrite every JSON string leaf through the same 17 hard-fingerprint rules the hook uses
   (`vigil_redaction::hard_secret_spans`), replacing hit spans with `[REDACTED <kind>]`.
4. Skip protocol envelope keys (`id`, `*_id`, `model`, `role`, `signature`, `encrypted_content`,
   `thinking`, …) — rewriting those breaks the protocol or achieves nothing. Inline binary payloads
   get **no** exemption: a media type is the caller's own claim, and honouring it would hand anyone a
   free pass by wrapping a credential in one. Real image bytes are not text and never match a rule.
5. Re-scan the **bytes about to be sent**. Rewriting works on the parsed tree; what goes upstream is
   bytes. A skipped envelope key, a duplicate JSON key, or a placeholder-stripping mismatch can carry
   a credential all the way here — a hit at this point is a **422 refusal**, not a forward.
6. Forward with headers intact (minus hop-by-hop), then relay the response chunk by chunk. SSE is
   never buffered or parsed.

Rewrites are audited locally (`outbound.request.redacted`) with rule names and counts only — never
any original bytes.

## Honest boundary

This is **not** a reversible-masking proxy. Only credential-shaped hard fingerprints are handled, and
they are **not** restored: the model sees `[REDACTED …]`, and no plaintext mapping table is kept
anywhere. Also:

- Only the model-API leg. Tool traffic to other hosts belongs to the hook and the gateway.
- Hard fingerprints only — semantic PII is the ML engine's job, and deliberately encoded or
  cross-call-split exfiltration still gets through.
- The outbound byte self-check is **not** a second, independent detector. It runs the same rules, so
  it inherits the same blind spots: a 256-run scanning budget per body that plain non-credential
  base64 strings can exhaust, single-level decoding only, and text-only payloads. What it does cover
  is the case where the rewritten tree and the bytes on the wire disagree.
- One known, constructible gap, named rather than glossed: put enough long non-credential base64 runs
  early in the body, then a base64-encoded credential later, and the early runs exhaust the scanning
  budget so the credential is never examined and the request is forwarded. Padding and payload need
  not share a field. A test asserting the 422 exists and is currently red on purpose, marked ignored
  so the gap stays visible; the fix belongs to the shared redaction crate. Ordinary traffic is
  unaffected, but do not treat the gate as a guarantee that credentials cannot leave.
- Response bodies are not scanned.
- Bedrock / Vertex / Foundry modes are refused (they do not use the base URL; Bedrock signs the body).
- Codex with a custom `model_provider` is refused; Gemini CLI is not wired yet.
- Codex's compaction / memories backend routes do not pass through the gate — Codex reserves those for
  the built-in `OpenAI` provider whose URL ends in `/backend-api/codex`. Sampling requests, the ones
  carrying your context, still go through.
- `requires_openai_auth = true` covers users authenticated through `codex login` (subscription or API
  key). A bare `OPENAI_API_KEY` env var with no prior login is not silently used; Codex asks you to log in.
- Cloud / remote sessions are invisible — that traffic is not on this machine.
- While the gate is down, agents pointed at it fail closed rather than silently bypassing it.

The listen address must be loopback; a non-loopback address in the config is treated as corrupt and
the gate stays off.
