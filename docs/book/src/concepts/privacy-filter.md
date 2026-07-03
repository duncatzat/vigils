# Privacy Filter

`vigil-redaction` provides two layers of defense in depth.

## Layer 1 — Hard fingerprints

Fixed-prefix and structured-credential rules with 100% precision, zero ML dependency, and
instant startup:

| Kind | Pattern |
|---|---|
| github_token | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 |
| slack_webhook | `hooks.slack.com/services/T...` |
| stripe_secret | `sk_live_` / `sk_test_` |
| google_api_key | `AIza` + 35 |
| gitlab_pat | `glpat-` + 20 |
| aws_access_key | `AKIA` + 16 uppercase |
| database_url | `<scheme>://user:password@host/db` |
| private_key | PEM block |
| ... | 13 kinds total |

## Layer 2 — ONNX model (opt-in: the ML release build, or `--features ort`)

> ⚠️ **Honest boundary:** **the _default_ `vigils-cli-<plat>` build runs Layer 1 (hard
> fingerprints) only.** Layer 2 (the ML model) needs (1) an ort-enabled binary — either the
> prebuilt **`vigils-cli-ml-<plat>`** release build or your own `cargo build --features ort`,
> (2) `vigil-hub serve --engine ml` (or `auto`) at runtime, and (3) the model files (fetched on
> first use; ~0.8–1.5 GB, Hugging Face + vigils.ai mirror, SHA-256 verified). If any is missing,
> behavior falls back to Layer 1 — see the table below and ADR 0022. The ML release build bundles
> the ONNX Runtime 1.24 dylib and floors at Linux glibc ≥ 2.28 / macOS ≥ 14.

OpenAI Privacy Filter (PII NER) + a DeBERTa prompt-injection classifier (soft signal); ort
builds additionally carry a multilingual ensemble (`xlmr` / `yonigo`). Typical latency: cold
~7–11 s, warm p95 ~420 ms — inference runs **synchronously** in the gateway preflight, which is
exactly why `--engine` lets latency-sensitive deployments stay Layer-1-only.

A per-`(language, label)` threshold profile calibrates recall vs. false positives — for example
tightening `zh.account_number` cut a noisy false-positive cluster while improving F1.

## Engine selection — `--engine` (ADR 0022)

`vigil-hub serve --engine <hardfp|ml|auto>`, default `hardfp`:

| `--engine` | Layer 2 ML | When the model / dylib is missing |
|---|---|---|
| `hardfp` (default) | off | — (hard fingerprints only) |
| `ml` | on (strict) | **refuses to start** — if you ask for ML it must be available, no silent fallback |
| `auto` | on (if already cached) | **degrades to hard fingerprints + warns** — never triggers a download |

**Coexistence is structural:** hard-fingerprint hits are always kept; the ML layer only *adds*
non-overlapping findings (ADR 0013 merge) — so credentials covered by Layer 1 are never missed,
ML on or off.
