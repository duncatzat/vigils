# SDK Feature Flags

## `ort` (default: off)

```toml
vigil-sdk = { version = "0.1", features = ["ort"] }
```

Enabled:

- The `ort` crate + ONNX Runtime 1.24.4 (dynamic library).
- A 3-engine ensemble (OpenAI Privacy Filter + `xlmr-pii-v1` + `yonigo-pii-v1`).
- An 8-class `PrivacyLabel`.

Disabled (default):

- 17 hard fingerprint rules.
- A `NoopEngine` placeholder.
- No ONNX dependency; sub-second startup.

## Choosing

| Scenario | Feature |
|---|---|
| CLI tool wrapper | default — hard rules cover the vast majority of leaks, instant |
| Long-running agent | `ort` — higher recall (~11 s cold + ~419 ms warm) |
| Browser extension | default — size- and cold-start-sensitive |

## Runtime environment (with `ort`)

```bash
export ORT_DYLIB_PATH=/path/to/onnxruntime-<platform>-1.24.4/lib/libonnxruntime.so.1.24.4
export VIGIL_PRIVACY_FILTER_MODEL_DIR=/path/to/models/openai-pf/v1
```

See ADR 0012, 0016, and 0017.
