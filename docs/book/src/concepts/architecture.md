# Architecture Overview

Vigils is a 5-layer control plane (T0 → T4):

```
T4 — Desktop UI / Browser Extension / CLI
T3 — MCP Hub (server registry, descriptor pinning)
T2 — Action Firewall + Approval Queue + Policy + Audit Ledger
T1 — Privacy Filter + Sandbox Runner (Wasm + native)
T0 — Types + Schemas (vigil-types)
```

## Crate layout

### SDK boundary (publishable, 10 crates)

| Layer | Crate |
|---|---|
| T0 | `vigil-types` |
| T0 | `vigil-redaction` (hard rules + optional ORT) |
| T0 | `vigil-runner-types` |
| T2 | `vigil-policy` / `vigil-audit` / `vigil-lease` / `vigil-firewall` |
| T3 | `vigil-ui-protocol` / `vigil-mcp` |
| — | **`vigil-sdk`** (facade) |

### Internal (not published)

- `vigil-runner` concrete (wasmtime + sandbox-linux + vigil-redaction deps)
- `vigil-sandbox-linux` (Linux-only, target-gated)
- `vigil-daemon-ipc` (daemon wire protocol + thin client, shared by hook / native-host)
- `vigil-http-auth` / `vigil-http-transport` / `vigil-browser`
- `apps/desktop` / `apps/native-host` / `apps/vigil-hub-cli`

## Key invariants

- Fail-closed errors → DENY
- No-plaintext audit
- `DecisionRecord` mandatory
- `inherit_env=false` (native) + fuel/epoch dual limit (Wasm) + Landlock (Linux)
- preopen allowlist only / per-run independent engine

See the [ADR Index](../adr/index.md) for the design rationale behind each layer.

## Data flow (typical action)

```
1. AI agent → MCP request → vigil-hub stdio
2. vigil-hub::descriptor_lookup → drift check
3. vigil-firewall::evaluate → policy + scope + PII
4. (if approval needed) → ApprovalBroker → Desktop UI
5. (on approve) vigil-runner::spawn_native/wasm → sandbox
6. vigil-audit::append → SQLite ledger
7. result → AI agent
```

Every step is fail-closed: any error → DENY plus a ledger event.
