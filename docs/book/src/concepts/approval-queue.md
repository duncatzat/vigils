# Approval Queue

Human-in-the-loop gating for risky effects (driven by `FirewallOutcome::ApprovalRequired`):

```
firewall::evaluate → ApprovalRequired(req)
  → ApprovalBroker (SQLite, persistent)
  → Desktop UI "Approval Queue" page
  → user: Approve / Reject / Delegate / Defer
  → ledger event
  → vigil-runner spawn (only if approved)
```

## ApprovalScope

Each request carries a scope (see ADR 0014):

- `server_id` + `tool_name`
- `effect_kind` (read / write / network / …)
- `resource_path`
- `duration` (once / session / forever)

`Delegate` hands the decision to a super-user or batch-approval flow.

See ADR 0003 and ADR 0014.
