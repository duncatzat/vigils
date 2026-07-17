# Desktop Quickstart

## First launch

The window opens on the **Protection Overview** — the Aegis command deck: a shield hero
surrounded by an eight-emblem defense ring (firewall, approval, policy, sandbox, lease,
redaction, gateway, audit). On a fresh machine it honestly reports **no protection yet** and
offers the two one-click paths:

- **Deploy Guardian** — wires protection into every detected agent (per-agent status shown).
- **Download engine** — if the `vigil-hub` engine isn't on this machine yet, fetches it
  securely (HTTPS + SHA-pin against the signed engine manifest + run-verify, fail-closed).

Closing the window hides Vigils to the **system tray** — it keeps guarding in the background.
Reopen or quit from the tray menu; launching the app again focuses the existing instance
instead of starting a second one.

## Connect an AI agent

The fastest path is the CLI turnkey (the desktop app's **Deploy Guardian** button drives the
same engine):

```bash
vigil-hub setup --all
```

This registers native-tool hooks (Claude Code / Codex / Gemini / Cursor) and rewrites each
detected agent's stdio MCP servers through Vigils (Claude Code / Codex / Cursor / Windsurf /
Kimi CLI / ZCode / pi). Full matrix: [Agent Integration](./agent-integration.md).

Manual MCP stdio entry (any MCP-capable agent):

```json
{ "mcpServers": { "vigil": { "command": "vigil-hub", "args": ["serve", "--stdio"] } } }
```

### Browser extension

Chrome MV3 extension → native host → the same local engine and ledger the desktop app shows.

## Pages at a glance

| Page | What it shows |
|---|---|
| Protection Overview | Shield hero + defense ring, per-agent guardian status, browser-guard card, one-click deploy |
| Approval Queue | Risky effects awaiting a decision — approve / reject, scoped grants |
| Activity Feed | Live audit stream, SQLite FTS5 search, hash-chain verification |
| Privacy Findings | What redaction caught — classes, counts, trends (no plaintext) |
| Server Registry | Active / Pending / Removed servers, descriptor drift |
| Session Replay | The full decision timeline for a chosen `session_id` |
| Settings | Engine mode (hardfp / ml / auto), posture, resident daemon, ML model install, audit checkpoint anchor |

See [Architecture](../concepts/architecture.md).
