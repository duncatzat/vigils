# Security Policy

Vigils is a security tool, so we hold its own security to a high bar. Thank you for helping
keep it and its users safe.

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public issue, pull
request, or discussion for a security report.

- Preferred: [GitHub private vulnerability reporting](https://github.com/duncatzat/vigils/security/advisories/new)
  (the repository's **Security → Report a vulnerability** button).

When reporting, please include where you can:

- the affected component and version (e.g. `vigil-firewall`, desktop app `v0.1.2`),
- a description of the issue and its impact,
- reproduction steps or a proof of concept.

We aim to acknowledge new reports within a few business days and will keep you updated as we
work on a fix. We're happy to credit you in the release notes once a fix ships, unless you
prefer to stay anonymous.

## Supported versions

Vigils is pre-1.0 (`0.1.x`). Security fixes land on the **latest release** only; please
upgrade to the newest version before reporting, and when a fix is published.

## Scope

In scope:

- the Rust workspace (`crates/`, `apps/`) and its release/build pipeline,
- the Chrome MV3 extension (`extensions/chrome-mv3/`) and the native-messaging host.

Generally out of scope: issues that require an already-compromised host or OS account,
social-engineering attacks, and the behavior of third-party MCP servers or AI sites you
choose to connect Vigils to (Vigils mediates them, but does not control them).
