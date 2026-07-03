# Contributing to Vigils

Thanks for your interest. Vigils is a focused, security-sensitive project (a local AI-agent
secret-firewall), so we keep the contribution bar deliberately high.

Please read this before opening an issue or pull request. By participating you agree to the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Before you open an issue

1. **Check the [documentation](https://duncatzat.github.io/vigils/)** and the troubleshooting guide.
2. **Search [existing issues](https://github.com/duncatzat/vigils/issues?q=is%3Aissue)** (open and closed).
3. Pick the right channel:
   - **Bug report** (Issues) — a reproducible defect, with version + exact steps to reproduce.
   - **Feature request** (Issues) — a concrete, in-scope proposal with a real problem it solves.
   - **Question / help / idea** → [Discussions](https://github.com/duncatzat/vigils/discussions), not Issues.
   - **Security vulnerability** → [Security Policy](https://github.com/duncatzat/vigils/security/policy) (private), never a public issue.

Issues that are questions, vague, off-topic, promotional, duplicate, or that ignore the template
will be closed without further response. This is not personal — it keeps the tracker actionable for
everyone.

## Pull requests

- Open an issue first for anything non-trivial, so the approach can be agreed before you invest time.
- Keep PRs small and focused; one logical change per PR.
- Match the existing code style. The CI gates must pass: `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and the
  desktop UI typecheck/build.
- Never commit real secrets, tokens, or credentials — not even in tests or fixtures.

## Reporting abuse / spam

If you see harassment, spam, or bad-faith accusations, please report it to GitHub directly (the
"Report" option on the issue/comment/profile). See the [Code of Conduct](./CODE_OF_CONDUCT.md).
