# Releasing — gotchas & checklist (maintainer notes)

Hard-won notes from cutting releases (esp. the v0.2.1 ML-variant line). The release
workflow's own version gate only catches some of these; the rest fail *later* (dependency
resolution, the desktop build, or a CI leg) — so check them before tagging.

## Version bump touches **four** places, not three

The release.yml gate asserts `tag == Cargo.toml == tauri.conf.json`. But a fourth place
must move in lockstep:

1. `Cargo.toml` → `[workspace.package] version`
2. `apps/desktop/tauri.conf.json` → `version`
3. the git tag (`vX.Y.Z`)
4. **the inter-crate `path` dependency version pins** — ~26 of them across 7 crates
   (`vigil-audit`, `vigil-firewall`, `vigil-mcp`, `vigil-sdk`, `vigil-policy`, `vigil-lease`,
   `vigil-ui-protocol`), e.g. `vigil-redaction = { path = "...", version = "0.2.0-beta.9" }`.

These pins exist for crates.io publishing and **are not checked by the version gate**. They
went stale at `0.2.0-beta.9` and nobody noticed through `v0.2.0`, because a *stable* version
(`0.2.0`) satisfies the caret range `^0.2.0-beta.9`. A **pre-release** does not:

> Cargo only lets a pre-release (`0.2.1-rc.1`) satisfy a requirement if a comparator with the
> **same `major.minor.patch`** also carries a pre-release. `^0.2.0-beta.9` (pre-release on
> `0.2.0`) does **not** admit `0.2.1-rc.1` → `cargo` errors with *"Could not find … if you are
> looking for the prerelease package it needs to be specified explicitly"*, and the release
> build dies at the resolution step.

**Fix / habit:** bump all pins with the version. Catch it locally before tagging:

```bash
sed -i 's/<OLD>/<NEW>/g' Cargo.toml apps/desktop/tauri.conf.json crates/*/Cargo.toml
cargo check -p vigil-hub-cli   # fails loudly if a pin is stale; also refreshes Cargo.lock
```

(Better long-term: move these to `version.workspace = true` so they track automatically.)

## `cargo update` can drift the Tauri Rust crate away from the npm package

The desktop build runs `cargo tauri build`, which **refuses to build** if the Rust `tauri`
crate and the npm `@tauri-apps/api` are on different `major.minor`:

```
Error Found version mismatched Tauri packages … tauri (v2.11.3) : @tauri-apps/api (v2.10.1)
```

A `cargo update` done for an *unrelated* reason (clearing a wasmtime RUSTSEC advisory) bumped
the whole Rust tauri stack `2.10 → 2.11`, while `apps/desktop/ui/package.json` /
`package-lock.json` stayed at `2.10`. `v0.2.0` had matching `2.10`, so every release *after*
that `cargo update` would have failed the desktop build — but no release was cut until it
surfaced. **After any `cargo update`, diff `Cargo.lock`'s `tauri` version against
`apps/desktop/ui` and keep them on the same minor** (align the npm side forward with
`npm install @tauri-apps/api@^2.11 @tauri-apps/cli@^2.11` and verify `npm run build`).

## Don't let a CI runner's python resolve a native-dylib wheel

The ML variant bundles the onnxruntime 1.24 native dylib, extracted from a PyPI wheel.
`pip download onnxruntime==1.24.4` **resolved on the windows/macos runners but not on
ubuntu-22.04** — that runner's python had no compatible 1.24.4 wheel (`pip` only saw up to
`1.23.2`), so only the Linux ML leg failed. The dylib inside the wheel is the same native
object regardless of the cp tag, so:

- **Don't** rely on `pip download` (it filters by the *runner's* python/ABI).
- **Do** fetch the platform wheel URL from the PyPI JSON API
  (`https://pypi.org/pypi/onnxruntime/<ver>/json`, filter by `matrix.pip_platform` +
  `cp312`), `curl` it, and **sha256-verify against the JSON digest** before bundling it into
  a signed release artifact. The runner python only runs `urllib` + `zipfile` (version-independent).

Also: ubuntu runners may have only `python3` (no `python` alias) — use
`PY=$(command -v python || command -v python3)`.

## Release-validation discipline

1. Cut an **rc tag** (`vX.Y.Z-rc.N`) — it triggers the full pipeline; the `-` marks it as a
   GitHub *pre-release* (not "Latest").
2. Let the whole workflow go green (`cli` ×3, `cli-ml` ×3, `desktop` ×3, `extension`).
3. **Download the published artifacts** (`gh release download`), verify `.sha256` +
   `gh attestation verify`, and **run them on real hardware** — packaging/distribution bugs
   only show up in the *published* artifact, not a local build.
4. Only then **promote**: tag `vX.Y.Z` (no `-` → "Latest"), and **re-test the stable
   published asset** (it's a fresh build with a different version string baked in).
5. Housekeeping: delete the superseded rc releases + tags
   (`gh release delete <tag> --cleanup-tag --yes`).
