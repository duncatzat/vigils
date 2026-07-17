# Auto-Update

Installed desktop apps update over the Tauri auto-updater, using Ed25519 (minisign) signatures.

## Flow

```
client startup
  → Tauri updater plugin polls
    https://vigils.ai/desktop-updates/<target>-<arch>/<current_version>.json
  → server returns { version, url, signature, ... }
  → client compares server.version > local.version
  → downloads the bundle and verifies its .sig against the embedded public key
  → restarts on the new version
```

The update endpoint and signing key are operated by the project; release bundles are signed
in CI. macOS is served as two independent lines — `darwin-aarch64` (Apple Silicon) and
`darwin-x86_64` (Intel) — each with its own manifest and arch-suffixed updater archive, so an
update can never deliver the wrong architecture.

## Building a signed bundle

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat <your-updater-key>)"
cargo tauri build --features gui --config '{"bundle":{"createUpdaterArtifacts":true}}'
# produces the platform bundle plus a matching .sig
```

For the full pipeline (CI signing → manifest generation → endpoint sync), see
[`docs/ota-pipeline.md`](https://github.com/duncatzat/vigils/blob/main/docs/ota-pipeline.md).
