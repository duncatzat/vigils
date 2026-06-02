# Desktop OTA update pipeline

How the Tauri auto-updater is fed. The desktop app polls
`https://vigils.ai/desktop-updates/{{target}}-{{arch}}/{{current_version}}.json` and applies
any update whose signature verifies against the public key baked into
`apps/desktop/tauri.conf.json` (`plugins.updater.pubkey`).

The pipeline is **pull-based**: GitHub Actions never holds any credential for the mirror.
CI publishes signed artifacts + manifests to the GitHub release; the mirror pulls them.

```
release tag ─▶ GitHub Actions (release.yml)
                 ├─ build + SIGN updater artifacts (all platforms)   [needs secret]
                 ├─ upload artifacts (+ .sig) to the GitHub release
                 └─ upload latest-<plat>.json manifests as release assets
                          │  (scripts/gen-updater-manifest.mjs)
                          ▼
vigils.ai timer (scripts/ota/) ─▶ pull latest-<plat>.json ─▶ /var/www/.../desktop-updates/<plat>/latest.json
                          │  (vigils-ota-sync.{sh,service,timer}, every 15 min)
                          ▼
nginx rewrite: desktop-updates/<plat>/<anyver>.json → <plat>/latest.json (or 404)
                          ▼
installed app polls → gets latest.json → verifies signature → updates
```

## One-time setup

### 1. GitHub repo secret (REQUIRED to produce OTA artifacts)

| Secret | Value |
|--------|-------|
| `TAURI_SIGNING_PRIVATE_KEY` | Contents of the Tauri minisign private key (`~/.tauri/vigil-desktop-update.key`). Its public half is already in `tauri.conf.json`. |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | The key password, or leave unset if the key has none. |

Without the secret the release still succeeds — it just ships plain installers and no OTA
(the workflow's updater steps are guarded on the key being present). **Never commit the
private key.**

### 2. nginx (already deployed on vigils.ai)

A rewrite makes every version's poll resolve to the single per-platform `latest.json`:

```nginx
location ~ ^/desktop-updates/(?<plat>[^/]+)/[^/]+\.json$ {
    try_files /desktop-updates/$plat/latest.json =404;
    default_type application/json;
    add_header Cache-Control 'no-cache' always;
}
```

A missing platform returns a clean `404` (the updater treats it as "no update"), never the
site's SPA HTML fallback.

### 3. Mirror sync timer (already deployed on vigils.ai)

`scripts/ota/vigils-ota-sync.{sh,service,timer}` — installed to `/usr/local/bin/` and
`/etc/systemd/system/`, enabled via `systemctl enable --now vigils-ota-sync.timer`. Runs
every 15 min, pulls the latest release's `latest-<plat>.json` assets into the docroot
(idempotent; only outbound HTTPS to the public GitHub API).

## Verifying a release

The updater chain can be checked end-to-end without installing anything:

```bash
PUBKEY=$(node -e 'console.log(require("./apps/desktop/tauri.conf.json").plugins.updater.pubkey)')
node scripts/verify-ota.mjs https://vigils.ai/desktop-updates/windows-x86_64/0.1.3.json 0.1.3 "$PUBKEY"
```

`scripts/verify-ota.mjs` faithfully reproduces the updater's checks — manifest fetch → semver
gate → artifact download → minisign signature verify — plus a tampering negative-control (a
flipped byte must be rejected, proving the verifier isn't a no-op). The decisive check is that
the artifact's signature validates against the `tauri.conf.json` pubkey; if it does, the
updater will accept it.

## Notes

- Updater artifact per platform (Tauri v2): Windows = NSIS `*-setup.exe`, macOS =
  `*.app.tar.gz`, Linux = `*.AppImage` (`.sig` alongside each). The `.dmg` / `.deb` / `.rpm`
  are **manual-download** installers, not updater artifacts.
- macOS `.app.tar.gz` and the Linux updater artifact only exist on a build that ran on those
  OSes with signing enabled — which is exactly what `release.yml` does once the secret is set.
