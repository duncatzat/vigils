#!/usr/bin/env bash
# vigils.ai OTA manifest sync — pull the latest GitHub release's per-platform Tauri updater
# manifests into the web docroot. PULL-based by design: the server holds NO CI credentials;
# it only makes outbound HTTPS to the public GitHub API. Idempotent + safe on a timer.
#
# Each release built by .github/workflows/release.yml (with the TAURI_SIGNING_PRIVATE_KEY
# secret set) uploads latest-<plat>.json assets; this script mirrors them to
#   <docroot>/<plat>/latest.json
# which nginx serves for any version's updater poll (see the desktop-updates rewrite block).
set -euo pipefail

REPO="${VIGILS_REPO:-duncatzat/vigils}"
DOCROOT="${VIGILS_OTA_DOCROOT:-/var/www/vigils.ai/desktop-updates}"
PLATFORMS=(windows-x86_64 darwin-aarch64 linux-x86_64)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
log() { echo "[ota-sync] $*"; }

TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | jq -r '.tag_name // empty')"
[ -z "$TAG" ] && { log "no latest release tag — nothing to do"; exit 0; }
log "latest release: $TAG"

changed=0
for PLAT in "${PLATFORMS[@]}"; do
  url="https://github.com/$REPO/releases/download/$TAG/latest-$PLAT.json"
  if ! curl -fsSL -o "$TMP/$PLAT.json" "$url" 2>/dev/null; then
    log "$PLAT: no manifest asset in $TAG (skip)"; continue
  fi
  # Structural sanity: must be a real updater manifest, never an HTML error page.
  if ! jq -e '.version and .platforms' "$TMP/$PLAT.json" >/dev/null 2>&1; then
    log "$PLAT: downloaded manifest invalid (skip)"; continue
  fi
  dest="$DOCROOT/$PLAT/latest.json"
  if [ -f "$dest" ] && cmp -s "$TMP/$PLAT.json" "$dest"; then
    log "$PLAT: unchanged ($TAG)"; continue
  fi
  mkdir -p "$DOCROOT/$PLAT"
  cp "$TMP/$PLAT.json" "$dest.tmp" && mv "$dest.tmp" "$dest"   # atomic replace
  log "$PLAT: updated -> $TAG"
  changed=1
done

if [ "$changed" = 1 ]; then
  chown -R www-data:www-data "$DOCROOT" 2>/dev/null || true
  chmod -R a+rX "$DOCROOT"
  log "permissions refreshed"
fi
log "done"
