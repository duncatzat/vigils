#!/usr/bin/env bash
# Local (controller-side) audit of a published release: download all assets, verify
# checksums, per-platform binary architecture, ML dylib bundling, desktop signatures,
# and OTA manifests. Catches packaging/distribution defects without any test machine.
# Env: VERSION, REPO. Requires: gh, file, tar, unzip, sha256sum, python3+pynacl (for sigs).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$HERE/lib.sh"
: "${VERSION:?}"; : "${REPO:?}"
W="${TMPDIR:-/tmp}/vigil-acc-local"; rm -rf "$W"; mkdir -p "$W/assets" "$W/ex"

hdr "Download all release assets ($VERSION)"
gh release download "$VERSION" -R "$REPO" -D "$W/assets" --clobber >/dev/null 2>&1 \
  && ok "downloaded $(ls "$W/assets" | wc -l) assets" || { bad "gh release download failed"; suite_summary; exit 1; }

hdr "CLI checksums (+ CRLF lint)"
for s in "$W"/assets/*.sha256; do
  exp=$(tr -d '\r' < "$s" | awk '{print $1}'); f="${s%.sha256}"
  act=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
  asrt "checksum $(basename "$f")" "$exp" "$act"
  if file "$s" | grep -q CRLF; then bad "$(basename "$s") has CRLF line endings (Unix sha256sum -c breaks)"; fi
done

hdr "Binary architecture (flat-collision regression) + ML dylib bundling"
declare -A WANT=( [linux-x64]="ELF*x86-64" [macos-arm64]="Mach-O*arm64" [windows-x64]="PE32+*x86-64" )
for plat in linux-x64 macos-arm64 windows-x64; do
  for kind in "" "ml-"; do
    a="$W/assets/vigils-cli-${kind}${plat}"; [ -f "$a.tar.gz" ] && a="$a.tar.gz" || a="$a.zip"
    [ -f "$a" ] || { bad "missing archive $(basename "$a")"; continue; }
    d="$W/ex/${kind}${plat}"; mkdir -p "$d"
    case "$a" in *.tar.gz) tar -xzf "$a" -C "$d";; *.zip) unzip -oq "$a" -d "$d";; esac
    hub=$(find "$d" -name 'vigil-hub*' | head -1)
    if file -b "$hub" | grep -q "${WANT[$plat]%\**}"; then ok "${kind}${plat}: vigil-hub is ${WANT[$plat]}"; \
      else bad "${kind}${plat}: wrong arch: $(file -b "$hub")"; fi
    if [ "$kind" = "ml-" ]; then
      dy=$(find "$d" -iname '*onnxruntime*' | grep -viE 'providers' | head -1)
      [ -n "$dy" ] && ok "${plat}: ORT dylib bundled exe-adjacent ($(basename "$dy"))" || bad "${plat} ML: dylib missing"
      grep -aoE '1\.2[0-9]\.[0-9]+' "$dy" 2>/dev/null | sort -u | grep -q . && info "ORT version strings: $(grep -aoE '1\.2[0-9]\.[0-9]+' "$dy" | sort -u | tr '\n' ' ')"
    fi
  done
done

hdr "Desktop updater signatures (minisign crypto verify)"
PUB=$(gh api "repos/$REPO/contents/apps/desktop/tauri.conf.json?ref=$VERSION" -H "Accept: application/vnd.github.raw" 2>/dev/null | grep -oE '"pubkey": *"[^"]+"' | sed 's/.*"pubkey": *"//;s/"//')
if [ -n "$PUB" ] && python3 -c 'import nacl' 2>/dev/null; then
  pairs=(); for sig in "$W"/assets/*.sig; do pairs+=("${sig%.sig}" "$sig"); done
  if python3 "$HERE/verify_minisign.py" "$PUB" "${pairs[@]}"; then ok "all updater artifacts cryptographically signed by repo key"; else bad "signature verification FAILED"; fi
else info "skip sig verify (need pubkey + python3 pynacl)"; fi

hdr "OTA manifests"
for j in "$W"/assets/latest-*.json; do
  [ -f "$j" ] || continue
  v=$(grep -oE '"version": *"[^"]+"' "$j" | head -1 | sed 's/.*"version": *"//;s/"//')
  asrt "$(basename "$j") version" "${VERSION#v}" "$v"
  u=$(grep -oE 'https://[^"]+' "$j" | head -1)
  # GitHub release asset URLs answer 302 -> CDN; a 2xx/3xx means it resolves (updater follows).
  code=$(curl -fsS -o /dev/null -w '%{http_code}' -I "$u" 2>/dev/null || echo 000)
  case "$code" in 2*|3*) ok "$(basename "$j") url resolves ($code)";; *) bad "$(basename "$j") url HTTP $code";; esac
done

rm -rf "$W"
suite_summary
