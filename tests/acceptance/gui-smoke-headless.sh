#!/usr/bin/env bash
# gui-smoke-headless.sh — Linux / macOS 桌面产物「装 → 启 → 活 → 截图非空」冒烟。
#
# 这两个平台的 tauri WebView(WebKitGTK / WKWebView)没有 CDP,深交互走不了
# gui-smoke.mjs(那是 Windows WebView2 专属);本脚本守住发布桌面包的底线:
# 能安装、能启动、进程活过 N 秒不崩、屏幕/窗口截图不是空白。
#
# 用法:
#   Linux : DEB=path/to/Vigils_*_amd64.deb  bash gui-smoke-headless.sh
#           (需要:sudo、xvfb、xdotool、imagemagick —— CI 步骤里安装)
#   macOS : DMG=path/to/Vigils_*_aarch64.dmg bash gui-smoke-headless.sh
# 产物:$OUT(默认 gui-shots/)下截图,供 artifact 上传人工复核。
set -u
OUT="${OUT:-gui-shots}"; mkdir -p "$OUT"
P=0; F=0
ok(){ printf '  PASS %s\n' "$*"; P=$((P+1)); }
no(){ printf '  FAIL %s\n' "$*"; F=$((F+1)); }
fin(){ printf '\n========== GUI-SMOKE(headless) SUMMARY: %d passed, %d failed ==========\n' "$P" "$F"; [ "$F" = 0 ]; exit $?; }

size_of(){ wc -c < "$1" 2>/dev/null | tr -d ' '; }

case "$(uname -s)" in
Linux)
  : "${DEB:?set DEB=path to Vigils .deb}"
  echo "== install (.deb pulls WebKitGTK deps) =="
  if sudo apt-get install -y "./$DEB" >/dev/null 2>&1 || sudo apt-get install -y "$DEB" >/dev/null 2>&1; then
    ok "deb installed"
  else no "deb install failed"; fin; fi
  BIN="$(command -v vigils || echo /usr/bin/vigils)"
  [ -x "$BIN" ] && ok "binary on PATH ($BIN)" || { no "vigils binary missing after install"; fin; }

  echo "== launch under Xvfb =="
  Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
  XVFB=$!
  export DISPLAY=:99
  "$BIN" >/dev/null 2>&1 &
  APP=$!
  sleep 10
  kill -0 "$APP" 2>/dev/null && ok "process alive after 10s" || { no "app exited early"; kill "$XVFB" 2>/dev/null; fin; }

  echo "== window + screenshot =="
  WIN=""
  for _ in $(seq 1 20); do
    WIN="$(xdotool search --name -- Vigils 2>/dev/null | head -1)"
    [ -n "$WIN" ] && break; sleep 1
  done
  [ -n "$WIN" ] && ok "window found (id=$WIN)" || no "no window matching 'Vigils'"
  import -display :99 -window root "$OUT/linux-root.png" 2>/dev/null
  SZ="$(size_of "$OUT/linux-root.png")"
  [ -n "$SZ" ] && [ "$SZ" -gt 15000 ] && ok "screenshot non-blank (${SZ}B)" || no "screenshot blank/tiny (${SZ:-0}B)"
  kill "$APP" 2>/dev/null; wait "$APP" 2>/dev/null
  kill "$XVFB" 2>/dev/null
  fin
  ;;
Darwin)
  : "${DMG:?set DMG=path to Vigils .dmg}"
  echo "== mount dmg + copy app =="
  MNT="$(mktemp -d)/dmg"
  if hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "$DMG" >/dev/null 2>&1; then ok "dmg mounted"; else no "dmg mount failed"; fin; fi
  APPSRC="$(ls -d "$MNT"/*.app 2>/dev/null | head -1)"
  [ -n "$APPSRC" ] || { no "no .app inside dmg"; hdiutil detach "$MNT" >/dev/null 2>&1; fin; }
  APPDST="${TMPDIR:-/tmp}/VigilsSmoke.app"; rm -rf "$APPDST"
  cp -R "$APPSRC" "$APPDST" && ok "app copied ($(basename "$APPSRC"))" || no "app copy failed"
  hdiutil detach "$MNT" >/dev/null 2>&1
  xattr -cr "$APPDST" 2>/dev/null   # 未签名 beta:去 quarantine,免 Gatekeeper 拦启动

  echo "== launch =="
  BIN="$(find "$APPDST/Contents/MacOS" -type f -perm +111 2>/dev/null | head -1)"
  [ -n "$BIN" ] && ok "binary found ($(basename "$BIN"))" || { no "no executable in Contents/MacOS"; fin; }
  "$BIN" >/dev/null 2>&1 &
  APP=$!
  sleep 10
  kill -0 "$APP" 2>/dev/null && ok "process alive after 10s" || { no "app exited early"; fin; }

  echo "== screenshot =="
  screencapture -x "$OUT/mac-screen.png" 2>/dev/null
  SZ="$(size_of "$OUT/mac-screen.png")"
  [ -n "$SZ" ] && [ "$SZ" -gt 30000 ] && ok "screenshot captured (${SZ}B)" || no "screenshot blank/tiny (${SZ:-0}B)"
  kill "$APP" 2>/dev/null; wait "$APP" 2>/dev/null
  rm -rf "$APPDST"
  fin
  ;;
*)
  echo "unsupported platform for headless smoke (Windows uses gui-smoke.mjs over CDP)"; exit 2 ;;
esac
