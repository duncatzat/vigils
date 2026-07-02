#!/usr/bin/env bash
# Regression for the two macOS daemon-transport bugs found in v0.4.0 acceptance (also a
# positive check on Linux). Uses the published *model-less* ML binary (no 738MB download).
#   R1    : daemon must be reachable via peer-credential check (status -> running).
#           Pre-fix macOS: "not responding / R1 peer-cred mismatch" (peer_creds().pid()==None).
#   stale : after an unclean exit (kill -9, Drop doesn't run), `daemon start` must rebind.
#           Pre-fix macOS: permanent EADDRINUSE (GenericNamespaced /tmp socket not reclaimed).
# Env: VERSION, REPO.
set -u
: "${VERSION:?}"; : "${REPO:?}"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) PLAT=linux-x64 ;; Darwin/arm64) PLAT=macos-arm64 ;;
  *) echo "unsupported $(uname -s)/$(uname -m)"; exit 2 ;;
esac
SBX="${TMPDIR:-/tmp}/vigil-dreg-$$"; rm -rf "$SBX"; mkdir -p "$SBX/home"
# macOS $TMPDIR 过长 → 默认 socket 超 sun_path(104)。env 指定 sandbox 内短路径(见 transport.rs)。
export HOME="$SBX/home" XDG_DATA_HOME="$SBX/home/.local/share" \
       XDG_CONFIG_HOME="$SBX/home/.config" XDG_CACHE_HOME="$SBX/home/.cache" \
       VIGIL_DAEMON_SOCKET="$SBX/d.sock"
export VIGIL_LANG=en   # 断言锚定英文文案(zh locale 下 status 输出中文,'running (pid' 失配)
HUB="$SBX/ml/vigil-hub"; P=0; F=0
ok(){ printf '  PASS %s\n' "$*"; P=$((P+1)); }; no(){ printf '  FAIL %s\n' "$*"; F=$((F+1)); }
cleanup(){ pkill -f "$SBX/ml/vigil-hub" 2>/dev/null || true
           rm -rf "$SBX"; }
trap cleanup EXIT

curl -fsSL --connect-timeout 20 --speed-limit 10000 --speed-time 30 --retry 3 --retry-delay 5 --max-time 600 \
  -o "$SBX/ml.tgz" "https://github.com/$REPO/releases/download/$VERSION/vigils-cli-ml-${PLAT}.tar.gz" \
  || { echo "download failed (or too slow: <10KB/s for 30s)"; exit 1; }
mkdir -p "$SBX/ml"; tar -xzf "$SBX/ml.tgz" -C "$SBX/ml"; chmod +x "$HUB"

wait_running(){ for i in $(seq 1 25); do sleep 1; "$HUB" daemon status 2>&1 | grep -q 'running (pid' && return 0; done; return 1; }

echo "### daemon regression ($PLAT, model-less) ###"
nohup "$HUB" daemon start >"$SBX/d1.log" 2>&1 & D1=$!
if wait_running; then ok "R1: daemon reachable (status: running)"; else no "R1: daemon UNREACHABLE"; cat "$SBX/d1.log"; fi
kill -9 "$D1" 2>/dev/null; sleep 1
nohup "$HUB" daemon start >"$SBX/d2.log" 2>&1 & D2=$!
if wait_running; then ok "stale-socket: rebind succeeds after kill -9 (no EADDRINUSE)"; else no "stale-socket: cannot rebind after unclean exit"; cat "$SBX/d2.log"; fi
"$HUB" daemon stop >/dev/null 2>&1; kill -9 "$D2" 2>/dev/null || true

printf '\n### result: %d passed, %d failed (%s) ###\n' "$P" "$F" "$PLAT"; [ "$F" = 0 ]
