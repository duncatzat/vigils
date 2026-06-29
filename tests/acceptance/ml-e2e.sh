#!/usr/bin/env bash
# daemon hook-ML end-to-end against a PUBLISHED CLI ML variant (Linux/macOS).
# Runs ON a test machine. Env: VERSION, REPO, RUN_ML_MODEL (0/1). Self-isolating + self-cleaning.
#
# Verifies, as a real user would experience it:
#   - ML variant binary runs; bundled ORT dylib is exe-adjacent + loads
#   - turnkey: `model install` -> `daemon start` (warm-load) -> `engine set ml` -> hook PostToolUse
#   - daemon reachable via R1 (this is what was BROKEN on macOS pre-fix)
#   - ML scrubs SEMANTIC PII (person/address) that hard-fingerprints cannot
#   - fail-closed: daemon-less / model-less still scrubs hard fingerprints, no leak, exit 0
set -u
: "${VERSION:?set VERSION}"; : "${REPO:?set REPO}"; : "${RUN_ML_MODEL:=1}"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)   PLAT=linux-x64;    EXT=tar.gz; DYLIB=libonnxruntime.so ;;
  Darwin/arm64)   PLAT=macos-arm64;  EXT=tar.gz; DYLIB=libonnxruntime.dylib ;;
  *) echo "unsupported $(uname -s)/$(uname -m)"; exit 2 ;;
esac
ARCHIVE="vigils-cli-ml-${PLAT}.${EXT}"
URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"

SBX="${TMPDIR:-/tmp}/vigil-acc-$$"; rm -rf "$SBX"; mkdir -p "$SBX/home"
# macOS $TMPDIR(/var/folders/.../T)过长 → 默认 ~/Library socket 超 sockaddr_un sun_path(104)
# → bind 失败。env 显式指定 sandbox 内**短**路径(daemon + hook 同 env,经 daemon.json 一致)。
export HOME="$SBX/home" XDG_DATA_HOME="$SBX/home/.local/share" \
       XDG_CACHE_HOME="$SBX/home/.cache" XDG_CONFIG_HOME="$SBX/home/.config" \
       VIGIL_DAEMON_SOCKET="$SBX/d.sock"
HUB="$SBX/ml/vigil-hub"
P=0; F=0
ok(){ printf '  PASS %s\n' "$*"; P=$((P+1)); }; no(){ printf '  FAIL %s\n' "$*"; F=$((F+1)); }

cleanup(){ "$HUB" daemon stop >/dev/null 2>&1 || true
           pkill -f "$SBX/ml/vigil-hub" 2>/dev/null || true
           rm -rf "$SBX"; }
trap cleanup EXIT

echo "### ML hook-ML e2e: $ARCHIVE (RUN_ML_MODEL=$RUN_ML_MODEL) ###"
curl -fsSL -o "$SBX/ml.$EXT" "$URL" || { echo "download $URL failed"; exit 1; }
mkdir -p "$SBX/ml"; tar -xzf "$SBX/ml.$EXT" -C "$SBX/ml"; chmod +x "$HUB"

# --- bundled dylib present, exe-adjacent, right arch ---
[ -f "$SBX/ml/$DYLIB" ] && ok "ORT dylib bundled exe-adjacent ($DYLIB)" || no "ORT dylib missing"
case "$(uname -s)/$(file -b "$SBX/ml/$DYLIB" 2>/dev/null)" in
  Linux/*ELF*x86-64*|Darwin/*Mach-O*arm64*) ok "dylib arch matches platform" ;;
  *) no "dylib arch mismatch: $(file -b "$SBX/ml/$DYLIB")" ;;
esac
VER_OUT="$("$HUB" --version)"
[ "$VER_OUT" = "vigil-hub ${VERSION#v}" ] && ok "version == ${VERSION#v}" || no "version mismatch: $VER_OUT"

"$HUB" engine set ml >/dev/null 2>&1
[ "$("$HUB" engine show)" = "ml" ] && ok "engine set ml persisted" || no "engine set ml failed"

# --- turnkey real-model path ---
DAEMON_UP=0
if [ "$RUN_ML_MODEL" = "1" ]; then
  echo "  ---- model install --privacy (real ~738MB turnkey)…"
  if "$HUB" model install --privacy >"$SBX/install.log" 2>&1; then
    ok "model install --privacy (turnkey download)"
    nohup "$HUB" daemon start >"$SBX/daemon.log" 2>&1 &
    for i in $(seq 1 40); do sleep 1; "$HUB" daemon status 2>&1 | grep -q 'running (pid' && { DAEMON_UP=1; break; }; done
    if [ "$DAEMON_UP" = 1 ]; then
      ok "daemon reachable via R1 (status: running)"
      "$HUB" daemon status 2>&1 | grep -q 'pii_loaded=true' && ok "daemon warm-loaded real PII model" || no "daemon pii_loaded != true"
    else
      no "daemon NOT reachable (R1 broken? — was the macOS pre-fix failure)"
      info=$(cat "$SBX/daemon.log" 2>/dev/null); echo "  ---- daemon.log: $info"
    fi
  else
    no "model install FAILED (download bug?): $(tail -1 "$SBX/install.log")"
  fi
fi

# --- hook PostToolUse with semantic + hard PII ---
EVENT='{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"acc","tool_response":{"stdout":"Patient Jonathan Whitfield at 742 Evergreen Terrace Springfield, email jw@x.org, awskey AKIAIOSFODNN7EXAMPLE"}}'
OUT="$(printf '%s' "$EVENT" | "$HUB" hook --cli claude --redact-results 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "hook exit 0" || no "hook exit $RC"
echo "$OUT" | grep -q 'AKIAIOSFODNN7EXAMPLE' && no "RAW AWS KEY LEAKED (fail-open!)" || ok "fail-closed: bare AWS key never leaks"
echo "$OUT" | grep -q 'REDACTED aws_access_key_id' && ok "hard-fingerprint floor scrubbed AWS key" || no "hard-fp floor did not scrub"
if [ "$DAEMON_UP" = 1 ]; then
  echo "$OUT" | grep -qiE 'REDACTED (person|name)' && ok "ML scrubbed semantic PII (person) — beyond hard-fp" || no "ML did not scrub person name (daemon up but no ML span)"
  # VIGIL-SEC-ML-SKIP 回归:含 secret:// 的 leaf 不再整段跳 ML → 同段 soft-PII 仍被 ML scrub(可证伪)。
  SKEV='{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"acc","tool_response":{"stdout":"deploy with secret://prod-key for patient Margaret Chen at 88 Willow Lane Boston"}}'
  SKOUT="$(printf '%s' "$SKEV" | "$HUB" hook --cli claude --redact-results 2>&1)"
  echo "$SKOUT" | grep -qiE 'REDACTED (person|name|address)' && ok "ML-SKIP closed: secret:// leaf still ML-scrubs soft-PII" || no "ML-SKIP: secret:// leaf suppressed ML (soft-PII not scrubbed)"
fi
echo "  ---- redacted: $(echo "$OUT" | grep -o '"stdout":"[^"]*"' | head -1)"

# --- core functional scenario sweep (reuse this published binary, run.sh wires VIGIL_FN_SWEEP) ---
if [ -n "${VIGIL_FN_SWEEP:-}" ] && [ -f "$VIGIL_FN_SWEEP" ]; then
  echo "  ---- functional sweep (HUB=$HUB)…"
  if HUB="$HUB" VIGIL_FN_MCP_PROBE=/tmp/mcp_probe.py bash "$VIGIL_FN_SWEEP" >"$SBX/fn.log" 2>&1; then
    ok "functional sweep: all scenarios passed ($(grep -oE '[0-9]+ passed' "$SBX/fn.log" | head -1))"
  else
    no "functional sweep: scenario failure(s) — $(grep -oE '[0-9]+ passed, [0-9]+ failed' "$SBX/fn.log" | head -1)"
    grep -iE 'FAIL ' "$SBX/fn.log" | head -5
  fi
fi

printf '\n### result: %d passed, %d failed (%s) ###\n' "$P" "$F" "$PLAT"
[ "$F" = 0 ]
