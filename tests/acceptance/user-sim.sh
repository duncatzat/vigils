#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# user-sim.sh — 模拟真实用户旅程(对**已发布**的 vigil-hub 二进制)
#
# 与 functional-sweep.sh 互补:sweep 验「防护语义」(deny/redact/tamper/握手),
# 本脚本验「用户旅程」:onboarding → demo → turnkey 装/卸往返 → daemon 生命周期
# → checkpoint/verify,并固化历次用户级验证发现的**发布回归断言**(见 U 编号注释)。
#
# 用法:  HUB=/path/to/vigil-hub bash user-sim.sh
#   可选:USER_SIM_ALLOW_SETUP=1  在非即抛环境也跑写路径旅程(见下)
#
# 沙箱:Linux/macOS 下 dirs::home_dir 吃 $HOME、data_local 吃 XDG_* —— 重定向后
# 完全隔离。Windows 下 dirs 走 KnownFolder(不理 env),setup/daemon 旅程会触真实
# 用户目录,故仅在**即抛环境**(CI runner,$GITHUB_ACTIONS)或显式
# USER_SIM_ALLOW_SETUP=1 时执行,否则如实 SKIP(demo/hook/checkpoint/verify 全程
# 用显式 --ledger,任何平台都安全)。
#
#   U1 --version 可运行
#   U2 quickstart 检测到 agent + 计数;skip 统称标签回归(不得再把一切标 http/sse)
#   U3 demo 旅程完整 + 下一步指向 `setup --all`(转化漏斗回归)
#   U4 setup --all:hook 注册 + MCP wrap;**大写 server 名经 slugify 进入保护**
#   U5 setup --status 报 ACTIVE
#   U6 setup --all --uninstall:agent 配置**语义完整还原**(canonical JSON 比对)
#   U7 daemon start/status/stop:uptime 实时递增(曾恒 0s);stop 输出干净(不透传
#      OS kill 助手文案)
#   U8 checkpoint 提示平台正确(Windows 绝不出现 Linux 专属 chattr)
#   U9 verify:锚定后链校验通过
# ----------------------------------------------------------------------------
set -u
: "${HUB:?set HUB=path to vigil-hub}"

SBX="${TMPDIR:-/tmp}/vigil-usim-$$"; rm -rf "$SBX"; mkdir -p "$SBX/home"
export VIGIL_LANG=en          # 断言锚定英文输出(与 locale 无关地稳定)
export VIGIL_LEDGER_PATH="$SBX/ledger.sqlite3"
export VIGIL_DAEMON_SOCKET="$SBX/d.sock"
case "$(uname -s)" in
  Linux|Darwin)
    export HOME="$SBX/home" \
           XDG_DATA_HOME="$SBX/home/.local/share" \
           XDG_CONFIG_HOME="$SBX/home/.config" \
           XDG_CACHE_HOME="$SBX/home/.cache"
    FULL=1 ;;
  *)  # Windows(git-bash):env 沙箱对 dirs::home_dir 无效 → 写路径旅程须即抛环境
    FULL=0
    [ -n "${GITHUB_ACTIONS:-}" ] && FULL=1
    [ -n "${USER_SIM_ALLOW_SETUP:-}" ] && FULL=1 ;;
esac
trap 'rm -rf "$SBX"' EXIT

P=0; F=0; S=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; P=$((P+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; F=$((F+1)); }
skip(){ printf '  \033[33mSKIP\033[0m %s\n' "$*"; S=$((S+1)); }
PY="$(command -v python3 || command -v python)"

echo "### Vigil user-journey simulation — $("$HUB" --version 2>&1 | head -1) (full=$FULL) ###"

echo "== U1 first touch: --version =="
V="$("$HUB" --version 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "--version runs ($V)" || no "--version exit=$RC"

# 伪造一个真实形态的 Claude Code 配置:1 个合法名 + 1 个**大写名**(slugify 回归靶)。
plant_agent_config() {
  local h; h="$(cd ~ && pwd)"
  mkdir -p "$h/.claude"
  cat > "$h/.claude.json" <<'EOF'
{
  "mcpServers": {
    "filesystem": { "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
    "Playwright":  { "type": "stdio", "command": "npx", "args": ["-y", "@playwright/mcp@latest"] }
  }
}
EOF
  [ -f "$h/.claude/settings.json" ] || echo '{}' > "$h/.claude/settings.json"
  cp "$h/.claude.json" "$SBX/claude.json.orig"
  cp "$h/.claude/settings.json" "$SBX/settings.json.orig"
}

echo "== U2 quickstart: agent detection + skip-label regression =="
if [ "$FULL" = 1 ]; then
  plant_agent_config
  Q="$("$HUB" quickstart 2>&1)"; RC=$?
  [ "$RC" = 0 ] && ok "quickstart exit 0" || no "quickstart exit=$RC"
  printf '%s' "$Q" | grep -q "Claude Code" && ok "quickstart detects the planted agent" || no "quickstart: agent not detected"
  # 两个 stdio server(含大写名)都应计入 unprotected —— 大写名曾被 Skip 且被统称 http/sse
  printf '%s' "$Q" | grep -q "2 unprotected" && ok "both servers counted protectable (uppercase incl.)" || no "quickstart: expected '2 unprotected'; got: $(printf '%s' "$Q" | grep 'Claude Code' | head -1)"
  printf '%s' "$Q" | grep -q "unsupported (http/sse)" && no "stale skip label 'unsupported (http/sse)' resurfaced" || ok "no blanket http/sse skip label"
else
  Q="$("$HUB" quickstart 2>&1)"; RC=$?
  [ "$RC" = 0 ] && ok "quickstart exit 0 (read-only)" || no "quickstart exit=$RC"
  printf '%s' "$Q" | grep -q "unsupported (http/sse)" && no "stale skip label resurfaced" || ok "no blanket http/sse skip label"
  skip "agent-detection assertions (non-throwaway Windows: real \$HOME would be touched)"
fi

echo "== U3 demo journey: complete + funnels to setup --all =="
D="$("$HUB" demo 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "demo exit 0" || no "demo exit=$RC"
printf '%s' "$D" | grep -q "setup --all" && ok "demo's next step points at 'setup --all' (turnkey)" || no "demo next-step regression: no 'setup --all' (funnel broke once before)"

if [ "$FULL" = 1 ]; then
  echo "== U4 turnkey: setup --all (hook registered + uppercase name wrapped via slug) =="
  SO="$("$HUB" setup --all 2>&1)"; RC=$?
  [ "$RC" = 0 ] && ok "setup --all exit 0" || { no "setup --all exit=$RC"; printf '%s\n' "$SO" | tail -5; }
  H="$(cd ~ && pwd)"
  grep -q "vigil" "$H/.claude/settings.json" && ok "hook registered in settings.json" || no "hook missing from settings.json"
  "$PY" - "$H/.claude.json" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8-sig"))
srv = cfg["mcpServers"]["Playwright"]
args = srv.get("args", [])
def die(msg):
    print("ASSERT-FAIL:", msg); sys.exit(1)
if "--vigil-managed-mcp" not in args: die("Playwright not wrapped (no sentinel)")
try:
    sid = args[args.index("--server-id") + 1]
except (ValueError, IndexError):
    die("no --server-id in wrapped argv")
if not sid.startswith("user-playwright-"): die(f"server-id not slugified: {sid}")
if "--" not in args or "npx" not in args[args.index("--"):]: die("original argv not preserved after --")
print("OK", sid)
PYEOF
  [ $? = 0 ] && ok "uppercase 'Playwright' wrapped with slugified id (user-playwright-<hash>)" || no "slugify wrap assertion failed"

  echo "== U5 setup --status: ACTIVE =="
  ST="$("$HUB" setup --status 2>&1)"
  printf '%s' "$ST" | grep -q "ACTIVE" && ok "status reports ACTIVE" || no "status not ACTIVE: $(printf '%s' "$ST" | head -3)"

  echo "== U6 uninstall: config restored semantically =="
  UO="$("$HUB" setup --all --uninstall 2>&1)"; RC=$?
  [ "$RC" = 0 ] && ok "setup --all --uninstall exit 0" || no "uninstall exit=$RC"
  "$PY" - "$H/.claude.json" "$SBX/claude.json.orig" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1], encoding="utf-8-sig"))
b = json.load(open(sys.argv[2], encoding="utf-8-sig"))
sys.exit(0 if a == b else 1)
PYEOF
  [ $? = 0 ] && ok "agent config restored (canonical-JSON equal)" || no "agent config NOT restored after uninstall"
  grep -q "vigil" "$H/.claude/settings.json" && no "vigil hook left behind in settings.json" || ok "settings.json clean of vigil entries"
else
  skip "U4-U6 turnkey install/uninstall (needs throwaway env on Windows; set USER_SIM_ALLOW_SETUP=1)"
fi

if [ "$FULL" = 1 ]; then
  echo "== U7 daemon lifecycle: uptime ticks (was frozen at 0s), stop output clean =="
  "$HUB" daemon start >"$SBX/daemon.log" 2>&1 &
  DPID=$!
  sleep 3
  DS="$("$HUB" daemon status 2>&1)"
  printf '%s' "$DS" | grep -q "running" && ok "daemon status: running" || no "daemon not running: $DS"
  UP="$(printf '%s' "$DS" | sed -n 's/.*uptime=\([0-9]*\)s.*/\1/p')"
  if [ -n "$UP" ] && [ "$UP" -ge 2 ]; then ok "uptime ticks (${UP}s after 3s — was frozen at 0s)"; else no "uptime regression: '$UP' (want >=2)"; fi
  SO="$("$HUB" daemon stop 2>&1)"
  printf '%s' "$SO" | grep -q "stopped" && ok "daemon stop reports stopped" || no "daemon stop output: $SO"
  # OS kill 助手的文案(taskkill「SUCCESS: …」等)曾直漏用户输出 —— stop 输出须只有 Vigil 自己的行
  LINES="$(printf '%s\n' "$SO" | grep -c .)"
  if [ "$LINES" -le 1 ] && ! printf '%s' "$SO" | grep -qiE 'SUCCESS:|taskkill'; then ok "stop output clean (no OS kill-helper passthrough)"; else no "stop output leaked helper text: $SO"; fi
  wait "$DPID" 2>/dev/null
  DS2="$("$HUB" daemon status 2>&1)"
  printf '%s' "$DS2" | grep -q "not running" && ok "daemon gone after stop" || no "daemon still reported after stop: $DS2"
else
  skip "U7 daemon lifecycle (daemon.json lands in the real LOCALAPPDATA on Windows)"
fi

echo "== U8 checkpoint: platform-correct tip (no chattr on Windows) =="
# 先经 hook 写一条审计事件,checkpoint 才有链头可锚(显式 --ledger,全平台无副作用)。
EV='{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"usim","tool_response":{"stdout":"key AKIAIOSFODNN7EXAMPLE"}}'
printf '%s' "$EV" | "$HUB" hook --cli claude --redact-results --ledger "$VIGIL_LEDGER_PATH" >/dev/null 2>&1
CP="$("$HUB" checkpoint --ledger "$VIGIL_LEDGER_PATH" 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "checkpoint exit 0" || no "checkpoint exit=$RC: $CP"
case "$(uname -s)" in
  Linux)  printf '%s' "$CP" | grep -q "chattr" && ok "tip suggests chattr (Linux)" || no "Linux tip missing chattr" ;;
  Darwin) printf '%s' "$CP" | grep -q "chflags" && ok "tip suggests chflags (macOS)" || no "macOS tip missing chflags" ;;
  *)      printf '%s' "$CP" | grep -q "chattr" && no "Windows tip suggests Linux-only chattr (platform regression)" || ok "no chattr on Windows tip" ;;
esac

echo "== U9 verify: anchored chain passes =="
VO="$("$HUB" verify --ledger "$VIGIL_LEDGER_PATH" 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "verify exit 0" || no "verify exit=$RC: $VO"
printf '%s' "$VO" | grep -qiE "anchored|consistent" && ok "verify reports anchored/consistent" || no "verify output unexpected: $VO"

printf '\n========== USER-SIM SUMMARY: %d passed, %d failed, %d skipped ==========\n' "$P" "$F" "$S"
[ "$F" = 0 ]
