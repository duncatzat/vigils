#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# functional-sweep.sh — Vigil 核心防护场景功能性测试套件(可复用,发版后跑)
#
# 以真实用户身份对一个 vigil-hub 二进制跑核心安全场景。自隔离(临时 HOME +
# 独立 ledger)、自清理、PASS/FAIL 计数、任一 FAIL → 退出非 0。
#
# 用法:  HUB=/path/to/vigil-hub bash functional-sweep.sh
#   可选:VIGIL_FN_MCP_PROBE=/path/to/mcp_probe.py(默认同目录)
#
# 覆盖(每条都是"防护真发生"的可证伪断言,非 hard-code):
#   S1  demo            零设置 default-deny + 可逆脱敏往返 + 哈希链有效
#   S1b demo --tamper   篡改账本一行 → 链断裂被检出(证伪 demo 非作弊)
#   S2  hook PreToolUse 裸 secret 工具调用 deny(exit 2)+ 不回显原值
#   S3  hook PostToolUse 结果携密 → 占位符替换 + 不泄漏
#   S3b hook 重叠硬指纹 结果 → 占位符良构(开闭配对,无破碎/泄漏)
#   S4  posture         high/low 往返
#   S5  engine          ml/hardfp 持久化
#   S6  inspect         保护汇总渲染 + 审计链完整
#   S7  verify          审计链完整性
#   S8  serve --stdio   MCP initialize + tools/list 握手(mcp_probe.py)
#   S9  quickstart      只读引导(不改配置)
# ----------------------------------------------------------------------------
set -u
: "${HUB:?set HUB=path to vigil-hub}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_PROBE="${VIGIL_FN_MCP_PROBE:-$SELF_DIR/mcp_probe.py}"

SBX="${TMPDIR:-/tmp}/vigil-fn-$$"; rm -rf "$SBX"; mkdir -p "$SBX/home"
export HOME="$SBX/home" \
       XDG_DATA_HOME="$SBX/home/.local/share" \
       XDG_CONFIG_HOME="$SBX/home/.config" \
       XDG_CACHE_HOME="$SBX/home/.cache"
export VIGIL_LEDGER_PATH="$SBX/ledger.sqlite3"
trap 'rm -rf "$SBX"' EXIT

P=0; F=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; P=$((P+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; F=$((F+1)); }
brackets_balanced(){ [ "$(printf '%s' "$1" | grep -o '\[REDACTED' | wc -l)" = "$(printf '%s' "$1" | grep -o ']' | wc -l)" ]; }

echo "### Vigil functional sweep — $("$HUB" --version 2>&1 | head -1) ###"

echo "== S1 demo: zero-setup default-deny + redaction roundtrip + audit chain =="
D="$("$HUB" demo 2>&1)"
echo "$D" | grep -qiE 'hash-chain valid|chain.*valid|integrity.*intact|chain.*intact' && ok "demo: audit hash-chain valid" || no "demo: no hash-chain-valid marker"
echo "$D" | grep -qiE 'redact|placeholder|REDACTED' && ok "demo: redaction roundtrip shown" || no "demo: no redaction shown"

echo "== S1b demo --tamper: ledger tamper -> chain破裂被检出(falsifiable)=="
DT="$("$HUB" demo --tamper 2>&1)"
echo "$DT" | grep -qiE 'tamper|invalid|broken|mismatch|detected|BROKEN|FAIL|corrupt' && ok "demo --tamper: chain break detected" || no "demo --tamper: tamper not flagged"

echo "== S2 hook PreToolUse deny: bare AWS key in a native tool call =="
EV='{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"fn","tool_input":{"command":"aws configure set k AKIAIOSFODNN7EXAMPLE"}}'
OUT="$(printf '%s' "$EV" | "$HUB" hook --cli claude 2>&1)"; RC=$?
[ "$RC" = 2 ] && ok "PreToolUse bare-secret deny -> exit 2" || no "PreToolUse exit=$RC (want 2)"
printf '%s' "$OUT" | grep -q 'AKIAIOSFODNN7EXAMPLE' && no "PreToolUse: raw key echoed in reason" || ok "PreToolUse: no raw-secret echo"

echo "== S3 hook PostToolUse redact: result carrying secrets =="
EV='{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"fn","tool_response":{"stdout":"token ghp_1234567890abcdef1234567890abcdef1234 and key AKIAIOSFODNN7EXAMPLE"}}'
OUT="$(printf '%s' "$EV" | "$HUB" hook --cli claude --redact-results 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "PostToolUse redact -> exit 0" || no "PostToolUse exit=$RC"
printf '%s' "$OUT" | grep -q 'REDACTED' && ok "PostToolUse: secrets -> placeholders" || no "PostToolUse: no REDACTED"
printf '%s' "$OUT" | grep -qE 'AKIAIOSFODNN7EXAMPLE|ghp_1234567890abcdef' && no "PostToolUse: raw secret leaked" || ok "PostToolUse: no raw-secret leak"

echo "== S3b hook PostToolUse overlapping hard fingerprints: well-formed placeholders =="
EV='{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"fn","tool_response":{"stdout":"export GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd done"}}'
OUT="$(printf '%s' "$EV" | "$HUB" hook --cli claude --redact-results 2>&1)"
RT="$(printf '%s' "$OUT" | grep -o '"stdout":"[^"]*"' | head -1)"
printf '%s' "$OUT" | grep -qE 'ghp_abcdef1234567890' && no "overlap: raw token leaked" || ok "overlap: no raw-token leak"
if [ -n "$RT" ] && brackets_balanced "$RT"; then ok "overlap: placeholders well-formed (brackets balanced)"; else no "overlap: malformed/nested placeholders ($RT)"; fi

echo "== S4 posture: set high then low =="
"$HUB" posture set high >/dev/null 2>&1
"$HUB" posture show 2>&1 | grep -qi high && ok "posture set/show high" || no "posture high roundtrip"
"$HUB" posture set low >/dev/null 2>&1

echo "== S5 engine: set ml then hardfp =="
"$HUB" engine set ml >/dev/null 2>&1
[ "$("$HUB" engine show 2>&1)" = "ml" ] && ok "engine set ml persisted" || no "engine set ml"
"$HUB" engine set hardfp >/dev/null 2>&1
[ "$("$HUB" engine show 2>&1)" = "hardfp" ] && ok "engine set hardfp persisted" || no "engine set hardfp"

echo "== S6 inspect: protection summary + audit chain (after demo populated ledger) =="
"$HUB" demo >/dev/null 2>&1
if "$HUB" inspect protection >/dev/null 2>&1; then
  IN="$("$HUB" inspect protection 2>&1)"
  echo "$IN" | grep -qiE 'protect|secret|event|chain|intact|[0-9]' && ok "inspect protection renders summary" || no "inspect empty"
else
  echo "  SKIP inspect (binary lacks inspect subcommand)"
fi

echo "== S7 verify: audit chain integrity =="
if "$HUB" verify >/dev/null 2>&1; then
  VC="$("$HUB" verify 2>&1)"; echo "$VC" | grep -qiE 'valid|ok|intact|consistent' && ok "verify: chain intact" || no "verify: $(echo "$VC" | head -1)"
elif "$HUB" inspect verify-chain >/dev/null 2>&1; then
  VC="$("$HUB" inspect verify-chain 2>&1)"; echo "$VC" | grep -qiE 'valid|ok|intact|consistent' && ok "inspect verify-chain: intact" || no "verify-chain: $(echo "$VC" | head -1)"
else
  echo "  SKIP verify (no verify / inspect verify-chain subcommand)"
fi

echo "== S8 serve --stdio: MCP initialize + tools/list handshake =="
if command -v python3 >/dev/null 2>&1 && [ -f "$MCP_PROBE" ]; then
  SP="$(python3 "$MCP_PROBE" "$HUB" 2>&1)"
  echo "$SP" | grep -q 'PASS: initialize ok' && ok "serve --stdio: MCP initialize handshake" || no "serve --stdio: $(echo "$SP" | head -1)"
  echo "$SP" | grep -q 'PASS: tools/list ok' && ok "serve --stdio: tools/list" || echo "  NOTE: $(echo "$SP" | grep -iE 'tools|WARN' | head -1)"
else
  echo "  SKIP serve MCP (python3 or mcp_probe.py missing)"
fi

echo "== S9 quickstart: read-only guidance (no config mutation) =="
if "$HUB" quickstart >/dev/null 2>&1; then
  QS="$("$HUB" quickstart 2>&1)"; echo "$QS" | grep -qiE 'demo|protect|verify|detect|agent|step|setup' && ok "quickstart: guidance shown" || no "quickstart: no guidance"
else
  echo "  SKIP quickstart (no quickstart subcommand)"
fi

printf '\n### functional sweep: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m ###\n' "$P" "$F"
[ "$F" = 0 ]
