#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# agent-matrix.sh — 8-agent turnkey 功能矩阵(对已发布 vigil-hub,黑盒)。
#
# 对全部受支持 agent 面(Claude user+local / Codex TOML / Cursor / Windsurf /
# Kimi / pi / ZCode 嵌套键 + hook 注册面 Codex/Gemini/Cursor)验证完整生命周期:
#   检测(quickstart) → apply(wrap 形态/附加字段保留) → doctor --probe(网关真
#   spawn + MCP initialize 握手) → status 计数 → uninstall 逐字节还原。
#
# fixture-home 注入(HOME/XDG),绝不碰真实配置 — 仅 Unix(dirs-rs 在 Windows
# 读 KnownFolder 不理 env)。server 用内联 python3 最小 MCP stdio server(真握手)。
#
# 用法: HUB=/path/to/vigil-hub bash agent-matrix.sh
set -u
: "${HUB:?set HUB=path to vigil-hub}"
case "$(uname -s)" in Linux|Darwin) : ;; *) echo "unix only (fixture-home injection)"; exit 2;; esac

SBX="${TMPDIR:-/tmp}/vigil-matrix-$$"; rm -rf "$SBX"; mkdir -p "$SBX"
export HOME="$SBX" XDG_DATA_HOME="$SBX/.local/share" XDG_CONFIG_HOME="$SBX/.config"
export VIGIL_LEDGER_PATH="$SBX/ledger.sqlite3" VIGIL_LANG=en
trap 'rm -rf "$SBX"' EXIT

P=0; F=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; P=$((P+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; F=$((F+1)); }

# ── 内联最小 MCP stdio server(python3;真 initialize/tools-list 握手)────────
SRV="$SBX/mini_mcp.py"
cat > "$SRV" <<'PYEOF'
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: req = json.loads(line)
    except Exception: continue
    rid = req.get("id")
    m = req.get("method", "")
    if m == "initialize":
        r = {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":req.get("params",{}).get("protocolVersion","2025-03-26"),"capabilities":{"tools":{}},"serverInfo":{"name":"mini","version":"0"}}}
    elif m == "tools/list":
        r = {"jsonrpc":"2.0","id":rid,"result":{"tools":[{"name":"echo","description":"echo","inputSchema":{"type":"object"}}]}}
    elif rid is None:
        continue
    else:
        r = {"jsonrpc":"2.0","id":rid,"result":{}}
    sys.stdout.write(json.dumps(r)+"\n"); sys.stdout.flush()
PYEOF
PY="$(command -v python3 || command -v python)"

# ── 8 家 fixture 配置(+hook 检测目录)──────────────────────────────────────
mkdir -p "$SBX/.claude" "$SBX/.codex" "$SBX/.cursor" "$SBX/.gemini" \
         "$SBX/.codeium/windsurf" "$SBX/.kimi" "$SBX/.pi/agent" "$SBX/.zcode/cli"

cat > "$SBX/.claude.json" <<EOF
{"mcpServers":{"cl-user":{"command":"$PY","args":["$SRV"]}},
 "projects":{"/work/projA":{"mcpServers":{"cl-local":{"command":"$PY","args":["$SRV"]}}}}}
EOF
printf '{}' > "$SBX/.claude/settings.json"
cat > "$SBX/.codex/config.toml" <<EOF
[mcp_servers.cx]
command = "$PY"
args = ["$SRV"]
EOF
printf '{"mcpServers":{"cu":{"command":"%s","args":["%s"]}}}' "$PY" "$SRV" > "$SBX/.cursor/mcp.json"
printf '{"mcpServers":{"wf":{"command":"%s","args":["%s"]}}}' "$PY" "$SRV" > "$SBX/.codeium/windsurf/mcp_config.json"
printf '{"mcpServers":{"km":{"command":"%s","args":["%s"]}}}' "$PY" "$SRV" > "$SBX/.kimi/mcp.json"
printf '{"mcpServers":{"pi1":{"command":"%s","args":["%s"]}}}' "$PY" "$SRV" > "$SBX/.pi/agent/mcp.json"
# ZCode:嵌套 mcp.servers + GUI 附加字段 enabled(必须逐字保留)+ 其它设置键(不能被破坏)
cat > "$SBX/.zcode/cli/config.json" <<EOF
{"theme":"dark","mcp":{"servers":{"zc":{"command":"$PY","args":["$SRV"],"enabled":false}}}}
EOF

echo "### agent 矩阵 — $("$HUB" --version 2>&1 | head -1) ###"

# ── 1) 检测:quickstart 8 面全见 ───────────────────────────────────────────
QS="$("$HUB" quickstart 2>&1)"
for a in "Claude Code" "Codex" "ZCode" "Cursor" "Windsurf" "Kimi CLI" "pi"; do
  printf '%s' "$QS" | grep -q "$a" && ok "detect: $a in quickstart" || no "detect: $a MISSING in quickstart"
done
printf '%s' "$QS" | grep -q "8 MCP server" && ok "detect: 8 unprotected servers counted" \
  || { printf '%s' "$QS" | grep -qE "[0-9]+ MCP server" && no "detect: wrong count: $(printf '%s' "$QS" | grep -oE '[0-9]+ MCP servers? are NOT' | head -1)" || no "detect: no count line"; }

# ── 2) apply:setup --all(hook 面 + 全部 MCP 面)────────────────────────────
AP="$("$HUB" setup --all 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "setup --all exit 0" || no "setup --all exit=$RC: $(printf '%s' "$AP" | tail -2)"

grep -q '"command": *"'"$HUB"'"' "$SBX/.cursor/mcp.json" 2>/dev/null \
  || grep -q 'wrap' "$SBX/.cursor/mcp.json" && ok "cursor: wrapped" || no "cursor: not wrapped"
grep -q -- '--vigil-managed-mcp' "$SBX/.codeium/windsurf/mcp_config.json" && ok "windsurf: wrapped" || no "windsurf: not wrapped"
grep -q -- '--vigil-managed-mcp' "$SBX/.kimi/mcp.json" && ok "kimi: wrapped" || no "kimi: not wrapped"
grep -q 'kimi-km' "$SBX/.kimi/mcp.json" && ok "kimi: namespace kimi-" || no "kimi: namespace missing"
grep -q -- '--vigil-managed-mcp' "$SBX/.pi/agent/mcp.json" && ok "pi: wrapped" || no "pi: not wrapped"
grep -q 'pi-pi1' "$SBX/.pi/agent/mcp.json" && ok "pi: namespace pi-" || no "pi: namespace missing"
grep -q -- '--vigil-managed-mcp' "$SBX/.codex/config.toml" && ok "codex: wrapped (TOML)" || no "codex: not wrapped"
grep -q -- '--vigil-managed-mcp' "$SBX/.claude.json" && ok "claude: wrapped" || no "claude: not wrapped"
grep -q 'local-' "$SBX/.claude.json" && ok "claude: local-scope project id derived" || no "claude: local scope not wrapped"
grep -q -- '--vigil-managed-mcp' "$SBX/.zcode/cli/config.json" && ok "zcode: wrapped (nested key)" || no "zcode: not wrapped"
grep -q '"enabled": *false' "$SBX/.zcode/cli/config.json" && ok "zcode: GUI field 'enabled' preserved" || no "zcode: 'enabled' LOST"
grep -q '"theme": *"dark"' "$SBX/.zcode/cli/config.json" && ok "zcode: sibling settings preserved" || no "zcode: sibling settings LOST"
grep -q 'zcode-zc' "$SBX/.zcode/cli/config.json" && ok "zcode: namespace zcode-" || no "zcode: namespace missing"

# hook 注册面(检测到目录才注册)
grep -q -- '--vigil-managed' "$SBX/.codex/hooks.json" 2>/dev/null && ok "codex hooks.json registered" || no "codex hooks.json missing"
grep -q -- '--vigil-managed' "$SBX/.gemini/settings.json" 2>/dev/null && ok "gemini hooks registered" || no "gemini hooks missing"
grep -q '"failClosed": *true' "$SBX/.cursor/hooks.json" 2>/dev/null && ok "cursor hooks failClosed:true" || no "cursor hooks missing/not failClosed"
grep -q -- '--vigil-managed' "$SBX/.claude/settings.json" 2>/dev/null && ok "claude settings.json hook registered" || no "claude hook missing"

# ── 3) doctor --probe:每个 wrap 后的 server 网关真 spawn + initialize ─────
DOC="$("$HUB" setup --mcp --doctor --probe 2>&1)"; RC=$?
NPROBE="$(printf '%s' "$DOC" | grep -c 'initialized OK' || true)"
if [ "$RC" = 0 ] && [ "$NPROBE" -ge 8 ]; then ok "doctor --probe: $NPROBE/8+ servers spawn+handshake OK"
else no "doctor --probe rc=$RC handshakes=$NPROBE"; printf '%s\n' "$DOC" | tail -12; fi

# ── 4) status:逐 agent 计数 ───────────────────────────────────────────────
ST="$("$HUB" setup --status 2>&1)"
printf '%s' "$ST" | grep -q '8 server(s) wrapped' && ok "status: 8 servers wrapped total"   || no "status: total wrong: $(printf '%s' "$ST" | grep 'MCP gateway' | head -1)"
for a in "Claude Code" "Codex" "ZCode" "Cursor" "Windsurf" "Kimi" "pi"; do
  printf '%s' "$ST" | grep -q "$a" && ok "status detail: $a present" || no "status detail: $a missing"
done

# ── 5) uninstall:语义等价还原 ─────────────────────────────────────────────
# 产品契约 = 语义等价可运行还原(JSON 写盘走 pretty-print,字节形态可变;Codex TOML 经
# toml_edit 保格式,应逐字节)。断言:全部面零 wrap 残留 + JSON 解析后对象级等于原 fixture。
UN="$("$HUB" setup --all --uninstall 2>&1)"; RC=$?
[ "$RC" = 0 ] && ok "uninstall exit 0" || no "uninstall exit=$RC"
RESIDUE=0
for f in "$SBX/.claude.json" "$SBX/.codex/config.toml" "$SBX/.cursor/mcp.json" \
         "$SBX/.codeium/windsurf/mcp_config.json" "$SBX/.kimi/mcp.json" \
         "$SBX/.pi/agent/mcp.json" "$SBX/.zcode/cli/config.json"; do
  grep -q -- '--vigil-managed' "$f" && { no "restore: residue in $(basename "$f")"; RESIDUE=1; }
done
[ "$RESIDUE" = 0 ] && ok "restore: zero vigil residue across all 7 configs"
if "$PY" - "$SBX" "$PY" "$SRV" <<'PYCHK'
import json, sys
sbx, py, srv = sys.argv[1], sys.argv[2], sys.argv[3]
e = {"command": py, "args": [srv]}
expect = {
  f"{sbx}/.claude.json": {"mcpServers": {"cl-user": dict(e)},
      "projects": {"/work/projA": {"mcpServers": {"cl-local": dict(e)}}}},
  f"{sbx}/.cursor/mcp.json": {"mcpServers": {"cu": dict(e)}},
  f"{sbx}/.codeium/windsurf/mcp_config.json": {"mcpServers": {"wf": dict(e)}},
  f"{sbx}/.kimi/mcp.json": {"mcpServers": {"km": dict(e)}},
  f"{sbx}/.pi/agent/mcp.json": {"mcpServers": {"pi1": dict(e)}},
  f"{sbx}/.zcode/cli/config.json": {"theme": "dark",
      "mcp": {"servers": {"zc": {**e, "enabled": False}}}},
}
bad = 0
for path, want in expect.items():
    got = json.load(open(path))
    if got != want:
        bad += 1
        print(f"  SEMANTIC-DIVERGE {path}: {json.dumps(got)[:160]}")
sys.exit(1 if bad else 0)
PYCHK
then ok "restore: all 6 JSON surfaces semantically identical to fixtures"
else no "restore: semantic divergence (see above)"; fi
printf '[mcp_servers.cx]\ncommand = "%s"\nargs = ["%s"]\n' "$PY" "$SRV" > "$SBX/toml.expect"
cmp -s "$SBX/.codex/config.toml" "$SBX/toml.expect" \
  && ok "restore: codex TOML byte-identical" || no "restore: codex TOML diverged"

echo
echo "### result: $P passed, $F failed (agent-matrix) ###"
[ "$F" = 0 ]
