#!/usr/bin/env bash
# run.sh — 契约金丝雀(P0-2,再评估 §6.1):每天真装**最新版** Claude Code / Codex,用 GLM(智谱)当模型,
# 对着已注册 Vigil hook 的沙箱 HOME 真跑几条带合成 secret 的任务,断言拦截 / 脱敏 / 不误杀 —— 全部以
# 账本事件(含触发规则)为准。厂商改 hook 契约 → 这里先红。
#
# 用法(Linux / macOS;需要 node ≥ 22、npm、curl、tar、timeout 或 gtimeout):
#   GLM_API_KEY=... bash tests/canary/run.sh
# 可选环境:
#   CANARY_AGENTS=claude,codex     跑哪些 agent(默认两者)
#   CANARY_MODEL=glm-5.3           GLM 模型 id(Claude Code 与 Codex 共用)
#   GLM_ANTHROPIC_BASE / GLM_OPENAI_BASE   端点(默认智谱国内:/api/anthropic 与 /api/v1)
#   VIGIL_HUB_BIN=/path/vigil-hub  用指定二进制;否则 VIGIL_TAG(默认 latest)从 GitHub release 下载
#   CANARY_PIN_CLAUDE / CANARY_PIN_CODEX   npm 版本钉(默认 latest = 金丝雀本意)
#   CANARY_NPM_REGISTRY            npm 源(国内可用 https://registry.npmmirror.com)
#   CANARY_KEEP=1                  保留沙箱目录排障;CANARY_OUT=<dir> 报告目录;CANARY_TMP=<dir> 沙箱根
# 退出码:0 全绿;1 有 FAIL(产品 / 厂商契约红);3 前置条件、安装或模型传输失败(环境红,别误读成产品红)。
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/lib.sh"

# ── 0. 前置(fail loudly,绝不静默 skip)──────────────────────────────────────────────
[ -n "${GLM_API_KEY:-}" ] || die "GLM_API_KEY is not set (CI: add it as a repository secret; the canary must not silently skip)"
case "$(uname -s)" in Linux|Darwin) ;; *) die "Linux/macOS only: HOME sandboxing does not work on Windows (dirs::home_dir ignores HOME)";; esac
for t in node npm curl tar git; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"; done
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout)" || die "missing tool: timeout (macOS: brew install coreutils)"
export TIMEOUT_BIN
NODE_MAJOR=$(node -v | sed 's/^v//' | cut -d. -f1); [ "$NODE_MAJOR" -ge 22 ] || die "node >= 22 required for node:sqlite (have $(node -v))"

CANARY_AGENTS="${CANARY_AGENTS:-claude,codex}"
CANARY_MODEL="${CANARY_MODEL:-glm-5.3}"
GLM_ANTHROPIC_BASE="${GLM_ANTHROPIC_BASE:-https://open.bigmodel.cn/api/anthropic}"
GLM_OPENAI_BASE="${GLM_OPENAI_BASE:-https://open.bigmodel.cn/api/v1}"
VIGIL_TAG="${VIGIL_TAG:-latest}"
VIGIL_REPO="${VIGIL_REPO:-duncatzat/vigils}"
CANARY_TMP="${CANARY_TMP:-$PWD}"
CANARY_OUT="${CANARY_OUT:-$PWD/canary-out}"
# 报告目录与上一轮残留沙箱(SIGKILL 会跳过 EXIT trap)在开跑前清掉:自托管 runner 上不留 agent 原文。
rm -rf "$CANARY_OUT"; mkdir -p "$CANARY_OUT"
for d in "$CANARY_TMP"/vigil-canary.*; do [ -d "$d" ] && rm -rf "$d"; done

# 模型可达性探针:一次最小 messages 调用。401/403/429/网络不通 → 环境红(3),不会伪装成契约漂移。
probe_code=$(curl -s -o "$CANARY_OUT/glm-probe.json" -w "%{http_code}" --max-time 60 "$GLM_ANTHROPIC_BASE/v1/messages" \
  -H "x-api-key: $GLM_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d "{\"model\":\"$CANARY_MODEL\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK\"}]}")
[ "$probe_code" = 200 ] || die "GLM probe failed: HTTP $probe_code from $GLM_ANTHROPIC_BASE (key/quota/network) — environment, not a hook signal"
rm -f "$CANARY_OUT/glm-probe.json"

# ── 1. 沙箱 HOME(一切 agent / vigil 状态都在这里,结束即删)──────────────────────────
# 沙箱根不用 /tmp:codex 拒绝在临时目录下建 PATH helper(只警告,但避免噪声);CI 用工作区,本机用 $PWD
SBX="$(mktemp -d "$CANARY_TMP/vigil-canary.XXXXXX")"
[ -n "$SBX" ] && [ -d "$SBX" ] || die "mktemp failed under $CANARY_TMP"
cleanup(){ if [ "${CANARY_KEEP:-0}" = 1 ]; then echo "canary: sandbox kept at $SBX"; else rm -rf "$SBX"; fi; }
trap cleanup EXIT
export HOME="$SBX" XDG_DATA_HOME="$SBX/.local/share" XDG_CONFIG_HOME="$SBX/.config" XDG_CACHE_HOME="$SBX/.cache"
export CODEX_HOME="$SBX/.codex"; mkdir -p "$CODEX_HOME" "$SBX/work" "$SBX/npm"
export W="$SBX/work" LEDGER="$SBX/ledger.sqlite3" VIGIL_LANG=en
# work 目录自成 git 仓:agent 的项目指令文件(Codex AGENTS.md)按「最近的 .git 根 → cwd」发现,否则金丝雀跑在
# 宿主项目 checkout 里时会继承宿主的 AGENTS.md(gitea CI 实证:Vigil 自己的 AGENTS.md「secrets 绝不进
# prompt/log/tests」让 GLM 拒绝 S3 读文件 → 假红)。Claude Code 的 CLAUDE.md 仍按祖先目录发现,见 README。
git init -q "$W" || die "git init work dir failed"
export PATH="$SBX/npm/bin:$PATH"
[ "$(id -u)" = 0 ] && export IS_SANDBOX=1   # Claude Code 拒绝 root 用 --dangerously-skip-permissions,除非声明沙箱
echo "canary: sandbox=$SBX agents=$CANARY_AGENTS model=$CANARY_MODEL"

# ── 2. 真装最新 agent(npm --prefix 进沙箱,不碰全局)──────────────────────────────────
PKGS=""
case ",$CANARY_AGENTS," in *,claude,*) PKGS="$PKGS @anthropic-ai/claude-code@${CANARY_PIN_CLAUDE:-latest}";; esac
case ",$CANARY_AGENTS," in *,codex,*)  PKGS="$PKGS @openai/codex@${CANARY_PIN_CODEX:-latest}";; esac
npm_install(){ npm i -g --prefix "$SBX/npm" --no-fund --no-audit --loglevel=error ${CANARY_NPM_REGISTRY:+--registry "$CANARY_NPM_REGISTRY"} $PKGS; }
echo "canary: npm install$PKGS"
npm_install || { echo "canary: npm install failed; retrying via registry.npmmirror.com"; CANARY_NPM_REGISTRY=https://registry.npmmirror.com npm_install || die "npm install of agent CLIs failed"; }
CLAUDE_VERSION="n/a"; CODEX_VERSION="n/a"
case ",$CANARY_AGENTS," in *,claude,*) CLAUDE_VERSION="$(claude --version 2>/dev/null | head -1)"; [ -n "$CLAUDE_VERSION" ] || die "claude not runnable after install";; esac
case ",$CANARY_AGENTS," in *,codex,*)  CODEX_VERSION="$(codex --version 2>/dev/null | head -1)";  [ -n "$CODEX_VERSION" ]  || die "codex not runnable after install";; esac
echo "canary: claude=$CLAUDE_VERSION codex=$CODEX_VERSION"

# ── 3. vigil-hub:指定二进制,或从 GitHub release 下载(= 用户拿到的发货物)──────────────
if [ -z "${VIGIL_HUB_BIN:-}" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) ASSET=vigils-cli-linux-x64.tar.gz;; Linux-aarch64) ASSET=vigils-cli-linux-arm64.tar.gz;;
    Darwin-arm64) ASSET=vigils-cli-macos-arm64.tar.gz;; Darwin-x86_64) ASSET=vigils-cli-macos-x64.tar.gz;;
    *) die "no release asset mapping for $(uname -s)-$(uname -m); pass VIGIL_HUB_BIN";;
  esac
  if [ "$VIGIL_TAG" = latest ]; then URL="https://github.com/$VIGIL_REPO/releases/latest/download/$ASSET"; else URL="https://github.com/$VIGIL_REPO/releases/download/$VIGIL_TAG/$ASSET"; fi
  echo "canary: downloading $URL"
  curl -fsSL --retry 3 --max-time 300 -o "$SBX/cli.tgz" "$URL" || die "download failed: $URL"
  mkdir -p "$SBX/vigil" && tar -xzf "$SBX/cli.tgz" -C "$SBX/vigil" || die "untar failed"
  VIGIL_HUB_BIN="$(find "$SBX/vigil" -type f -name vigil-hub | head -1)"; [ -n "$VIGIL_HUB_BIN" ] || die "vigil-hub not found in $ASSET"
  chmod +x "$VIGIL_HUB_BIN"
fi
export VIGIL_HUB_BIN
VIGIL_HUB_VERSION="$("$VIGIL_HUB_BIN" --version 2>/dev/null | head -1)"; [ -n "$VIGIL_HUB_VERSION" ] || die "vigil-hub not runnable: $VIGIL_HUB_BIN"
export PATH="$(dirname "$VIGIL_HUB_BIN"):$PATH"
echo "canary: $VIGIL_HUB_VERSION"

# ── 4. 把 agent 指向 GLM(不写任何 key 到磁盘:Claude 走 env,Codex 走 env_key)────────────
export ANTHROPIC_BASE_URL="$GLM_ANTHROPIC_BASE" ANTHROPIC_AUTH_TOKEN="$GLM_API_KEY"
export ANTHROPIC_MODEL="$CANARY_MODEL" ANTHROPIC_DEFAULT_OPUS_MODEL="$CANARY_MODEL" ANTHROPIC_DEFAULT_SONNET_MODEL="$CANARY_MODEL" ANTHROPIC_DEFAULT_HAIKU_MODEL="$CANARY_MODEL" ANTHROPIC_SMALL_FAST_MODEL="$CANARY_MODEL"
export API_TIMEOUT_MS=600000 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1
printf '{"hasCompletedOnboarding":true}\n' > "$HOME/.claude.json"     # 跳过首跑向导
{
  echo 'model_provider = "ZAI"'
  echo "model = \"$CANARY_MODEL\""
  echo 'model_reasoning_effort = "low"'
  echo "model_catalog_json = \"$CODEX_HOME/models.json\""
  echo 'approval_policy = "never"'
  echo 'sandbox_mode = "danger-full-access"'
  echo
  echo '[model_providers.ZAI]'
  echo 'name = "ZAI"'
  echo "base_url = \"$GLM_OPENAI_BASE\""
  echo 'env_key = "GLM_API_KEY"'
  echo 'wire_api = "responses"'
} > "$CODEX_HOME/config.toml"
cp "$HERE/glm-models.json" "$CODEX_HOME/models.json"

# ── 5. 注册 Vigil hook(与用户同一条命令)+ 状态记录────────────────────────────────────
echo "canary: vigil-hub setup"
"$VIGIL_HUB_BIN" setup --ledger "$LEDGER" >"$CANARY_OUT/setup.txt" 2>&1 || { cat "$CANARY_OUT/setup.txt"; die "vigil-hub setup failed"; }
"$VIGIL_HUB_BIN" setup --status --json >"$CANARY_OUT/setup-status.json" 2>/dev/null || true

# ── 6. 场景────────────────────────────────────────────────────────────────────────
export CANARY_MODEL VIGIL_HUB_VERSION CLAUDE_VERSION CODEX_VERSION
case ",$CANARY_AGENTS," in *,claude,*) source "$HERE/scenarios/claude.sh";; esac
case ",$CANARY_AGENTS," in *,codex,*)  source "$HERE/scenarios/codex.sh";;  esac

# ── 7. 报告(不含 secret / 输出原文;agent 原始输出留在沙箱,CANARY_KEEP=1 时可查)────────
write_report "$CANARY_OUT/canary-report.json"
echo "canary: report -> $CANARY_OUT/canary-report.json"
summary; rc=$?
# 有 FAIL 才把每场景的 agent 末消息 / stderr 打进日志(排障用),合成 secret 与 GLM key 先遮蔽。
if [ "$rc" -ne 0 ]; then
  for f in "$W"/*-S[0-9X]-last.txt "$W"/*-S[0-9X].json "$W"/*-S[0-9X]-stderr.txt; do
    [ -s "$f" ] || continue
    echo "----- $(basename "$f") (masked, first 1200 bytes) -----"
    head -c 1200 "$f" | mask_secrets; echo
  done
fi
exit "$rc"
