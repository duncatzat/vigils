# 契约金丝雀(P0-2)—— 真 agent 每日真跑

> 目的:**厂商改了 hook 契约,这里先红。** 以前的验收只把冻结的合成事件喂给 `vigil-hub hook`,Claude Code / Codex
> 自己改了事件形状、信任模型或 headless 行为时 CI 不会变红(再评估 §4 A2)。金丝雀每天真装**最新版** agent,用
> GLM(智谱)当模型,在沙箱 HOME 里注册 Vigil hook,跑几条带**合成 secret** 的任务,**以账本事件(含触发规则)为准**断言。

## 跑什么

| 场景 | 动作 | 断言(账本事件 + 副作用) |
|---|---|---|
| S0 接线 | `vigil-hub setup` 后检查配置 | Claude `settings.json` 三事件在(精确拼写);Codex `hooks.json` 三事件在 **且** `setup --status --json` 如实报 `pending_trust`(Vigil 绝不替用户伪造 codex trust) |
| SX 模型可达 | `Reply with exactly one word: pong` | 模型真的答了(Claude 看 `num_turns`/`usage`)。答不了 → **退出码 3(环境红)**,后面不再跑,免得把 401/429 伪装成契约漂移 |
| S1 prompt 守门 | 把裸 `ghp_` token 贴进 prompt | `hook.userpromptsubmit.blocked` 且 payload `finding=github_token` +1;Claude 侧无模型往返(被挡的 prompt Claude 会回显在输出里,所以不用「输出不含 token」断言);Codex 侧输出不含裸 token |
| S2 工具侧拦截 | prompt 里把 `AKIA` 与后 16 位(AWS 文档公开示例)**分开**给,让模型拼成 20 位写进文件 | `hook.pretooluse.denied` 且 `finding=aws_access_key_id` +1;文件里没有 AKIA key |
| S3 结果脱敏 | 文件里埋 token,让 agent 读回 | `hook.posttooluse.redacted` 且 `hard_hits` 含 `github_token` +1;输出不含裸 token。Codex 走 `decision:block` + 脱敏文本 |
| S4 不误杀 | `echo hello-canary > ok.txt` | 文件存在;denied 计数不变。Vigil 设计上不记录 allow 事件,所以 S4 只有与 S2 同跑才有意义(S2 证明 hook 在跑) |

S2 的 prompt 里前缀与后 16 位不连续(不触发 prompt 守门),模型拼接后 PreToolUse 才看到合法形状的 key —— deny 路径是被**真 agent**走到的,且不再依赖模型「自己编」(编错位数 / 程序生成会让 Vigil 合法地不拦,曾造成两次假红)。
所有「+1」都是同一沙箱账本里按 `event_type` + `payload_json` 规则名过滤后的前后差:不是「任意 deny 都算数」。

## 怎么跑

```bash
# Linux / macOS;需要 node >= 22(node:sqlite)、npm、curl、tar、git、timeout(macOS:brew install coreutils 提供 gtimeout)
GLM_API_KEY=... bash tests/canary/run.sh
```

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `GLM_API_KEY` | 必填 | 智谱 GLM Coding Plan key。缺失 → 退出码 3,**绝不静默 skip**;开跑前先用一次最小调用探针验证 key / 网络 |
| `CANARY_AGENTS` | `claude,codex` | 跑哪些 agent |
| `CANARY_MODEL` | `glm-5.3` | Claude Code 与 Codex 共用的模型 id |
| `GLM_ANTHROPIC_BASE` | `https://open.bigmodel.cn/api/anthropic` | Claude Code 用的 Anthropic 兼容端点(国际版 `https://api.z.ai/api/anthropic`) |
| `GLM_OPENAI_BASE` | `https://open.bigmodel.cn/api/v1` | Codex 用的 Responses 端点(国际版 `https://api.z.ai/api/v1`) |
| `VIGIL_HUB_BIN` / `VIGIL_TAG` | — / `latest` | 指定二进制;否则从 GitHub release 下载发货物 |
| `CANARY_PIN_CLAUDE` / `CANARY_PIN_CODEX` | `latest` | npm 版本钉(排障用;金丝雀本意就是 latest) |
| `CANARY_NPM_REGISTRY` | npmjs,失败自动退到 npmmirror | npm 源 |
| `CANARY_KEEP=1` / `CANARY_OUT` / `CANARY_TMP` | 删 / `./canary-out` / `$PWD` | 保留沙箱排障 / 报告目录 / 沙箱根(开跑前会清掉上一轮残留) |

退出码:`0` 全绿;`1` 有 FAIL(产品或厂商契约红);`3` 前置条件、安装或模型传输 / 鉴权失败(环境红,别误读成产品红)。
有 FAIL 时日志末尾会打印每场景 agent 的末消息与 stderr(合成 secret 与 GLM key 已遮蔽);报告 JSON 只有计数与结果行。

## 为什么是 GLM

真 agent 必须能调模型才会产生工具调用。GLM Coding Plan 是包月订阅,每日几次调用不计成本;Claude Code 走
`ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`,Codex 走 `model_providers` + `wire_api = "responses"` + `models.json`
(`glm-models.json` 与智谱文档一致)。**key 不落盘**:Claude 走 env,Codex 走 `env_key`;沙箱结束即删。

## CI

- `.github/workflows/canary.yml`:`workflow_dispatch`(输入 `target=head|release`、`vigil_tag`、`agents`);`head` 从源码构建
  当前 checkout 的 vigil-hub → 红 = 厂商漂移或我们的回归;`release` 用 GitHub release 发货物 → 红 = 用户手里的版本已被打穿
  (或修复未发版)。
- 定时触发(每日 head / 每周 release)在仓库加了 secret `GLM_API_KEY` 后再打开:金丝雀缺 key 是**退出码 3 的响亮失败**而不是
  静默 skip,没 secret 就开 schedule 只会天天红。

## 已知边界(诚实说明)

- **Codex trust hash 的规范化不在覆盖内**:headless 用官方 `--dangerously-bypass-hook-trust`,所以 codex 改 trusted-hash
  算法时金丝雀不会红(该算法由 `setup_hooks.rs` 单测里的真机样本向量守着)。Vigil 不替用户写 trust,也不在测试里伪造。
- **宿主项目的指令文件不能漏进金丝雀**:沙箱 `work/` 自成 git 仓,Codex 只会读到它自己的(空)项目根,不会继承
  金丝雀所在 checkout 的 `AGENTS.md`(gitea CI 首跑实证:Vigil 仓自己的 AGENTS.md 让 GLM 拒绝 S3 读文件 → 假红)。
  Claude Code 的 `CLAUDE.md` 按祖先目录发现,不受 `.git` 边界限制:宿主仓若有禁止此类操作的 CLAUDE.md,把 `CANARY_TMP`
  指到仓外。S3 的 prompt 明说文件里是合成占位 token,减少模型自行拒绝;模型仍拒绝时是需要人看的 S3 红,不用 SKIP 掩盖。
- 只覆盖 Claude Code 与 Codex(首月 Tier 1);Cursor / Copilot CLI 的端点覆盖能力待核实后再加。
- 模型行为不是断言对象:模型拒绝执行(例如不肯写 AWS key)或用程序生成 key 会表现为 S2 红 —— 那也是需要人看的信号,
  不用 SKIP 掩盖;必要时换 prompt 或换模型,不放松账本断言。
- Windows 不支持 HOME 沙箱(`dirs::home_dir` 不读 `HOME`),故金丝雀只在 Linux / macOS 跑;Windows 的 codex
  引号 / trust 问题由 `apps/vigil-hub-cli` 单测与发版真机验收覆盖。
