# ADR 0025 — 出站 LLM-API 闸门(opt-in 环回代理 + 请求体硬指纹脱敏)

- 状态:**Accepted(实施同批定稿)**(2026-09-12)
- 日期:2026-09-12
- 依赖:ADR 0013(硬指纹 × 模型 merge)/ ADR 0022(引擎选择)/ ADR 0024(常驻 daemon 生命周期)
- 驱动:用户决策(2026-09-12)——「像 maskit 一样代理客户端的 LLM 请求,作为**可选开启**的功能做上去」;
  竞品对照见 `project-vigil-maskit-research-2026-09-12`
- 相关结论:`docs/user-guide/README.md` 早已把「出站代理」写为**路线图**(「当前版本尚未提供」);本 ADR 落地
  其**第一条腿**,并把那句话按实际范围如实改写

## 0. 摘要(TL;DR)

Vigil 既有两条腿都在**入口**:hook 看 agent 的工具调用,MCP 网关看工具结果。两者对下列进入模型上下文的内容
**结构性看不见**:`@文件` 直接内联(不走 Read 工具)、`CLAUDE.md` / `AGENTS.md` 记忆文件、压缩摘要、模型自己
复述出来的凭据。叠加 Claude Code 的上下文是 **append-only**——密钥一旦进去,该会话此后**每一次**模型调用都
带着它——入口拦截对已进入的内容无能为力。

本 ADR 引入**第三条腿**:`vigil-outbound`,一个**可选开启**的环回 HTTP 反向代理。agent 经自身配置指向它,
每个出站模型请求体在离开本机前逐叶子扫**同一套硬指纹**并就地替换命中段;响应**按块直通**。

**一句话不变量**:闸门**只脱不还原、只改请求不碰响应、只认硬指纹、看不懂就拒绝**。它不持有任何明文映射表,
不解析 SSE,不做 allow/deny 语义决策——脱敏规则的唯一真源仍是 `vigil-redaction`,闸门只是它的第三个消费者。

## 1. 背景与问题

| 事实(已核验) | 出处 | 影响 |
|---|---|---|
| hook 只在 `PreToolUse` / `PostToolUse` / `UserPromptSubmit` 三事件触发 | `setup.rs` 注册面 | `@文件` 内联、记忆文件、压缩摘要都不经过任何 hook 事件 |
| Claude Code 上下文 append-only,进去的内容每次调用重发 | anthropics/claude-code#29434(2026-02 开,至今未关) | 入口漏一次 = 整个会话持续外发 |
| 官方只对特定 token 家族做定点脱敏,无通用上下文脱敏 | Claude Code changelog(GitLab token 家族) | 不能指望宿主兜底 |
| 社区实测 `@.env` 内联**绕过所有 hook** | cc-redact README 明确记载 | 该盲区是真实且已被第三方独立发现 |
| Claude Code 认 `ANTHROPIC_BASE_URL`;订阅 OAuth 可透传 | 官方 env-vars 文档 + 多家网关(LiteLLM / Tailscale Aperture / Vercel)一致做法 | 代理接入无需改 agent 源码 |
| Claude Code 在非一方 base URL 下**默认关闭** MCP tool search | 官方 env-vars 文档(`ENABLE_TOOL_SEARCH`) | 不显式开回来 = 用户上下文暴涨,体验回归 |
| Codex `wire_api = "chat"` 已于 2026-02 移除,只剩 `responses` | openai/codex + OpenRouter 迁移说明 | provider 块必须写 `responses` |
| Codex ChatGPT 登录走 `chatgpt.com/backend-api/codex`,须原样转 `ChatGPT-Account-ID` | Tailscale Aperture passthrough 文档 + headroom#773 | 单一上游写死会打断订阅用户 |
| 工作区已有 hyper 1 / hyper-util / http-body-util / reqwest(rustls)/ tokio | 根 `Cargo.toml` workspace deps | 闸门零新增第三方依赖 |
| daemon 是同步线程模型,传输仅 UDS / 命名管道,**无任何 TCP 监听** | `daemon/server.rs`、ADR 0024 D5 | 闸门必须自带运行时,且不得污染 daemon 的传输姿态 |

**为什么不直接抄 maskit**:那类代理做**可逆** PII 脱敏,必须持明文映射表落盘、必须解析 SSE 逐通道缓冲还原
(其引擎约 18k 行、604 测试、变更日志里十余条流式踩坑)。Vigil 的账本无明文是铁律,且我们要保护的是**凭据**——
凭据恰恰是**不需要还原**的那一类(模型不需要真值;真值由既有执行边界脱别名注入)。取舍点就在这里分岔。

## 2. 核心决策

| # | 决策 | 理由 |
|---|---|---|
| **D1** | 新增 crate `vigil-outbound`(环回 HTTP/1.1 反代),默认 `127.0.0.1:8445`;**默认关闭**,`vigil-hub outbound on\|off\|status\|serve` 控制 | 第三条腿补的是入口看不见的面;opt-in 因为它要改用户的 agent 配置、且引入一个新监听面 |
| **D2** | **只脱不还原**:命中换 `[REDACTED <kind>]`(与 hook PostToolUse 同形),**响应不扫不改**,本机**不存**任何明文映射 | 与可逆脱敏代理的本质分岔(见 §1 末)。不还原 ⇒ 不必解析 SSE ⇒ 无跨 chunk 缓冲、无通道错位类 bug;账本无明文铁律不破 |
| **D3** | **只认硬指纹,且复用同一套规则**:新公开 API `vigil_redaction::hard_secret_spans` 给出与 `scrub_text` **同口径**的命中区间 | 规则 SSOT 只能有一份。给区间而非脱敏串,是因为出站改写需要知道「哪段字节是凭据」才能就地替换 / 未来换别名;语义 PII 属 ML 引擎领域,不在此层 |
| **D4** | **看不懂的请求体一律拒绝,绝不放行假装看过**:非 JSON 415、压缩体拒、超 64 MiB 413、未知路径前缀 404、带 `Origin` 403 | 这是 fail-closed 的具体化。放行未检查的体等于本功能不存在却让用户以为存在——比不做更糟 |
| **D5** | **响应按块直通**,不缓冲、不解析、不改写;用 `Response::chunk()` 而非 `bytes_stream()` | 流式手感必须与直连一致(网关模板的硬约束:绝不等生成完再转)。不用 `stream` feature 是因为它拉进 wasm32-only 的 wasm-streams 并触碰 `deny.toml` 的 reqwest feature 白名单 |
| **D6** | **不是开放代理**:上游是**固定集合**(4 条路径前缀 → 4 个可配上游根),监听地址**强制环回**,accept 循环二次校验 peer 为环回 | 闸门透传用户的 API 凭据。任意转发 = SSRF 跳板;非环回监听 = 把凭据挂到局域网 |
| **D7** | **改 agent 配置复用 `setup` 的同一段写盘核心**(备份 `.vigil-bak` + 原子替换 + TOCTOU stamp + abort-on-unexpected-shape),**只动自己写的键**;`off` 只在值仍是闸门地址时还原 | 用户配置是用户的。这段逻辑安全敏感且已被 setup 面反复评审过,重造必然退化 |
| **D8** | 用户既有的自家网关(LiteLLM / Portkey …)**串接而非覆盖**:记住原 `ANTHROPIC_BASE_URL` 当 anthropic 上游,`off` 时还原 | 抢掉企业用户的网关 = 直接不可用。串接让两者叠加(闸门管凭据,网关管路由 / 配额) |
| **D9** | **闸门随 daemon 运行**(ADR 0024 的进程),独立线程内跑自带 tokio 运行时;daemon 未运行时指向它的 agent **fail-closed** | 复用既有常驻进程,不新增生命周期面;不污染 daemon 的同步线程模型与 UDS-only 传输姿态。fail-closed 而非绕过:安全功能宁可显眼地坏掉,也不要静默地不生效 |
| **D10** | **不支持的模式显式拒绝开启**,不静默假装保护:Bedrock / Vertex / Foundry(不走 base URL,Bedrock 还对整个请求体签名)、Codex 已配自定义 `model_provider` | 「装了但没生效」是最坏的一种安全产品状态 |
| **D11** | **协议信封字段不改写**:`id` / `*_id` / `model` / `role` / `signature` / `encrypted_content` / `thinking` 等键的字符串值,以及内联二进制载荷 | 改它们要么破协议(签名、加密推理块、工具调用关联 id),要么纯属白烧 CPU |
| **D12** | 审计只记**路由 + 规则名 + 计数 + 别名**,绝无原文;鉴权头永不进任何日志 | 账本 `append_event` 的硬指纹自检本就会拒含凭据的 payload;主动不写是第一道,自检是第二道 |
| **D13** | 预留别名扩展点 `AliasSink`(默认 `NoAlias`),**本轮不 commit 可逆语义** | 未来若要 `secret://<alias>` + 执行边界脱别名,接口已在;但现在不为未来过度设计(YAGNI) |

## 3. 边界(诚实声明,文档与 `status` 同口径)

- **只管模型 API 这条腿**。agent 用工具访问别的主机(curl / git push / MCP server)不经闸门——那是 hook 与网关的领域。
- **只认硬指纹**。语义 PII 不在此层;刻意用 hex / 字符码 / 跨多次调用分段外泄的内容,闸门同样看不出(base64 载荷**能**命中)。
- **出站字节自检不是「独立的第二套检测器」**(敌意评审 2026-09-12)。它跑的是同一个
  `detect_hard_secret`,因此**继承同一批盲区**:base64 段预算(256 段)可被非凭据的 base64 字母表
  长串吃干、**只解一层**(`base64(base64(secret))` 照过)、**只认解码后是 UTF-8 文本**的载荷
  (DER 私钥、原始 32 字节 key 永不命中)。它真正兜住的是「**改写结果与上行字节不一致**」那一类
  (重复 JSON 键、按键名跳过的信封字段、占位符剥离口径差),**不能**当作覆盖面的证明。
- **响应不扫**。模型复述的内容原样回到用户终端(本就在本机)。
- **Gemini CLI 未接线**:API key 模式可走 `GOOGLE_GEMINI_BASE_URL`,但 Google 登录走 `cloudcode-pa` 另一端点,留下一批。
- **Codex 的 backend 路由(压缩 / 记忆等)不经闸门**:Codex 把那条路留给内置 `OpenAI` provider(且 URL
  以 `/backend-api/codex` 结尾),自定义 provider 名不匹配即拿不到;**采样请求**(真正携带上下文者)仍经闸门。
  `requires_openai_auth = true` 覆盖「经 `codex login` 认证」的用户(订阅或 API key 登录),裸
  `OPENAI_API_KEY` 环境变量不会被静默使用。以上经 Grok Build 联网检索 Codex 源码与 issue 核实
  (`url_for_path` 拼接确认 `base_url` 结尾 `/codex` → `POST /codex/responses`,与本闸门路由前缀吻合)。
- **云端 / 远程会话看不到**:流量不在本机。
- 与既有诚实边界(GitSpawn 启动期 git 调用、Codex Guardian 审查期、hook exit 1 放行)并列,进 P0-5 边界文档。

## 4. 验证

- 引擎单测 **24**(rewrite 的真实 Anthropic Messages / OpenAI Responses / Gemini 体形 + 信封不碰 + base64 整段 + 键名不改 + **凭据键名下的值整段替换而泛后缀游标不动** + **三种「媒体外衣」伪装(自称 `image/png` 的明文 `data`、两条件不相邻的伪 `data:` URI、合法 `data:` URI 里解出凭据的 base64)一律被抓住,而真 PNG 不被误伤**;route 的前缀 / query 保留 / Codex 按鉴权头选上游 / 上游覆盖 / **缺字段的 upstreams 补内置默认**;**越界或非 char 边界的区间让整次改写 fail-closed**;**残留定位只回结构不回内容** —— 凭据被拿来当键名时路径渲染成 `<field>`,且该判定**直接问规则表**而非靠长度余量;**定位超检查预算即放弃**而不是无限付费;**巨大的工具 schema 排在 `messages` 前面也不会饿死定位**(两趟:信封跳过集优先且不设预算);**单个超大叶子只跳过它自己、不中止整次搜索**;**宽 body 只渲染胜出路径**;**信封那一趟同样受预算约束** —— 大量 `*_id` 叶子撑不出无上限全扫)。
- e2e **10**(真 TCP + 真 HTTP/1.1 + mock 上游记录收到的字节):改写后上行、鉴权头逐字节透传、**SSE 按块到达**(断言收到 ≥ 2 块,证明未整包缓冲)、无命中时**字节完全一致**直通、Codex 双上游分流、六类拒绝形态**均未到达上游**、只读方法直通、上游不可达 → 502 可读错误、**3xx 原样中继且不跟随**、**残留凭据一律 422 且一条都不上行**(信封 `name`、信封 `*_id`、`thinking`、重复 JSON 键四类;伪媒体载荷与媒体 `data:` URI 在 R2 后已不再走「跳过」这条路,改由正常改写覆盖,断言移入引擎单测)、**`/vigil/healthz` 带 `Origin` 必 403**(不带则正常返回,且含 `audit_dropped`)。**200 层嵌套 body 在入口即 400 `unparseable_json`**(把「递归深度由解析器负责」这条**借来的**不变量钉成可执行事实)。另有 **1 条 `#[ignore]` 的 422 断言**钉住跨叶子 base64 预算饿死这个**已知未修**的缺口。
- CLI 面 **18**(配置往返 / 损坏与非环回 fail-closed / Claude apply-revert 幂等 + 保留他键与键序 + 自家网关串接 + 用户改过不动 + Bedrock 拒绝 + 畸形 abort / Codex TOML 注释保留 + 自定义 provider 拒绝 + 陈旧检测 / 账本 payload 无原文 / **userinfo 伪装不被认作本机闸门** / **连续两次 `on` 保全首次恢复记录** / **`off` 不动用户改过的 provider** / **`on` 不覆盖同名的他人 provider**)。
- `vigil-redaction` 新增 **2**:`hard_secret_spans` 与 `scrub_text` 的边界一致性、**base64 配额不被明文命中吃掉**。
- **真上游冒烟**(`scripts/test-local/outbound-real-upstream.ps1`):用无效 key 打真 `api.anthropic.com`,上游 401 原样中继、`healthz` 显示请求体被改写、非 JSON 体 415。
- 远端 `fmt --check` / `clippy --workspace --all-targets -D warnings` / `cargo test --workspace`
  全绿 **1451 / 0 / 9 ignored**;`cargo deny check bans` ok;桌面 `vue-tsc --noEmit && vite build` 绿。
  **第 9 条 ignored 是刻意的**:`cargo test -p vigil-outbound --test gate_e2e -- --ignored` 当前
  **确实红**(`left: 200, right: 422`)—— 这条缺口因此是**可见且可复现**的,而不是被默认为已覆盖;
  修好 base64 预算口径当天删掉 `#[ignore]` 即转绿。
- **评审(两路,均为 REQUEST-CHANGES)**:第一路 Codex(`gpt-5.5`,只读)**11 条**;第二路本地敌意子代理
  **去重后新增 7 条**。逐条复核与处置见 §5。该子代理的 LOW 段经再次索取后已补齐(**4 条,全部在改后的树上复现**,
  见 §5.2 的「LOW 段」);另有 2 条 SUSPECTED 随截断丢失后补回,列入 §6 追踪。

## 5. 评审(2026-09-12,两路)

### 5.1 第一路:Codex `gpt-5.5` 只读审计

verdict **REQUEST-CHANGES**,11 条。逐条由本轮实现者对照源码复核后处置如下 —— 其中 3 条(信封字段、
重复键、base64 预算)是**真实的静默泄漏**,不是风格问题。

| # | findings | 处置 |
|---|---|---|
| 1 | 信封键名在**任意层级**生效,`{"input":{"name":"<secret>"}}` / 伪 `media_type` 载荷 / 媒体 `data:` URI 全部原样外发 | **修**:信封字段由出站字节自检(D14)转成 422 拒绝(**仅对明文载荷成立**,base64 载荷受预算饿死影响,见 D14 下方引注);**媒体类豁免已在第二路评审后整类删除**,不再存在「跳过」这一步(见 §5.2) |
| 2 | 逐叶子扫丢掉「键名 + 值」上下文,`{"password":"hunter2000"}` 漏检;键名本身不扫;跨数组元素拆分的凭据可拼回 | **部分修**:凭据键名下的值整段替换(与网关 `scrub_object_value` 同口径);键名本身由字节自检兜住;**跨元素拆分不修**,属 §3 已声明边界 |
| 3 | 重复 JSON 键:解析器只留最后一个 → 改写「没命中」→ 原字节(仍含凭据)照常上行 | **修**:出站字节自检 |
| 4 | `hard_secret_spans` 的 base64 配额被明文命中吃光(明文 token 自身也在 base64 字符集内),尾部真载荷漏盖;`scrub_text` 因先替换明文不会踩到 | **修**:先跳过已被明文整段覆盖的段再计预算,两侧口径归一 |
| 5 | reqwest 默认跟随重定向,跨主机只清 `Authorization` 类头、**不清** `x-api-key` | **修**:`redirect::Policy::none()`,3xx 原样中继 |
| 6 | 连续两次 `on`:第二次把首次记下的企业网关覆盖成 `None`,`off` 再也还不回去 | **修**:`claude_apply` 接收首次记录并保全 |
| 7 | agent 配置写失败仍落 `enabled=true`;`off` 恢复失败仍清空记录 | **修**:无 agent 生效则不落开关并返错;恢复失败的记录保留供重试 |
| 8 | `off` 无条件删 `[model_providers.vigil]`,用户改过或本就同名也删 | **修**:只删仍指向闸门的表;`on` 同样拒绝覆盖同名的他人 provider |
| 9 | TOCTOU stamp 在**读取之后**取得,读与 stat 之间的并发写检不出 | **本 crate 内修**(改为先 stamp 后读);`setup` / `setup_mcp` 既有调用点是同一模式 —— **记为既有问题**,不在本轮范围 |
| 10 | userinfo 伪装骗过手工 URL 切串:`http://127.0.0.1:80@evil.com/anthropic` 被判成本机闸门 | **修**:改用真 URL 解析器,拒 userinfo,严格比对 host / path |
| 11 | `detect_hard_secret` 先剥 `[REDACTED …]` 占位符而 `hard_secret_spans` 不剥,`AKIA[REDACTED …]IOSFODNN7EXAMPLE` 一个 `Some` 一个空 | **不改 spans**:区间必须映射**原文字节**,剥离后偏移即失效。由字节自检把这类输入变成**安全拒绝**而非泄漏 |

Codex 同时明确核验为**不可绕过**的部分:路径穿越不改主机、absolute-form 的 authority 不参与路由、
`Host` 被丢弃、`CONNECT` 无匹配路由、JSON `\u` 转义会解码后脱敏、UTF-8 边界与逆序替换无误、完整 PEM
整串替换、方法矩阵与各类畸形体的拒绝码均如设计。URL / query / 请求头不扫描是 **body-only 的既定边界**
(§3 已声明)。

#### D14(评审新增决策)出站字节自检

> 改写基于**解析后的 JSON 树**,上行的是**字节**。凡两者可能不一致的位置(重复键、按键名跳过的信封
> 字段、伪媒体载荷、预算耗尽),都在**真正要发的字节**上再查一遍硬指纹,仍命中即拒绝。

与 MCP 网关「序列化后自检 → 整包扣留」同一纪律:**改写是尽力而为,自检是最后一道**。这条把上表
1/3/11 从「静默泄漏」转成「显式拒绝」。

> **但它只在载荷是明文时成立。** 自检跑的是同一个 `detect_hard_secret`,共用那份 base64 扫描预算,
> 而**填充不必与载荷同处一个叶子** —— 自检扫的是整包序列化字节、按文档顺序走,于是前面若干段
> 解不出文本的 base64 就能把预算烧光,后面 `thinking` 里的真载荷永远扫不到(敌意评审 2026-09-12)。
> 该缺口有一条**写死 422 断言的 `#[ignore]` 测试**钉在 `gate_e2e.rs`,修法在 §6。

### 5.2 第二路:本地敌意子代理

verdict **REQUEST-CHANGES**;与 §5.1 去重后**新增 7 条**(LOW 段未获,见 §4)。三条 HIGH 同源于一个病:
**媒体豁免完全由请求方自称决定**,因此不是三个补丁,而是一次**整类删除**。

| # | findings | 处置 |
|---|---|---|
| H1 | `is_data_uri` 的「前缀是媒体」与「含 `;base64,`」两个条件**不要求相邻**:`data:image/png,<明文凭据>;base64,AAAA` 整串被跳过 | **修**:见下「根因处置」 |
| H2 | **本轮自己写的单测把该绕过断言成了预期行为** —— `gemini_inline_image_data_and_data_uris_are_skipped` 用的 base64 解出来就是个真 `ghp_` token,却断言 `!report.rewrote()` | **修**:该测试删除,换成 `media_self_declaration_no_longer_buys_a_free_pass`,断言三种伪装**均被抓住** |
| H3 | `is_binary_source` **从不校验** `data` 是否真是 base64:`{"media_type":"image/png","data":"<明文凭据>"}` 直接免检 | **修**:见下「根因处置」 |
| M1 | 单个 agent 接线失败时 `run_on` 仍 exit 0(只要另一个成功),桌面绿灯照亮 —— 那条链路此刻**完全不过闸门** | **修**:任一 `Err` 即返错(非零退出);桌面新增 `outboundDegraded`,`error` / `stale` 降黄灯(`unsupported` 是 Gemini 的设计态,不计入) |
| M2 | `previous_base_url` 可能形如 `https://<key>@host`,其 userinfo 被**落盘并回显**到 `status` / `--json` / GUI | **修**:新增 `redact_userinfo`,**只在展示路径**剥;**落盘保持原样** —— 剥了 `off` 就还不回带凭据的网关 |
| M3 | `thinking` 是模型生成的**自由文本**且跨轮回传,却被无条件跳过 | **维持跳过**(受 signature 保护,改即破协议)+ **补 e2e**:放进 `thinking` 的凭据由字节自检 **422 拒绝**,不静默上行 |
| M4 | `hard_secret_spans` 文档声称与 `detect_hard_secret`「口径一致」,实际不是等价谓词(detect 剥占位符、spans 不剥) | **修文档**:改写成「**不是等价谓词**」,写明差异来源与兜底(字节自检),不许调用方据此推断「会放行」 |

#### 根因处置:删掉整类媒体豁免,而不是逐条打补丁

`is_binary_source` 与 `is_data_uri` **连同三个调用点整个删除**,不留任何媒体例外。三种伪装本质相同 ——
`data` 从不校验是不是真 base64、两个条件不要求相邻、**带 `data:image/png;base64,` 前缀的 base64 反而比
不带前缀的更宽松**。删除**不产生误报**:真实图片 / 音视频字节解出来含控制字符、不是 UTF-8 文本,
`decode_base64_text` 本就返 `None`(已补一条真 1×1 PNG 的单测钉住)。

> **为省 CPU 加的自证式快捷判断,换来的是一整类绕过。这笔账永远不划算。**

#### LOW 段(索取两次才拿到;4 条经复核**全部在改后的树上复现**)

| # | findings | 处置 |
|---|---|---|
| L1 | `/vigil/healthz` 分支排在 `Origin` 拒绝**之前**:任意网页 `fetch()` 的请求会真实落地返 200 —— 浏览器无 CORS 头读不到 body,但 load / error 的时序差足以当作「本机装没装闸门、在哪个端口」的存在性探针 | **修**:`Origin` 拒绝整块上移到 healthz 之前;e2e 断言带 `Origin` 必 403、不带则正常返回 |
| L2 | `rewrite_text` 对越界区间只 `continue`,**与它自己的注释相反**:其余替换照做、照返 `Some`,被跳过的那条凭据原样留在体里却「看起来已处理」—— 一个本该 fail-closed 的分支写成了 fail-open | **修**:抽出 `spans_applicable` 先整体校验,破契约即返 `None`、一个字节不动;单测用**构造出来的**越界 / 倒挂 / 非 char 边界区间钉住(正常路径造不出反例) |
| L3 | 账本写失败只 `eprintln` 后返回,事件消失而流量照放,`Counters` 也无对应计数 → 「没有改写」与「改写了但没记上」在**任何外部观测面**上一模一样,事后取证会得出错误结论 | **修**:`GateAudit::dropped_events`(默认返 0,不破坏既有实现)+ `healthz` / `status --json` 暴露 `audit_dropped`。桌面卡片当前不展示任何计数,**故未上界面**,列入 §6 |
| L4 | `Routes` 四个字段**无 field 级默认值**:手工只写 `upstreams.anthropic` → 整份 `outbound.json` 解析失败 → `enabled` 被强制 false,闸门静默不启动而 agent 配置仍指向它。不是泄漏(连不上即 fail-closed),是**极难自查的砖化** | **修**:每字段 `#[serde(default = "…")]`;单测断言缺字段补内置上游 |

#### 一条**不采纳**的建议:`thinking` 按上游来源分档放行

评审提出:`thinking` 文本本来就是上游生成、又发回同一个上游,默认拓扑下拒绝它买不到机密性,
却会让**整个会话**永久 422(extended thinking 要求逐轮回传此前的 thinking 块),建议只在上游被
覆盖时才拒。**可用性代价的判断成立并已接受,分档方案不采纳。**(评审方复核后已自行撤回该建议。)

理由必须写成**强形式**,否则将来有人正好从弱点上把这个决定翻过来:

- ❌ **弱形式(不要这么写)**:「任何本机调用方都能往 `thinking` 塞任意字节配假签名」。这句**单独立
  不住** —— 能构造 HTTP POST 的任意本机进程本来就有不受限的出网能力,闸门既不注入凭据、也不提供
  它没有的东西,走闸门对它不构成能力增益。
- ✅ **强形式(真正的理由)**:吃亏的是**网络受限的本机调用方** —— 沙箱里的工具执行、被 firewall
  管住的 MCP server、浏览器 native host。**这些东西恰恰是 Vigil 自己造出来的**:它们够不到外网,
  却够得到 loopback,而闸门是一个**不鉴别调用方**的监听器。对它们来说,一个「按键名免检、可放任意
  字节」的字段就是一条现成出口,这才是真实的能力增益,也才是必须拒绝的理由。

闸门分不清 `thinking` 的真伪,**分不清时选 fail-closed 是本项目的家法**。缓解改为三条,都不牺牲
fail-closed:422 文案给出可行动的补救路径;**报出残留的结构位置**(`locate_residual`,只回路径不回
内容),把「整个会话作废」降成「裁掉那一个 assistant 轮次」;并把这道可用性悬崖写进用户指南排查表。

#### 复核轮(R3 / R4 / R5 / R6)收口

同一评审方在改后的树上复核,又打掉三处。**都不是新缺陷,而是本轮新代码自己带进来的成本与耦合**:

- **拒绝路径上的重解析纯属浪费,已删**。它不是「第二个解析器」(差分解析风险来自两个**不同实现**
  给出不同的树;这里同一个 `serde_json`、同一份字节、同一套 `preserve_order`,结果必然逐位一致),
  而是对最多 64 MiB 的字节再做一次完整解析加整棵树重新分配。把 `value` 提到块外即可复用。
- **定位加了检查预算**(叶子数 / 字节数)。走不走拒绝路径**完全由请求方决定**,而定位是逐叶子各跑
  一遍 `detect_hard_secret`,比常态的「整包跑一次」陡得多 —— 等于给可用性攻击加了个乘数。超预算
  即放弃定位、落通用文案。
- **`safe_key` 的跨模块隐式不变量已消除**。此前只有一个 `len() <= 24` 挡着,而 `github_token`
  (最短 40)、`stripe_secret_key`(32)、`huggingface_token`(33)三条规则**本来就可以是全小写 +
  数字 + 下划线**,最窄余量 33 对 24:本文件的长度常量在替 `vigil-redaction` 的规则表做安全保证,
  中间没有任何东西相连。现在**直接问规则表**,长度常量只再影响可读性;并补了以这三条为样本的守门。

**R5** 打掉的三条**全是 R4 新代码自己带进来的**,不是新缺陷:

- **预算看不见对象键 —— 加预算要掐的那条放大路径从旁边绕过去了**。`safe_key` 对**每一个对象键**
  调 `detect_hard_secret`,而预算只统计字符串**叶子**。`{"a":1,"b":1,…}` 铺满 64 MiB ≈ 900 万次
  检测调用,计费为零。处置:**路径延迟构造** —— walk 只携带原始键的借用,命中后才渲染,检测调用量
  从「键总数」降到「命中路径深度」(≤128),顺带消掉每节点一次 `format!`。
- **单趟前缀扫描会在它唯一重要的场景里先死**。真实键序是 `model` / `system` / `tools` / `messages`,
  工具 schema 排在对话前面且叶子密度极高,而残留几乎总在后半段的 `messages` 里。处置:**改两趟** ——
  第一趟只看信封跳过集(固定小集合,不设预算,常见情形必然命中),找不到才跑第二趟扫其余叶子并把
  预算挂在那一趟。于是两个常数**既不承担安全职责也不影响常见路径**,与 `safe_key` 长度常量同一招:
  把隐式职责摘掉,而不是给它配守门。
- **一个超大叶子会终结整次搜索**。此前 `blown` 是全局终止,于是一次大文件读的工具结果或一张内联
  图片的 base64 就能当场打爆定位,而这类叶子是常态。处置:超额**只跳过这一叶**,继续走。

**R5 同时补上了此前两轮一直延后的 accept 并发上限**(`MAX_INFLIGHT_CONNECTIONS = 64`,原子计数 +
Drop 守卫,零新增依赖):常态路径上每条连接都可能吃掉一次 64 MiB 的读取加全量扫描,而这是所有
预算都约束不到的那一项。超限**直接关连接**而非排队 —— 排队会让 agent 不知情地挂起。

**R6** 只有一条,但它是把同一个洞挪到了隔壁门:**定位第一趟用的是无预算扫描**。写下的前提是
「信封跳过集是个固定小集合」,而那个集合按**键名**固定、不按**数量**固定 —— `is_envelope_key`
含 `ends_with("_id")`,键名完全由请求方决定;就算只用固定名字,`[{"name":"x"}, …]` 每个数组元素
也贡献一片信封叶子。把凭据放进**重复 JSON 键**即可保证两趟都扫到底却都找不到(残留只在原字节里),
于是攻击者**稳定**换到一次完整的无上限全扫;`MAX_INFLIGHT_CONNECTIONS` 限的是并发数、不是单请求
成本,压不住它。处置:**两趟共用同一个 `LocateBudget`**,第一趟优先支取(真实 body 的信封叶子是
个位数到几十个,共用上限对常见路径毫无影响),并补上以大量 `*_id` 叶子为形状的回归测试。
**这正是 R5 自己写下的那条教训 —— 加限制时要枚举昂贵操作的每一个调用点 —— 落在 R5 刚发的那个
限制上。** 另:单次调用的 wall-clock **未实测**,这里钉住的是「最多 `LOCATE_MAX_LEAVES` 次
`detect_hard_secret`」这个结构上界,不假装量过。

复核**确认为不构成风险**的一条:递归深度。`serde_json` 默认 128 层限制,本仓无 `unbounded_depth`
/ `disable_recursion_limit`,超深 body 在入口即 400 `unparseable_json`。但该不变量是**借来的**,
已按建议钉成 e2e(`excessively_nested_bodies_are_refused_before_any_recursion_of_ours`)。

#### 收尾裁决与**评审方自述的验证边界**

敌意子代理最终给出 **ACCEPT-WITH-CHANGES**(初始为 REQUEST-CHANGES):其提出的全部 HIGH / MEDIUM /
LOW 加两条 SUSPECTED 均已修复并经其在源码上逐条复核。

**但必须原样记下它自述的边界:它没有 cargo / rustc,「1451 通过 / 9 ignored / clippy 与 fmt 干净」
全部是本轮实现者的结论,评审方只核了源码形态,能独立确认的是结构性质、不是执行结果。**
两条独立性因此是非对称的:缺陷判断双路交叉,**执行结果单路**。记在此处,不把它读成双路验证。

#### 两路盲区不重叠(本轮实证)

Codex 抓的是**协议 / 供应链 / 配置往返**:重复 JSON 键、reqwest 默认跟随重定向不清 `x-api-key`、
连续两次 `on` 覆盖首次的恢复记录。敌意子代理抓的是**自证式豁免,以及被自家测试背书的绕过** —— 后者
任何「跑一遍测试都绿」的流程都发现不了,因为那条测试**就是**绕过的担保人。任一路单独跑都会整片漏掉
对方那半边。

## 6. 未落地子范围(可追踪)

- Gemini CLI 接线(API key 模式先行)。
- `AliasSink` 的真实实现(`secret://` + 执行边界脱别名),需先解决「模型看到别名后如何在工具调用里正确回填」的语义。
- 请求头 / query string 的扫描口径(当前只扫 JSON 体)。
- 出站闸门的 GUI 统计可视化(当前只有开关 + 存活 + 三个计数);`audit_dropped` 目前只进
  `healthz` 与 `status --json`,未上界面。
- **base64 扫描预算的通用饥饿**:256 段上限可被**非凭据**的 base64 字母表长串吃干,尾部真载荷
  漏扫。Codex 第 4 条只修了「padding 本身就是明文命中」的窄情形。
  **⚠️ 「把预算从段数改成解码字节数」这条处方已被 Codex 复审推翻,不要照做**(2026-09-12):
  两段各 `4MiB - 4` 的填充即可吃掉 8 MiB 预算、只剩 8 字节,后面的 base64 凭据被跳过 —— 而**现行的
  按段计数(3 段 ≤ 256)会把三段全扫、能检出**。即字节预算会引入一个**当前并不存在的新漏报**。
  同轮还证伪两点:8 MiB 预算可容纳约 209715 段最短段(而非 256),单段开销与分配大增,且
  `hard_secret_spans` 每个候选段要与**不断增长的 `hits` 向量**比对 ⇒ **平方级**比较,所以「最坏
  工作量降到 8 MiB」不成立;`scrub_base64_runs` 若「跳过超预算段」会**丧失幂等性**(替换掉前段会在
  下次调用腾出预算),其输出可能过不了账本自检。
  **✅ 正确方向(根因比预算单位深一层)**:现在**预算耗尽返回 `None`,与「扫干净了」无法区分**,
  对每个把 `None` 当「干净」的 fail-closed 消费方而言这是 fail-**open**。修法应当
  **把「未扫完」显式暴露成第三态**,并让三个 fail-closed 消费方(账本 `append_event_internal`、
  MCP hub 结果自检、出站字节自检)**在「未扫完」时一律拒绝**;脱敏器则必须对**未检查的候选段
  保守遮蔽**,而不是原样放行。这会改变账本拒绝事件的时机,属共用 API 语义变更,**必须单开一轮**
  并配完整回归。
- **base64 只解一层**(`base64(base64(secret))`)与**非文本凭据**(DER 私钥、原始 32 字节 key)不命中。
- **解码开销**:逐叶子一次、字节自检再一次,每次还各试 STANDARD / URL_SAFE 两套字母表,所以
  「计费 N 字节」实际最多是 2N 的解码输入。accept 并发上限与定位预算已在 R4 / R5 落地;**仍未做**的是
  「按首段探测结果择一套字母表」。注意:**不要**把「每请求累计解码字节上限」当作独立改进 —— 见上一条,
  单纯的字节预算会引入新漏报,必须与「未扫完显式拒绝」一并设计。
- **base64 预算的跨叶子饿死**(上面那条的最尖锐形态):填充与载荷**不必同处一个叶子**,自检按整包
  字节顺序扫描,前置填充即可把预算烧光。已有 `#[ignore]` 的 422 断言钉在
  `crates/vigil-outbound/tests/gate_e2e.rs::cross_leaf_base64_padding_must_not_starve_the_byte_self_check`,
  修好预算口径当天删掉 `#[ignore]` 即转绿。
  **★ 暴露面不止闸门(评审方线索,已查证并收窄)**:`detect_hard_secret` 同时是
  `vigil-audit` 账本 `append_event_internal` 的 fail-closed 守门(`ledger.rs:503/507`,对 JCS
  规范化后的**整个 payload** 扫描),`outbox.rs:92` / `registry.rs:196,610` / `hub.rs:1614,1643`
  亦然。若预算可被填充饿死,理论上「填充在前、base64 凭据在后」的 payload 可绕过账本自检 ——
  而「账本无明文」是产品级铁律,不是闸门的一个功能点。
  **查证结论:三条主要入账路都是「构造出来的元数据」,不承载攻击者文本,故不可利用**:
  浏览器分类器路只放 `origin` / `event_kind` / `request_id` / `text_len`(**长度**而非文本)/
  `engine`(接口 `BrowserAuditMeta` 把「不得含 raw text」编码进了类型边界);hook 工具输出路只放
  工具名、命中计数、**静态规则名**与 `tool_response_sha256`(**指纹而非真值**);MCP 泄漏事件路只放
  rule / invocation_id / server_id / tool_name / decision_id,且额外过一遍 `redact()`。
  饿死预算需要在同一份 payload 里塞进 ≥256 段各 ≥40 字符的 base64 串**再**跟一段 base64 凭据,
  元数据字段承载不了。**残留不确定性(如实记):未逐一审阅全部 `append_event` 调用点**
  (`vigil-lease/broker.rs`、`http-auth`、`demo.rs`、`posture.rs` 等未查),故本条记为
  **已收窄、未排除**,共用 crate 那一轮仍须先复核这一面。
- **PEM 跨 JSON 叶子切分**:含 header 的那段整串替换,纯 base64 的 body 段因解出二进制而原样上行。
- **Codex `model_providers` 为 inline table 时**:`codex_state` 用 `as_table_like` 判定正常而
  `codex_apply` 报 `UnsupportedConfigShape`,出现「状态说可写、实际写不进」。
