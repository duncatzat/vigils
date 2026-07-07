# ADR 0009 — Browser Extension MVP(I09a:Native Host + Browser Check Contract)

- 状态:**Proposed**
- 日期:2026-04-20
- 依赖:ADR 0001 / 0002 / 0003 / 0006 / 0008

## 1. 背景与范围

主方案 §10:很多泄漏发生在用户把 secret / `.env` / 客户数据粘进网页 AI。浏览器扩展
MVP 做两件事:**粘贴前检查 + 发送前检查**。架构:
```
Content Script → Service Worker → Native Messaging Host → Vigil Core
```

**现状**(非从零):
- `extensions/chrome-mv3/{manifest.json, background.js, README.md}` 已是 I00 占位
- `apps/native-host/src/main.rs` 是 I00 占位 bin
- `vigil-redaction` 已实装 github / anthropic / openai / aws / jwt / env_assignment /
  email / internal_ipv4 / pem_private_key 等硬指纹规则

## 2. 分段交付

I09 拆三段,本轮只承诺 **I09a**:

| 段 | 交付 | 本轮验收? |
|----|------|---------|
| **I09a** | 新 crate `vigil-browser`(协议 + 分类器)+ `apps/native-host` length-prefixed JSON framing + audit metadata-only 写入 + Rust 集成测试 | **是** |
| I09b | Chrome MV3 content script / service worker / E2E 浏览器测试 + 安装脚本(Windows 注册表 / Unix JSON manifest) | 后续(需 Node + Chrome 工具链) |
| I09c | 页内提示气泡 / 每站点开关 / `Ask` 交互 | 后续 |

## 3. 关键决策(Codex 协作)

### D1 — 本轮只 I09a
理由:Node/pnpm/Chrome 工具链状态未定;I09a 足以验证 §12.3 I09 前三条验收(规则 + metadata 审计),第四条 "no raw in storage" 由 Core 审计不入原文间接保证。

### D2 — 新 crate `vigil-browser`
`BrowserCheckRequest/Response` / `FindingKind` / `BrowserAction` / classifier 放这里。
- **不**塞 `vigil-redaction`:后者做脱敏原语,browser 需更窄 UX 策略
- **不**塞 `vigil-ui-protocol`:后者是桌面 UI 边界,非浏览器内容检查

依赖图:`vigil-native-host → vigil-browser → vigil-redaction`;host 自调 `vigil-audit`。

### D3 — 规则集(窄化)
本轮 classifier 只用:
- `github_token` / `openai_key` / `anthropic_key` / `aws_access_key`(走 Redact)
- `jwt` / `env_assignment`(走 Redact)
- `pem_private_key`(走 **Block**)
- 新增:`localhost URL`(http/https://(localhost|127.0.0.1|::1|\*.local) → Redact + finding)

延后:`email` / `phone`(语义指纹,误报容忍度问题,需上下文敏感判定 / 熵评分层;见 Revised 2026-04-23 C5/C7)。
注:`database_url` 已在 I09c 第三批作为结构化硬指纹落地(要求含 `user:password@`),见 Revised 2026-04-23 C1。

### D4 — Native Messaging 协议
Chrome Native Messaging 标准:**4-byte little-endian length prefix + UTF-8 JSON**(单消息),**不**叠 NDJSON。消息上限 Chrome 端 64 MB,本实现默认接受到 1 MB(超过返 `too_large` error)。

### D5 — 审计 payload(metadata-only)

```json
{
  "origin": "https://chatgpt.com",
  "event_kind": "paste",
  "finding_kinds": ["github_token"],
  "finding_count": 1,
  "length_bucket": "100-500",
  "action": "redact",
  "redacted": true,
  "request_id": "uuid-v4",
  "rule_profile_version": "v1"
}
```

**严禁**:原文 / redacted_text / 全量文本 sha256(可被字典攻击还原)。
finding 指纹若将来需要,用 **域分离 hash**:`sha256("browser:<rule>:" + matched_span)`,
本轮不写进 payload(延 I09c 若运维需要再加)。

### D6 — Action 仅三类
- **Allow**:无 finding
- **Redact**:有 finding,返 `redacted_text` 让扩展替换输入
- **Block**:首版仅 `pem_private_key`;其他高置信 finding 走 Redact(MVP 更稳)
- `Ask` 延 I09c

### D7 — Origin 校验
Core 不维护产品 allowlist(`chatgpt.com / claude.ai / ...` 由扩展 `optional_host_permissions` 管);Core **fail-closed 拒绝**特权 scheme:
- `chrome-extension://`
- `file://`
- `devtools://`
- `chrome://`
- `about:`
- 非 `http/https` scheme

### D8 — 测试不依赖 Chrome
- `vigil-browser` classifier unit tests
- Protocol framing unit tests(parse / encode round-trip + partial read / length bomb)
- `apps/native-host` 集成测试:child stdin 写 frame → stdout 读 response
- §12.3 I09 前三条覆盖:GitHub token Redact / private key Block / normal paste Allow
- 第四条("no raw in storage")由 "audit payload 不含 raw" + `cli_redline_sentinel_never_in_any_output` 同款断言

### D9 — Host 二进制独立
`apps/native-host` 自含,不合并到 `vigil-desktop`(Chrome Native Messaging 要求固定路径的 executable)。`vigil-desktop` 以后可加 `browser-check <text>` 子命令做运维调试(延后)。

## 4. 数据模型

```rust
pub struct BrowserCheckRequest {
    pub request_id: String,             // UUIDv4,audit 关联
    pub origin: String,                 // 完整 origin,scheme:host[:port]
    pub event_kind: BrowserEventKind,
    pub text: String,                   // raw 文本;Host 读取后立即 scrub + drop
}

pub enum BrowserEventKind { Paste, Submit }

pub struct BrowserCheckResponse {
    pub request_id: String,
    pub action: BrowserAction,
    pub findings: Vec<FindingKind>,     // 仅类别,不含 matched span
    pub redacted_text: Option<String>,  // action=Redact 时 Some
}

pub enum BrowserAction { Allow, Redact, Block }

pub enum FindingKind {
    GithubToken,
    OpenaiKey,
    AnthropicKey,
    AwsAccessKey,
    Jwt,
    EnvAssignment,
    PemPrivateKey,
    LocalhostUrl,
}
```

## 5. 安全不变量

- **I-9.1**:`BrowserCheckRequest.text` **只**存在 Host 进程内存中,分类完立即 drop;不写 SQLite / log / tracing
- **I-9.2**:audit payload 字段白名单固定(D5);新字段加入须同步更新白名单测试
- **I-9.3**:特权 scheme(chrome-extension/file/devtools/chrome/about)+ 非 http/https /
  带 userinfo / 带 path / 带 query / 带 fragment / 空 host → 直接返
  `BrowserErrorFrame { error: OriginDenied, request_id }`,**不**走分类器、不写审计
- **I-9.4**:text 超 1 MB → 返 error frame(`too_large`),不进分类器;超限由 Host 在 frame 解包时 fail-closed
- **I-9.5**:Native Messaging frame 的 length prefix > 1 MB → 拒接,不分配 buffer(防内存炸弹)
- **I-9.6**:redacted_text 若包含硬指纹残留 → `vigil_redaction::detect_hard_secret` 再扫一遍,命中 fail-closed 返 Block(redact 不彻底时不要让半成品进 DOM)

## 6. 测试与验收(§12.3 I09 映射)

| # | 验收 | I09a 测试 |
|---|------|---------|
| 1 | GitHub token paste blocked/redacted | `classifier_github_token_triggers_redact` |
| 2 | private key blocked | `classifier_pem_private_key_triggers_block` |
| 3 | normal paste allowed | `classifier_plain_text_allows` |
| 4 | no raw content in storage | `audit_payload_never_contains_raw_text` + `SENTINEL 扫描` |

### 补充:
- `protocol_framing_roundtrip`
- `protocol_rejects_oversized_length_prefix`
- `origin_scheme_denylist`(特权 scheme)
- `redacted_text_does_not_leak_matched_spans`
- `native_host_stdin_stdout_integration`

## 7. 跨版本契约

- `BrowserCheckRequest/Response` / `FindingKind` / `BrowserAction` 作为 I09-I10 稳定 API
- 审计事件 `browser.paste_checked` / `browser.submit_checked`(非保留前缀)
- `rule_profile_version` 字段让未来规则升级可被审计区分
- Native Messaging framing:`u32 LE length + UTF-8 JSON`,上限 1 MB

## 8. 延后项

| 延后项 | 目标 |
|--------|------|
| Chrome content script / service worker | I09b |
| Windows 注册表 / Unix manifest 安装脚本 | I09b |
| 页内提示气泡 / 每站点开关 | I09c |
| `Ask` 交互(native 对话框) | I09c |
| email / phone 规则(语义指纹需熵评分层) | I09c++ / I11(database_url 已在 I09c 第三批落地) |
| finding-level 域分离 hash | I09c(若运维需要) |
| Chrome E2E(headless) | I09b |

## Revised 2026-04-23 (I09b α1-α3 + β1 追加决策)

原 ADR 正文定稿于 I09a 阶段(2026-04-20),聚焦 Rust 协议契约 + Native Host。I09b 在既有 I09a 契约上实装 MV3 JS 侧 + 跨平台安装支持,相关决策、相对原 §8 延后项的变更、以及新增不变量,**在此追加**(不改动原 §1-§8)。

### R1. I09b 子迭代 ACCEPT 清单(交付细节见 `docs/iterations/I09b.md`)

| 子迭代 | 交付 | Codex 轨迹 |
|---|---|---|
| α1 | MV3 真 scaffold:`manifest.json` 真配 + `background.js` 长连接 + `content-script.js` paste/submit/Enter 三路径 + README 重写 | R1 REJECT(3 MUST-FIX)→ R2 ACCEPT |
| α2 | 站点深度选择器(ChatGPT / Claude / Gemini / Perplexity)+ form-level redact 真写(`findPrimaryInput` scope 到 form) | R1 REJECT(1 BLOCKER)→ R2 ACCEPT |
| α3 | popup 展示最近 findings(in-memory 32 条环形队列)+ options page 展示扩展 ID + Native Host install 命令可复制 | R1 ACCEPT(一轮通过) |
| β1 | 三平台 Chrome Native Host 注册脚本(`vigil-native-host install / uninstall / status` CLI 子命令)+ argv 分流 + Windows HKCU 注册表 | R1 REJECT(1 BLOCKER Chrome argv + 1 NICE)→ R2 ACCEPT |

### R2. 相对原 ADR 的差异与细化

1. **原 §8 "Chrome content script / service worker"** → α1 实装为**纯 vanilla JS**(无 npm 依赖 / 无构建步骤 / manifest 直接 `load unpacked`);环境约束"禁 heavy install"下文件就绪版策略。
2. **原 §8 "页内提示气泡"(I09c 延后)** → **α1 已实装** `showToast` 为 content-script 顶部固定 banner(fixed position + inline style + textContent 防 XSS);α3 popup 进一步做了独立 action popup。真正的"每站点气泡"UX 设计(I09c)仍延后。
3. **原 §8 "Windows 注册表 / Unix manifest 安装脚本"(I09b 目标)** → **β1 兑付**,但**存放位置由 Vigil 项目决定**:Windows manifest 文件放 `%LOCALAPPDATA%\Vigil\NativeMessagingHosts\`(HKCU 注册表指过去),而非 Chrome 官方示例的"任意位置"。选择 LocalAppData 与 desktop β5 ledger 同一根目录,语义一致(本机审计,不 roam)。
4. **`exe_path` 必须绝对**(β1 install.rs `InstallError::ExePathNotAbsolute`):**Vigil 项目策略**,收紧于 Chrome 官方(Chrome 只在 Linux/macOS 强制绝对,Windows 允许相对 manifest 目录)。避免"本地调试绝对 / CI 打包相对"的路径歧义。
5. **α3 permissions 最小化延续**:只保留 `["nativeMessaging"]`(α1 R1 修复后),α3 popup + options 不加 storage / tabs / activeTab。原 ADR 未展开 permissions 讨论,此处固化"每新功能必须评估是否真需新权限,能否用 in-memory 替代 storage"的守门。

### R3. ADR §8 延后项状态更新

| 原 §8 延后项 | R1/R2/β1 后状态 |
|---|---|
| Chrome content script / service worker | **Done**(α1 实装,α2 站点深度选择器 + form-level redact 细化) |
| Windows 注册表 / Unix manifest 安装脚本 | **Done**(β1 三平台 install/uninstall/status CLI,15 install-related 单测守门) |
| 页内提示气泡 | **Partial Done**(α1 固定顶部 toast / α3 action popup;per-site 气泡 + 用户交互确认仍 I09c 范围) |
| 每站点开关 | **Deferred**(需 `storage` 权限 + 动态 `chrome.permissions` 管理,与 MV3 host_permissions 交互复杂,I09c) |
| `Ask` 交互 | **Deferred**(I09c) |
| database_url 规则 | **Done**(I09c 第三批,结构化硬指纹;见 Revised 2026-04-23 C1) |
| email / phone 规则 | **Deferred**(语义指纹,I09c++ / I11 需熵评分 / 软规则层) |
| finding-level 域分离 hash | **Deferred**(I09c,运维驱动) |
| Chrome E2E(headless) | **Deferred**(β,需 Playwright + tauri-driver 级工具链,环境约束下留发行前) |

### R4. 新增不变量(I09b 阶段固化)

- **DOM 查询承载安全决策必须 scope 到事件源子树**(α2 教训):`form.querySelector(...)` 而非 `document.querySelector(...)`,加 `contains` 二次 sanity;找不到就降级 fail-safe 而非回退全局搜
- **外部契约 argv / 环境变量 / protocol 必须核对官方文档真实值 + CLI 层手工分流**(β1 教训):假设"无参启动"会 BLOCKER 级失败(Chrome Native Host 会传 extension origin argv)
- **规范 vs 项目策略措辞必须精准区分**(β1 NICE):Chrome 官方约束 vs Vigil 主动收紧,文档不能越权冠以"官方要求"
- **MV3 permissions 最小化是默认**(α1/α3 连续守门):每新功能先问"能否用 in-memory / manifest 静态声明替代 storage / tabs / activeTab"
- **XSS "backend/runtime 数据全 textContent"不变量**(popup/options + I08b UI 一致):即使 `chrome.runtime.id` 等看似安全的值也作纯文本 textContent 插入,未来 innerHTML 回退会有清晰违反信号
- **Option 字段不能先依赖存在**(α1 教训):Rust `Option<T>` → JS `undefined`,分流逻辑必须在值可选前提下仍 fail-closed(ErrorFrame 无 request_id 时 block 全 pending)

### R5. 量化

| 节点 | workspace 测试 | 累计 Codex ACCEPT | Vigil-native-host 测试 |
|---|---|---|---|
| I09a 完成(2026-04-20) | 258 | R3 ACCEPT | 8 acceptance tests |
| I09b-α1 完成(2026-04-22) | 408(workspace 其它迭代累加) | + α1 R2 ACCEPT | 不变(纯 JS) |
| I09b-α2 完成(2026-04-23) | 408 | + α2 R2 ACCEPT | 不变(纯 JS) |
| I09b-β1 完成(2026-04-23) | **423** | + β1 R2 ACCEPT | 8 acceptance + **9 install 单测 + 6 argv_dispatch 单测 = 23** |
| I09b-α3 完成(2026-04-23) | 423 | + α3 R1 ACCEPT | 不变(纯 JS) |

### R6. 新增延后项

| 延后项 | 阻塞原因 | 目标 |
|---|---|---|
| Playwright + headed Chrome E2E | 需 npm install Playwright + GUI runtime | 发行前在 CI |
| 三平台打包 CI | 需 GitHub Actions build matrix(Windows/macOS/Linux) | 发行前 |
| 图形化 install 向导 | 需额外 UI(Tauri 向导 or native dialog) | 发行前 |
| session-scoped 用户豁免(α4) | 需 `tabs` 权限 + per-tab Map + UI 豁免按钮 | I09b-α4 |
| 每站点开关 / 自定义 host 白名单 | 需 `storage` + `chrome.permissions` 动态 host | I09c |

### R7. Codex review 关键修复摘要

#### α1(R1 REJECT → R2 ACCEPT)
- 3 MUST-FIX:form.submit() 绕 HTML validation + 其他 submit listener / ErrorFrame 无 request_id 只能等 TTL fail-closed / manifest 超权(activeTab/scripting/storage 未用)
- 修复:`WeakSet allowedOnce` + `form.requestSubmit(submitter)`;`onHostMessage` 先看 error 再看 request_id,无 reqId 全 pending fail-closed block;permissions 削减为 `["nativeMessaging"]`

#### α2(R1 REJECT → R2 ACCEPT)
- 1 BLOCKER:`site.findPrimaryInput(document)` 在全 document 搜,"决策元素 ≠ 提交元素" bypass(allow 未改原 form 直接提交 / redact 写错字段)
- 修复:SiteAdapter typedef 收紧为 `(root: ParentNode) => Element | null`,`collectSubmitPayload` 改 `site.findPrimaryInput(target)` 把 form 作 scope + `target.contains(primary)` 二次 sanity + 找不到降级(不回退 document 全局搜)

#### β1(R1 REJECT → R2 ACCEPT)
- 1 BLOCKER:Chrome 启动 Native Host 传 `argv[1] = <extension origin>`(Linux/macOS),Windows 额外 `argv[2] = --parent-window=<HWND>`;原 `Cli::parse()` 吃到未知 subcommand exit 2 → 扩展 onDisconnect,install 流程对 Chrome 实际不可用
- 修复:抽 `pub fn is_admin_subcommand(args)` 纯函数白名单(install/uninstall/status/help/--help/-h/--version/-V)+ `main()` 先调本函数再决定是否走 clap + 6 守门单测覆盖 Chrome 真实启动场景

#### α3(R1 一轮 ACCEPT)
- 0 BLOCKER / MUST-FIX;2 NICE(可维护性):`flashHint._t` 函数属性挂 timer 可改为 let flashTimer / popup 冷启动 lastError 时直接渲染空可保留上次状态

## Revised 2026-04-23 (I09c 规则扩展 三批追加决策)

承接 I09b 扩展闭环,I09c 聚焦 **硬指纹规则库扩容**(非 UX 改造);ADR 0002 §D1 明示 I01 承诺范围仅含 github / openai / anthropic / aws / jwt / env / pem / localhost_url 8 类,I09c 三批扩至 **13 类**,兑付 ADR §6 "规则随站点形态演进"承诺。

### C1. 规则库增量(三批合计 +5 FindingKind)

| 批次 | 新增 FindingKind | regex / 识别特征 | 风险语义 |
|---|---|---|---|
| 第一批(R2 ACCEPT 2026-04-23) | `SlackWebhook` | `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/\w{24,}` | 泄漏 = 任意人可向该频道 post |
| 第一批 | `StripeSecretKey` | `sk_(live|test)_[A-Za-z0-9]{20,}` | 生产/测试 live 密钥,支付面完全暴露 |
| 第二批(R2 ACCEPT 2026-04-23) | `GoogleApiKey` | `\bAIza[A-Za-z0-9_\-]{35}\b`(AIza + 35 chars = 39 total) | Maps/YouTube/Gemini/Firebase 调用配额即金钱 |
| 第二批 | `GitlabPat` | `\bglpat-[A-Za-z0-9_\-]{20,}\b`(glpat- + 20+ chars) | 仓库/CI/runner 全权限(较 GitHub PAT 更 opaque 无权限位检测) |
| 第三批(R1 ACCEPT 2026-04-23 本 Revised) | `DatabaseUrl` | `\b(postgresql\|postgres\|mysql\|mongodb+srv\|mongodb\|rediss\|redis\|amqps\|amqp)://user:password@host[:port][/path]` | 含凭证 DB 连接串泄漏 = DB 全权限(读写删 schema) |

### C2. `RULE_PROFILE_VERSION` 演化

| 版本 | 内容 | 审计回溯语义 |
|---|---|---|
| `v1` | I09a 基线 8 kinds | "某条审计是 I09a 首发规则集产出" |
| `v2` | I09c 第一批,+ slack_webhook + stripe_secret_key(10 kinds) | 回溯时可明确 v1 历史库无 Slack/Stripe,不是漏判 |
| `v3` | I09c 第二批,+ google_api_key + gitlab_pat(12 kinds) | 同上,v1/v2 无 Google/GitLab 语义 → 非漏判 |
| `v4` | I09c 第三批,+ database_url(**13 kinds**) | 同上,v1-v3 无 DB URL 语义 → 非漏判 |

**审计不变量**:扩 FindingKind → bump `RULE_PROFILE_VERSION` 是 MUST(第一批 R1 教训);不 bump 会破坏"某条审计由哪一版规则产生"的追溯链。

### C3. 跨 crate 守门扩展(一次性同步到位)

扩 FindingKind 的必改清单(三批累积教训,第二/三批一次性 hit):

| 位置 | 守门作用 | 第三批同步 |
|---|---|---|
| `crates/vigil-redaction/src/lib.rs` ALL_RULES + HARD_RULES 双份 | scrub + hard fingerprint re-scan 都命中 | ✓ +1 each |
| `crates/vigil-browser/src/protocol.rs` FindingKind enum + `as_str()` + `RULE_PROFILE_VERSION` | 协议契约 + 审计字段 | ✓ +1 variant / v3→v4 |
| `crates/vigil-browser/src/classifier.rs` `map_rule_name` | Rust 规则名 → enum 映射 | ✓ +1 arm + 3 新 tests(含"无凭证不匹配"误报抑制) |
| `crates/vigil-browser/tests/rule_sync.rs` SAMPLES + all_kinds + contract | 三处链式长度守门 | ✓ 12→13 三处全同步(contract.len == SAMPLES.len 守门自动生效) |
| `crates/vigil-browser/tests/audit_strings_golden.rs` as_str + count | 跨进程 IPC 契约 | ✓ +1 + count match 扩至 13 |

### C4. 第二批 Codex R1/R2 修复摘要

- **R1 REJECT**(1 MUST-FIX + 1 NICE):
  - MUST-FIX:`classifier_google_key_does_not_trigger_env_assignment_only` 断言不完整 —— 只验 GoogleApiKey 存在,漏验 EnvAssignment 共存 + redacted_text 原文清除
  - NICE:`rule_sync.rs` contract 未像 SAMPLES 那样长度守门
- **R1 修复**:
  - 测试改名 `classifier_google_key_coexists_with_env_assignment`,加三断言(两 rule 共存 + redacted_text 不含原文)
  - contract 末尾 `assert_eq!(contract.len(), SAMPLES.len(), ...)` 链式守门
- **R2 REJECT(文档层)**:STATUS.md + ADR 0009 未同步 I09c 第二批 → 本 Revised 段 + STATUS.md 新 section 修复
- **R2 ACCEPT**(文档修复后)

### C4b. 第三批 Codex R1 摘要(一轮 ACCEPT)

- **主动收敛**:原 C7 延后项列出 email / phone / database_url 三候选,本轮**只实装 database_url** —— email / phone 是"语义指纹",纯 regex 误报率高(所有邮件签名 / 客服地址 / 正常业务文本都触发),必须配套"熵评分 / 软规则层 / 上下文判定"新子系统,推迟到 I09c++ 或 I11
- **regex 设计要点**:
  - 必须含 `user:password@`(`postgres://host/db` 不匹配 → 无凭证不算泄漏)
  - scheme 白名单 **longest-first**:`postgresql > postgres` / `mongodb+srv > mongodb` / `rediss > redis` / `amqps > amqp`(alternation 顺序敏感)
  - password 允许非 `@`/非空白字符(含 URL-encoded `%XX`);host 收紧到 `[A-Za-z0-9.\-]`
  - 有意收紧:**不匹配 IPv6 literal / 下划线 host**(Codex 确认设计选择,非 bug)
- **R1 一轮 ACCEPT**:主链路闭合,regex 合理,测试达标,版本正确。**0 MUST-FIX**,2 NICE 不阻塞:
  - NICE:vigil-redaction 自身无针对 database_url 的单测(classifier 端到端 + cross-crate sync 已足够)
  - NICE:IPv6/下划线 host 未覆盖(后续 DSN 形态扩展再重新评估)
- **累积教训全到位**:
  - 第一批 R1 教训(rule_sync 三处漏同步 + VERSION 未 bump)→ 一次性五处 hit + v3→v4
  - 第二批 R1 教训(coexists 测试 + contract 长度守门)→ 已加"无凭证不匹配"误报抑制测试;contract 长度守门自动生效
  - 第二批 R2 教训(文档同步是 R2 必备)→ 本 Revised 段 + STATUS section 同批完成

### C5. 不变量(I09c 规则扩展阶段固化)

- **扩 FindingKind 必须 bump `RULE_PROFILE_VERSION`**:不 bump = 审计追溯链断裂(第一批 R1 教训)
- **扩 FindingKind 必须一次性 hit 五处守门**(C3 表):第一批 R1 漏了 3/5,第二/三批一次到位
- **每条新规则必须配"组合/边界"测试**:
  - 第二批:`coexists_with_env_assignment`(`KEY=VALUE` 形 + 规则值同时触发两条规则,断言共存 + redacted 不留原文)
  - 第三批:**"误报抑制"测试**(`classifier_database_url_without_credentials_does_not_match` —— 无凭证 URL 不应触发),防止 regex 过度匹配
- **contract / SAMPLES / all_kinds 三者长度必须相等**:`assert_eq!(.len(), .len())` 而非手数(第二批 R1 NICE)
- **文档同步是 R2 的一部分**:代码通过不等于 ADR/STATUS 更新,两者需同批完成(第二批 R2 教训)
- **硬指纹 vs 语义指纹区分**(第三批新固化):硬指纹(固定前缀 / 结构化凭证 / 固定 len)可直接入 HARD_RULES;语义指纹(email/phone/地址)必须配熵评分 / 软规则层,不能硬加 → 否则正常业务文本被广泛误伤

### C6. 量化(I09c 三批累积)

| 节点 | workspace 测试 | RULE_PROFILE_VERSION | FindingKind 数 |
|---|---|---|---|
| I09c 前(I09b-α4 完成) | 423 | v1 | 8 |
| I09c 第一批(Slack/Stripe)ACCEPT | 426(+3) | v2 | 10 |
| I09c 第二批(Google/GitLab)ACCEPT | 429(+3) | v3 | 12 |
| **I09c 第三批(database_url)ACCEPT** | **432**(+3) | **v4** | **13** |

### C7. 延后项(I09c 规则扩展尚未涵盖)

| 延后项 | 阻塞原因 | 目标 |
|---|---|---|
| email / phone | 语义指纹,纯 regex 误报高(签名 / 客服 / 正常业务都触发),须配套**熵评分 / 软规则层 / 上下文判定**新子系统 | I09c++ 或 I11(新规则层) |
| Azure SAS / GCP service account JSON | 多字段结构化判定(非单行 regex,JSON 解析 + 字段名白名单) | I09c+ |
| AWS secret key(`[A-Za-z0-9/+=]{40}`)| 熵过低,当前 vigil-redaction 仅硬指纹无熵门控 → 高误报 | 待熵评分框架(同上与 email/phone) |
| IPv6 literal / 下划线 host 形 DB URL | 第三批 regex 有意收紧;后续 DSN 形态扩展时重新评估 | 待真实泄漏样本驱动 |
| 运维驱动 finding-level 域分离 hash | 非规则扩展,是 audit payload 结构 | I09c 运维反馈驱动 |

## Revised 2026-07-06(Phase 1「引擎连接」:native host 成为 daemon 第二瘦客户端)

背景与全量评估(现状客观评价 / 外部生态 / 四断裂系统分析 / 能力增量矩阵 / 三阶段方案)
见引入本段的 PR 描述。本段固化 Phase 1 决策与不变量。

### P1. 决策

1. **连接方式 = daemon(ADR 0024)第二瘦客户端**:host 每请求
   `query_daemon(RedactScan{kind: Args, text=基底前缀≤16KiB}, 800ms)`;复用 R1(peer-cred)/
   R2(总截止)/R3(无路径注入)。否决项:扩展内跑 ML(CWS 远程代码禁令 + 模型体积)、
   host 自持 ort(内存×N / 冷启动 45s / ML 变体分发复杂)。**零 daemon 端改动**
   (server dispatch 忽略 `kind`,cap 由客户端裁)。
2. **IPC 抽 crate `vigil-daemon-ipc`**(纯移动):protocol / client / transport(客户端侧;
   `serve` 归位 `daemon/server.rs`)/ **wire**(hook 的 `apply_wire_spans` 等四个 WireFinding
   安全应用原语,签名改返 `(String, usize)`)。hub-cli `daemon/mod.rs` re-export 保路径,
   消费侧零改动;hook 与 native-host 共用 wire 原语,防 VIGIL-SEC-OVERLAP/-PH 修复漂移。
3. **协议扩展(只加可选字段)**:`BrowserCheckResponse.ml_labels: Vec<String>`
   (serde default + skip empty,双向兼容;**纯展示层**,不进扩展 tier 决策);
   审计 payload 白名单 +`engine`("hardfp" | "hardfp+ml")+`ml_labels`(§I-9.2 白名单
   测试双向同步;均类别级 metadata,无 span 文本)。

### P2. 新增不变量

- **ML 只收紧**:`ml_augment` 仅 Allow→Redact(或纵深 re-scan 触 Block);Block 短路不查;
  daemon 缺席/超时/Error/engine.json 关闭 → 响应**逐字节等于**纯硬指纹现状(单测黄金对照)。
- **坐标系结构性守恒**:ML 基底 = 硬指纹层最终文本(Redact→`scrub_text_with_spans`,其
  `.0 == scrub_text()` 与 `classify` 同源);spans 相对基底前缀,`protected` 减法保占位符完整。
- **长驻进程失败冷却**:hook 的"one-shot 进程回收阻塞 worker"假设对 Chrome 常驻 host 不成立;
  `DaemonProbe` 失败后 60s 静默(防 detached worker 累积 + 重复 deadline 延迟),窗口过后自愈。
- **engine.json 门控**(独立解析,同 SSOT fail-closed 方向):缺失=auto(查,缺席自然降级);
  显式 hardfp=不查;损坏/坏版本=不查。
- **daemon 输出按不可信处理**:label 经 `safe_label` sanitize(≤32 alnum+_)去重升序;
  SW 层再加限长(≤16)+ 仅字符串纵深守门。

### P3. 审查与量化

- hostile sub-agent 审查(2026-07-06)**SOUND**:A(移植保真,与 HEAD 逐逻辑 diff)/
  B(fail-open 面)/C(坐标系)/D(资源)/E(审计白名单)/F(JS 层)/G(协议兼容)全 OK;
  0 CRITICAL/HIGH/MED;3 个 LOW/信息级非阻断(慢滴漏 ≤1 worker/60s 已文档化、daemon 可控
  label 字节入本地账本有界、JS 尺寸上限——第三项已当场加固)。
- 远端(192.168.252.20,cargo 1.96)`fmt --check` / `clippy --workspace --all-targets
  -D warnings` / `test --workspace` 全绿:**1270 passed / 0 failed**(基线 1260,+10:
  wire 13 全量随迁+2 补、native-host ml_augment 10、server e2e 4 随迁)。
- 后续:Phase 2(posture→tier 统一 + GUI 观测)、Phase 3(setup 编排 + 文档一致性)。
  Chrome Web Store 消费版扩展(0.2.0,纯 JS consumer 模式)已独立上架;本轮 native host
  ML 能力对应其 enterprise 模式的 provider 接缝,接线属 Phase 2+ 产品决策。

## Revised 2026-07-07(Phase 2「策略+观测」移植:posture 下发 + 浏览器防线统计)

自内部实现轮移植(方案承接上一 Revised 段所引 PR 描述的三阶段计划)。

### P2-1. 决策

1. **posture→tier 下发通道 = Response 可选字段**(否决「新增 host 消息」:会新开协议
   request 形态、且启动时拉取会陈旧):host 每请求现读 `posture.json`(与 engine.json
   现读同纪律)→ `BrowserCheckResponse.posture_tier`("balanced"|"strict")。逐次新鲜
   —— 桌面/CLI 切姿态,下一次 paste 即生效;映射闭集与穷举 match 留在 Rust
   (`posture_to_tier` 纯函数)。
2. **映射**:缺失→balanced(Low 默认,`load_posture` 唯一"更松"分支的镜像);
   low→balanced;medium/high→strict(浏览器 paste 路径无 Ask 通道,medium 收敛更严);
   损坏/坏版本/未知档位→strict(镜像 SSOT fail-closed 收敛 High;漂移只会更严不会更松)。
3. **扩展消费(0.2.x consumer/enterprise 形态)**:consumer 模式采用固定推荐策略、
   无用户档位,不消费 `posture_tier`;该字段的消费点是 enterprise 后端策略层
   (「本机 Vigils 引擎」启用后按系统姿态收紧,后续接线)。原内部 0.1.x 形态的
   三档跟随语义随 2026-07-06 内外扩展收敛(公开形态为唯一权威)退役。
4. **观测面**:Response 增 `engine`(与审计 payload 同源;供扩展未来展示实际引擎)+
   GUI Protection Overview 浏览器防线卡增最近 24h 守门统计
   (`vigil_audit::Ledger::browser_guard_counts`,payload 仅 metadata,整数计数;
   注册态判定沿用 `StatusReport::is_registered` 收口)。

### P2-2. 新增守门

- `BROWSER_GUARD_EVENT_TYPES`(vigil-audit,统计侧字面量)与 `event_type_for` 全变体
  产出(写入侧)**精确集合相等**,由 native-host `browser_event_ssot_tests` 双向守门
  (vigil-audit 不依赖 vigil-browser,防字面量漂移静默丢统计)。
- `posture_to_tier` 输出闭集守门(只允许产出扩展 tier 闭集成员)。
- 协议只加可选字段不 bump:旧扩展×新 host(忽略未知字段)/新扩展×旧 host
  (字段缺省 → 行为=现状)双向兼容。

### P2-3. 验证

- 远端 `fmt --all --check` / `clippy --workspace --all-targets -- -D warnings` /
  `test --workspace` 全绿:**1266 passed / 0 failed**(基线 1257,+9:posture_to_tier 3
  + SSOT 集合守门 1 + browser_guard_counts 4 + acceptance 响应字段 1);
  前端 vue-tsc + vite build 绿。
