# ADR 状态索引

本文件维护 ADR 0001-0017 的 **最终落地状态** 与 **Codex review 踪迹**。

> **为什么单独建文件**:ADR 一旦提交不覆盖正文(保护审计链),状态变更与审查轨迹集中记录于此,并在每轮迭代完成时 **追加** 而非改动 ADR 头部。
>
> **读者**:审计员 / 新接手开发 / Codex / 自己(防状态漂移)。

## 状态一览(I00-I10a 系列截至 2026-04-30;v0.x release 状态见 § Release-Era 索引)

> **文档分工(2026-05-10 同步)**:本表只覆盖 I00-I10a/c 系列(ADR 0001-0011)。
> v0.x 后 release 系列(ADR 0012-0017 + 后续 Revised)的迭代状态散落在:
> - `CHANGELOG.md`(每 release 段)
> - `RELEASE-v0.X.md`(release notes)
> - 各 ADR 末尾 `## Revised YYYY-MM-DD` 段(沿 § 维护约定 line 654)
>
> **当前 release-era 概览(读 CHANGELOG/RELEASE 详)**:v0.6 / v0.7 / v0.8 / v0.9 已发,
> v0.10 Unreleased(SDK trait/typed config 暴露起步,Sprint 1+2+3+4(设计冻结)+6 已 commit,
> Sprint 5 Phase 4 多语言深度模型待 brainstorm)。

## 状态一览(I00-I10a 系列,截至 2026-04-30)

| ADR | 主题 | 迭代 | 最终状态 | Codex 审查轮次 | 交付测试数 |
|----|----|----|----|----|----|
| 0001 | Action Control Plane | I00 | **Accepted(Done)** | R1 ACCEPT | — |
| 0002 | Audit Ledger | I01 | **Accepted(Done)** | R1 ACCEPT | — |
| 0003 | Firewall + Approval | I02+I03 | **Accepted(Done)** | R1 ACCEPT | 97 |
| 0004 | MCP Hub + Outbox | I04 | **Accepted(Done)** | R1 ACCEPT | 136 |
| 0005 | Descriptor Pinning + Drift | I05 | **Accepted(Done)** | R3 ACCEPT(R1/R2 REJECT) | 154 |
| 0006 | Secret Lease Broker | I06 | **Accepted(Done)** | R2 ACCEPT(R1 REJECT) | 178 |
| 0007 | Sandbox Runner | I07 + I07.5 + I07.5+ | **Accepted** | R3 ACCEPT(R1/R2 REJECT)/ I07.5 R3 ACCEPT(R1/R2 REJECT)/ **I07.5+ R1 ACCEPT** | 378(I07 基线 + I07.5 Linux-gated + **I07.5+ +3 helper 单测**) |
| 0008 | Desktop UI | I08a + I08b α1-α5 + β1 + β3 + β5 | **Accepted(I08a Done;α1-α5 MVP 四页;β1 真白名单;β3 EffectKind 强类型;β5 Ledger 磁盘持久化 + 审计跨会话不变量)** | I08a R3 / α1 R3 / α2 R2 / α3 R3 / α4 R1 / α5 R2 / β1 R2 / β3 R2 / **β5 R2 ACCEPT** | 213(I08a,workspace **408** 零 regression)|
| 0009 | Browser Extension MVP | I09a + I09b α1/α2/α3/α4/β1 + **I09c 规则扩展第一+第二+第三批** + **ISS-021 跨 crate sync** | **Accepted(I09a + I09b 全 α+β1 全 Codex ACCEPT;I09c 第一/二/三批全 Codex ACCEPT;ISS-021 RULE_PROFILE_VERSION v4 → v5 + 跨 crate PrivacyLabel sync 守门)** | I09a R3 / I09b α1 R2 / α2 R2 / α3 R1 / α4 R1 / β1 R2 / I09c 一批 R2 / 二批 R3 / 三批 R1 ACCEPT / **ISS-021 R2 ACCEPT(R1 CONDITIONAL → R2 ACCEPT)** | 258(I09a);workspace **536**(一批 +3 + 二批 +3 + 三批 +3 classifier tests + rule_sync/golden 同步;I09c RULE_PROFILE_VERSION v1 → v2 → v3 → v4;FindingKind 8 → 13;**+ ISS-021 RULE_PROFILE_VERSION v4 → v5,rule_sync.rs +2(alias 表 + count 守门),merge.rs +4(全 14 Hard kind × PrivacyLabel × 重叠/非重叠 矩阵 golden)**;**+ Phase 1 引擎连接 2026-07-06(daemon 第二客户端,workspace 1270)**)|
| 0010 | HTTP MCP Auth | I10a | **Accepted(Done — 仅 I10a 认证核心 + mock transport)** | R2 ACCEPT(R1 REJECT) | 294 |
| 0011 | HTTP Transport + JWKS 验签 | I10b 全段 + I10c-α1/α2/α3/α3+/β2 | **Accepted** | 设计 R4 / I10b α1 R2 / α2 R3 / β R2 / I10c-α1 R4 / α2 R2 / β2 R3 / α3 R2 / **α3+ R3** 全 ACCEPT | 375(α1 +18 / α2 +15 / β +17 / I10c-α1 +5 / α2 +5 / β2 +9 / α3 +6 / **α3+ +3**) |
| 0012 | 模型分发策略 | ISS-001 spike + ISS-004 + ISS-022(Phase 2 forward 实测)+ **v0.5 P2 bootstrap 实施**(commit `b5419b5`)| **Accepted(Implemented)** | ISS-004 R0 直接 ACCEPT(决策表 + 9 决策 + 反馈固化)/ ISS-022 R0(forward 实测验证 §3.6 并发下载规则)/ **v0.5 P2 R0**(§3.2-§3.7 全实施,placeholder URL/sha256 待 v0.5.1 注入)| 10(`crates/vigil-redaction/src/bootstrap/tests.rs`:happy / sha256 mismatch / ETag 304 / fallback / all-fail / manifest parse / disk full / partial resume / verify-skip / mirror order)|
| 0013 | T0 模型 × 硬指纹 merge 决策层 | ISS-013 + **ISS-021** | **Accepted(Revised ISS-021 收尾;硬指纹层定位为 fast-path + fallback,跨 crate PrivacyLabel × FindingKind 矩阵 golden 守门)** | ISS-013 R0 直接 ACCEPT(纯函数 + 10 单测)/ **ISS-021 R2 ACCEPT(R1 CONDITIONAL → R2 ACCEPT)** | 14(merge.rs:10 ISS-013 基线 + **+4 ISS-021 全 14 Hard kind 矩阵**)+ 6(rule_sync.rs:4 基线 + **+2 ISS-021 跨 crate alias / count**) |
| 0014 | Tauri GUI 同进程 embed Hub | ISS-019 Phase 1+2(v0.4 短轮询 fallback)+ **v0.5 P1 α1+α2+α3+α4 全实施**(commits `9cc55c7` / `cb6becd` / `aa410bf`)| **Accepted(α1-α4 Implemented;β1+ 留 v0.6)** | α1 R0(embed.rs gui-feature-gated)/ α2 R0(C3 thin-wrapper 选定,Hub.resolve_approval Ledger-first + publish-after)/ α3 含于 α2(Condvar wakeup < 100ms)/ α4 R0(Option C 进程级 e2e + CI matrix)| 17(approval_cross_proc_wait.rs:3 + serve_smoke b2:1 + embed_hub_skeleton:4 + embed_hub_resolve_approval:4 + vigil-mcp resolve_approval:4 + e2e-embed-approval wakeup gate:1)|

**注**:ADR 头部仍写 `Proposed` 的(0006-0010)以本文件为准,下一次该 ADR 扩展(I08b/c / I09b/c / I10b/c)时再在 ADR 正文追加 "Revised" 段落 + 新决策。

## 未落地子范围(追踪至对应 ADR)

| ADR | 延后子项 | 目标迭代 |
|----|----|----|
| 0007 | Linux Landlock(v1/v3 ABI 矩阵) | **I07.5**(延后,见 [I10a done 记忆]) |
| 0008 | Tauri 2 shell / Server Registry UI / Approval UI | **I08b / I08c** |
| 0009 | Chrome MV3 扩展 JS 代码 / E2E | **I09b / I09c** |
| 0010 | 真 HTTP transport(reqwest+rustls)+ JWKS 验签 | **I10b-α2**(见 ADR 0011) |
| 0010 | loopback redirect UX / refresh / opaque introspection | **I10b-β / I10c** |
| 0011 | issuer 绑定 + TokenStore sealed 契约重写 + 类型级 planner 强制 | **I10b-α1**(纯 Rust,无网络,先行) |
| 0011 | reqwest + rustls + JWKS 发现 + 签名验证 + 真 TLS 集成测试 | **I10b-α2** |
| 0011 | loopback redirect UX + 最小 token onboarding | **I10b-β** |

## Codex review 关键修复摘要

### ADR 0014 v0.5 P1 α1-α4 全实施(2026-04-30,Accepted)

**v0.5 P1 4 phases 一气推完**(commits `9cc55c7` α1 / `cb6becd` α2+α3 / `aa410bf` α4):

- **α1 GUI bin 持 Arc<Hub>**(`apps/desktop/src/embed.rs::gui_build_hub`,gui-feature-gated)
  - 7 步 Hub 装配,**不**再调 Ledger::open(避免 SQLite WAL 双 open 竞争)
  - app.manage(Arc<Hub>) 注册 Tauri State 给 α2 用
  - INVOKE_COMMANDS=21 不变(SSOT 三联冻结);守门测试 4 项
- **α2 + α3 Hub.resolve_approval + Condvar wakeup**
  - **关键决策 C3 thin-wrapper**(rejected α1 sketch A rename / B new name):handler `resolve_approval` 名保留,语义下沉到 vigil-mcp::Hub
  - Hub.resolve_approval:Ledger write 先(audit 永远不丢) → publish + Condvar notify_all 后(原子)
  - α3 wakeup 顺手交付:`hub_resolve_approval_wakes_waiter_under_100ms` 测试 < 100ms 通过
- **α4 e2e wakeup latency CI gate**
  - **关键决策 Option C 进程级**(rejected A tauri test harness alpha / B GUI dev IPC SSOT 污染):0 npm 依赖
  - `scripts/test-local/e2e-embed-approval/run.mjs` 132 LOC + GitHub Actions matrix
  - 实测 wakeup ~ 0.65ms / 100ms 阈值 = 150× 余量
  - macOS + 真 Tauri WebView e2e 留 v0.6

**ADR 0014 §3.4 fail-closed 不变量贯穿**:Hub 初始化失败 → GUI 拒启动;publish() 失败 → Tauri Error;ApprovalBroker panic → process abort
**ISS-019 Phase 1 短轮询 fallback 保留**:作为 cross-proc CLI bin 兜底(belt-and-suspenders)

### ADR 0012 v0.5 P2 模型分发实施(2026-04-30,Accepted-Implemented)

ADR 0012 §3.2-§3.7 全实施(commit `b5419b5`):

- §3.2 first-run-download 流程 ✓
- §3.3 cache 目录 `~/.vigil/models/<id>/<ver>/` ✓
- §3.4 MODELS_MANIFEST.json schema ✓(placeholder URL/sha256 待 v0.5.1 真 mirror 基建注入)
- §3.5 Mirror chain Primary(`mirror.vigil.ai`)→ Fallback HuggingFace CDN ✓(env `VIGIL_MODEL_MIRROR` 可覆盖)
- §3.6 16-chunk 并发 byte-range ✓(参考 ISS-001 spike 实测峰值 46 MB/s)
- §3.7 Runtime fail-closed ✓(网络/sha256/磁盘失败 → cli 启动失败,绝不静默 NoopEngine 降级)

10 mock-server 测试 / 4.07s 全过(happy / sha256 mismatch / ETag 304 / fallback / all-fail / 5 边界)。

### ADR 0014 Tauri embed Hub Stub(2026-04-28,v0.5 Planned 占位)
- **范围**:占位 ADR,记录 v0.4 ISS-019 Phase 1+2 短轮询 fallback 已 99% 覆盖 cross-proc approval 唤醒;完整 Tauri 同进程 embed Hub 重构推 v0.5(目标:approve 后 < 100ms 唤醒 vs 现 ≤ 500ms)。零代码改动,纯文档先行。
- **关键决策(待 v0.5 R1)**:
  - **D1 双 bin 分支**:GUI bin embed Hub(直接持 `Arc<Hub>`,Tauri command 通道)/ CLI bin 续 IPC + DB fallback(Claude Code/Codex/Cursor/Zed 不变)
  - **D2 fallback 保留**:ISS-019 Phase 1 短轮询作为 embed 路径的兜底保险,而非主路径
  - **D3 SSOT 三联延续**:I08b-β1 commands.rs/gui.rs/capabilities 三处同步纪律,新增 `resolve_approval` / `query_pending_approvals` / `subscribe_approval_events` 共 3 个 Tauri command
  - **D4 fail-closed**:Hub 初始化失败 → GUI 拒启动;ApprovalBroker panic → process abort
- **rejected alternatives**:Tauri sidecar 进程(仍跨进程,根因不解决)/ 共享内存 + futex(三平台实现差异大,与 SQLite ledger 双轨)
- **v0.5 子任务拆分**(ISS-019b α1-α4 + β1-β2,~ 2.5-4 天)
- **当前状态**:仅 stub 文档落盘(`docs/adr/0014-tauri-embed-hub.md`),v0.4 不据此提交代码改动

### ADR 0013 ISS-021 跨 crate 硬指纹 × PrivacyLabel sync 收尾(2026-04-25,wave-5 Stage 4 收官,R1 待 ACCEPT)
- **范围**:ADR 0013 Revised(硬指纹层最终定位 = fast-path + fallback)+ `RULE_PROFILE_VERSION` v4 → **v5** + 跨 crate `vigil_browser::FindingKind` ↔ `vigil_redaction::PrivacyLabel` 矩阵 golden 守门。零代码功能改动 —— 只加测试 + 文档 + version bump
- **5 处改动**:
  - `crates/vigil-browser/src/protocol.rs:22`:`RULE_PROFILE_VERSION` v4 → **v5**(版本注释加 v5 历史)
  - `crates/vigil-redaction/src/merge.rs`:**+4 单测**(`iss_021_hard_kind_to_privacy_label_golden` / `_merge_overlap_hard_wins_for_each_kind` / `_merge_no_overlap_both_kept_for_each_kind` / `_hard_kind_set_size_matches_redaction_rules`),全 14 Hard kind × PrivacyLabel × merge 决策矩阵
  - `crates/vigil-browser/tests/rule_sync.rs`:**+2 单测**(`iss_021_finding_kind_maps_to_privacy_label_via_alias` / `_finding_kind_count_matches_redaction_hard_rules`),显式 alias 表绑死短形(FindingKind::as_str())↔ 长形(HARD_RULES.name)
  - `docs/adr/0013-hardfp-model-merge.md`:文末追加 **Revised — ISS-021** 段(D-final-1/2/3 + 跨 crate 不变量表 + 短形/长形 alias 漂移点 + Profile 版本史)
  - `docs/adr/STATUS.md`:本 section + 状态一览表加 0013 行 + 0009 行追加 ISS-021 完成度
- **关键发现(Codex 视角对齐)**:
  - **短形 / 长形漂移**:`FindingKind::as_str()` 用短形(`aws_access_key` / `anthropic_key` / `openai_key`),vigil-redaction `HARD_RULES.name` 用长形(`aws_access_key_id` / `anthropic_api_key` / `openai_api_key`);本 ISS 用 alias 表绑死,改任一侧都会让测试 fail
  - **D-final-2 封闭映射**:14 Hard kind 全部能 from_kind → Some(PrivacyLabel),无未识别项
  - **D-final-1 全 kind 矩阵化**:把 ADR 0013 D3 一刀切细化到每条 Hard rule 的具体 merge 行为(同 span 重叠 Hard 赢 / 非重叠两侧保留 / risk 不双倍)
- **量化**:workspace 530 → **536**(merge.rs +4 + rule_sync.rs +2,零 regression);`cargo clippy --workspace --all-targets -- -D warnings` 零警告;`cargo fmt --all --check` 清洁
- **教训吸收**:延续 I09c 三批累积的"扩 FindingKind 必查 4 处"checklist;本 ISS 新加"加 PrivacyLabel variant 或改 HARD_RULES name 必查 1 处"——`crates/vigil-browser/tests/rule_sync.rs::alias` 表(SSOT,与 ADR 0013 Revised "alias 漂移点" 段联动)

### ADR 0005(I05)— R1/R2 REJECT → R3 ACCEPT
- R1 BLOCKER:drift 状态机缺 `Approved → DriftPending → ReapprovalPending` 闭环
- R2 MUST-FIX:server command drift(argv)未纳入状态机

### ADR 0006(I06)— R1 REJECT → R2 ACCEPT
- R1 BLOCKER:`PreparedChildEnv.env` 字段可复用泄漏,改为私有 + `take_env()` 一次性消费

### ADR 0007(I07)— R1/R2 REJECT → R3 ACCEPT
- R1 BLOCKER:`WasmRunner::engine` 跨 run 共享 → epoch bumper leak,改为 per-run Engine
- R2 MUST-FIX:Native runner `env_clear` 验证不足,补充审计断言

### ADR 0008(I08a)— R1/R2 REJECT → R3 ACCEPT
- R1 BLOCKER:UiCommand redact 范围遗漏 ToolArgs
- R2 MUST-FIX:旧 DB 无 `sandbox_profiles` 列 → 走 `COLUMN_MIGRATIONS` 幂等迁移

### ADR 0009(I09a)— R1/R2 REJECT → R3 ACCEPT
- R1 BLOCKER:`validate_browser_origin` 接受带 userinfo/path 的 origin → 严格拒绝纯 origin 以外形式
- R2 MUST-FIX:native-host framing length 上界未 clamp,补 `MAX_FRAME_BYTES`

### ADR 0011(I10b-α1 / α2 / β,设计审查)— R1/R3 REJECT → R2 CONDITIONAL → R4 ACCEPT
- **R1 BLOCKER**:issuer 绑定缺失 / planner 只是软约束 / sealed API 不够装 JWKS / "产品能力"范围不一致 / TLS 不变量 vs wiremock 测试方法不匹配 / Hub trait 化低估
- **R1 MUST-FIX**:`alg=none` feature 开关风险 / `kid miss` 刷新非 singleflight / `McpUpstream` trait 范围 / 审计事件语义模糊 / metadata-alive-secret-gone 语义 gap / 依赖策略 / STATUS.md 滞后
- **R2 修订**:采用 Path C 拆 α1 / α2 / β 三段;α1 重写 sealed 契约 + `AuthorizedSender` / `JwtKeyVerifier` / `JwksSource` 三 trait + issuer 四元组信任锚 §I-11.4 + singleflight §I-11.6 不变量 + `TokenRehydrateRequired` 独立语义 + webpki-roots 季度 checklist + cargo deny 禁 default-tls
- **R2 CONDITIONAL-ACCEPT 的两项遗留**:`feature = "i10a-compat"` 与 `alg=none` 不给 feature 冲突 / `ExpectedBinding.key_verifier: Option<_>` 生产态可不验签
- **R3 REJECT**:文档内部仍有两套说法("compat shim 已删" vs "α1 保留 α2 再删")
- **R4 ACCEPT**:彻底放弃 compat shim,α1 直接迁移 I10a 9 条 integration test,`AlwaysAcceptVerifier` 放 `tests/common/mod.rs`(test crate 本地,非 pub API 非 feature);`key_verifier` 必填;`iss = None` 映射稳定 reason code;nullable + 读侧 fail-closed 护栏明示

### ADR 0011 α1 代码交付(2026-04-21)
- **T1 issuer 列迁移**:`vigil-audit/src/ledger.rs::COLUMN_MIGRATIONS` + `registry.rs::register_oauth_token_metadata` 双处同步;nullable + 读侧 fail-closed;回归 3 条(idempotent_on_reopen / legacy_row_readable / rejects_empty_issuer)
- **T2 ExpectedBinding + JwtKeyVerifier + JoseHeader**:`ExpectedBinding.key_verifier: Arc<dyn JwtKeyVerifier>` 必填(非 Option);`DecodedAccessToken.iss: Option<String>` 仅 decode 容器;`decode_jwt_access_token` 返 `(JoseHeader, DecodedAccessToken)`
- **T3 sealed 契约 + I10a 9 条迁移**:`resolve_access_token(token_ref, &ExpectedBinding, now)` 按 8 步流程(metadata → issuer eq → value → decode → verifier → iss → claims → resolved);`AlwaysAcceptVerifier` 放 `tests/common/mod.rs`;无 compat shim 无 feature;新回归 5 条
- **T4 JwksSource trait + MockJwksSource**:缓存按 `(issuer, jwks_uri)` 双键(§I-11.4 不跨 issuer 共享);singleflight 语义写进 trait doc(α2 实装);3 条单测
- **T5 AuthorizedSender trait**:与 `HttpClient` 两条面独立 DI;`MockHttpClient` 同时实现;2 条 runtime smoke 验证 dyn-compatibility + 两 trait 类型不相容
- **T6 McpUpstream trait + UpstreamError**:`UpstreamError #[non_exhaustive]`(unary-only / 401 vs 403 分开 / JSON-RPC 只留 `message_sha256`);Hub `upstreams` 改 `Arc<dyn McpUpstream>`;`HubError::Upstream(#[from] UpstreamError)`;`StdioUpstream::call → call_raw / shutdown → shutdown_raw`(避免与 trait 同名冲突);2 条 unit + 2 条 integration 守门(消费者 crate 视角验证 `#[non_exhaustive]`)
- **T7 审计事件常量**:α1 新增 `EVENT_TOKEN_REJECTED_WRONG_ISSUER`;α2 预留 `EVENT_JWT_SIGNATURE_REJECTED` / `_VERIFIED` / `EVENT_JWKS_FETCHED` / `_AS_METADATA_FETCHED` / `EVENT_HTTP_UPSTREAM_REQUEST_SENT` / `_FAILED`(6 条);`HttpAuthEvent` enum `#[non_exhaustive]`
- **守门**:`git grep "AlwaysAcceptVerifier" crates/vigil-http-auth/src/` 仅 doc 注释引用(合法);`git grep "i10a_compat\|i10a-compat"` 全部禁止性表述;测试 297 → **313**(+16),fmt / clippy -D warnings 零警告

### ADR 0009 I09c-规则扩展第三批(database_url 含凭证) R1 ACCEPT(2026-04-23,一轮通过)
- **范围**:I09c 第三批 —— 在前两批(Slack/Stripe 硬形态 + Google/GitLab 前缀形态)基础上扩 1 条**结构化硬指纹**:含凭证的 database URL(`scheme://user:password@host[:port][/path]`)。FindingKind 12 → **13**
- **技术决策(本轮主动收敛)**:ADR 0009 C7 原列 I09c+ 候选三项(email / phone / database_url),本轮只实装 database_url ——
  - `database_url` 是**结构化硬指纹**:必须含 `user:password@`,误报率低,适配现有 ALL_RULES/HARD_RULES 硬形态框架
  - `email` / `phone` 是**语义指纹**:纯 regex 误报率高(所有邮件签名 / 客服地址 / 正常业务都会触发),必须配套"熵评分 / 软规则层 / 上下文判定"新子系统 → 推迟到 I09c++(或 I11)
- **5 文件改动**(完全沿用第一/第二批验证过的同形 checklist):
  - `crates/vigil-redaction/src/lib.rs`:ALL_RULES + HARD_RULES 各加 `database_url` regex
  - `crates/vigil-browser/src/protocol.rs`:`FindingKind::DatabaseUrl` + `as_str()` 同步 + `RULE_PROFILE_VERSION` v3 → **v4**(补版本历史注释 v4 = I09c 第三批 13 kinds)
  - `crates/vigil-browser/src/classifier.rs`:`map_rule_name` +1 arm + **3 新 tests**(含凭证 redact / **无凭证不匹配(误报抑制)** / mongodb+srv longest-first)
  - `crates/vigil-browser/tests/rule_sync.rs` 三处(SAMPLES / all_kinds / contract)+1 同步
  - `crates/vigil-browser/tests/audit_strings_golden.rs`:as_str 断言 +1 + count match 扩至 13
- **regex 设计要点**:
  - 必须含 `user:password@` 才匹配(`postgres://host/db` 不触发)—— 凭证是必要条件
  - scheme 白名单 **longest-first**:`postgresql > postgres` / `mongodb+srv > mongodb` / `rediss > redis` / `amqps > amqp`(regex alternation 顺序敏感,防前缀被短 scheme 先吃)
  - password 允许非 `@`/非空白字符(含 URL-encoded `%XX`、特殊符号);host 收紧到 `[A-Za-z0-9.\-]` 防粘连
  - 有意收紧:**不匹配 IPv6 literal / 下划线 host**(Codex 确认为设计选择,不是 bug)
- **Codex R1 ACCEPT**(2026-04-23,一轮通过,无 MUST-FIX):
  - 主链路闭合(5 文件同步 + v3→v4 bump + 13 kinds 一致)
  - regex 设计合理(必须凭证 + longest-first + password/host 字符集)
  - 测试覆盖达标(3 新 classifier + rule_sync + golden 共同守门)
  - 版本语义正确(新增 FindingKind 同步 bump)
  - 2 NICE 级残余(不阻塞):① IPv6/下划线 host 未覆盖(设计选择,后续 DSN 形态扩展时重新评估) ② vigil-redaction 自身未加针对 database_url 的单测(classifier 端到端 + cross-crate 已足够)
- **累积教训吸收**(三批累积,全到位):
  - 第一批 R1 教训(rule_sync 三处 + VERSION bump)→ 第二/三批一次性到位
  - 第二批 R1 教训(contract 长度守门)→ 第三批自动生效
  - 第二批 R2 教训(文档同步是 R2 必备)→ 本 section + ADR 0009 Revised 同批完成
- **量化**:workspace 429 → **432**(+3 新 classifier 测试,零 regression);`cargo clippy --workspace --all-targets -- -D warnings` 零警告

### ADR 0009 I09c-规则扩展第二批(Google API key + GitLab PAT) R1 REJECT → R2 REJECT(文档) → R2 ACCEPT(2026-04-23,与第一批同日)
- **范围**:I09c 第二批 —— 在第一批(Slack/Stripe)之上继续扩 2 条硬指纹规则,10 → 12 FindingKind;兑付 ADR 0002 §D1"承诺外"但高频场景(Google 系 AIza + GitLab glpat)
- **4 文件改动**(纯 Rust,与第一批同形同构):
  - `crates/vigil-redaction/src/lib.rs`:ALL_RULES + HARD_RULES 各加 `google_api_key`(`\bAIza[A-Za-z0-9_\-]{35}\b`,AIza + 35 chars = 39 total)+ `gitlab_pat`(`\bglpat-[A-Za-z0-9_\-]{20,}\b`,glpat- + 20+ chars)
  - `crates/vigil-browser/src/protocol.rs`:`FindingKind` +2 variants(`GoogleApiKey` / `GitlabPat`)+ `as_str()` 同步 + `RULE_PROFILE_VERSION` v2 → **v3**(补版本历史注释 v3 = I09c 第二批)
  - `crates/vigil-browser/src/classifier.rs`:`map_rule_name` +2 映射 + 3 新 tests(google redact / gitlab redact / **google + env_assignment 共存验证**)
  - `crates/vigil-browser/tests/{rule_sync,audit_strings_golden}.rs`:SAMPLES / all_kinds / contract 10→12 同步(吸收第一批 R1 教训,一次性同步到位);golden count match 扩 10→12
- **Codex R1 REJECT**(1 MUST-FIX + 1 NICE):
  - MUST-FIX:`classifier_google_key_does_not_trigger_env_assignment_only` 断言不完整 —— 只 assert GoogleApiKey 存在,未 assert EnvAssignment 共存,redacted_text 也未检查
  - NICE-TO-HAVE:`rule_sync.rs` `finding_kind_stable_rule_name_strings` 的 contract 未像 SAMPLES 那样被长度守门
- **R1 修复**:
  - MUST-FIX:测试改名 `classifier_google_key_coexists_with_env_assignment` + 三断言(GoogleApiKey ∈ findings / EnvAssignment ∈ findings / redacted_text 不含原文 `AIzaSy...`)
  - NICE-TO-HAVE:contract 末尾加 `assert_eq!(contract.len(), SAMPLES.len(), ...)` —— 链式守门(contract == SAMPLES == all_kinds,SAMPLES 已由 `finding_kind_enum_exhaustive` 与枚举绑定 → contract 间接与枚举强绑)
- **Codex R2 REJECT(文档层)**(2 MUST-FIX):代码层面两处修复对位,但 STATUS.md + ADR 0009 未同步 I09c 第二批
- **R2 修复**(本 section 自身 + ADR 0009 Revised 段)
- **Codex R2 ACCEPT**(文档修复后)
- **关键策略核对**:Google `AIza` 前缀 vs OpenAI `sk-` / Anthropic `sk-ant-` / Stripe `sk_`(无字符冲突);GitLab `glpat-` 前缀独占命名空间
- **量化**:workspace 426 →  **429**(+3 新 classifier 测试,零 regression;`cargo clippy --workspace --all-targets -- -D warnings` 零警告)
- **R1 教训**(第一批 + 第二批累积):扩 FindingKind 必查 4 处:`rule_sync.rs`(SAMPLES/all_kinds/contract)+ `audit_strings_golden.rs`(as_str + count)+ `RULE_PROFILE_VERSION` bump + **文档(STATUS.md + ADR Revised)同步**

### ADR 0009 I09c-规则扩展(Slack webhook + Stripe secret key) R1 REJECT → R2 ACCEPT(2026-04-23)
- **范围**:I09c 第一块 —— 兑付 ADR 0002 §D1 明示"I01 承诺范围"不含的 Slack / Stripe 两类硬指纹规则
- **4 文件改动**(纯 Rust):
  - `crates/vigil-redaction/src/lib.rs`:ALL_RULES + HARD_RULES 各加 `slack_webhook`(`hooks.slack.com/services/T.../B.../...`)+ `stripe_secret_key`(`sk_(live|test)_...`)regex
  - `crates/vigil-browser/src/protocol.rs`:`FindingKind` +2 variants(`SlackWebhook` / `StripeSecretKey`)+ `as_str()` 同步 + `RULE_PROFILE_VERSION` v1 → **v2**(补版本历史注释)
  - `crates/vigil-browser/src/classifier.rs`:`map_rule_name` +2 映射 + 3 新 tests(slack redact / stripe live+test redact / **stripe 不误伤 anthropic `sk-ant-`**)
  - `crates/vigil-browser/tests/audit_strings_golden.rs`:golden 8 → 10 variants + count match 扩
- **Codex R1 REJECT**(2 MUST-FIX):
  - `rule_sync.rs` 三处(SAMPLES / all_kinds / contract)漏同步 → "新增 variant 必漏测"目标失效
  - `RULE_PROFILE_VERSION` 未 bump → 违反 protocol.rs 自声明"新增 finding 或调整策略时 bump"的审计可追溯语义
- **R1 修复**:
  - `rule_sync.rs` 三处全部同步(SAMPLES 8→10 + all_kinds 扩 + contract 10 条)
  - `RULE_PROFILE_VERSION` v1 → v2;补"v1 = I09a 8 kinds / v2 = I09c 10 kinds"版本历史
- **Codex R2 ACCEPT**(1 微注:rule_sync.rs 旧注释 "enum is non_exhaustive" 措辞不准 → 顺手精准化)
- **关键策略核对**:Stripe `sk_`(下划线) vs Anthropic `sk-ant-` + OpenAI `sk-`(连字符) —— 字符集隔离,`classifier_stripe_live_does_not_match_anthropic` 回归守门
- **量化**:workspace 423 → **426**(+3 新 classifier 测试,零 regression)

### ADR 0009 I09b-α4 session-scoped 豁免 R1 ACCEPT(2026-04-23,self-review 修 2 MUST-FIX → Codex 复核 ACCEPT)
- **范围**:用户主动豁免当前 tab + origin 短期跳过守门(session-scoped escape hatch)。MV3 扩展最后一块 UX 拼图
- **3 文件改动**(纯前端):
  - `manifest.json`:permissions +`activeTab`(**选 activeTab 而非 tabs** 作最小权限 —— popup 打开时自动授予当前 tab 的 URL + id,不读其它 tab)
  - `background.js`:`exemptMap: Map<"tabId|origin", until_ms>` + `EXEMPT_MAX_MS=10min` / `EXEMPT_MIN_MS=30s` clamp;`vigil_check` hook 命中豁免直接 allow 不走 Host + findingsLog 记 `action: "allow_exempt"`;3 新 API(get/set/clear);`chrome.tabs.onRemoved` 清该 tab 所有豁免项
  - `popup.html/.css/.js`:新 exempt-section + 状态文字 + 3 按钮(5m/10m/结束豁免)+ 倒计时;`loadCurrentTab` 非 http(s) 禁按钮;2s 合并 refresh
- **安全约束清单**:
  - **硬上限** `EXEMPT_MAX_MS = 10min`(SW 内部 clamp,防误操作长期失守)
  - **tab+origin 双绑**:key `${tabId}|${origin}` —— cross-origin iframe 自然隔离;SPA pushState 改 URL 但 origin 不变时豁免保留
  - **in-memory only**:exemptMap 不落 chrome.storage;Chrome 杀 SW 即清零(重启浏览器恢复守门)
  - **tab 复用防御**:`chrome.tabs.onRemoved` 立即清该 tab 所有豁免
  - **defense-in-depth**(self-review MUST-FIX 1):SW `vigil_set_exempt` 内部校验 `origin.startsWith("http(s)://")`,popup UI + SW 双守 —— 即使 popup 被绕过以 `file://` 等作 origin 调 API 也拒 invalid_params
  - **审计可见**(self-review MUST-FIX 2):findings log 记 `action: "allow_exempt"` + popup.css 新增 `.tag-allow_exempt`(warning 色)让审计员视觉区分"守门放行 vs 用户豁免放行"
  - **sender.tab.id 真**:Chrome 运行时元数据,content-script 无法伪造
- **ADR 0009 §I-9 影响**:不受影响(豁免只跳过 Host 调用;`checkWithHost` 早退守门路径未改;无新数据流入 storage/log)
- **Self-review 过程**(Codex MCP 连续 5 次不可用期间):对原拟 7 个关注点逐条自查,发现 2 项 MUST-FIX:
  1. popup.css 缺 `.tag-allow_exempt` 类 → 已补 warning 色 + 深色文字
  2. SW `vigil_set_exempt` 未校 origin 协议 → 已补 defense-in-depth(`origin.startsWith("http(s)://")`)
- **Codex 正式 R1 ACCEPT**(服务恢复后复核):实装从安全角度收敛;无 BLOCKER / MUST-FIX;1 NICE 可加固但不强制 —— `vigil_set_exempt/get/clear` 可在 SW 侧对 `msg.tab_id` 与 `sender.tab.id`(popup 是扩展 context 无 sender.tab,需用 `chrome.tabs.get(msg.tab_id).url` 解 origin)做交叉校验;当前威胁模型(同扩展内部通信,`chrome.runtime.sendMessage` 不跨扩展)下够用,未补
- **验收**:`cargo fmt/clippy --workspace --all-targets -- -D warnings` ✅;`cargo test --workspace --no-fail-fast` **423 passed / 0 failed**(纯 JS,零 Rust regression)

### ADR 0009 I09b-α3 popup + options UX 增强 R1 ACCEPT(2026-04-23,一轮通过)
- **范围**:最小 UX 增强 —— ① popup 展示最近 findings(origin / event_kind / action / findings enum) ② options page 展示扩展 ID + `vigil-native-host install` 命令可复制(桥接 β1 CLI 的 `<ID>` 参数来源)
- **主动收缩**(避免扩权):**不加** storage / tabs / activeTab 权限;**不做** session-scoped 豁免 / 用户自定义 host 白名单(留 α4/β);permissions 仍 `["nativeMessaging"]`
- **7 个新/改文件**:
  - `manifest.json`:`action.default_popup` + `options_ui`,零新权限
  - `background.js`:+ in-memory 环形队列 `findingsLog`(上限 32,shape 仅脱敏元数据 `{ts, origin, event_kind, action, findings[]}` 不记 `text`)+ `vigil_recent_findings` / `vigil_clear_findings` 两新 msg.type API
  - **新** `popup.html` / `popup.css` / `popup.js`:list 展示,2s 轮询 refresh,全程 `textContent` + `document.createElement` + `replaceChildren`
  - **新** `options.html` / `options.css` / `options.js`:`chrome.runtime.id` 展示 + Unix/Windows 两份 install 命令 + `navigator.clipboard` + `execCommand('copy')` fallback
- **ADR 0009 §I-9 契约守门**(延续):
  - §I-9.1:findings 环形队列**仅脱敏元数据**;不记原文;不落 chrome.storage
  - CSP `script-src 'self'`:popup/options 外链 JS + CSS,无 inline script / handler
  - XSS 不变量:所有动态插入走 textContent + createElement(含 `chrome.runtime.id` 亦作纯文本)
  - sendMessage 分流清晰(`vigil_check` async / `vigil_recent_findings` + `vigil_clear_findings` 同步)
- **Codex R1 ACCEPT**(0 BLOCKER / MUST-FIX;2 NICE:`flashHint._t` 函数属性微洁净问题 / popup 冷启动短暂空闪烁 UX 可选优化)
- **验收**:workspace **423 passed / 0 failed**(纯前端,零 Rust regression)

### ADR 0009 I09b-β1 Chrome Native Messaging Host 三平台注册脚本 R1 REJECT → R2 ACCEPT(2026-04-23,α1 README 延后项兑付)
- **范围**:兑付 I09b-α1 README 明示的 "Host manifest 注册脚本延 β" —— 没有 Host 注册用户无法真装真用,扩展 fail-closed 全部 block
- **3 文件改/新 + Cargo.toml**:
  - `apps/native-host/Cargo.toml`:新 dep `clap`(workspace)+ `dirs="6"`;Windows-only `winreg="0.55"`。均已在 Cargo.lock(tauri transitive)零新网络下载
  - **新** `apps/native-host/src/install.rs`(lib 模块):`HOST_NAME = "com.vigil.host"` / `InstallConfig` / `InstallError` 结构化错误 + Display 脱敏 / `validate_extension_id`(32 chars a-p)/ `render_manifest` / `manifest_dir_{macos,linux}` DI 纯函数 / `install`/`uninstall`/`status` 三平台 cfg 分流 + 幂等 + Windows HKCU 注册表读写
  - `apps/native-host/src/lib.rs`:`pub mod install;` + 新 `pub fn is_admin_subcommand(args)`(R1 BLOCKER 修复核心)
  - `apps/native-host/src/main.rs`:clap 子命令改造(`install`/`uninstall`/`status`),默认 `is_admin_subcommand(&argv)` 先判再 `Cli::parse`,Chrome argv 路径走 `run_stdio_loop`
- **Codex R1 REJECT**(1 BLOCKER + 1 NICE):
  - **BLOCKER**:Chrome 启动 Host 传 `argv[1] = <extension origin>`(Linux/macOS),Windows 额外 `argv[2] = --parent-window=<HWND>`;原 `Cli::parse()` 吃到未知 subcommand exit 2,扩展 onDisconnect "Specified native messaging host not found" —— 整个 install 流程对 Chrome 实际不可用
  - **NICE**:相对路径策略表述越权 —— Chrome 只在 Linux/macOS 强制绝对,Windows 允许相对 manifest 目录;我们收紧为跨平台绝对是 Vigil 项目策略,不应冠以"Chrome 规范"
- **R1 修复**:
  - 抽 `pub fn is_admin_subcommand(args: &[String]) -> bool` 纯函数:仅对白名单字面量(install/uninstall/status/help/--help/-h/--version/-V)返 true;其它 argv 一律 fallback run_stdio_loop。`main()` 先调本函数再决定是否走 clap
  - **6 新单测**(lib.rs 底部 `argv_dispatch_tests`,满足 `clippy::items-after-test-module`):覆盖无参 / Chrome origin / Windows --parent-window / 管理员子命令 / help/version 标志 / 未知 argv fallback
  - ExePathNotAbsolute 的 doc + Display + 模块/main.rs 顶部注释改写为"Vigil 项目策略",明确 "Chrome itself requires absolute on Linux/macOS, allows relative on Windows" 边界
- **Codex R2 ACCEPT**:两项修复完整;R1 其它通过项(扩展 ID 校验 / 错误脱敏 / 幂等 / DI 覆盖)未回退;唯一残余提醒:未来新增管理员子命令需同步更新白名单 + 测试
- **量化**:workspace β1 前(I09b-α2 完成)408 → β1 完成(R2)**423**(+15 新测 = 9 install 单测 + 6 argv_dispatch 单测);既有 8 acceptance tests 未改。R1 中间时点曾出现 416(`vigil-http-transport` 既有 singleflight e2e 时序 flake 命中 1 条,`concurrent_refresh_legacy_no_expires_at_also_singleflights`,隔离重跑立即过,与 α3 / I09b-α1 遇到同一 flake),R2 时未重现
- **发行前仍需**:三平台打包脚本(产出绝对路径的 exe 位置)/ 用户体验"一键装"(封装 `vigil-native-host install --extension-id <ID>` 为图形向导)

### ADR 0009 I09b-α2 站点深度选择器 + form-level redact R1 REJECT → R2 ACCEPT(2026-04-23,α1 遗留简化升级)
- **范围**:兑付 α1 明确标记的两项"MVP 简化 → α2 升级"——① 4 host 站点深度 selector 替代通用 textarea 降级,② form-level redact 真写替代 α1 降级 block
- **1 文件改动**:`extensions/chrome-mv3/content-script.js`
  - 新 `siteAdapters` 注册表:ChatGPT(`#prompt-textarea` + `div.ProseMirror[contenteditable="true"]` + `[role="textbox"]` 兜底)/ Claude(`ProseMirror` + role) / Gemini(`rich-textarea` 内 contenteditable + `ql-editor` 兜底) / Perplexity(`textarea[placeholder*="Ask"]` + `main textarea` + contenteditable 兜底);未注册 host → 回退 α1 通用
  - `collectSubmitPayload` 签名从 `(target) => string` 改为 `(target) => { text, primaryInput }`,form-level redact 路径可写回精确主输入
  - submit listener 三态分支:redact 且 primaryInput 非 null → 真写 + site-label toast;primaryInput=null → 保留 α1 降级 block(heterogeneous form fail-safe)
- **Codex R1 REJECT**(1 BLOCKER):初版 `site.findPrimaryInput(document)` 在全 document 搜,可能返页面其它 editor —— 决策元素 ≠ 提交元素:allow 场景下原 form 文本未改直接 submit(bypass),redact 场景下写错字段
- **R1 修复**:
  - SiteAdapter typedef 签名收紧为 `(root: ParentNode) => Element | null`,JSDoc 明示 "root 必须是被提交的 form,不能是 document"
  - `collectSubmitPayload` 改 `site.findPrimaryInput(target)` 把 form 作 scope 传入(`form.querySelector` 天然子树 scope)
  - 二次 sanity `target.contains(primary)`(防未来 findPrimaryInput 扩展 shadow DOM 等外部搜)
  - 找不到 → **不回退 document 全局搜**(Codex 要求),直接走 α1 form.elements 聚合 + primaryInput=null 禁 redact 回写
- **Codex R2 ACCEPT**(1 Minor doc drift:顶部注释还写 `findPrimaryInput(document)` —— 已顺手清理)
- **设计延续**:
  - adaptTarget 白名单(password/hidden/file 跳过)不变
  - allow-once WeakSet + requestSubmit(submitter) 不变
  - 早退四守门 + ErrorFrame 分流 + toast XSS 守门 全部保持
- **验收**:workspace **408 passed / 0 failed**,零 Rust regression(纯 JS 改)
- **残余观察**:
  - 站点 selector 会随站点改版漂移,β Playwright E2E 可作为回归触发器
  - Gemini shadow DOM / web component 封装若加深,现有 rich-textarea querySelector 可能失配 → 走 form-scoped 降级
  - Enter submit allow 仍走 `execCommand("insertLineBreak")`(R1 α1 标为可接受 MVP 折衷,β 换 trusted event dispatch)

### ADR 0009 I09b-α1 Chrome MV3 扩展 JS 实装 R1 REJECT → R2 ACCEPT(2026-04-22,I00 占位升级真 scaffold)
- **范围**:ADR 0009 Chrome MV3 扩展 JavaScript 侧实装起步 —— I09a Native Host(Rust)已 ACCEPT,本轮把 I00 空壳 `extensions/chrome-mv3/` 升级为真 MV3 最小闭环(纯 vanilla JS,零 npm 依赖,"文件就绪版")
- **3 文件改动**:
  - `extensions/chrome-mv3/manifest.json`:v0.0.1 占位 → v0.1.0 真 MV3(`host_permissions` 4 host + `content_scripts` 注入 + `content_security_policy.extension_pages: "script-src 'self'; object-src 'self'"`);**permissions 最小化仅 `nativeMessaging`**(R1 MUST-FIX 3 削减 activeTab/scripting/storage)
  - `extensions/chrome-mv3/background.js`:service worker,`chrome.runtime.connectNative("com.vigil.host")` 长连接 + pending-request Map + UUIDv4 `request_id` + 10s TTL GC;**ErrorFrame 按 error 字段优先分流**(兼容 Rust `BrowserErrorFrame.request_id: Option`):有 reqId 精准路由 block / 无 reqId 所有 pending fail-closed block + clear(R1 MUST-FIX 2)
  - **新建** `extensions/chrome-mv3/content-script.js`:3 路径(paste / submit / contenteditable Enter)+ `adaptTarget`(textarea/input/contenteditable,`password/hidden/file` 跳过)+ simple `textContent` toast(info/warn/error 三色,inline 样式拒 CSS 覆盖)+ **submit allow 走 `form.requestSubmit(submitter)` + `WeakSet` allow-once**(R1 MUST-FIX 1 保留 HTML validation + 其他 submit listener)
  - `extensions/chrome-mv3/README.md`:完整文档(范围 / Native Host 注册路径三平台 / §I-9 安全契约核对表 / α2/α3/β 后续规划)
- **协议对齐**:JSON 字段 / `action` / `event_kind` / `findings` 严格对 `crates/vigil-browser/src/protocol.rs`;Codex R1 验证通过(无漂移)
- **ADR 0009 §I-9 契约核对**:
  - §I-9.1 原文 in-memory only:SW/CS 无 `chrome.storage.set` / `console.log(text)` / `window.*[text]` 出口
  - §I-9.3 特权 scheme fail-closed:SW 对非 http(s) origin / 非法 event_kind 早退 block(双守门)
  - §I-9.5 1 MB 帧上限:Host 层规范化;SW 做 32 MB 字符早退防 postMessage 异常
  - §D6 三态原样执行;非法/错误/timeout 全部 fail-closed block
  - toast 防 XSS:`textContent` 赋值 + inline 样式字面量(无 innerHTML)
- **Codex R1 REJECT**(3 MUST-FIX):
  - form.submit() 绕 HTML validation + 其他 submit listener(真 behavioral regression)
  - ErrorFrame 无 request_id 时只能等 TTL 才 fail-closed
  - manifest 超权(activeTab/scripting/storage 未用)
- **R1 修复 → R2 ACCEPT**:
  - `WeakSet allowedOnce` + `form.requestSubmit(submitter)` 保留 validation + listener 参与,allow-once 消费防循环
  - `onHostMessage` 分流顺序调整:先 error 再 request_id,Option reqId 的错误帧即时 fail-closed 全 pending(stream-level 协议错误保守选择)
  - manifest permissions = `["nativeMessaging"]`(削减 3 条)
- **已知 α2/α3/β 留项(README + 代码内注释已标)**:
  - α2:按站点深度选择器(ChatGPT `#prompt-textarea` 等)替代通用 textarea 降级 / form-level redact 真写 / allow-once 更稳健的 dispatch 机制
  - α3:popup UI + 用户临时豁免 / options page
  - β:Playwright E2E(真 Chrome + 构造 hard-secret) / 三平台 Host manifest 注册脚本 / 打包 CI
- **验收**:`cargo fmt/clippy --workspace` 全绿;`cargo test --workspace` **408 passed / 0 failed + 1 既有 flake**(vigil-http-transport singleflight 时序测试,α3 也遇到过,隔离立即 pass,非 I09b regression);JS 文件点验留给用户 Chrome `load unpacked`

### ADR 0008 I08b-β5 Ledger 磁盘持久化 R1 REJECT → R2 ACCEPT(2026-04-22,审计跨会话不变量兑付)
- **范围**:GUI 启动从 `Ledger::open_in_memory()` 切换到磁盘持久化,兑付 ADR 0002 §I-2.1 "审计不变量"跨会话要求 —— 进程退出审计链不丢
- **3 文件改动**:
  - `apps/desktop/Cargo.toml`:新 optional dep `dirs = { version = "6", optional = true }`(gui feature gated;仅 tauri transitive 已在 Cargo.lock,零新网络下载)
  - **新** `apps/desktop/src/ledger_path.rs`:lib 模块,**默认 feature 下编译 + 测试**
    - `resolve_ledger_path(env_override, local_data_dir) -> Result<PathBuf, LedgerPathError>` **依赖注入** pattern
    - 常量导出 `LEDGER_ENV_VAR = "VIGIL_LEDGER_PATH"` / `VIGIL_SUBDIR = "Vigil"` / `LEDGER_FILENAME = "ledger.sqlite3"`
    - 结构化错误枚举 `{ MissingLocalDataDir, ParentDirCreateFailed { parent } }` + Display 脱敏(不透 io::Error 原文)
  - `apps/desktop/src/bin/gui.rs`:main 改写,binary 仅查询 `dirs::data_local_dir()`,路径解析 + 错误处理全走 lib;fail-closed `exit(1)` 不回退 `open_in_memory`
  - `apps/desktop/src/lib.rs`:`pub mod ledger_path;` 带 `///` outer doc
- **选择 `data_local_dir()` 而非 `data_dir()`**:ledger 本机审计数据不应 roam 跨机(Windows `%LOCALAPPDATA%` vs `%APPDATA%\Roaming`;macOS/Linux 等价)
- **Codex R1 REJECT**(1 BLOCKER):初版 helper 内联 gui.rs,**默认测试矩阵不覆盖**"关键安全入口";重演 β1 "测试与生产分叉"教训前的陷阱
- **R1 修复**(抽 lib 模块 + DI pattern):
  - 逻辑 100% 挪入 `ledger_path` lib 模块,gui.rs main 仅取 env + `dirs::data_local_dir()` 注入
  - 8 新单测覆盖所有分支:env override 优先级 / trim 空白回退 / trim 真生效 / fallback vigil 子目录构造 / `MissingLocalDataDir` 两条 fail-closed 路径 / `ParentDirCreateFailed`(用"文件作障碍"trick 跨 Windows/Linux 稳定失败)/ Display 脱敏(含 env 提示 + 含 parent 路径 + 不含 "os error" / "Permission denied" 原文)
  - R1 NICE 修复:`env_override.trim()` 结果**真的用于** `PathBuf::from` 而非原值
- **Codex R2 ACCEPT**(残余观察:默认测试守住"路径解析 + 错误脱敏",`Ledger::open(...)` 失败时 stderr 文案仍仅靠 review 覆盖,非本轮 blocker)
- **量化**:workspace 400 → **408**(+8 单测);零 regression;default feature 不编 gui / 不拉 dirs

### ADR 0008 I08b-β3 EffectKind TS enum 建模 R1 REJECT → R2 ACCEPT(2026-04-22,α2 遗留 NICE 债务兑付)
- **范围**:兑付 α2 R2 文档"遗留 NICE:EffectKind 未建模 TS enum"。β2 specta(Cargo.lock 无,环境"禁 heavy install")暂搁,先做纯前端强类型化。零新依赖,零 Rust 改动
- **2 文件改动**:
  - `apps/desktop/ui/src/api/ipc.ts` —— 新增 `EffectKind` 字面量 union(11 variants 严格对 `vigil_types::effect.rs::EffectKind` PascalCase serde)+ 新 helper `effectKindTagMeta` 集中色彩/label 映射 + `EffectVector.effects` 从 `string[]` 强类型化为 `EffectKind[]`
  - `apps/desktop/ui/src/components/ApprovalDetailDrawer.vue` —— 顶部 typed tags(中文 label + 原字面量并列)+ destructive/reversible 独立徽章 + 分段列表(paths_read/write / network_hosts / secret_refs / recipients,非空才渲染)+ 原 JSON pretty-print 改为 `<details>` 折叠作透明性附注
- **Codex R1 REJECT**(1 MUST-FIX):
  - 注释错误声称"TS 会在 Rust 新增 variant 且 TS 未同步时编译失败" —— `const _exhaustive: never = kind` 只守"TS union → switch 穷尽",不具备跨 Rust/TS 自动同步检测能力
- **R1 修复**(仅文档措辞,代码行为不变):
  - `EffectKind` union 文档新增"跨语言同步守门的范围澄清"子段,明确三点:TS 编译器看不到 Rust 变更 / 真跨语言守门等 β2 specta / 手工同步 + code review 是当前唯一机制
  - `effectKindTagMeta` default 分支注释改为精确描述 TS-内部穷尽 + 运行时 default 色兜底
- **Codex R2 ACCEPT**:措辞准确区分"TS-内部守门" vs "Rust ↔ TS 跨语言同步",不再冒充跨语言检测器
- **设计取舍**:ApprovalQueue 列表页未同步(仅 drawer/详情页改动),与 α2 原分工(列表 title/summary/status,详情 effect_vector)一致
- **残余观察**:跨语言同步仍靠手工 + code review,β2 specta 落地前是唯一方案
- **验收**:`cargo fmt/clippy --workspace --all-targets -- -D warnings` ✅,`cargo test --workspace` **400 passed / 0 failed**,零 regression(纯前端改动)

### ADR 0008 I08b-β1 Tauri AppManifest 真 command 白名单 R1 REJECT → R2 ACCEPT(2026-04-22,α1 遗留技术债兑付)
- **范围**:兑付 I08b-α1 R1 明确延期的 "AppManifest::commands 构建期真白名单 gate";从 α1 的"软白名单(仅 generate_handler! 宏展开)"升级为 hard-gate(未列入白名单的 handler frontend invoke 被 ACL 拒绝)
- **4 个改/新文件**:
  - **新** `apps/desktop/src/commands.rs` —— SSOT `INVOKE_COMMANDS: &[&str]`(19 条)+ 4 守门单测(count / unique / well_formed / capability_json_allow_set);**文件头用 `//` 而非 `//!`**,因 build.rs 通过 `include!` 把文件插入构建脚本中段,`//!` inner-doc 在非顶层触发 E0753
  - **改** `apps/desktop/src/lib.rs` —— `pub mod commands;`(带 `///` outer doc 满足 `#![deny(missing_docs)]`)
  - **改** `apps/desktop/build.rs` —— 顶部 `include!("src/commands.rs")` 共享 SSOT;`#[cfg(feature = "gui")]` 块内从 `tauri_build::build()` 改为 `try_build(Attributes::new().app_manifest(AppManifest::new().commands(INVOKE_COMMANDS)))`;保留 `cargo:rerun-if-changed=src/commands.rs`
  - **改** `apps/desktop/capabilities/default.json` —— 追加 19 条 `"allow-<slugified>"` app permission(无前缀 = APP_ACL_KEY;slugified = underscore → hyphen,`tauri-utils::acl::build.rs:290`);description 改写为 β1 白名单语义
- **Codex R1 REJECT**(1 Medium + 1 Low):
  - **Medium**:守门仅 count/unique/well_formed 3 测,缺"SSOT ↔ capabilities/default.json 精确集合一致性"——replace-without-count-change 场景会静默通过
  - **Low**:`gui.rs` 头部和 `README.md` 仍写 "α1.5 补齐 AppManifest 级 gate" / "α1 不做 app-command 级白名单",与已落地的 β1 矛盾
- **R1 修复**:
  - 新增 `capability_json_allow_set_matches_invoke_commands` 测试:读 JSON 手工扫 `"allow-*"` 字符串(避免引入 serde_json dev-dep 仅为一个测试)+ 生成 `INVOKE_COMMANDS` slugified 期望集合 + 双向 diff;`missing_in_cap` 或 `extra_in_cap` 任一非空即 fail
  - `gui.rs` 头部安全不变量段重写:明示 β1 hard gate + SSOT 定位 + 单测守门;"已知未实装"改为 β2+ 延后项
  - `apps/desktop/README.md` "安全不变量"升级为 α1-β1 累计;"已知延期项"移除 α1.5 全部条目,改为 β2-β5 + 发行前
- **Codex R2 ACCEPT**(残余风险:`generate_handler!` 宏展开无反射,三处对齐的 gui.rs 侧仍靠人工 + review;Codex 承认这是 Rust 宏系统限制,非本次范围可解)
- **量化**:workspace 397 → **400**(+3 守门测试最终 +1 精确集合一致性测试,净 +4);零 regression
- **残余观察**:`capability_json_allow_set_matches_invoke_commands` 手工 JSON 扫是 format-coupled;若 default.json 未来引入对象形 app permission 或引用文本里含 `"allow-*"` 会误正。记为可接受权衡

### ADR 0008 I08b-α5 Session Replay 页面 R1 REJECT → R2 ACCEPT(2026-04-22,α 系列收官)
- **范围**:MVP 第 4 页 —— session 列表 + 选中 replay(NTimeline)+ ledger-wide hash chain verify badge + 独立 verify 按钮
- **Rust**(`apps/desktop/src/bin/gui.rs`):2 新 Read handler(`replay_session` / `verify_chain`),都走 `state.read_capability`;响应 match 对齐 `dispatcher.rs` L137-L165 真实 shape
- **前端 3 新/改**:
  - `api/ipc.ts`:追加 `SessionReplay` / `ChainVerifyReport` / `ReplaySessionReq` 严格镜像(grep 自 `response.rs` L168/L181 + `command.rs` L200);**顺手修 α1 legacy 协议漂移** —— `ListSessionsReq.limit` 从 `?: number` 改为必填 `number`(Rust 端是 `limit: u32` 必填,原 TS 可选会被 serde reject),wrapper 默认 100
  - `stores/sessions.ts`:Pinia(sessions list + replay + standaloneVerify + polling 仅列表)
  - `pages/SessionReplay.vue`:左表 + 右 NTimeline + chain verify badge + expand-per-event payload(同时只展开一条)
  - router `/sessions` 指向真实页面 + App.vue 菜单解 disabled
- **Codex R1 REJECT**(1 MUST-FIX):broken 态 badge 文案仅显示 `chain_broken_at=N`,未明示 "ledger-wide" —— 用户易误读为"本 session 子链坏"。success 态有 "ledger-wide hash chain verified",broken 态反而丢。
- **R1 修复**:
  - `chainBadge` computed 三态(not verified / OK / BROKEN)全部明示 "ledger-wide"
  - NDescriptions summary row 从 "Chain verified" 改为 "Ledger-wide chain",断点行从 "Broken at" 改为 "Broken at (ledger-wide)"
- **R2 ACCEPT**:三态文案一致性补齐;其余结论(capability / 协议镜像 / 脱敏展示 / polling 交互)R1 均已通过
- **验收**:`cargo fmt/clippy/test --workspace` 全绿,**396 passed / 0 failed**,零 regression(default feature 不编 gui)
- **MVP 里程碑**:I08b α 系列 **4 页全部实装**(Approval Queue / Activity Feed / Server Registry / Session Replay),方案 §9 "Desktop UI 看见 agent + 审批 + 追踪 + 回溯"能力闭环

### ADR 0008 I08b-α4 Server Registry 页面 R1 ACCEPT(2026-04-22,一轮通过)
- **范围**:ADR 0008 第 3 大页面 —— 3 Tab(Servers / Pending tools / Drift)+ 5 Read + 5 Write invoke handler
- **范围明细**:
  - Rust(`apps/desktop/src/bin/gui.rs`):10 新 handler,read 走 `state.read_capability`,write 显式 `Capability::Write`
  - 前端 5 新/改:`api/ipc.ts`(TransportKind/TrustLevel/StoredServerProfile/ServerOnboardingData/ToolApprovalCard + 6 Req + 10 wrapper)+ `stores/servers.ts`(Pinia,Promise.all 并行 4 list + detail + 5 write action)+ `components/ServerOnboardingCard.vue`(argv 逐元素 + env keys only-keys + drift diff + 双层 confirm)+ `pages/ServerRegistry.vue`(NDataTable + NBadge + NModal)+ router/App 菜单启用
- **关键安全守门**(无 regression,α2→α3 教训转化):
  - **Rust serde 真相镜像**:TransportKind / TrustLevel 两个 `#[non_exhaustive]` PascalCase enum + 3 个 DTO 字段全由 `registry.rs` L34/L64/L106 grep 确认
  - **argv 禁拼接**:ServerOnboardingCard 逐元素 `<code>{{ arg }}</code>`(ADR 0005 §D1 不变量)
  - **env keys 仅 key**:DTO 无 value 字段(后端守);三态(null = 未知 / [] = 明确无 / 非空 = 已知 key)明示
  - **drift 双层 confirm**:`useDialog` warning/error preset,modal 打开时暂停 polling 防 detail 被覆盖
- **Codex R1 ACCEPT**(静态审查 6 风险面全通):capability 最小权限正确 / TS serde 镜像正确 / argv 安全展示 / 二次确认 / modal 轮询交互 / 路由菜单接线非占位
- **验收**:`cargo fmt/clippy/test --workspace` 全绿,**396 passed / 0 failed**,零 regression(default feature 不编 gui)
- **残余观察(R1)**:`#[non_exhaustive]` 的 Rust enum 后续新 variant 时,TS union + tag 映射需同步扩

### ADR 0008 I08b-α3 Activity Feed 页面 R1 REJECT → R2 REJECT → R3 ACCEPT(2026-04-22)
- **范围**:方案 §9.4 / §14 "看见 agent 做了什么" —— 3 新 invoke handler(list_recent_events / get_event_detail / fts_search,全部 `Capability::Read`)+ Pinia events store + NTimeline 页面 + EventDetailModal + FTS5 搜索
- **Codex R1 REJECT**(1 BLOCKER + 3 MUST-FIX):
  - **BLOCKER**:`EVENT_TYPE_OPTIONS` 事件名伪造,未对齐 `vigil-audit` / `vigil-mcp` 真实 `append_event` 字面量
  - **MUST-FIX 1**:`lease.*` 写成 `secret.lease_*` 漂移
  - **MUST-FIX 2**:`typeTagType()` 漏报 error 信号(`execute_failed` / `command_drifted` / `killed_by_timeout` / `io_error`)
  - **MUST-FIX 3**:FTS raw SQLite 错误透传用户,缺友好包装
- **R2 REJECT**(1 MUST-FIX):白名单里 `runner.rejected` / `runner.killed_by_timeout` / `runner.io_error` 仅在 vigil-runner **注释**存在,workspace 无实际 `append_event("runner.*")` 写入点 → 仍是未落地的"依赖推断"
- **R3 ACCEPT**:
  - `EVENT_TYPE_OPTIONS` 18 项均 grep 确认的真实字面量(span.rs / approvals.rs / registry.rs / hub.rs);runner.* 三条彻底移除 + 注释说明"若未来 Hub 接入再补回"
  - `typeTagType` `errorExact` 同步清理 → 5 项;suffix 兜底扩展 `.rejected` / `.killed_by_timeout` 未来兼容
  - `friendlyFtsError()` 按 `syntax|fts5|no such table` 分支生成用户可操作提示,原文作 `[详情]` 附注
- **交付**:5 新/改前端文件(pages/ActivityFeed.vue + components/EventDetailModal.vue + stores/events.ts + api/ipc.ts 扩展 + router.ts/App.vue 菜单启用)+ 1 改 gui.rs(3 handler)
- **验收**:`cargo clippy/fmt/test --workspace` 全绿;**395 passed + 1 flake**(`concurrent_refresh_legacy_no_expires_at_also_singleflights` 在并发全量下 /token 计数偶发 3 != 1,隔离单测立即通过;既有 vigil-http-transport 时序测试,非 α3 regression)
- **遗留 NICE**:`EffectKind` TS enum 未建模(α2 延后项,与 α3 解耦可留给 β 收官);`runner.*` 若 Hub 未来接入需同步补回两处(注释已标注)

### ADR 0008 I08b-α2 Approval Queue 页面 R1 REJECT → R2 ACCEPT(2026-04-22)
- **范围**:方案 §14 "AI 动作前审批" 核心 UI 载体 —— 3 新 invoke handler + Pinia store + 列表页 + Drawer + Approve scope modal
- **Codex R1 REJECT** (3 BLOCKER + 1 MUST-FIX + 1 NICE) — 均是真实协议漂移错误:
  - **BLOCKER 1**:TS enum 大小写错误(ApprovalStatus/Scope 应 PascalCase,Action 应 lowercase)
  - **BLOCKER 2**:TS `ApprovalRequest` shape 虚构字段(`effects_json` / `resolved_*` 不存在);真实字段是 `effect_vector: EffectVector`
  - **BLOCKER 3**:Approve 路径未传 `scope` — dispatcher 强制 `scope.ok_or(Invalid)`,会稳定拒绝
  - **MUST-FIX**:`AppState.capability` 默认 Write 违反 least-privilege
  - **NICE**:router `/activity` 虚假指向 ApprovalQueue
- **R2 ACCEPT**(核对 Rust serde / 真字段后全面重写):
  - `ipc.ts` 三 enum 严格对齐 Rust serde + `ApprovalRequest` 字段精确镜像 + `EffectVector` TS 定义补齐
  - Store `resolve(action="approve")` 前端强制 scope 守门;`ApprovalQueue.vue` NModal 选 scope + dialog 二次确认双层流程
  - `gui.rs` `read_capability = Read` + 写 handler 显式 `Capability::Write`(least-privilege)
  - `NotImplemented.vue` 占位页 + router `/activity` `/servers` `/sessions` 均指向它 + App.vue 菜单 4 项同步禁用态
- **交付**:6 新/改前端文件 + 1 改 gui.rs(α1 DTO bug 同步修复)
- **验收**:`cargo check/clippy/test --workspace` 全绿,**396 passed / 0 failed / 零 regression**(default feature 不编 gui)
- **遗留 NICE**:`EffectKind` 未建模 TS enum(α3 ActivityFeed 时一起做更合适)

### ADR 0008 I08b-α1 Tauri 2 + Vue 3 脚手架 R1 REJECT → R2 CONDITIONAL → R3 ACCEPT(2026-04-22)
- **范围**:I08a 协议层(已 Done)之上的首个渲染层迭代 — Tauri 2 + Vue 3 + TS + Naive UI + Tailwind 脚手架
- **策略**:**选项 A 最小 smoke,文件就绪版**(不跑 heavy install:`npm install` / `cargo install tauri-cli` / `cargo tauri dev` 留给用户环境触发)
- **关键设计**:
  - **Feature gate 隔离**:`apps/desktop/Cargo.toml` 加 `[features] gui = ["dep:tauri", "dep:tauri-build", "dep:tokio"]`;默认 `default = []` 确保 `cargo test --workspace` 零 tauri deps 拉取
  - **双 binary**:`vigil-desktop` CLI(I08a 保留)+ `vigil-desktop-gui` (feature=gui,`required-features`)
  - **`build.rs`**:`rerun-if-changed` 放公共路径,`tauri_build::build()` 放 `#[cfg(feature = "gui")]` 内(Cargo 两种 feature 检测方式都支持,但 tauri_build 作为 optional build-dep 需 cfg gate 符号解析)
- **R1 REJECT**:2 BLOCKER(build.rs feature 检测 / capability 表述误导成 app-command gate)+ 1 MUST-FIX(文档不一致:`npm run tauri` script 缺失 / `cargo tauri build` 警告缺)
- **R2 CONDITIONAL**:BLOCKER 修正(`#[cfg]` + rerun-if-env-changed 组合;capability 降调为"系统能力基线")+ README + package.json 完整 → 剩 1 NICE 架构树残留注释
- **R3 ACCEPT**:README 架构树注释同步
- **交付**:17 新文件(Cargo.toml 改 + build.rs + tauri.conf.json + capabilities + icons/README + gui.rs + 14 个 ui/* 文件 + apps/desktop/README.md)
- **验收**:
  - `cargo check --workspace`:8s 编译完,**零 tauri deps 拉取**
  - `cargo clippy --workspace --all-targets -- -D warnings`:全绿
  - `cargo test --workspace`:**394 passed + 1 pre-existing α1 flaky**(非 I08b-α1 引入;`concurrent_refresh_legacy_no_expires_at_also_singleflights`)
  - **workspace 默认路径零 regression**
- **已知延期**(α1.5 / β):
  - `tauri_build::AppManifest::commands(&[...])` 构建期 app-command 级白名单
  - specta TS 类型自动生成(当前手写 `ui/src/api/ipc.ts`)
  - ESLint CSP 违反测试
  - 正式 `icons/` + `cargo tauri build` 发行包
  - Playwright + tauri-driver E2E
  - 三平台打包 CI
- **环境要求**(用户跑 smoke 前):
  - Node.js ≥ 18 ✓ (已有 v23.3.0)
  - npm ≥ 9 ✓ (已有 11.6.0)
  - `cargo install tauri-cli --version '^2.0.0' --locked`(~3-5 min)
  - `cd apps/desktop/ui && npm install`(~300 MB / 2-3 min)
  - `cargo tauri dev --features gui`(首次 tauri deps 编译 3-5 min)

### HttpAuthError thiserror Display golden R1 ACCEPT 首轮(2026-04-22)
- **范围**:兑现 audit golden R3 留下的建议"只对下游当 machine-readable token 消费的 `#[error(...)]` 做 golden",先做最关键的 `HttpAuthError`(进告警规则 + 审计事件)
- **分类三类**(覆盖 18 variants):
  - **纯 token**(8):`missing_token` / `token_expired` / `jwt_signature_invalid` 等无占位
  - **结构体变体**(2):`AudienceMismatch` / `TokenRejectedWrongIssuer`—— Display 只输 stable token 不含字段
  - **前缀 + tail**(8):`invalid_prm: {0}` / `http_error: {0}` 等,双断言(完整 Display + split-prefix)
- **交付**:
  - `crates/vigil-http-auth/tests/error_display_golden.rs` 新 4 tests(共 18 variants 全覆盖)
  - `crates/vigil-http-auth/src/error.rs` 末尾 `#[cfg(test)] mod variant_exhaustiveness_guard` — 定义 crate 内穷尽 match classify(err) 三分类,新增 variant 编译错误(模式复用 `vigil-runner::reject_field_guards`)
- **R1 ACCEPT 首轮**:
  - 三类分类覆盖合理;prefix-split 对 tail 含 `:` 安全
  - 双层 guard(内部 compile-time 穷尽 + 外部 `all_known.len() == 18` 数字守门)互补
  - Codex 建议:不一刀切补 `FirewallError` / `PolicyError` / `StdioError`(偏人读不稳);下一优先级是 `UpstreamError`
- **测试增量**:391 → **396**(+5:4 外部 golden + 1 内部 classify guard)

### Workspace-wide 审计字符串 golden tests R1/R2 CONDITIONAL → R3 ACCEPT(2026-04-22)
- **范围**:稳定审计契约字符串的守门(`as_str` / `as_path_segment` / `reason_code` / thiserror `Display`)—— 未来意外改动会断裂下游消费方(UI / 日志聚合 / SQLite 列值 / IPC 契约)
- **交付**:4 个新 test 文件 + 1 个定义侧内部 guard + 1 个 pub 常量 = **13 golden tests**
  - `crates/vigil-lease/tests/audit_strings_golden.rs`:MismatchField (+1) + SecretStoreError reason_code 与 Display 一致性 (+2) = 3 tests
  - `crates/vigil-browser/tests/audit_strings_golden.rs`:FindingKind + BrowserErrorCode + as_str↔serde 契约 = 3 tests
  - `crates/vigil-runner/tests/audit_strings_golden.rs`:RejectField as_str + fallback 守门 = 2 tests
  - `crates/vigil-http-auth/tests/audit_strings_golden.rs`:TokenKind as_path_segment + as_str + 两方法一致 + serde 契约 = 4 tests
  - `crates/vigil-runner/src/error.rs` inline `#[cfg(test)] mod reject_field_guards`:定义 crate 内穷尽 match guard,新增 variant 触发编译错误 = 1 test
  - `RejectField::ALL_KNOWN: &[RejectField]` 新 pub 常量,跨 crate 契约清单
- **R1 CONDITIONAL**(Codex 2 Important):SecretStoreError::reason_code 漏 golden + RejectField non_exhaustive 外部 guard 无法检测新增 variant
- **R2 CONDITIONAL**:SecretStoreError 补上但 RejectField 的 ALL_KNOWN 方案仅闭合一半(不能检测"新增 variant 漏登记 ALL_KNOWN")
- **R3 ACCEPT**:
  - 定义 crate 内 `reject_field_guards` 穷尽 match(`#[non_exhaustive]` 内部不强制 `_`,漏分支编译错误)
  - 双层 guard 职责分工清晰:内部守"定义完整性" + 外部守"字符串映射正确性"
  - 注释收敛,不过度宣称外部能单独捕获所有情况
- **测试增量**:378 → **391**(+13:跨 4 crate 的 12 integration + 1 lib unit)
- Codex 备注:其他 thiserror `#[error(...)]` 文本是否纳入 golden,应只对"下游当 machine-readable token 消费"的做,不要把所有 display 文本升级

### ADR 0007 I07.5+ helper 抽取 R1 ACCEPT 首轮(2026-04-22)
- **范围**:兑现 ADR 0007 §I-7.1 明确承诺"两份实现的 helper 抽取延至 I07.5" —— I07.5 只做了 Landlock,helper 抽取遗留
- **交付**:
  - 新 pub API `vigil_runner::apply_native_env_policy<I, K, V>(cmd, user_env)` —— 原子三步封装(`env_clear` → Windows `RESERVED_SYSTEM_ENV_KEYS` 注入 → `envs`)
  - `vigil-runner::spawn_native` 替换 9 行内联 env 政策为 helper 调用
  - `vigil-mcp::StdioUpstream::spawn` 替换 4 行内联为 helper 调用 + 新增 `vigil-runner` 依赖
  - **副效应修 bug**:StdioUpstream 获得 Windows SystemRoot 注入(此前缺失导致 cmd.exe / ping 作为 MCP server 启动失败)
  - ADR 0007 §I-7.1 原"延至 I07.5"文字更新为"I07.5+ 完成"
- **R1 ACCEPT** 首轮(无 BLOCKER / MUST-FIX):
  - 1 NICE:`StdioUpstream::spawn` doc comment 过期(只说"只留 caller 批准的项",未反映 Windows SystemRoot 也被注入)→ 顺手修
  - 1 future consideration:§I-7.3 仍靠"代码形状 + review 守门"而非编译期强制 —— 可接受
- **测试增量**:375 → **378**(+3:helper 跨平台基础行为 / Windows SystemRoot 注入 / user env 覆盖 system 键 defense-in-depth)

### ADR 0007 I07.5 代码 R1 REJECT → R3 ACCEPT(2026-04-22)
- **范围**:Linux Landlock LSM 沙箱 —— `SandboxProfile.read_dirs/write_dirs` 编译成 kernel-enforced 白名单,子进程 exec 前 `restrict_self`
- **新 crate**:`vigil-sandbox-linux`(Linux-only 编译,唯一 unsafe 暴露面;其他 11 个 vigil-* crate 保持 `forbid(unsafe_code)` 不变)
- **交付**:
  - `LandlockPolicy { read_paths, write_paths }` + `from_dirs(read, write)`
  - `LandlockPolicy::install_into(cmd)`:**父进程**构造完整 `RulesetCreated`(ABI 检查 → PathFd::new → handle_access → create → add_rule × N),所有可预见失败前置;**子进程** pre_exec 闭包 `Option::take()` + `restrict_self()` + `FullyEnforced` 校验
  - `pub const LANDLOCK_PRE_EXEC_ERRNO: i32 = libc::EPROTO` —— pre_exec 失败 errno 信号
  - `vigil-runner::spawn_native`:install_into 失败 → `Rejected { Sandbox }` + 4 reason_code;`cmd.spawn()` 失败 `raw_os_error == EPROTO` → `Rejected { Sandbox, landlock_restrict_self_failed }`
  - `RejectField::Sandbox` + `#[non_exhaustive]` + `as_str` `_ => "rejected"` fallback
  - ADR 0007 §5 追加 **I-7.7 / I-7.8 / I-7.9**:Linux native spawn 必走 Landlock / unsafe 集中 / pre_exec async-signal-safe + TOCTOU 已知限制声明
- **R1 REJECT**(Codex 3 BLOCKER + 3 MUST-FIX):pre_exec 失败不能识别为 Sandbox / pre_exec 内有 format!+分配 / non_exhaustive match 缺 `_` / TOCTOU / RejectField::as_str 缺 `_` / I07.5 迭代文档缺
- **R2 CONDITIONAL**:3 BLOCKER + MUST-FIX 代码层关闭,剩 ADR 0007 未同步 + 1 NICE 注释过头
- **R3 ACCEPT**:
  - ADR 0007 §3 RejectField 代码块加 `#[non_exhaustive]` + `Sandbox`;§5 追加 I-7.7/7.8/7.9 三条新不变量 + TOCTOU 延期声明
  - drop 注释收敛,去除"PathBeneath 仍持 FD"错误暗示
- **测试矩阵**:
  - Windows 开发机:cargo build / fmt / clippy -D warnings 全绿,372 passed(既有基线,Linux 模块 cfg-gated)
  - Linux 内部 4 单测(policy_from_dirs / kernel_support / path_open_failed / unsupported_kernel / pre_exec_errno_is_eproto)—— 需 SSH 真机跑
- **已知延期**:
  - TOCTOU 彻底消除(需 openat2 + RESOLVE_NO_SYMLINKS + fstat inode 校验)→ I07.6 或 landlock 0.5+
  - 真 Linux kernel runtime 验收(read 通过 / write 拒绝 / outside 拒绝)→ SSH 测试环境手动跑

### ADR 0011 I10c-α3+ lock cleanup 代码 R1/R2 CONDITIONAL → R3 ACCEPT(2026-04-22)
- **范围**:兑现 α3 R1 推迟的 NICE —— `introspection_locks` HashMap 长期增长防护
- **交付**:
  - `TokenStore::try_cleanup_introspection_lock(key)`:在 outer mutex 内原子 check `Arc::strong_count == 1` + remove;失败 best-effort 不影响正确性
  - `resolve_opaque_via_introspection` 重构 IO 路径:`_guard` 释放 → `drop(lock)` → cleanup → `fresh_result?`(Ok/Err 两路径都 cleanup,错误优先级保留)
  - `introspection_locks_len_for_test` 测试辅助(`_for_test` 后缀 + `#[doc(hidden)] pub`,对齐 I04 `inject_route_for_test` 纪律)
- **R1 CONDITIONAL**:Medium = cleanup 不是真 best-effort(poisoned 覆盖 IO 结果);Low = 测试 API 命名未对齐仓库 `_for_test` 先例
- **R2 CONDITIONAL**:Medium = `fresh_result?` 提前返回跳过了 Err 路径 cleanup,失败 token 的 lock 仍积累
- **R3 ACCEPT**:
  - cleanup 在 `fresh_result?` 之前执行,Ok/Err 两路径都跑
  - 原 IO 错误优先级透传(cleanup 错误 `let _ = ...` 静默吞掉)
  - 命名对齐 `*_for_test` 仓库纪律
- **测试增量**:372 → **375**(+3:success / failed(TokenExpired)/ 8-thread concurrent,全部断言 `introspection_locks_len_for_test() == 0`)

### ADR 0011 I10c-α3 代码 R1 CONDITIONAL → R2 ACCEPT(2026-04-22)
- **范围**:introspection 响应缓存 + per-key singleflight(§I-11.6 模式)—— 避免同一 opaque token 高频 resolve 把 AS introspection endpoint 压垮
- **交付**:
  - `IntrospectionConfig.cache_max_ttl_secs: u64`(默认 60s,上限 300s via `INTROSPECTION_CACHE_HARD_CAP_SECS`),builder `with_cache_max_ttl_secs(secs)` 自动 clamp;`0` 关闭
  - `TokenStore.introspection_cache: Mutex<HashMap<String, CachedIntrospection>>` + `introspection_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>`(per-key singleflight)
  - cache key = `sha256(raw_token || '\0' || endpoint)` hex(**不持 raw token**)
  - `compute_cache_ttl` 三条规则:`exp>now` → `min(remaining, cfg, HARD_CAP)`;`exp<=now` → 0;`exp=None` → `min(cfg, HARD_CAP)`
  - **只缓存 active:true**(active:false / 网络失败不污染)
  - `resolve_opaque_via_introspection` Step 0 插入 cache lookup → miss 拿 per-key 锁 → 锁后重查(double-check)→ 真 IO + 写缓存
- **R1 CONDITIONAL**(Codex 指出):MUST-FIX = 4 处 `expect()` 生产路径 panic 违反仓库不变量(`refresh_locks` 已有 `Internal` 映射先例)
- **R2 ACCEPT**:
  - 所有 4 处 `expect` 改 `map_err(|_| HttpAuthError::Internal(...))`,对齐 α1 `refresh_singleflight_poisoned`
  - `cache_lookup` / `cache_store` 签名改 Result,调用点 `?` 上抛
  - `compute_cache_ttl` 文档展开为 3 条明确规则(R1 NICE 2 修复)
  - R1 推迟 NICE:`introspection_locks` 不清理 + 显式负缓存 → β/后续
- **测试增量**:366 → **372**(+6:cache hit / TTL expiry / ttl=0 关闭 / active:false 不缓存 / exp cap TTL / 8 线程并发 singleflight)

### ADR 0011 I10c-β2 代码 R1 → R3 ACCEPT(2026-04-22)
- **范围**:PolicyEngine OAuth scope allowlist DSL(ADR 0011 §8 "allowed_scopes" 功能的底层原语)
  - `vigil_policy::Condition::ScopeNotInAllowList { allowlist_key }`:DSL op `scope_not_in_allow_list`,Deny 规则 + 此条件 = "只允许 allowlist 内 scope"
  - `vigil_policy::PolicyContext.requested_scopes: Option<Vec<String>>`:**三态语义** `None`(非 OAuth,规则不适用)/ `Some(vec![])`(OAuth 无 scope,fail-closed 触发)/ `Some(scopes)`(RFC 6749 §3.3 case-sensitive 精确比较)
  - `vigil_firewall::FirewallConfig.allowed_scopes: HashMap<String, Vec<String>>`:scope allowlist 注入通道;保留键 `"allowed_hosts"` runtime 拒绝(`FirewallError::ReservedScopeKey`)
  - `vigil_firewall::OAuthScopeContext { NonOauth, Scopes(Vec<String>) }` + `Firewall::evaluate(call, oracle, scope_ctx)`:scope_ctx 必填,消除"忘了传 OAuth 上下文"静默降级
- **R1 REJECT**(Codex 指出):BLOCKER = `vigil-firewall` 未构造 `requested_scopes` → 规则在真实路径默认失效;MUST-FIX 1 = `empty=>false` 混淆"无 OAuth"与"OAuth 漏传",MUST-FIX 2 = `allowed_scopes` DSL 契约仅停留在注释
- **R2 REJECT**:BLOCKER = `allowed_scopes` 无 runtime 注入入口,`_with_oauth` 双 API 仍可误走 `evaluate()` 静默降级
- **R3 ACCEPT**:
  - `FirewallConfig.allowed_scopes` 注入 + `evaluate` 自动合并到 `PolicyContext.allowlists`
  - `OAuthScopeContext` 必填参数,`evaluate_with_oauth` 删除,统一单一 API
  - 16 个调用点(`acceptance.rs` + `hub.rs`)全部更新为 `NonOauth`(stdio MCP 语义正确)
  - `ReservedScopeKey` guard:config 层误用保留键 `"allowed_hosts"` 作 scope 键 → `evaluate` 首次调用即 fail-closed
  - 端到端集成测试 `firewall_oauth_scope_context_end_to_end_with_config_injected_allowlist` 覆盖 4 条路径(NonOauth / Scopes 内 / Scopes 越界 / Scopes 空)
  - R3 剩 NICE(文档级 canonical key convention)延后
- **测试增量**:357 → **366**(+9:6 policy 单测 + scope_deny_overrides_approve 偏序回归 + firewall OAuth 端到端 4-path 集成 + ReservedScopeKey guard)

### ADR 0011 I10c-α2 代码 R1 → R2 ACCEPT(2026-04-22)
- **范围**:RFC 7662 opaque token introspection
  - `vigil_http_auth::introspect_token`(client_secret_basic + HTTP Basic)
  - `IntrospectionResponse` / `IntrospectionConfig::new`(强制 https 或 loopback,字段 pub(crate))
  - `ExpectedBinding.introspection: Option<IntrospectionConfig>`(与 `key_verifier` 互不干扰)
  - `TokenStore::resolve_access_token`:step 4 `UnsupportedTokenFormat` + introspection 启用 → 走 `resolve_opaque_via_introspection`(active / iss / aud / exp / scope 5 步 fail-closed)
- **R1 REJECT**:BLOCKER = `client_secret_basic` 不符 RFC 6749 §2.3.1(直接 base64(id:secret),含 `:`/空格/`%` 时与 AS 互操作失败)
- **R2 ACCEPT**:
  - `introspect_token`:`percent_encode(client_id)` + `percent_encode(client_secret)` 后拼 `:` + base64
  - 新测试 `introspect_token_basic_auth_percent_encodes_id_and_secret`:client_id=`"client:with spaces%"` / client_secret=`"sec%ret"`,断言 base64 decode = `"client%3Awith+spaces%25:sec%25ret"`
  - 注释已改正(去掉"HTTP Basic 不 percent-encode"旧语义)
  - R1 NICE(introspection 缓存/CLI --client-secret)延 α3 或 β
- **测试增量**:352 → 356(α2 初版 +4)→ **357**(R1 修订 +1 percent-encode 守门)

### ADR 0011 I10c-α1 代码 R1 → R4 ACCEPT(2026-04-22)
- **范围**:refresh token 自动预刷(`exchange_refresh_token_for_token` + `TokenStore::try_refresh_access_token` + singleflight + `HttpUpstream::with_auto_refresh` + `AutoRefreshConfig` + CLI 存 refresh_token)
- **R1 REJECT**:BLOCKER 5(token_endpoint 未强制 https,refresh_token 可发明文 http)+ MUST-FIX 1(singleflight 假实装,第二 caller 仍 IO)+ MUST-FIX 2(缺并发压测)
- **R2 REJECT**:`AutoRefreshConfig` 字段 `pub` 可 struct literal 绕过 `new`
- **R3 REJECT**:`__new_for_integration_test` 仍是 crate-外 pub 入口 + `expires_at=None` legacy 并发退化
- **R4 ACCEPT**:
  - BLOCKER 5:`AutoRefreshConfig::new` 强制 `https://` 或 loopback(127.0.0.1/::1/localhost);CLI `add_remote::run_with_deps` 对 `token_endpoint` / `authorize_endpoint` 也 gate
  - MUST-FIX 1 / legacy:真 singleflight —— 入锁前 `pre_value_hash = sha256(SecretStore access value)`;入锁后 `value_rotated || expires_advanced` 任一短路 Ok(false);legacy `expires_at=None` 靠 value 指纹合并
  - MUST-FIX 2:`concurrent_refresh_same_token_ref_only_hits_network_once`(10 并发 Barrier 同起跑,AS /token 恰好 1 命中)+ `concurrent_refresh_legacy_no_expires_at_also_singleflights`(legacy 场景同)
  - R2 修复:`AutoRefreshConfig` 字段 `pub(crate)`;R3 修复:整体删除 `__new_for_integration_test`,用 loopback exception 让 test 走 `new` 统一入口
- **测试增量**:347(β) → 350(α1 初版 +3) → 351(R1 修订 +1 并发压测) → **352**(R3 修订 +1 legacy singleflight)

### ADR 0011 β 代码 R1 → R2 ACCEPT(2026-04-22)
- **新 crate 面**:
  - `vigil-http-transport::loopback`:std::net 同步 loopback HTTP server(不引 tokio/hyper),
    ephemeral port / 60s timeout / CSRF state 精确等 / 单请求后 drop listener
  - `open = "5"` workspace dep:跨平台默认浏览器打开 + fallback 打印 URL
  - `vigil-hub-cli`:从占位升级为 lib+bin + clap;`add-remote-mcp --url/--client-id/--scopes` 串联 PRM → AS metadata → loopback → exchange → token persist
- **R1 REJECT(BLOCKER 1 + MUST-FIX 3)**:CLI 用 InMemorySecretStore / loopback header 无字节上限 / 坏请求关 listener / 缺 CLI 级 integration test
- **R2 ACCEPT(4 项全过)**:
  - 启 `vigil-lease/os-keychain` feature,`Deps::production()` 返 `Arc<KeyringSecretStore>("vigil")`
  - `run_with_deps(args, deps)` 依赖注入;测试可注 InMemorySecretStore,prod 强制 Keyring
  - `MAX_REQUEST_BYTES = 8 * 1024` + `consume_headers(reader, budget)` 累计字节上限
  - `wait_for_callback` 重构为循环:坏请求记 `last_err` + continue(不关 listener);timeout 返 last_err
  - CLI 级 5 条 integration test 含 `production_deps_use_keyring_backend_not_memory` 守门
- **测试增量**:9 → 11 loopback 单元 + 1 β e2e + 5 CLI integration = **+7**(340 → 347)

### ADR 0011 α1 代码 R1 → R2 ACCEPT(2026-04-21)
- **R1 BLOCKER**:`validate_and_resolve_access_token` 仍在 `lib.rs:44` `pub use` 导出,下游可绕过 sealed `TokenStore::resolve_access_token`;破坏 R4 设计 ACCEPT 承诺
- **R1 MUST-FIX**(4 项):Hub 双错通道(`HubError::Stdio` + `HubError::Upstream`)/ `call_raw` `shutdown_raw` `pub` / `key_verifier` 无 compile-fail 守门 / legacy NULL issuer 测试靠 schema 默认行为
- **R1 NICE-TO-HAVE**:`let _ = jwt;` 死代码
- **R2 修订**:
  - BLOCKER 修复:`jwt.rs::validate_and_resolve_access_token` 改 `pub(crate)`;`lib.rs` pub use 移除;integration 3 处直接调用迁移到 sealed `TokenStore::resolve_access_token(&ExpectedBinding, ...)`
  - MUST-FIX 1:`HubError::Stdio` 整条删除;StdioError 只在 `impl McpUpstream for StdioUpstream::call` 内映射到 `UpstreamError`
  - MUST-FIX 2:`StdioUpstream::call_raw` / `shutdown_raw` 改 `pub(crate)`
  - MUST-FIX 3:`ExpectedBinding` rustdoc 加 **2 条** `compile_fail` doctest(缺字段 / `None` 各 1 条)
  - MUST-FIX 4:`__insert_oauth_token_metadata_raw_for_test` 签名加 `issuer_raw: Option<&str>`,显式 `None` 写 NULL,不依赖 schema 默认行为
  - NICE-TO-HAVE:`let _ = jwt;` 清零,旧 JWT 构造合并
- **R2 ACCEPT**:所有 6 项 OK;测试 313 → **315**(+2 compile_fail doctest);撤回条件仅挂在"claim 与实际不一致"(已验证一致)

### ADR 0011 α2 代码交付 + R1→R3 ACCEPT(2026-04-21)
- **新 crate** `vigil-http-transport`:`ReqwestHttpClient` / `HttpJwksSource` / `JwksSignatureVerifier` / `HttpUpstream`;workspace deps 严格约束 reqwest `default-features = false` + rustls-tls only
- **α2 R1 REJECT**:4 BLOCKER(singleflight 空锁 / PostForm 发 JSON-RPC / fetch_as_metadata 未 e2e + fixture 凑数 / `__new_for_integration_test` 生产公开)+ 4 MUST-FIX(per-call timeout 忽略 / jwk.alg 未校 / cargo deny 未落 / RS256 空壳测试)+ 3 NICE
- **α2 R1 修订(8 项最小集合 + 3 nice)**:
  - BLOCKER 1:`HttpJwksSource` 真 singleflight(per-key `Arc<Mutex<()>>`)+ 100 并发压测断言 `total_hits == 1`
  - BLOCKER 2:`HttpMethod::Post`(JSON body)新变体 + `#[non_exhaustive]` + `send_inner` 分支 `application/json` + `HttpUpstream` 用它
  - BLOCKER 3:`TlsFixture::start_with_routes` 先 bind 端口再 build body(用真 base_url);`fetch_as_metadata` 真 HTTPS e2e + §12.3 I10-3 真走发现链
  - BLOCKER 4:删 `ReqwestHttpClient::__new_for_integration_test`;信任自签 CA 收拢到 `tests/common::TestTlsHttpClient`(integration test crate 本地,非 crate pub API)
  - MUST-FIX 1:`AuthorizedSender::send_authorized_with_timeout` 默认方法(向后兼容扩展)+ `ReqwestHttpClient` 覆盖真 per-request timeout + `HttpUpstream::call` 用新 API
  - MUST-FIX 2:verifier 在 `jwk.alg.is_some()` 时强制 `jwk_alg == header.alg`,§I-11.4 四元组信任锚完整兑现
  - MUST-FIX 3:`deny.toml` + `.github/workflows/ci.yml` 真跑 `cargo deny --all-features check`(ban native-tls/openssl/cookies)
  - MUST-FIX 4:`rsa` crate dev-dep + `TestRs256Key` 2048-bit keypair + `rs256_round_trip_signature_verifies_via_verifier` 真签真验
  - NICE:`TestRsaKey` → `TestEs256Key` / `TestRs256Key` 拆分 / 字节级 tamper(base64 decode + XOR + encode)/ `Jwk` doc 明示 "不承诺字段级 semver"
- **α2 R2 CONDITIONAL**:7/8 OK,2 项收尾(cargo deny CI gate 未挂,`/mcp/rpc` 无 Content-Type 黑盒断言)
- **α2 R3 ACCEPT**:两项收尾完成 —— `.github/workflows/ci.yml` cargo deny step + `boxed_rpc_require_json` 415 断言
- **量化**:测试 315 → **330**(+15:6 verifier 单元 + 9 e2e 含真 TLS/真签名/singleflight 压测/Content-Type 黑盒断言);fmt / clippy -D warnings / cargo deny(CI)零警告

### ADR 0010(I10a)— R1 REJECT → R2 ACCEPT
- R1 BLOCKER:PRM 未校验 `prm.resource == resource_base` → 加 fail-closed
- R1 BLOCKER:API 边界未收 "token-resource 绑定" → 新 `resolve_access_token` 封闭入口
- R1 MUST-FIX:`token_type=Bearer` 未校 → `eq_ignore_ascii_case("Bearer")`
- R2 NICE-TO-HAVE(2026-04-21 横向清理已消化):`list_metadata` 遇未知 `token_kind` 已改为 `return Err("unknown_token_kind")`,与 `get_metadata` 对齐,`tests/integration.rs::list_metadata_fails_closed_on_unknown_token_kind` 回归覆盖

### ADR 0009 Phase 1「引擎连接」+ ADR 0024 第二客户端(2026-07-06)

- **交付**:`crates/vigil-daemon-ipc` 抽取(protocol/client/transport 客户端侧/wire 四原语,纯移动;hub-cli re-export 保路径)+ native-host `ml_augment`(daemon ML PII 增强,fail-closed 纯加性)+ `BrowserCheckResponse.ml_labels` + 审计 `engine`/`ml_labels`(白名单同步)+ 扩展 JS 透传(不进 tier 决策)
- **审查**:hostile sub-agent SOUND(A-G 全 OK,0 Crit/High/Med;3 LOW 非阻断,其一 JS 限长已当场加固);远端 fmt/clippy(-D warnings)/test 全绿 **1270/0**(+10)
- **评估依据**:见引入 PR 描述(四断裂分析 + 能力增量矩阵 + 三阶段方案);Phase 2/3 后续推进

## 维护约定

- **每轮迭代 ACCEPT 后**:作者在表格相应行填 "最终状态 / Codex 审查轮次 / 交付测试数",并在"Codex review 关键修复摘要"追加段落
- **状态迁移 Proposed → Accepted**:不改 ADR 正文,只在本文件更新;若需对 ADR 增删决策点,在 ADR 末尾追加 "## Revised YYYY-MM-DD" 段落
- **超期未落地子项**:在"未落地子范围"保持可追踪,不允许从 ADR 原文删除
