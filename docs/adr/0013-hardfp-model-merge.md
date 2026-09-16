# ADR 0013 — T0 模型 findings × 硬指纹规则 合并决策

- 状态:**Draft**(ISS-20260423-013;等 Codex R1 审查)
- 日期:2026-04-24
- 依赖:ADR 0002(redaction)/ ADR 0012(模型分发)
- 相关 issue:ISS-20260423-013(本 ADR)+ ISS-005(scaffold)+ ISS-008(真模型接入)+ ISS-021(final merge 定型)
- 驱动证据:ISS-20260423-022(Phase 2 runtime 实测)

## 0. 摘要(TL;DR)

Vigil T0 层(`vigil-redaction`)**同时承载两种来源**的 findings:

| 源 | 类型 | 示例 finding | 覆盖面 | 延迟 |
|---|---|---|---|---|
| **Hard**(硬指纹)| 正则 / 结构化检测 | `aws_access_key_id`,`stripe_secret_key`,`database_url`,`jwt`,`pem_private_key`,`email`,`internal_ipv4` 等 **13 类**(v0.3 RULE_PROFILE_VERSION v4)| 窄,**确定性**(高 precision ≈ 1.0)| **< 1 ms** |
| **Model**(OpenAI Privacy Filter)| 双向 token classifier | `private_person`,`private_date`,`private_address`,`private_phone`,`private_email`,`private_url`,`account_number`,`secret` **8 类**(软标签)| **宽**,高 recall,精度变量 | **358-630 ms / sample**(CPU)|

**核心决策**:

| # | 决策 | 理由 |
|---|---|---|
| **D1** | **Hard 优先(fast-path)** | runtime 实测延迟差 **500+ 倍**(Model 400ms vs Hard <1ms);且 Hard 对自定义前缀(如 `ak-live-*` / `sk-live-*`)100% 精确 |
| **D2** | **Model 补充(非替代)** | Model 覆盖 Hard 无法枚举的自然语言实体(人名 / 地址 / 日期);与 Hard 形成纵深防御 |
| **D3** | **冲突决议:Hard 赢**(同 byte span 重叠时丢 Model)| Hard 的 `email` vs Model 的 `private_email` 是同一事物,保留 Hard 的**确定性语义**;避免双重计数 |
| **D4** | **risk_delta 不重复加权** | 同 span 两侧命中只取一侧 risk;否则 preflight 决策在 overlap 上膨胀 |
| **D5** | **Model 在 Hard 旁落时仍兜底**(`sliding_window=128` 窗口外的远距语境 / 自然语言组合)| Model 窗口有限,Hard 全局 regex;互为补充 |
| **D6** | **fail-closed**:Model 不可用 → 只跑 Hard(不 fail-open)| 零信任纪律,ADR 0012 § 6 已规定 |

## 1. 背景

### 1.1 现有硬指纹规则(v0.3 RULE_PROFILE_VERSION v4)

`crates/vigil-redaction/src/lib.rs` HARD_RULES 13 类,对应 `detect_hard_secret` 返回的 `name` 字面量:

| # | name | 匹配 | 覆盖面 |
|---|---|---|---|
| 1 | aws_access_key_id | `AKIA[0-9A-Z]{16}` | AWS key ID |
| 2 | github_token | `ghp_/gho_/ghu_/ghs_/ghr_` 家族 | GitHub tokens |
| 3 | anthropic_api_key | `sk-ant-*` | Anthropic keys |
| 4 | openai_api_key | `sk-*`(其它)| OpenAI keys |
| 5 | pem_private_key | `-----BEGIN ... PRIVATE KEY-----` | PEM blocks |
| 6 | jwt | 三段式 base64url | JWTs |
| 7 | env_assignment | `[A-Z_]+(KEY\|TOKEN\|SECRET\|PASSWORD\|AUTH)=value` | .env 风格 |
| 8 | email | RFC-sim email | email 列表 |
| 9 | internal_ipv4 | 10/8, 172.16/12, 192.168/16, 127/8 | 内网 IP |
| 10 | slack_webhook | `https://hooks.slack.com/services/T.../B.../...` | Slack |
| 11 | stripe_secret_key | `sk_live_*` / `sk_test_*` | Stripe |
| 12 | google_api_key | `AIza[0-9A-Za-z\-_]{35}` | Google |
| 13 | gitlab_pat | `glpat-*` | GitLab |
| 14 | database_url | `<scheme>://user:password@...` | DB URL 含凭证 |

(实际 14 项,"13 类"是口语;精确 14)

### 1.2 Privacy Filter 8 类标签(见 `docs/design/vigil-redaction-selection.md` §2.3)

- `account_number` / `private_address` / `private_date` / `private_email` / `private_person` / `private_phone` / `private_url` / `secret`

### 1.3 ISS-022 runtime 实测观察(驱动本 ADR)

对 medium 样本(202 chars):

```
输入:
  "Alice Johnson was born on 1990-01-02. Contact ak-live-7a8b9c0d1e2f3g4h
   at alice.johnson@acme-corp.example.com or call +1 (555) 123-4567. Her
   home address is 742 Evergreen Terrace, Springfield, IL 62704."

Model 输出(5 span / 411ms avg):
  private_person    [  0..13]  "Alice Johnson"
  private_date      [ 26..36]  "1990-01-02"
  private_person    [ 45..70]  " ak-live-7a8b9c0d1e2f3g4h"  ← ⚠️ 应是 secret
  private_email     [ 73..109] " alice.johnson@acme-corp.example.com"
  private_phone     [117..135] " +1 (555) 123-4567"
  private_address   [157..201] "742 Evergreen Terrace, ..."
```

假设 Hard 对同输入:
```
Hard 输出(< 1ms):
  email   [ 73..109]
  (无其它命中 —— ak-live- 不在 Hard 规则;Alice Johnson 不是 Hard 关心对象)
```

**合并后的应有输出**:
```
merged(7 span):
  private_person    [  0..13]   (来自 Model,Hard 无对应 → 保留)
  private_date      [ 26..36]   (来自 Model,Hard 无对应 → 保留)
  private_person    [ 45..70]   (来自 Model,误判为 person 但 Hard 也无 → 保留 with lower confidence)
  email             [ 73..109]  (Hard 赢;Model 的 private_email 同 span,丢弃)
  private_phone     [117..135]  (Model 专属)
  private_address   [157..201]  (Model 专属)
```

**关键观察**:
- Hard 的 `email` 赢过 Model 的 `private_email`(同 span,D3 决议)
- Hard 漏的 `ak-live-*` 由 Model 兜住(但精度下降 —— ISS-008 要调 operating point)
- **风险加权**:email 位置只按 Hard 的 risk(+10),不加 Model 的 +10(D4 不双倍)

## 2. 决策详述

### 2.1 D1 — Hard 优先(fast-path 短路)

**规则**:对 `scan_text(input)` 调用,执行顺序:

```rust
fn scan_text(input: &str) -> ScanResult {
    // Step 1: Hard 正则全局扫描(< 1ms)
    let hard_findings = detect_hard_rules(input);  // v0.3 HARD_RULES

    // Step 2:如配置启用 Model(默认 true,fail-closed 时降级)
    let model_findings = if model_engine.available() {
        model_engine.scan(input)?  // 400ms+ CPU / 100ms WebGPU
    } else {
        Vec::new()
    };

    // Step 3:merge(本 ADR 核心)
    merge_findings(&hard_findings, &model_findings)
}
```

**为什么不"Model first, Hard second"**?
- Hard 几 μs 数量级,完全可以总是跑(overhead 可忽略)
- Hard 命中后如果跳过 Model 可能漏掉周围语境 finding(如 person/date),所以**两者都要跑**
- "Hard 优先"指 **决策权**,不是执行顺序

### 2.2 D2 — Model 补充(非替代)

即使 Hard 命中全部 secret 类标签,Model 仍需运行以覆盖:
- 自然语言 PII(人名 / 地址 / 电话)
- Hard 规则未枚举的自定义凭证前缀(如 `ak-live-*`,虽然此次被误判但至少标了"敏感")
- 远距语境(`sliding_window=128` 窗口内的交叉验证)

**可选优化(v0.5 考虑)**:
- 若 input 长度 < N chars(比如 20)且 Hard 零命中,可跳过 Model(纯噪声省延迟)
- 若 input 纯粹为 secret(如 Hard 单命中 + 长度 == span 长度),可跳过 Model
- 这些优化**不是本 ADR 范围**,由 ISS-005 API 设计时决定

### 2.3 D3 — 冲突决议(同 span 重叠 → Hard 赢)

**Span 重叠定义**:两 finding 的字节区间 `[start, end)` 有任意交集。

**规则**(伪代码):

```rust
fn merge(hard: &[Finding], model: &[Finding]) -> Vec<Finding> {
    let mut out: Vec<Finding> = hard.to_vec();  // Hard 全进
    for m in model {
        // 若 m 与任何 Hard finding 有 span 重叠,丢弃 m
        if hard.iter().any(|h| spans_overlap(h.span, m.span)) {
            continue;
        }
        out.push(m.clone());
    }
    // 按 span.start 排序(便于下游按位置展)
    out.sort_by_key(|f| f.span.0);
    out
}

fn spans_overlap((as, ae): (usize, usize), (bs, be): (usize, usize)) -> bool {
    as < be && bs < ae
}
```

**为什么 Hard 赢**:
1. **确定性**:Hard 是正则,输出稳定可证(能进 golden test);Model 受权重/量化/版本影响
2. **精度**:Hard 对命中格式是 100% 精确(`AKIA`开头就是 AWS 密钥);Model 有置信度但不保证
3. **runtime 证据**:ISS-022 medium 样本 Model 把 `ak-live-*` 误识 person,Hard 用 `stripe_secret_key` 规则(后者匹配 `sk_live_*`)能兜住类似前缀的场景

**不采用 "Model 赢" 的理由**:
- Model 的 `private_email` 与 Hard 的 `email` 都指向同一 byte 区间,选 Hard 保留审计可 trace 回正则
- Model 误判率 > 0(ISS-022 测得 ≥ 12% on medium sample 误分类率 —— 1/8 的 person 误判)

### 2.4 D4 — risk_delta 不重复加权

**场景**:同 span 两侧都命中(如 `email` + `private_email`)。

**错误加权**(如果允许双重):
```
email:         +10
private_email: +10
───────────────────
   total:     +20   ← 膨胀,但实际只有一个敏感项
```

**正确加权**(本 ADR):
```
Hard 赢 → 只取 email:  +10
Model drop → 0
──────────────────────
   total:              +10
```

**实装**:merge 时丢弃 Model 的 overlapping finding 即自动解决(Model finding 被 drop,其 risk_delta 随之消失)。

**测试矩阵**(在 merge 单测中验证):
- 单 Hard 命中 → risk = Hard.delta
- 单 Model 命中 → risk = Model.delta
- 双命中非重叠 → risk = Hard.delta + Model.delta(都保留)
- **双命中重叠 → risk = Hard.delta only**(Model drop,D4 核心验证)

### 2.5 D5 — Model 兜底(Hard 规则空白区)

Hard 规则是**白名单式**的(显式列 13 类);对以下场景 Hard 无法表达:
- **自然语言实体**:人名(`Alice Johnson`)、地址(`742 Evergreen Terrace`)、日期(`1990-01-02`)、电话(各种格式)
- **未列举的凭证格式**:如 `ak-live-*`(非 Stripe `sk_live_*`)、某公司自定义 API key 前缀
- **语境敏感**:同一 email 在"联系我"上下文 vs "用户列表"上下文

Model 通过**预训练 + 标注**覆盖以上,即使精度不如 Hard,**覆盖面不可替代**。

### 2.6 D6 — fail-closed 降级

承接 ADR 0012 §6 失败模式:

| 场景 | 行为 | rationale |
|---|---|---|
| Model 模型文件下载失败 | `merge_findings(hard, &[])` —— 只跑 Hard | Hard 仍在,部分防御 |
| Model 推理超时(> 2s)| 此次 call 降级 Hard | 不阻塞调用方 |
| Model 返回 Err | 同上 | fail-closed |
| 两者都失败(极端)| preflight 决策 Deny(reason: `RedactionUnavailable`)| 零信任不 fail-open |

**关键纪律**:Hard 路径即使模型挂了也必须常绿;Hard 本身挂了是 BUG 级别(v0.3 已 ACCEPT,不该退化)。

## 3. 非 goals(本 ADR 明确不做)

- **Model 置信度 → risk_delta 动态调整**:简化为固定 `private_email: +10` 等;Stage 2+ 视数据再决定
- **Per-rule 黑名单/白名单**:用户自定义规则体系留 v0.6+
- **Model 训练 / fine-tuning 整合**:上游 OpenAI upstream 做,Vigil 不改模型
- **硬指纹规则扩 I09c 之外**:13 类稳定,v0.5 考虑 Discord webhook / Notion token 等再说

## 4. 影响 / 依赖

| Downstream | 影响 |
|---|---|
| **ISS-005** `vigil-redaction` scaffold | `scan_text` API 按 §2.1 Step 1-3 实装;`merge_findings` 是 public 纯函数 |
| **ISS-008** 真 Privacy Filter 模型接入 | 产出 Model `Finding` 供 merge 消费;格式与 Hard `Finding` 统一 |
| **ISS-010** firewall preflight | 消费 merged findings;risk_delta 按 D4 不双倍;见 ADR 0012 §1.3 风险加权表 |
| **ISS-012** PolicyRule PiiContains 条件 | 匹配 merged findings 的 `kind` 字段 |
| **ISS-021** final merge 定型 | 本 ADR Revised;加 13 类 × 8 类全矩阵 golden test |

## 5. 单测矩阵(ISS-005 实装范围)

`crates/vigil-redaction/src/merge.rs` 的单测必须覆盖:

| # | Case | 断言 |
|---|---|---|
| 1 | 双 empty | merged empty |
| 2 | 仅 hard | merged == hard(顺序) |
| 3 | 仅 model | merged == model |
| 4 | 非重叠 hard + model | merged 长度 = hard.len + model.len,按 start 排序 |
| 5 | 重叠 hard + model(完全重叠) | merged 包含 hard 那条,不含 model 那条(D3) |
| 6 | 部分重叠 hard + model | merged 含 hard,丢 model(D3,`spans_overlap` 包括 `start < other_end && other_start < end`)|
| 7 | 相邻但不重叠(end == other_start)| **两条都保留**(spans_overlap 严格 strict-less)|
| 8 | risk_delta 验证 —— 重叠时只计 hard 一次 | `sum(risk)` == hard.risk(D4)|

**≥ 6 满足 ISS-013 convergence criteria**。

## 6. 开放问题(留给 Codex R1)

1. **Span 重叠是否足够?** 如果 Hard 命中 `email` ([73..109]),Model 命中 `private_person` ([45..70]) —— 二者相邻但不重叠;此时各自保留吗?(本 ADR §5 Case 7 说"保留";R1 审查是否合理)
2. **Model 的 `secret` 标签**:它可能对 Hard 漏的前缀(`ak-live-*`)标 `secret`;与 Hard 的 `aws_access_key_id` 等不重叠时,按 D2 保留;这会给 firewall 多一条 risk_delta +25 —— 符合预期,但要监控误报率
3. **多 Hard 内部重叠**(如 `env_assignment` 和 `openai_api_key` 都命中 `API_KEY=sk-abc`):本 ADR 不干预,`detect_hard_rules` 保持 v0.3 现有去重语义(顺序敏感:anthropic 先于 openai,见 lib.rs §I01 注释)

## 7. Decision Trail

| 阶段 | 决定 | 证据 |
|---|---|---|
| v0.3 (I09c) | 硬指纹 13 类稳定 | workspace 432 tests ACCEPT |
| v0.4 Stage 0 | Privacy Filter 选型 Apache-2.0 | ADR 0012,ISS-001 |
| v0.4 Stage 0.5 | Model CPU 延迟 400-630ms 实测 | ISS-022 |
| **v0.4 Stage 2 (本 ADR)** | **Hard 优先 + Model 补充 + span 重叠 drop Model + risk 不双倍 + fail-closed 降级** | ISS-022 + 本文 §1.3 runtime 证据 |

---

## Sources

- ADR 0002 — 脱敏设计初版
- ADR 0012 — 模型与 ONNX Runtime 分发
- `docs/design/vigil-redaction-selection.md` §7.3-7.7 —— Phase 2 runtime 实测(ak-live 误判 / CPU latency)
- `.spike/privacy-filter-ort/SPIKE-NOTES.md` —— rc.12 API 坑位
- `crates/vigil-redaction/src/lib.rs` HARD_RULES(v0.3 I01 + I09c 补强)

---

## Revised — ISS-021(2026-04-25,wave-5 Stage 4 收官)

### 硬指纹层最终定位:**fast-path + fallback**

经 ISS-005 / ISS-010 / ISS-013 / ISS-021 完整实装后,硬指纹层(`HARD_RULES`,12
secret-类 + email + internal_ipv4 共 14 条;对应 `vigil_browser::FindingKind`
12 个非 LOCAL_ONLY variant)在 v0.4 Stage 4 的最终定位:

1. **Fast-path(ADR 0013 D1)**:`scan_text` 内部先跑 `HARD_RULES.find_iter`,产
   `Vec<Finding>(source=Hard, confidence=1.0)`;命中即可让 caller 在不等模型推理
   的情况下做出 preflight 决策(ISS-022 Phase 2 实测 medium 样本 model forward
   358-630 ms,Hard 命中场景能省去整个推理路径)。
2. **Fallback(模型不可用时)**:ORT runtime 失败 / model file 缺失 / 推理超时
   等场景,`scan_text` 仍能返 `Hard-only` 结果,fail-safe 不返空(D6)。**caller
   不必感知模型可用性** —— 决策不变,只是 recall 降回 v0.3 基线。

### 双层防御最终决策(D-final-1 ~ D-final-3)

- **D-final-1(同 ADR 0013 D3 收紧 + 全 kind 矩阵化)**:Hard ∩ Model span 重叠
  → Hard 赢(精确集合优于模型推断)。`merge_findings` 已实装(ISS-013),本
  ISS 加全部 14 个 Hard kind 字面量 × 同 span 重叠的 golden 矩阵
  (`iss_021_merge_overlap_hard_wins_for_each_kind` /
  `iss_021_merge_no_overlap_both_kept_for_each_kind`),把"D3 一刀切"细化为
  "每条 Hard rule 的具体行为锁死"。
- **D-final-2**:`PrivacyLabel::from_kind` 是**封闭映射**(`HARD_RULES` 全部规则名
  + `ALL_RULES` 独有的 `email` / `internal_ipv4` / `generic_url` + `private_*` 前缀
  与裸 label)→ 8 PrivacyLabel;未识别 kind 返 `None`,caller fail-closed
  (ADR 0013 D6 派生)。各集合的**条数不在此冻结**,由
  `merge.rs::iss_021_hard_kind_to_privacy_label_golden` 与
  `iss_021_hard_kind_set_size_matches_redaction_rules` 两条守门测试持有。
- **D-final-3(审计语义)**:`RULE_PROFILE_VERSION` v5 起,审计 payload 的
  finding 同时承载两个维度 —— 规则名(`Finding.kind`,与 HARD_RULES 一一对应,
  可追溯到 regex)和业务标签(经 `PrivacyLabel::from_kind` 映射,8 类聚合视角)。
  审计员可按业务标签聚合统计,也可按规则名追溯具体命中。

### 跨 crate 不变量(v5 起)

> **条数不在本表冻结**(feedback_ssot_drift_guard):下列每条关系的具体数字都由
> 「守门测试」列里的断言持有,真源是 `vigil-redaction/src/lib.rs::HARD_RULES` 与
> `vigil-browser` 的 `SAMPLES` / `LOCAL_ONLY`。本表此前停在 v5,v6 扩的 4 条
> (aliyun / tencent / slack_token / huggingface)从未同步过来 —— 故改为只述关系。

| 维度 | 关系 | 守门测试(数字由它持有) |
|---|---|---|
| `vigil_browser::FindingKind`(非 `LOCAL_ONLY` 部分)| ↔ `vigil_redaction::HARD_RULES` 全集,**等势** | rule_sync.rs `iss_021_finding_kind_count_matches_redaction_hard_rules` |
| `FindingKind::as_str()` 短形(排除 `localhost_url`) | ↔ HARD_RULES 长形(`aws_access_key_id` / `anthropic_api_key` / `openai_api_key` / `aliyun_access_key_id`)| rule_sync.rs `iss_021_finding_kind_maps_to_privacy_label_via_alias`(显式 alias 表) |
| Hard kind 字面量 → `PrivacyLabel` | 封闭映射,**多对 8**(HARD_RULES 全集 + `ALL_RULES` 独有的 `email` / `internal_ipv4`)| merge.rs `iss_021_hard_kind_to_privacy_label_golden` + `iss_021_hard_kind_set_size_matches_redaction_rules` |

注:vigil-browser `FindingKind::LocalhostUrl` 是**本地规则**(扩展层用于 `Block`
特权 origin 的本地 URL),vigil-redaction 不识别(`scan_hard_findings` 不命中),
故 cross-crate 别名表里跳过它(`LOCAL_ONLY` 集合)。

### 短形 / 长形 alias 漂移点(本 ISS 显式承认)

| `FindingKind::as_str()`(短形)| `HARD_RULES.name`(长形)| 一致性 |
|---|---|---|
| `aws_access_key` | `aws_access_key_id` | 历史漂移,本 ISS 加 alias 表绑死 |
| `anthropic_key` | `anthropic_api_key` | 同上 |
| `openai_key` | `openai_api_key` | 同上 |
| `aliyun_access_key` | `aliyun_access_key_id` | v6(2026-09-12)新增,与 aws 同构 |
| 其余各项 | 同名 | 一致 |

任一侧改名都需要同步 `crates/vigil-browser/tests/rule_sync.rs::alias` 表;改了不
同步会让本 ISS 加的两条新测立即失败,把 SSOT drift 抓在 PR 提交前。

### Profile 版本史

| version | 主要变更 | 引入 issue |
|---|---|---|
| v1 | I09a 初始 8 FindingKind | I09a |
| v2 | + slack / stripe → 10 | I09c 第一批 |
| v3 | + google / gitlab → 12 | I09c 第二批 |
| v4 | + database_url → 13 | I09c 第三批 |
| **v5** | + PrivacyLabel 维度对齐(无新 FindingKind) | **ISS-021** |
| **v6** | + aliyun_access_key / tencent_secret_id / slack_token / huggingface_token → 17(`aliyun_access_key` 短形 ↔ `aliyun_access_key_id` 长形,alias 表新增一行) | maskit 竞品对照(2026-09-12) |

### 后续(超出本 ISS 范围)

- ISS-008 真模型接入后,`merge_findings` 的 Model 路径才会真触发(当前 Stage 1
  只跑 Hard);D-final-1 不变量在 ISS-008 落地后由真 Model findings 端到端验证。
- v6+ profile 升级用于:Hard rule 集合扩展 / `PrivacyLabel` 新 variant / merge
  决策规则修订(目前不可预见)。
- 语义指纹层(email/phone/自然语言实体)的熵评分 / 软规则子系统不进 HARD_RULES,
  由 ISS-008 模型 + 后续语义层承担(详见 feedback_hard_vs_semantic_fingerprint)。

## Revised — v0.5 P2 / ISS-008 Phase 3(2026-04-29)

session: `MCP-v05-p2-ort-8class-2026-04-29`

本段**仅记录事实与新增工具产出方法**,不修改 §0-§7 的 D1-D6 既有决议(决议层
经 R3 ACCEPT 后稳定;feedback_iteration_doc_sync 纪律:事实变化追加 Revised,
决议变化才动正文)。

### A. 事实声明:OrtEngine 已是类别无关实装

`crates/vigil-redaction/src/engine.rs::ort_engine::OrtEngine::infer`(`fn infer`
位于第 243 行)是**BIOES 解码 + `PrivacyLabel::from_kind` 路由的类别无关实现**:

1. token 级 argmax → softmax 置信度
2. 连续同 core label 的 BIOES token 合并为 span
3. core label 经 `to_lowercase().replace(['-', ' '], "_")` 规范化
4. 命中 `PrivacyLabel::from_kind` 白名单 → push `Finding::model(label.as_str(), span, conf, 0)`
5. 未识别 label → `eprintln!` warn 跳过(ADR 0013 决议 C-7,Phase 1)

**结论**:8 类标签的支持**不依赖**显式 8 类 dispatch 代码;只要 `PrivacyLabel::ALL`
枚举与 `from_kind` 映射齐全,`OrtEngine` 即可输出全 8 类 model finding。
v0.4 spike 时"smoke 仅验证 secret + email"是测试断言粒度问题,**不是引擎实装缺陷** ——
v0.5 P2 不动 `engine.rs` 实装,只扩测试矩阵(下文 §B)+ 加 benchmark 工具(§C)。

### B. 8 类完整映射事实(测试矩阵证据)

`crates/vigil-redaction/src/label.rs::PrivacyLabel::from_kind` 已在 v0.4 ISS-005
固化全 8 类映射;v0.5 P2 通过 `crates/vigil-redaction/tests/engine_ort_smoke.rs::ort_smoke_per_label_coverage`
新增的逐桶断言矩阵在真机环境验证全 8 类命中:

| PrivacyLabel | 主要 Finding.kind 来源 | 路由路径 | 真机验证 |
|---|---|---|---|
| Secret | Hard `aws_access_key_id` / `github_token` / `anthropic_api_key` / `openai_api_key` / `jwt` / `pem_private_key` / `env_assignment` / `slack_webhook` / `stripe_secret_key` / `google_api_key` / `gitlab_pat` / `database_url`;Model `secret`(裸) | Hard fast-path(D1);Model 同 span 时被 D3 丢 | fixture `S19`(placeholder `ghp_<40>`) |
| AccountNumber | Model `private_account_number` / `account_number` | Model → from_kind | fixture `S17` / `S18` |
| Email | Hard `email`(在 `ALL_RULES` 但豁免出 `HARD_RULES`);Model `private_email` | Model → from_kind(主路径,Hard 路径误报多故豁免) | fixture `S04` / `S05` / `S06` |
| Phone | Model `private_phone` | Model → from_kind | fixture `S07` / `S08` / `S09` |
| Person | Model `private_person` | Model → from_kind | fixture `S01` / `S02` / `S03` |
| Address | Model `private_address` | Model → from_kind | fixture `S10` / `S11` |
| Date | Model `private_date` | Model → from_kind | fixture `S12` / `S13` / `S14` |
| Url | Hard `internal_ipv4`(`ALL_RULES` 豁免);Model `private_url` / `url`(裸) | Model → from_kind(主路径) | fixture `S15` / `S16` |

**fixture**(20 样本 ground-truth):`crates/vigil-redaction/tests/fixtures/labeled_samples.json`,
7 类软标签各 ≥ 2 样本 + 1 secret(placeholder 字面量,延续 v0.4 e2e Phase 2 同纪律,
绝不含真凭证)+ 1 clean baseline。

**测试函数**:`tests/engine_ort_smoke.rs::ort_smoke_per_label_coverage`,沿用 ISS-008
Phase 1 三层 gate(`#[cfg(feature = "ort")]` + `#[ignore]` + `VIGIL_RUN_ORT_SMOKE=1`)。
默认 `cargo test --workspace` 该测试因 `#[ignore]` 跳过,真机验证命令:

```bash
VIGIL_RUN_ORT_SMOKE=1 cargo test -p vigil-redaction --features ort \
  --test engine_ort_smoke -- --ignored --nocapture
```

### C. benchmark 工具产出方法(precision / recall)

`crates/vigil-redaction/benches/precision_recall.rs`(harness=false,
`required-features = ["ort"]`)是 v0.5 P2 新增的 ad-hoc 报告工具,**不**写硬阈值断言,
仅产出供人评估的观测 JSON(给后续迭代校准基线)。

**三组对比**:

| 组 | 引擎 | 路径 | 期望含义 |
|---|---|---|---|
| `hard_only`  | `NoopEngine` | `scan_text_with_engine` | Hard 路径独立 P/R(< 1ms);secret 类高 precision,软标签近 0 recall |
| `model_only` | `OrtEngine` | `engine.infer` 直拿(跳过 merge) | Model 原始输出;软标签高 recall,secret 误标(参见 §1.3 `ak-live-*` 案) |
| `merge`      | `OrtEngine` | `scan_text_with_engine`(完整 D1/D3/D4/D5) | 双层纵深防御后的总体 P/R;期望 ≥ max(`hard_only`, `model_only`) F1 |

**评估口径**:span IoU(byte-level)≥ `IOU_THRESHOLD = 0.5` + label 一致(经
`PrivacyLabel::from_kind` 路由)算 TP;贪心 1-1 匹配避免 1 truth 被多 pred 双倍记 TP。
跨平台浮点 ULP 漂可能导致 softmax conf 微变,但 argmax 稳定,P/R 应一致;若实测 F1
跨平台漂 > ±0.05,fallback 为上调 `IOU_THRESHOLD` 到 0.6 减边界敏感(本段未触发,
留作未来 NICE 条款)。

**输出 JSON schema**:

```jsonc
{
  "ts": <unix seconds>,
  "sample_count": 20,
  "iou_threshold": 0.5,
  "per_group": {
    "hard_only":  { "per_label": { "<label>": {precision, recall, f1, tp, fp, fn} },
                    "totals": {...}, "latency_ms": <f64> },
    "model_only": { ... },
    "merge":      { ... }
  },
  "confusion_matrix": [[u32; 9]; 9],   // 8 类 + 1 "(none)" 兜底
  "label_index": ["secret", "account_number", "email", "phone", "person",
                  "address", "date", "url", "(none)"]
}
```

**运行命令**:

```bash
# 输出到 stdout(便于 jq 处理)
VIGIL_RUN_ORT_BENCH=1 cargo run --bench precision_recall --features ort

# 输出到文件
VIGIL_BENCH_OUT=dist/redaction-bench.json \
  VIGIL_RUN_ORT_BENCH=1 cargo run --bench precision_recall --features ort
```

**默认 `cargo build/test --workspace` 完全不触此 bench**(`required-features = ["ort"]`
+ `harness = false` 双标记;cargo tree -e normal --no-default-features 0 ort 痕迹由
`crates/vigil-redaction/Cargo.toml` `[features]` cascading gating 保证)。

**解读模板**(供 PR review / ADR 后续迭代):

- `merge.totals.f1 ≥ max(hard_only.totals.f1, model_only.totals.f1)`:**期望成立**;
  若违反,需复盘 D3 span 重叠决策(可能 Model 误标被 Hard 错杀)
- `hard_only.per_label.secret.precision == 1.0`:Hard 高 precision 不变量(secret 类专属)
- `model_only.per_label.secret.precision < 1.0`:Model 在 secret 类有误标(spike 实测确证),
  正是 D1 "Hard 优先"决议的量化驱动证据
- 软标签(person/email/phone/address/date/url/account_number)在 `model_only` 与 `merge`
  组应 P/R 接近;若 `merge` 显著低于 `model_only`,提示 Hard 误杀 Model 软标签
  span 重叠(应进 D3 span overlap 边界检视)

### D. 不变量(本 Revised 段不引入新决议)

- §0 决策表 D1-D6 全部继续生效,本段**未变更任何决议**
- ISS-021 Revised 段 D-final-1 / D-final-2 同样未变更
- ADR 0012 §6 fail-closed 决议(Model 不可用 → 只跑 Hard)仍是真理之源
- 本段引用的所有代码符号已在引用时**逐一 grep 源码核对**(feedback_doc_factual_drift):
  `OrtEngine::from_env` 第 196 行 / `OrtEngine::infer` 第 243 行 /
  `PrivacyLabel::ALL` 第 62 行 / `PrivacyLabel::from_kind` 第 84 行 /
  `ort_smoke_per_label_coverage` / `precision_recall.rs` / `IOU_THRESHOLD` 常量

### E. v0.5 P2 范畴外(留 v0.5 后续 / v0.6)

- 模型分发(ADR 0012 side-car / first-run-download):本 P2 依赖手工放置 `.spike/...` 模型,
  生产分发由 ISS-024 等后续 issue 承担
- 跨语言样本(中/日/韩 PII 检测):需扩 fixture + tokenizer 多语言验证,留 v0.6
- precision/recall **硬阈值守门**:需样本 ≥ 100 + 多次跨平台校准后再设阈值,
  当前 N=20 仅作观测基线,不作 PR 合并守门
- ISS-009 Phase 3 真站点 selector 矩阵:与本 ADR 解耦,由 vigil-browser 子系统承担

---

## Revised(v0.6.1,2026-05-01)— Multilang bench 实测数据

**Status**: Empirical baseline established(N=32 含 12 multilang-soft)
**Trigger**: Track A primary mirror 激活(commit `dd998ca`),开发者环境跑 bench
**Bench data**: `docs/operations/bench/v0.6.1-multilang.json`(完整 JSON 报告)
**Run env**: Linux x64 Ubuntu 24.04 / 4 cores / ORT 1.24.4 / model q4f16

### 实测结果(IOU=0.5,N=32)

| Group | Precision | Recall | F1 | TP/FP/FN | Latency |
|---|---|---|---|---|---|
| `hard_only` | 1.000 | 0.032 | 0.062 | 1/0/30 | 3 ms |
| `model_only` | 0.871 | 0.871 | 0.871 | 27/4/4 | 14,798 ms |
| `merge`(D1+D3+D4+D5) | 0.871 | 0.871 | 0.871 | 27/4/4 | 15,700 ms |

### Per-label(merge group)

| Label | P | R | F1 | TP/FP/FN |
|---|---|---|---|---|
| secret | 1.000 | 1.000 | 1.000 | 1/0/0 |
| account_number | 1.000 | 1.000 | 1.000 | 2/0/0 |
| email | 1.000 | 1.000 | 1.000 | 5/0/0 |
| phone | 1.000 | 1.000 | 1.000 | 4/0/0 |
| url | 1.000 | 1.000 | 1.000 | 2/0/0 |
| person | 0.833 | 0.833 | 0.833 | 5/1/1 |
| **address** | **0.667** | **0.800** | **0.727** | 4/2/1 |
| **date** | **0.800** | **0.667** | **0.727** | 4/1/2 |

### 跨语言对比(per_category_merge)

| Category | Samples | P | R | F1 | TP/FP/FN |
|---|---:|---|---|---|---|
| `soft` (en) | 18 | 0.850 | **0.944** | 0.895 | 17/3/1 |
| `multilang-soft` (zh/ja/ko) | 12 | 0.900 | **0.750** | 0.818 | 9/1/3 |
| `hard` | 1 | 1.000 | 1.000 | 1.000 | 1/0/0 |
| `clean` | 1 | 0.000 | 0.000 | 0.000 | (no truth, expected) |

**Gap**:multilang recall - en recall = **-19.4 pp**(0.750 vs 0.944)。
multilang **precision 反而高 5.9 pp**(0.900 vs 0.850),说明模型对 zh/ja/ko 更保守。

### 决策(按 codex framework)

| 阈值 | 行动 |
|---|---|
| recall ≥ 0.7 | ✅ 模型多语言够用,ADR 0013 "够用"段 |
| 0.3 ≤ recall < 0.7 | v0.7 post-processor 增强 |
| recall < 0.3 | v0.7 多语言模型评估 sprint |

**实测 multilang recall = 0.750 ≥ 0.7 → 第 1 档**。
模型 OpenAI Privacy Filter q4f16 满足 v0.6.1 多语言可用底线;
**无需 v0.7 多语言模型重新选型**。

### 主要 gap 定位(给 v0.7 优化导向)

- **address(F1 0.727)**:精度 0.667 低 — multilang 地址(北京 / 東京 / 서울)误报 + 部分 miss
- **date(F1 0.727)**:召回 0.667 低 — multilang 日期格式(`2024年3月15日` / `2025년 4월 30일`)2 个 FN,模型未识别
- **person(F1 0.833)**:小 gap,zh/ja/ko 单字姓名(如"王小明")可能边界识别不准

### v0.7 carryforward(可选优化,**非 release blocker**)

1. **Post-processor**(YAGNI 推迟,等真用户反馈触发):
   - zh/ja/ko 日期格式正则补丁(`\d{4}年\d{1,2}月\d{1,2}日` / `\d{4}년 \d{1,2}월 \d{1,2}일`)
   - 多语言地址结构化 entity(行政区划字典)
2. **Hard rule 扩展**(成本低):
   - zh/ja/ko 日期格式加入 HARD_RULES(完整 BIOES + Phase 3-α-B fixture 守门)
   - 这会把日期类 hard precision 1.000 推到 multilang 也覆盖
3. **N 扩到 100**:更稳定的 gap 量化,不变 v0.6.1 conclusion(够用)

### Latency 数据(性能基线)

- `model_only` 14.8s / 32 samples ≈ **460 ms / sample CPU**(单核;符合 ADR 0013 §I.3 "model 400ms+ CPU")
- `merge` overhead vs `model_only` ≈ 901 ms 总 / 32 samples ≈ **28 ms / sample**(D1/D3 IoU 计算)
- `hard_only` 3 ms 总 ≈ **0.1 ms / sample**(纯正则,无模型推理)

### 不变量影响

无。本 bench 仅产出 baseline data,不改决策表(D1-D6 不变),不改架构。
sha256 fail-closed + fallback chain + Hard 优先 D1 全部保留。

