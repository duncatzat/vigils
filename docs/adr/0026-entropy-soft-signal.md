# ADR 0026 — 高熵软信号(字符二元组交叉熵;只提分,不脱敏、不单独拒绝)

- 状态:**Proposed**(2026-09-16)
- 日期:2026-09-16
- 依赖:ADR 0012 §1.3(风险分级 SSOT)/ ADR 0013(硬指纹 × 模型 merge,含 D-final-2 封闭映射)/
  ADR 0023(异步注入 preflight,既有软信号形制)/ ADR 0025(出站 LLM-API 闸门)
- 驱动:用户决策(2026-09-16)——「立项」;实现对照 `CassiopeiaCode/CosyRedactGateway`(**MIT**,
  `worker.js` 已逐行读过:`tokenizeBlocks` / `ENTROPY_THRESHOLDS` 17 锚点 / `BIGRAM_COST` 37×37 /
  线性插值阈值 / 双门限 `isHighEntropyBlock`)
- 相关结论:**本 ADR 不是开新口子,是兑现一条挂了很久的后续项** ——
  ADR 0013 Revised「后续(超出本 ISS 范围)」段原文:「语义指纹层(email/phone/自然语言实体)的
  熵评分 / 软规则子系统**不进 HARD_RULES**,由 ISS-008 模型 + 后续语义层承担
  (详见 `feedback_hard_vs_semantic_fingerprint`)」

## 0. 摘要(TL;DR)

现有 16 条硬指纹**全部**靠固定前缀或固定结构锚定(`AKIA` / `ghp_` / `sk-ant-` / `glpat-` / `hf_` /
`LTAI` / `AKID` / `xox[baprs]-` / `AIza` / `sk_live_` / PEM 头 / JWT 三段 / `scheme://user:pass@` …)。
**没有前缀的凭据对 Vigil 结构性不可见**:自建系统签发的随机 token、数据库口令、私有云 AK、
内部服务的 session key —— 它们在字节层面与随机串无异,但不匹配任何一条正则。

本 ADR 引入**第四类信号**:高熵块检测。判据是「这段 `[A-Za-z0-9]+` 块的字符二元组交叉熵,
显著高于同长度自然语言/标识符的基线」。

**一句话不变量**:**熵只提分 —— 不脱敏、不单独构成拒绝理由、不进硬指纹表、不进 `scan_text`。**
(「不单独构成拒绝理由」是精确措辞:它仍会进 `risk_score` 累加,可作为累加项之一
参与升档,见 D3 与 §3。写成「不拒绝」是不准确的。)
它是 `FindingSource::MetaInstruction` 之后的**第二个软信号**,沿用同一条既有通路,
**不发明任何新机制**。

## 1. 背景与问题

### 1.1 已核验事实(逐条 grep 源码,`feedback_doc_factual_drift`)

| 事实 | 出处 | 影响 |
|---|---|---|
| `HARD_RULES` 全部规则均以固定前缀 / 固定结构锚定 | `lib.rs::HARD_RULES` | 无前缀高熵凭据**零覆盖** |
| 熵评分「不进 HARD_RULES」早有裁决 | ADR 0013 Revised「后续」段 | 本 ADR 是兑现,不是新决策 |
| `scan_meta_instructions` **不在** `scan_text` 内,由两条腿各自单独调用并只取 `.len()` | `vigil-mcp/src/hub.rs` / `vigil-hub-cli/src/hook.rs` | **软信号走独立调用路径**的现成先例 |
| `build_redacted_text` 对**所有** finding 的 span 做**并集替换**;`from_kind` 未命中时降级用 `[REDACTED <raw_kind>]` | `scan.rs` `RedactionResult.redacted_text` 文档 + `build_redacted_text` | **熵若进 `scan_text` 的 findings,高熵块会被成片替换成占位符** |
| `aggregate_risk` 对**任意** kind 累加 `risk_delta`,只有 `counts_by_label` 与审计落盘需要 `PrivacyLabel` | `scan.rs::aggregate_risk`(注释:「未识别 kind:risk 已累加,count 不落档」) | 熵可提分而**不污染** 8 类分档与审计枚举 |
| `vigil-outbound` 仅依赖 `vigil-redaction`,且只用 `detect_hard_secret` / `hard_secret_spans` / `is_secret_key_name`,**从不消费 `Finding` / `FindingSource`** | `vigil-outbound/Cargo.toml` + `rewrite.rs` | 软 `Finding` **在依赖方向上就够不到出站闸门** |
| `audit_injection_defense(kind: &str, …)` 为自由字符串,且**只落类别 + 命中数 + sha256,绝不含原文** | `hook.rs` | 新增审计事件类别**不需要动任何白名单** |
| `Condition::PiiContains` 比对的是 `PiiFindingSummary{label, count}`,由 caller 按 **`PrivacyLabel`** 聚合而成 | `vigil-policy/src/engine.rs` | 熵无 `PrivacyLabel` ⇒ 产不出 summary ⇒ **结构上无法满足任何 `PiiContains`** |
| `PolicyContext.risk_score` 存在,且 `Condition::RiskScoreAtLeast` 会读它 | `vigil-policy/src/engine.rs` | 熵**能**经 `total_risk_delta` 间接参与一次 deny —— 见 D3 / §3 |
| 审计落盘只收 fingerprint + 长度桶 + offset 桶 + label + action;`NewRedactionFinding` 的 `placeholder` 参数曾因「可把真 secret 直写 SQLite」被列为 R1 BLOCKER 而**删除** | `vigil-audit/src/ledger.rs` | 「绝不存原文」是既有硬不变量 ⇒ 过度脱敏**污染不了哈希链** |
| `vigil-browser::build_audit_payload` 生产实现只发 origin / event_kind / finding_kinds / 长度桶 / action / `redacted`(**布尔**)/ … | `vigil-browser/src/audit.rs` | 扩展腿审计同样零文本 |

### 1.2 为什么「不能像硬指纹那样处理」

出站闸门是**只脱不还原**的单向通道(ADR 0025)。硬指纹之所以敢在那里就地改写,前提是
**零误报**——`AKIA` 开头就是 AWS 密钥,不存在「其实是正常文本」的可能。

熵不具备这个前提。Cosy 自述其阈值表在自然语言上有约 **1%** 的误报率;本项目**尚无自己的实测基线**。
1% 误报 × 单向不可还原 = **每一百段正常文本就有一段被永久破坏**。这不是可以靠调阈值化解的
权衡,而是**信号性质与通道性质不匹配**:单向通道只配消费零误报信号。

### 1.3 第二个陷阱:`scan_text` 的 findings 同时驱动脱敏

比出站闸门更隐蔽的是 `scan_text`。它返回的 `redacted_text` 是按 findings 的 span **并集替换**
出来的,而**不看 label** —— 未识别 kind 会降级成 `[REDACTED high_entropy]`。也就是说:
**只要把熵 finding 塞进 `scan_text` 的返回里,所有消费 `redacted_text` 的路径都会成片吃掉正常文本**,
与出站闸门同样致命,只是发生的位置更多、更难察觉。

**这条是本 ADR 立项调研中最有价值的发现**:危险不在「熵会不会误报」(那是已知的),
而在「误报会经由哪些既有管道被放大成破坏」。

## 2. 核心决策

- **D1(挂载点)**:新增独立函数 `pub fn scan_high_entropy(text: &str) -> Vec<Finding>`
  (建议置于新模块 `crates/vigil-redaction/src/entropy.rs`),形制**逐点对齐**
  `scan_meta_instructions`。**不进** `scan_text` / `scan_text_with_engine` / 任何 `RedactionResult`。
- **D2(禁入清单)**:**不得**加入 `HARD_RULES`、`ALL_RULES`、`detect_hard_secret`、
  `hard_secret_spans`、`PrivacyLabel::from_kind`。前三者会让熵进入出站闸门与 audit fail-closed 自检;
  最后一者会让熵进入 8 类分档与审计枚举。
- **D3(语义,措辞已按核验结果收紧)**:产出 `FindingSource` 的新 variant `Entropy`
  (与 `MetaInstruction` 同级软信号),消费方**只允许**「提升风险分 + 审计标记」。
  精确边界分两句,**不可合并成一句「绝不 deny」**:
  - **绝不可触发脱敏**,且**绝不单独构成拒绝理由** —— 熵无 `PrivacyLabel`,
    产不出 `PiiFindingSummary`,**结构上无法满足任何 `Condition::PiiContains`**;
  - **但它会经 `total_risk_delta` 抬高 `PolicyContext.risk_score`**,而
    `Condition::RiskScoreAtLeast` 确实存在 ⇒ 熵**可以作为累加项之一**参与升档 /
    co-approval,乃至在已有其它信号时把总分推过阈值。**这正是它的用途**,
    但必须如实写明(§3),不能用「只提分」一句话盖过去。
- **D4(风险分)**:`HIGH_ENTROPY_RISK_DELTA = 5`,即 ADR 0012 §1.3 的**最弱档**
  (Secret 25 / Email·Url 10 / 元指令 8 / 其它 PII 5)。理由:熵是四类信号里**最不具体**的一条,
  证据强度低于「出现了注入指令语言」。取 5 而非 0,沿用 `risk_of` 的「不 0 避免隐式忽略」原则。
  **本项列为开放问题(§5),可在实测基线出来后重定。**
- **D5(判据)**:双门限,与 Cosy 同构 ——
  ① 块的字符二元组**交叉熵**超过按长度线性插值的阈值;② 小写化后的**香农熵** ≥ `min(2.5, log2(len)*0.72)`。
  单门限不够:纯重复长串(`aaaa…`)交叉熵可能偏高但香农熵极低,第二道门专治这类。
- **D6(fail-safe)**:熵计算异常 / 超预算 → **返空向量**,绝不阻断、绝不升级。
  软信号缺失的后果是漏一次提分;软信号误抛的后果是干扰主路径。两害相权取前者。

## 3. 边界(诚实声明)

- **误报率我们没有自己的数**。1% 来自 Cosy 自述,不是本项目实测。**落地前必须先建 fixture 并出基线**,
  否则 D4 的档位与 D5 的阈值都是猜的。
- **分块规则会切碎带分隔符的凭据**:`tokenizeBlocks` 只取 `[A-Za-z0-9]+`,`-` / `_` / `.` 一律断块。
  形如 `xxxx-yyyy-zzzz` 的凭据会被切成三段短块,各自达不到长度门限 ⇒ **漏报**。
- **非英文文本表现未知**:二元组代价表是按英文字母 + 数字构造的 37×37 表,中文/日文/韩文在
  `[A-Za-z0-9]+` 分块下基本不产生块,**既不误报也不检出**;但混排文本(中文里嵌英文标识符)未验证。
- **易混形态需要专门压制**:base64 片段、UUID、sha256/git commit hash、minified JS 标识符、
  压缩后的 CSS class 名 —— 这些天然高熵且**普遍存在于正常内容**里。
  - **可能的解法方向(二手,未核实)**:`xqy2006/ModelTrace`(MIT)在 `bank_builder.py`
    用「**nuisance 方向投影**」把「编码区制」当干扰方向投影掉,使判据从「**熵高不高**」
    变成「**在它自己的编码区制里算不算异常随机**」—— UUID / git SHA / minified 各有稳定
    区制,投影后不再显得异常。**来源是本会话研究代理的转述与设计推断,代理自述
    「未做任何实证」,本项目亦未核实其源码。** 记在此处是为了实施时先去验证,
    **不得**当作已知可用解法写进实现计划。
- **不覆盖出站闸门,且这是刻意的**(§1.2)。不是「暂未支持」,是**设计上永不支持**。
- **「只提分」不等于「不影响决策」**。熵进 `risk_score` 累加,在已有其它信号的会话里
  可能把总分推过 `RiskScoreAtLeast` 阈值。因此**误报的代价不是零** —— 它是「多一次
  不必要的升档 / co-approval 打扰」,而不是「毫无后果」。定 `HIGH_ENTROPY_RISK_DELTA`
  档位时必须按这个代价来权衡,而不是按「反正只是提分」。

## 4. 验证(实施时必须满足,缺一不可)

1. **零误报回归**:照 `scan_meta_instructions_no_false_positive_on_normal_text` 的形制,
   但样本量与覆盖面要大得多 —— 至少含:英文散文、中英混排、代码片段、base64、UUID、
   git hash、minified 资源名、日志行、URL、文件路径。
1b. **基线评估器必须在结构上无法自证**。本项目最容易发生的失败是「**用自己的规则集
   验自己的改写**」—— 评估器若能自证,§3 要求的那条基线就只是装饰。具体形状:
   ground truth **只能**来自评估者的外部输入;缺任一必需元数据即**拒绝计算**而非跳过;
   无数据时返回「拒绝计算 + 原因」而非「通过」;**永不输出「已校准」**。
   (形制吸收自 ModelTrace `scripts/evaluate-calibration.mjs`,MIT;**同为二手转述,
   未核实其源码** —— 采纳的是这个**形状**,不是那份实现。)
2. **禁入守门(双向集合断言)**:一条测试断言 `HARD_RULES` 与 `ALL_RULES` 的规则名集合中
   **永不**出现熵相关 kind;一条测试断言 `scan_text` 返回的 findings 里**永不**出现 `FindingSource::Entropy`。
3. **脱敏隔离守门**:构造一段必然触发熵命中的文本,断言 `scan_text(...).redacted_text`
   与原文**逐字节相同**(即熵完全没有参与脱敏)。
4. **出站闸门隔离守门**:断言 `vigil-outbound` 的改写计数对纯高熵(非硬指纹)请求体为 **0**。
5. **变异测试**:把上述 2/3/4 三条守门分别删掉后,必须能被别的测试抓住或明确变红 ——
   守门本身也要被证明有牙(本轮 `label.rs` 一役的教训:守门链要用变异测试证,不能靠读代码断言)。
6. **fail-safe 回归**:构造超预算输入,断言返空且不 panic、不改变任何决策。

## 5. 开放问题 → 已收敛为「一个前置 + 四个带默认值的参数」

原先此处列了 5 个待拍板问题。复核后:**其中 4 个的前提都是「拿到本项目自己的误报基线」**——
没有基线谁也选不出,而有了基线其中 3 个会自动有答案。**所以这不是 5 个决策,是 1 个前置工作
加 4 个下游参数。** 为免项目卡在「选不出来」,下表先给默认值与重定条件。

### P0 前置(阻塞其余全部)

**按 §4 第 1 / 1b 条建 fixture 并跑出误报基线**,且评估器必须**结构上无法自证**。
在此之前**不要**实装 D4 的档位、不要引入 nuisance 投影、不要争论阈值表来源 ——
那些争论在没有数字时只能靠口味,产出为零。

### 四个下游参数(先用默认值,基线出来后再定)

| # | 参数 | **默认值** | 重定条件 |
|---|---|---|---|
| Q1 | `HIGH_ENTROPY_RISK_DELTA` | **5**(ADR 0012 §1.3 最弱档) | 基线显示精度显著优于预期 → 可上调至 8 与元指令齐平;**不得**到 10(那是有确定语义的 Email/Url 档) |
| Q2 | 阈值表来源 | **先 vendor Cosy 的 MIT 表**(37×37 BIGRAM_COST + 17 锚点),保留版权声明 | 基线显示我们的输入分布与其差异显著 → 用本项目语料重算 |
| Q3 | 上哪几条腿 | **hook + MCP**,与 `scan_meta_instructions` 完全一致 | 不变;**出站腿永不**(§1.2 / §3) |
| Q4 | `FindingSource::Entropy` | **新增 variant** | 不变 —— `finding_source_variants_exhaustive_guard` 的编译期强制同步是收益而非成本 |
| Q5 | nuisance 方向投影 | **不引入** | 基线显示 UUID / git SHA / minified 是误报主因 → 再评估(注:该方向为二手转述且未核实,见 §3) |

### 为什么可以先定默认值

这四条**只影响强度,不影响安全边界**。安全边界由 D1–D3 与 §4 的守门钉死 —— 不进 `scan_text`、
不进 `HARD_RULES`、不触发脱敏、出站闸门改写计数为 0 —— 那几条**不依赖任何基线数据**,也不在
本节讨论范围。换句话说:**选错档位最多是噪声多一点,选错边界才是事故**;而边界已经不是开放
问题了。

## 6. 未落地子范围(可追踪)

- 熵检测的**桌面 UI 呈现**(Protection Overview 是否需要第四类信号卡)——本 ADR 不涉及。
- 与 ISS-008 模型路径的关系:模型侧 `secret` 裸标签与熵命中同 span 时的 merge 策略。
  当前 D1 决定熵不进 `scan_text`,故**不产生 merge 冲突**;若将来改变挂载点,须先回到 ADR 0013 D3。
- **浏览器腿**(`vigil-browser`):扩展侧规则集与 `RULE_PROFILE_VERSION` 的关系未评估。
  熵若上扩展腿会影响 `rule_sync` 跨 crate 不变量,须单开一轮。
