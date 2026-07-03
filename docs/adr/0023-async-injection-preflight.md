# ADR 0023 — 异步注入预检(同步隐私过滤 / 异步软信号注入)

- 状态:**Draft**(2026-06-21;设计 only,实施留 v0.3 A1 专项轮 + Codex 交叉审查)
- 日期:2026-06-21
- 依赖:ADR 0013(merge)/ ADR 0022(engine selection)/ P0 注入防护 Slice D(DeBERTa 软信号)
- 驱动证据:`docs/strategy/2026-06-20-modernization-review/feasibility-A1-selectable-hardfp.md`(ML 推理在网关**同步**热路径,warm 358–630ms/cold ~7s);L2/L5 lane

## 0. 摘要(TL;DR)

A1 ML 推理当前**全部同步**跑在网关 `handle_request` 热路径上,每次工具调用 +数百 ms。本 ADR 按**安全语义**把两个 ML 引擎分开处置:

| 引擎 | 作用 | 同步? | 理由 |
|---|---|---|---|
| **隐私过滤(OpenAI PII)** | 在 `firewall.evaluate` 内**门控决策 + 脱敏** | **必须同步** | 脱敏必须在动作放行**之前**完成,异步 = 动作先于脱敏 = **泄漏窗口** |
| **注入分类器(DeBERTa)** | **软信号**:命中只 bump 累积 session risk + 审计,**绝不 deny** | **可异步** | 不门控任何决策,异步 = **无泄漏窗口**;把 738MB DeBERTa 推理移出同步热路径 |

**净效果**:每次工具调用的同步 ML 延迟从"隐私 + 注入两段"降到"仅隐私一段";注入信号改为带外累积。延迟敏感场景仍可 `--engine hardfp`(ADR 0022)彻底关 ML。

## 1. 核心决策

| # | 决策 | 理由 |
|---|---|---|
| **D1** | **隐私过滤保持同步**(`firewall.evaluate` 内,hub.rs:1249) | 它消费 PII findings 做 deny/redact 决策;异步会让工具调用在脱敏完成前放行 = 泄漏。绝不动。 |
| **D2** | **注入分类器移到异步/带外**:`handle_request` 不再 `classifier.classify` 同步阻塞;改为 spawn 后台任务,完成时 bump session risk + 写审计,当前请求**不等待** | 软信号铁律(命中只累积 risk + 审计,绝不 deny,hub.rs:679)→ 它从不门控当前请求,异步**不引入泄漏窗口**,只是把延迟移走 |
| **D3** | **当前请求决策用请求开始时的 session risk**;异步注入扫描 bump 的 risk 作用于**后续**请求 | 与现有"累积 session risk(跨进程经 `sessions.risk_score` 可见)"语义一致;本请求本就不被注入信号 deny |
| **D4** | **仅 serve 长驻路径用异步注入**;一次性 hook 路径**不**用注入分类器(本就 serve-warm-session only) | 后台任务需进程存活才能完成;serve 长驻满足,hook 一次性不适用 |
| **D5** | **有界并发** + **审计独立事件**:后台注入任务数设上限(背压,防风暴);其审计作为**独立** hash-chain 事件(时间戳化,与请求主事件乱序无妨——账本 append 经 `BEGIN IMMEDIATE` 串行) | 防无界 spawn;hash 链不要求注入事件与请求事件相邻 |
| **D6** | always-on **非 ML** 元指令启发式(`scan_meta_instructions`,hub.rs:558,无 ort 依赖,μs 级)**保持同步** | 它极快且是 ML 缺位时的注入兜底;同步零感知开销 |

## 2. 同步/异步边界(一图)

```
handle_request(req):
  ├─ [SYNC] scan_meta_instructions      (μs;always-on 启发式,D6)
  ├─ [SYNC] firewall.evaluate           (隐私过滤 PII + 硬指纹 merge → deny/redact 决策,D1)
  │          └─ 决策用 session.risk_score @ 请求开始 (D3)
  ├─ 放行 / deny / 脱敏后转发            (← 决策点,隐私已同步完成)
  └─ [ASYNC] spawn 注入分类器 classify  (D2;完成 → bump session risk + 独立审计事件,D5)
             (当前请求不等待;risk 作用于后续请求)
```

## 3. 实施计划(本 ADR **不**实施;留 v0.3 A1 专项轮)

1. Hub 加一个有界后台执行器(tokio task + semaphore 限并发,或一个单 worker + bounded channel)。`serve` 启动时建,退出时 join/drain(best-effort,超时丢弃)。
2. 把现 `handle_request` 内同步 `classify` 调用点改为:构造 scan corpus → 投递到后台 channel → 立即返回。后台 worker `classify` → `bump_session_risk` + `append_event`(零回显审计,沿用现脱敏纪律)。
3. **不变量守门测试(进默认矩阵)**:① 隐私过滤仍同步门控(deny/redact 决策在转发前)② 注入软信号异步后**仍写审计 + bump risk**(可用 mock classifier + 等待 drain 断言)③ 后台队列满时背压不阻塞主路径(丢弃 + warn,绝不阻塞或 panic)。
4. `--engine` 交互:`auto`/`ml` 下注入分类器在(已加载时)走异步;`hardfp` 下本就不加载。

## 4. 非 goals

- **隐私过滤异步化**:明确**不做**(D1 泄漏窗口)。隐私延迟由 `--engine hardfp`(ADR 0022)或未来更快/量化模型解决,不靠异步。
- **后台注入的 backpressure 策略调优**(丢弃 vs 阻塞 vs 采样):本 ADR 定"满则丢弃 + warn,绝不阻塞主路径";精细策略留实施轮数据驱动。
- **跨请求注入信号的实时门控**:软信号语义不变(累积,不实时 deny);若未来要"注入即拦",那是另一条 deny-path 决策,不在本 ADR。

## 5. 关系

- **ADR 0013 / 0022**:正交。0013 管 merge,0022 管引擎是否运行;本 ADR 管(运行时)隐私同步 / 注入异步的**执行模型**。
- **P0 注入防护 Slice D**:本 ADR 不改"软信号命中只 bump risk + 审计绝不 deny"的铁律,只改它的**执行时机**(同步→带外)。

## Revised — 实装 + hostile review(2026-06-21)

**实装于 `crates/vigil-mcp/src/hub.rs`**(default + ort 双构建 / clippy `-D warnings` / 测试全绿)。与 §0–§3 草案的关键校正:

1. **整段软信号扫描带外(非"启发式同步 / DeBERTa 异步")。** 草案 D6 想让启发式留同步、只异步 DeBERTa,但二者对同一文本 `merge`(取 max risk,不累加,防双计)—— 拆开会破坏该不变量(双计 / 双审计)。故实装为:**仅当 ort + classifier 在场**时把**整段**扫描(启发式 + DeBERTa + merge + 审计)派给带外线程;**非-ort / 无 classifier 仍同步**(启发式-only),默认发行件**零改动**。
2. **机制 = 有界 detached 线程**(非常驻 worker+channel):`static INJECTION_INFLIGHT: AtomicUsize` < `INJECTION_ASYNC_CAP=4` 限并发;超 cap / spawn 失败 → 丢弃 + warn(软信号可丢)。共享 `finish_injection_audit` 让同步/带外两路审计语义**逐字节一致**。
3. **隐私过滤完全未动**(`firewall.evaluate` 仍同步,redaction 仍在放行前)——本 ADR 只动注入软信号路径(hostile review CONFIRM)。

**Hostile sub-agent review(codex 当轮 stall,走 fallback)抓出 2 个真缺陷,已修:**
- **#3 descriptor 扫描回归**:OLD `audit_descriptor` 对**全 corpus** 跑启发式 + sha;统一 `finish_injection_audit` 误把 16KB 前缀 cap 也加到 descriptor → 深埋 >16KB 的元指令投毒漏检 + 审计锚点漂移。**修**:`scan` 按 kind 区分(Result=16KB 前缀做 CPU 防护;Descriptor=全 corpus,还原 OLD);DeBERTa 两 kind 仍在 16KB 前缀上算(匹配 OLD `injection_classify_opt` 内部 cap)。
- **#4 panic 计数永久泄漏**:`classify` 若 **panic**(非 Err)会 unwind 跳过手动 `fetch_sub` → `INJECTION_INFLIGHT` 永久泄漏,4 次即楔死 cap、静默禁用所有后续注入软信号。**修**:`InjectionInflightGuard`(RAII Drop)在带外线程顶部持有,正常完成 / panic unwind 都归还 slot;over-cap / spawn-fail 仍手动归还(无双减)。

**残留(文档化,可接受)**:serve 进程在带外线程 drain 前退出会丢失个别软信号审计(非门控、跨进程 risk 仍累积);真 init *hang* 不在本路径(注入 classifier 已 warm-load)。**真机端到端 async 验证**(带 dylib+模型)留 ort smoke 测扩展(现 `#[ignore]`)。

## Sources
- `docs/strategy/2026-06-20-modernization-review/feasibility-A1-selectable-hardfp.md`(同步热路径延迟证据)
- 代码:`crates/vigil-mcp/src/hub.rs`(`handle_request:898` / `firewall.evaluate:1249` / `injection_classifier:367` / `classify:540` / 软信号 bump+audit:679)
