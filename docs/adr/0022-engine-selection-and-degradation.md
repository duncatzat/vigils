# ADR 0022 — 引擎选择(hardfp / ml / auto)与优雅降级

- 状态:**Draft**(2026-06-20;等 Codex 交叉审查 + 实装落地)
- 日期:2026-06-20
- 依赖:ADR 0012(模型与 ONNX Runtime 分发)/ ADR 0013(硬指纹 × 模型 merge)/ ADR 0001(action-control-plane,身份)
- 驱动证据:`docs/strategy/2026-06-20-modernization-review/feasibility-A1-selectable-hardfp.md`(可行性研究,verdict=FEASIBLE-WITH-WORK)
- 决策来源:2026-06-20 现代化审查 —— principal 定 **A1(真做 AI 过滤器)+ 用户可自选硬指纹版、二者兼容**;**原仓演进到 v1.0**

## 0. 摘要(TL;DR)

Vigil 的隐私过滤有两层:**硬指纹**(`vigil-redaction` HARD_RULES,正则,<1ms,常开 fail-closed 底座)与 **ML 模型**(OrtEngine PII NER + InjectionClassifier,358-630ms/样本,opt-in)。本 ADR **不改 merge 语义**(那是 ADR 0013),只定义**用户如何选择 ML 层是否运行,以及运行时缺失/损坏如何降级**。

引入单一用户面开关 `--engine {hardfp | ml | auto}`,默认 `hardfp`。三态语义:

| mode | ML 层 | 缺 dylib/模型时 | init 失败(可捕获 EngineError)时 | 适用 |
|---|---|---|---|---|
| **hardfp**(默认)| 关 | —(本就不跑 ML)| —(不跑 ML)| 默认发行;离线、确定性、零模型依赖 |
| **ml**(严格)| 开 | 拒绝启动(`ServeError`)| 拒绝启动(`ServeError`,**保留现有 fail-closed**)| 明确要 ML、且要知道它是否坏了 |
| **auto**(尽力)| 探测后决定 | **降级硬指纹 + warn**(永不拒启)| **降级硬指纹 + warn** | 既想要 ML,又不想因环境缺失而启动失败 |

## 1. 核心决策

| # | 决策 | 理由 |
|---|---|---|
| **D1** | 用户面三态 `--engine {hardfp\|ml\|auto}`,默认 **hardfp**,作为现有两布尔(`enable_privacy_filter` / `enable_injection_classifier`)的**语法糖** | 现有开关已存在(`serve.rs:89,114`),只缺统一入口与 `auto`;默认 hardfp = **与今天实际发行的二进制行为一致**(诚信:ship == described) |
| **D2** | **共存是结构性不变量,本 ADR 不新增 merge 语义** | ADR 0013 `merge_findings`(`crates/vigil-redaction/src/merge.rs:197-211`)无条件保留全部 Hard 命中,只补不重叠的 Model 命中;Hard 输出 ⊆ 合并输出。"二者兼容"已由构造保证 |
| **D3** | **单一 `load-dynamic` 二进制,运行时选择,不做编译分版** | `ort` 已 `load-dynamic`(运行时 dlopen);一个 `--features ort` 构建即可同时服务三态,避免双产物分发与文档复杂度 |
| **D4** | **`auto` 在任何 ort API 调用前做纯文件系统探测**(dylib + 模型目录就位?)| 缺失场景**永不进入** loader-lock 静默 hang 路径(`serve.rs:367-382` 超时 `abort()`);探测是纯 fs 检查,无 dlopen 风险 |
| **D5** | **`ml` 保留现有严格 fail-closed**(flag on + init Err → `ServeError`,拒启)| 零信任纪律(ADR 0013 D6;`serve.rs:82,108,554`);明确要 ML 的用户必须知道它坏了,而非静默裸奔 |
| **D6** | **`auto` 把可捕获的 `EngineError` 降级为 warn + 硬指纹**(auto 永不拒启)| `auto` 的契约是"尽力上 ML,不行就退硬指纹";降级后**仍 fail-closed 到硬指纹底座**(非 fail-open)——硬指纹永远在 |
| **D7** | 不可捕获的 loader-lock `abort()`(`serve.rs:380`)**保留为最后兜底**,仅在 dll **存在但损坏/版本错**时可达 | D4 探测已挡掉"纯缺失";剩下的"存在但坏"是罕见且无法安全 unwind 的 Windows loader-lock 情形,abort 是唯一安全逃逸(原注释 `serve.rs:355` 已论证)|

## 2. 实装计划(本增量 = v0.2.x,零破坏)

1. **CLI**:加 `--engine <hardfp|ml|auto>`(clap `ValueEnum`),默认 `hardfp`。置于 `serve` / `wrap` 共用参数面(`main.rs:305-345` 的 common args)。`--engine` 与裸 `--enable-privacy-filter`/`--enable-injection-classifier` 的关系:`--engine` 是高层入口;若用户两者都给,以更**保守**者为准(冲突解析见 §4 开放问题)。
2. **探测函数** `fn ort_runtime_available(model_dir, want_dylib) -> bool`(serve.rs):纯 fs 检查 —— ① dylib 可解析(`ORT_DYLIB_PATH` 已设 **或** exe 同目录存在合理大小的 `onnxruntime` 动态库,复用 `prepare_ort_dylib_path` 的同款判定);② 模型目录/文件存在。**不调用任何 ort API**。
3. **解析**:在 `build_hub_with_config`(`serve.rs:403`)之前把 `--engine` 解析成两布尔 + 一个 `degrade_on_init_err: bool`(auto=true / ml=false):
   - `hardfp` → 两布尔 false。
   - `ml` → 两布尔 true,`degrade_on_init_err=false`。
   - `auto` → 探测:present → 两布尔 true;absent → 两布尔 false + `eprintln!` warn("ML runtime not found at …; running hard-fingerprint-only");`degrade_on_init_err=true`。
4. **降级钩子**:`build_hub_with_config` 中 firewall(`serve.rs:462`)/ classifier(`serve.rs:555`)构造块,把现有 `OrtInitOutcome::Failed(e) => Err(ServeError::…)` 改为:`if degrade_on_init_err { warn + 继续(该层置 None)} else { Err(ServeError::…) }`。`Panicked` 同理。`abort()` 路径不动(D7)。
5. **wrap**:`wrap.rs:89-91` 当前硬编码两 false(= hardfp),保持默认;`--engine` 若给则透传(turnkey 仍默认 hardfp)。

## 3. 测试矩阵(进默认测试矩阵 —— feedback_production_logic_testable)

| # | Case | 断言 |
|---|---|---|
| 1 | `--engine hardfp` | 两布尔 false;无 ORT 探测/调用 |
| 2 | `--engine ml`(无 feature ort)| 现有行为:flag on + feature off → 既有 fail-closed `ServeError`(不退化)|
| 3 | `--engine auto` + 探测 absent | 两布尔 false + warn;Hub 正常启动(硬指纹)|
| 4 | `--engine auto` + 探测 present(mock fs)| 两布尔 true(进 init 路径)|
| 5 | `ort_runtime_available`:dylib 缺 | false |
| 6 | `ort_runtime_available`:模型目录缺 | false |
| 7 | `ort_runtime_available`:两者就位(temp fixture)| true |
| 8 | 解析冲突:`--engine hardfp` + `--enable-privacy-filter` | 取保守(见 §4)+ 明确测断言 |
| 9 | `auto` + `degrade_on_init_err` + 注入 `EngineError`(测试桩)| 降级硬指纹 + warn,不返 `ServeError` |

探测函数 `ort_runtime_available` 必须是**纯函数 / 可注入路径**,不依赖 `#[cfg(feature=ort)]`,以便默认 `cargo test --workspace` 守门(避免逻辑藏在 feature-gated binary 里)。

## 4. 开放问题(留 Codex 审查)

1. **`--engine` 与裸布尔冲突解析**:用户同时给 `--engine hardfp` 和 `--enable-privacy-filter` 时取保守(hardfp)还是报错?当前倾向**取保守 + stderr 提示**;Codex 评审是否该改 hard error。
2. **探测的 dylib"合理大小"阈值**复用 `prepare_ort_dylib_path` 既有判定;是否需要更强的 magic-byte 校验避免把 stub dll 判成 present(从而进 abort 路径)?
3. **模型目录探测粒度**:仅查目录存在,还是要校验关键文件(model.onnx + tokenizer)+ sha256?增量 1 倾向"查关键文件存在"(不验 sha,sha 在下载器已管),Codex 定夺。

## 5. 非 goals(本 ADR 明确不做)

- **模型分发**(per-platform dylib 捆绑 + 按需下载 + 镜像):这是 A1 的重活,留 **v0.3 track**(feasibility doc §Cost;`manifest.rs:189` `fallback_urls: vec![]` 单源风险另案)。
- **同步→异步预检**(把 358-630ms ML 推理移出网关同步热路径 `hub.rs:898`→`firewall.evaluate:1249`):留 v0.3(延迟优化)。
- **`ort` rc.12 → stable 2.0 迁移**:A1 前置,留 v0.3(独立 issue,验 load-dynamic 存活)。
- **ADR 0001 身份重写**(control-plane 核心 + privacy-filter 可选层的正式收敛):v1.0;本 ADR 把"ML 是显式可选层"落进代码,是那次重写的**前置事实**。

## 6. 关系与前向链接

- **ADR 0013**(merge):管 findings 如何**合并**(Hard 赢重叠、fail-closed)。本 ADR 管**是否运行 ML 层 + 缺失如何降级**。正交可组合。
- **ADR 0012 §6**(fail-closed):Model 不可用 → 只跑 Hard。本 ADR 的 `auto` 降级 = 该决议的用户面落地;`ml` 严格态 = 该决议的"显式要求则必须可用"强化。
- **ADR 0001**(身份):本 ADR 将隐私过滤正式定位为 control-plane 之上的**可选层**,为 v1.0 的 ADR 0001 重写铺垫(privacy-filter 不再是隐式强绑,而是 mode 选择)。

## 实装状态(2026-06-20)

**已实装(内部仓,未提交)** —— 单增量含完整 D1–D7,**不**再拆 1b:
- `vigil-redaction`:`model_cached` / `injection_model_cached`(非下载 sha256 缓存探测,复用 `check_existing`)。
- `serve.rs`:`EngineMode`(clap ValueEnum)+ `resolve_engine_selection`(纯,5 单测进默认矩阵)+ `resolve_engine_args`(探测 + warn)+ `ml_best_effort` 字段 + firewall/classifier 两个 init 块重构(`Option<Arc<dyn PiiScanner>>`:best-effort 用 `model_cached`**绝不下载** + Failed/Panicked 降级硬指纹;`ml`/legacy 严格 `ensure_*` + fail-closed)。
- `main.rs`:`--engine` flag;`From` 解析 + `ml_best_effort = (engine==Auto)`。

**Codex 交叉审查轨迹**:R1 verdict=FIX-REQUIRED —— 揪出"把 `auto` 折叠成 bool、build 层不知道是 auto"导致 (a) TOCTOU 仍可能 `ensure_*` 重下载、(b) D6 降级未落地。**已修**:`ml_best_effort` 携带进 `build_hub_with_config`,best-effort 路径改用 `model_cached`(无下载)+ 降级。绿:default build + 236 lib + 9 serve_smoke(含 `PrivacyFilterUnavailable` fail-closed 回归门)+ ort check + clippy ×2 `-D warnings`。

**残留(已知,文档化)**:真 init *hang*(loader-lock,存在但版本错的 dll)在 auto 下仍 `abort()`(D7)——`run_ort_init_with_timeout` 真超时无法安全 unwind;auto 探测要求 dylib 就位已挡掉纯缺失。后续可加 dll magic-byte/版本校验进一步收敛。

## Sources
- 可行性研究:`docs/strategy/2026-06-20-modernization-review/feasibility-A1-selectable-hardfp.md`
- 现代化路线图:`docs/strategy/2026-06-20-modernization-roadmap.md`(Theme A / Decisions)
- 代码:`apps/vigil-hub-cli/src/serve.rs`(`prepare_ort_dylib_path:298` / `run_ort_init_with_timeout:359` / `build_hub_with_config:403` / firewall:462 / classifier:555)、`main.rs:317,330`、`wrap.rs:89`、`crates/vigil-redaction/src/merge.rs:197-211`
