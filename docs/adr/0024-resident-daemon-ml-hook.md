# ADR 0024 — 常驻 daemon + hook ML 瘦客户端(暖模型本地 IPC + fail-closed 降级)

- 状态:**Accepted(实施前定稿)**(2026-06-25;hostile sub-agent review = **SOUND-WITH-CORRECTIONS**,逐条核码无 fail-open;must-fix R1–R7 已落为决策,见末段 **Revised**。Codex 二校本环境不可用 = OpenAI key 401 Unauthorized)
- 日期:2026-06-25
- 依赖:ADR 0012(模型/ONNX 分发)/ ADR 0013(硬指纹 × 模型 merge)/ ADR 0022(引擎选择 hardfp/ml/auto)/ ADR 0023(同步隐私 / 异步注入预检)
- 驱动:R3 用户决策(2026-06-25)——**AI 隐私模型接入 hook 主防护路径**,接受需常驻 daemon 持暖模型;降级铁律 = daemon/模型缺/超时 → 回落硬指纹,**绝不 fail-open**
- 相关结论:`project-vigil-review-2026-06-16`(daemon 真独占价值 = 持 ORT + monitor-resolver)/ `feasibility-A1-selectable-hardfp.md`(同步热路径 warm 358–630ms / cold ~7s)

## 0. 摘要(TL;DR)

今天 **hook 主防护路径只跑硬指纹 + μs 级元指令启发式 + posture**(`hook.rs`,零 ML)。ADR 0023 D4 明确把一次性 hook 排除在 ML 之外,理由是「后台任务需进程存活,hook 一次性不适用」。本 ADR **改变那个前提**:引入常驻 **`vigil-hub daemon`** 持暖 `OrtEngine`(PII NER)+ `InjectionClassifier`(DeBERTa),hook 退化为**瘦客户端**经本地 IPC(Unix domain socket / Windows named pipe)向 daemon 取 ML findings。

**本 ADR 的范围 = 传输 + 生命周期 + 鉴权 + fail-closed 降级**,**不**新增任何决策/merge 语义(那是 ADR 0013/0022 的领域,逐字节复用)。

**一句话不变量**:daemon 是**无状态推理 oracle**(给文本 → 返模型 findings),**不**做 allow/deny/merge/redact 决策;所有门控逻辑留在既有 `vigil-redaction` + `hook.rs`。因此:**ML 永远是叠加在硬指纹底座之上的 recall 增强层;daemon 任何缺失/损坏/超时/冒充 → hook 回落到"今天的硬指纹行为"**(= 当前发行件行为),只损失 ML recall,绝不击穿硬指纹底线,绝不放行未脱敏内容。

## 1. 背景与问题

| 事实(已核验) | 出处 | 影响 |
|---|---|---|
| hook 对**每个**工具调用触发,agent **同步阻塞**等 hook 决策 | `main.rs:456` / `hook.rs:479` | hook 延迟 = 每次工具调用的税,必须有界 |
| hook 路径**零 ML**(只 `detect_hard_secret` / `scan_meta_instructions` / posture / 逆替换再脱敏) | `hook.rs` grep 无 `PiiScanner`/`InjectionClassifier`/`model_cached` | P2 要补的正是这一环 |
| 一次性 hook 冷载 738MB+ORT ≈ 7s **不可行** | feasibility doc | 必须常驻进程持暖模型 |
| `OrtEngine` / `InjectionClassifier` 均 `Send + Sync`(编译期断言) | `engine.rs:610`(`ort_static_assertions`)/ `injection.rs:241` | daemon 可 `Arc` 共享给并发 IPC handler |
| 模型安装 API 齐备 | `bootstrap/mod.rs:62-105` | daemon warm-load + GUI 安装直接调用 |
| 代码库**无任何**本地 IPC 原语(UDS/named-pipe grep 全空) | 全仓 grep | IPC 是 greenfield,传输 + 帧 + 鉴权全新设计 → 高审查价值 |
| serve/wrap 的 ML 已成熟(`resolve_engine_selection` 纯 + `resolve_engine_args` 探测) | `serve.rs:196-323` | daemon 复用同款 warm-load 构造,不重造 |

**为什么是 hook 而非只 serve/wrap**:serve/wrap 只保护**经 MCP 网关路由**的工具;hook 保护 CLI agent 的**全部**工具调用(Bash/Edit/Read/…)。用户「接入模型处理」诉求落在 hook 主路径,这是 P2 的全部意义。

## 2. 核心决策

| # | 决策 | 理由 |
|---|---|---|
| **D1** | 引入 `vigil-hub daemon`(`Start`/`Stop`/`Status` 子命令,镜像 `posture`/`engine`),持暖 `Arc<OrtEngine>` + `Arc<InjectionClassifier>` | 解 feasibility 的 cold-load 738MB/7s;复用 serve 既有 warm-load 构造(不重造模型加载) |
| **D2** | **daemon = 无状态推理 oracle**:输入文本 → 返模型 findings(spans/labels)。**merge/redact/decision 全留 hook**(复用 `merge_findings` ADR 0013) | 最小化对 daemon 的信任:冒充 daemon 返"无 findings"只能**抑制 ML recall**,动不了硬指纹底座与 merge 不变量;且不重复安全逻辑(SSOT) |
| **D3** | **隐私过滤(PII,门控)= 同步**,hook 阻塞等 daemon,**有界超时**;超时/缺失/损坏/鉴权失败/响应畸形 → **硬指纹 only**(ADR 0023 D1:脱敏须在放行前) | 脱敏是门控决策,必须拿到 findings 再决策;有界超时 + 硬指纹兜底 = 延迟封顶且永不击穿底座 |
| **D4** | **注入分类(软信号)= fire-and-forget**:hook 把 corpus + session_id + ledger 投给 daemon **不等待**;**daemon** 异步 classify 后 `bump_session_risk` + 写独立审计事件 | 软信号铁律(命中只累积 risk + 审计,绝不 deny;ADR 0023 D2/D3);risk 经 SQLite `sessions.risk_score` 跨进程,作用于**下次** hook 调用 → 完美承接 0023 异步语义,**hook 零新增延迟** |
| **D5** | **传输 = 本地域套接字**(Unix:UDS;Windows:named pipe),**禁用 loopback TCP** | UDS/named-pipe 有文件权限/ACL 门控(`0600` / 当前用户 SID);loopback TCP 对**所有**本机进程/用户可达,只能靠 token 兜底,安全姿态更差 |
| **D6** | **鉴权 = 纵深**:① 套接字 fs 权限 `0600` + 父目录 `0700`(Win:named-pipe security descriptor 限当前用户 SID)② **per-launch token**:daemon 启动随机生成,原子写 `daemon.json`(`0600`),每个 IPC 请求握手必带 ③ protocol-version 握手不匹配 → 拒(降级硬指纹) | fs 权限挡跨用户;token 挡同用户随机进程驱动 daemon;version 握手防协议漂移。三层任一失败都**降级硬指纹**(fail-closed),绝不因鉴权失败而放行原文 |
| **D7** | **降级 = fail-closed 到硬指纹底座,绝不 fail-open**。hook **永远先在本地**跑硬指纹 + 启发式(如今天),ML 只**叠加**;daemon 任何异常 → 用纯本地硬指纹结果继续 | hard-fp ⊆ merged(ADR 0013 构造保证):丢 ML 丢**recall**,绝不丢**已被硬指纹捕获的正确性**;**hook 绝不因 daemon 不可用而拒绝/放行——只是少了 ML 那一层** |
| **D8** | **hook 路径上 `ml` 与 `auto` 同样降级**(daemon 不可用 → 硬指纹 + **响亮 warning**,GUI daemon 卡显「已选 ml 但 daemon 未运行 → 当前仅硬指纹」),**不**像 serve 的 `ml` 那样硬拒启 | hook 硬拒启 = 阻断 agent **每一次**工具调用 = 用户卸载 Vigil = 净安全损失。诚实的做法是**响亮降级**让用户知情,而非静默裸奔、也非全面 DoS。底座(硬指纹)始终在,故仍是 fail-closed |
| **D9** | **单实例 daemon / 用户**:启动检 `daemon.json` 的 pid 存活 + 持锁;已在跑则复用 | 一个用户一个暖模型进程(738MB×2 内存),避免重复占用;复用 R3 single-instance 纪律 |
| **D10** | daemon **前向兼容** monitor-resolver(2026-06-16 review 的另一独占价值),但 **P2 不实现** | 不为未来过度设计(YAGNI);只保证 IPC 消息枚举与生命周期**能容纳**未来 resolver 职责,不现在 commit |

## 3. daemon 架构

```
vigil-hub daemon start [--foreground] [--ledger <path>] [--engine <ml|auto>]
  ├─ 单实例守门(D9):daemon.json pid 活? → 复用退出 / 否则继续
  ├─ warm-load(复用 serve 既有构造):
  │     OrtEngine::load(model_cached(None))            (engine=ml 严格;auto=仅 cached)
  │     InjectionClassifier::load(injection_model_cached(None))
  │     缺模型/dylib → 见 §6 矩阵(ml 拒载并退出非0 / auto 空载只服务可用引擎)
  ├─ 原子写 daemon.json {pid, socket_path, token, protocol_version, pii_loaded, inj_loaded}(0600)
  ├─ 绑定 UDS/named-pipe(0600 / 当前用户 SID),accept loop
  │     每连接:握手(token + version)→ 分发请求 → bounded 线程池(Arc 共享暖模型)
  └─ 优雅停:停 accept → drain 在飞 → 删 daemon.json → 退
```

**进程模型**:同步 + **每连接线程(有界池上限 N)**,暖模型 `Arc` 共享。匹配既有 detached-thread 风格(ADR 0023 实装即用 `std::thread` + `AtomicUsize` 限并发,非 tokio),避免引入 runtime。ORT 推理内部可能串行化,但池上限 + 背压已防风暴。

## 4. IPC 协议

**帧**:`u32 LE 长度前缀 + JSON body`。body 上限(MAX_FRAME,如 4 MiB)防内存滥用;超限 → 拒。JSON 选型理由:消息小(文本进/findings 出)、可调试、与既有 serde 一致;后续可换紧凑二进制不改语义。

**握手(连接首帧)**:
```json
{"v": 1, "token": "<per-launch>", "op": "hello"}
```
token/version 任一不符 → daemon 立即关连接;**客户端(hook)把"握手失败"等同于"daemon 不可用"→ 降级硬指纹**(D6/D7)。

**请求 op**:

| op | 方向/时序 | body | 响应 | 用途 |
|---|---|---|---|---|
| `redact_scan` | **同步**(D3,hook 等) | `{kind: "result"\|"descriptor"\|"args", text}` | `{findings:[{label,start,end}...]}`(**仅** model PII spans,无决策) | 隐私门控:hook 本地 merge 硬指纹 + 执行脱敏 |
| `classify_injection` | **fire-and-forget**(D4,hook 不等) | `{session_id, ledger_path, text}` | `{ack}`(立即) | 软信号:daemon 异步 classify → bump risk + 审计 |
| `status` | 同步 | `{}` | `{pii_loaded, inj_loaded, uptime_secs, inflight}` | `daemon status` / GUI 卡 |

**scan 边界对齐 ADR 0023 #3**:`kind=result` → 16KB 前缀 cap(CPU 防护);`kind=descriptor` → 全 corpus(防深埋投毒漏检)。该 cap 由 **hook 侧**在投递前裁切(daemon 不猜语义),与现有 `finish_injection_audit` 的 kind-dependent scan 逐字节一致。

## 5. hook 瘦客户端路径(决策流)

```
hook.run(event):
  ├─ [本地·永远] 硬指纹 detect_hard_secret + scan_meta_instructions + posture   ← 今日基线,零依赖
  ├─ engine = --engine ?? engine_config::load_engine(默认路径)                  ← P2.2 回落
  ├─ if engine ∈ {ml, auto} 且 daemon 可达(connect+握手 ok 且对应引擎 loaded):
  │     ├─ [同步,有界超时] redact_scan → model findings
  │     │     ok    → merge_findings(硬指纹, model) → 脱敏/决策(ADR 0013 既有语义)
  │     │     超时/畸形/连接断 → 用硬指纹结果继续(D3/D7) + warn
  │     └─ [fire-forget] classify_injection(session_id, ledger)  ← 不等待,daemon 异步 bump risk
  └─ else(hardfp / daemon 不可达):硬指纹结果(= 今天行为),engine=ml 时额外响亮 warn(D8)
```

**关键**:虚线框外的硬指纹基线**无条件先跑**;ML 分支只在成功时**叠加**。这从控制流上保证 D7。

## 6. fail-closed 降级矩阵(本 ADR 核心)

| 条件 | 隐私过滤(门控) | 注入(软信号) | 净效果 |
|---|---|---|---|
| `engine=hardfp` | 不查 daemon | 不查 | 硬指纹 only(= 今天) |
| `ml`/`auto`,daemon 可达 + 模型已载 | ML PII **叠加**硬指纹(同步,有界) | fire-forget → daemon bump risk | 完整 ML + 硬指纹 |
| daemon **未运行**(connect 失败) | 硬指纹 only | 跳过 | **降级硬指纹**(+ ml 时 warn) |
| daemon 在,**模型未载/载失败** | 硬指纹 only + warn | 跳过 | 降级硬指纹 |
| daemon 在,**IPC 超时** | 硬指纹 only + warn | n/a(fire-forget 已返) | 降级硬指纹 |
| daemon 在,**token/version 握手失败** | 硬指纹 only + warn(视作非我方 daemon) | 跳过 | 降级硬指纹 |
| daemon 在,**响应畸形/截断** | 硬指纹 only + warn(绝不信垃圾) | 跳过 | 降级硬指纹 |
| `engine=ml`(严格)+ daemon 不可用 | 硬指纹 only + **响亮 warn**(D8,**不**硬拒) | 跳过 | 降级硬指纹(GUI 卡显「ml 已选/daemon 未跑」) |

**唯一的 fail-open 反例(必须杜绝)**:任何路径让工具调用**带未脱敏内容放行**,因为"以为 daemon 会处理"。控制流(§5)上不存在该路径:硬指纹基线永远先跑。守门测试(§9 #1)断言之。

## 7. 延迟预算

| 段 | 今天 | 本 ADR 后 |
|---|---|---|
| 硬指纹 + 启发式 | <5ms | <5ms(不变,永远先跑) |
| 隐私 ML(门控) | — | warm 推理 358–630ms + IPC <1ms,**超时上限**(默认 ~1500ms,可配)→ 超时降级硬指纹 |
| 注入 ML(软) | — | **0ms**(fire-and-forget,hook 不等;daemon 异步) |

**净税**:每次工具调用至多 +隐私推理一段(有界封顶);注入零税。延迟敏感者 `--engine hardfp` 彻底关 ML(ADR 0022)。实装可加优化(硬指纹已命中 secret 则跳 ML、按字段大小阈值跳过),非本 ADR 范围。

## 8. 分发(解锁 ml 真跑 — P2.1)

- **ort 变体**:`release.yml` 新增 `cargo build --release -p vigil-hub-cli --features ort`(现 `release.yml:81` 无),产 `vigils-cli-ml-<platform>`(与默认硬指纹件**并存**,诚信:默认件仍 == described)。
- **onnxruntime dylib 捆绑**:`load-dynamic`(`Cargo.toml`),exe 同目录放对应平台 dylib(`prepare_ort_dylib_path` / `exe_local_dylib_candidate` 已认 exe-adjacent);CI 取 dylib 来源见 ADR 0012。daemon 与 ML 变体 CLI 同二进制(`vigil-hub daemon` 在 ort 变体里才有真模型;非 ort 变体 `daemon` 启动即如实报「无 ML,请用 ML 变体」)。
- **模型**:`ensure_*_model_available`(16-chunk + sha256)按需下载;镜像 `fallback_urls` 已 live(`manifest.rs`,2026-06-21 验证)。
- 详见 P2.1 实施;本 ADR 只定「ort 变体 + dylib 捆绑 + 暖载在 daemon」的契约。

## 9. 测试矩阵(进默认 `cargo test --workspace` —— feedback_production_logic_testable)

纯逻辑/可注入,**不**藏在 `#[cfg(feature=ort)]` binary 里:

| # | Case | 断言 |
|---|---|---|
| 1 | hook + daemon 不可达(stub connect 失败)+ 含硬指纹 secret 的工具调用 | **硬指纹照常拦/脱敏**(基线无条件先跑);**绝无**未脱敏放行 |
| 2 | hook + `engine=ml` + daemon 不可达 | 降级硬指纹 + 发出 warn(D8);**不** panic、**不**硬拒、**不** fail-open |
| 3 | IPC 帧 round-trip(长度前缀 + JSON);超 MAX_FRAME | 拒(不 OOM) |
| 4 | 握手:token 错 / version 错 | daemon 关连接;客户端等同 daemon 不可用 → 硬指纹 |
| 5 | `redact_scan` 响应畸形/截断(stub daemon 返垃圾) | 客户端弃用 → 硬指纹(绝不把垃圾当 findings) |
| 6 | `classify_injection` fire-forget | hook **不阻塞**(mock daemon 慢响应,hook 仍及时返);risk bump 由 daemon 侧测 |
| 7 | daemon 暖载:`auto` 缺模型 | 空载该引擎,`status` 如实报 `*_loaded=false`,不进 loader-lock(ADR 0022 D4 纯 fs 探测) |
| 8 | 降级矩阵(§6)逐行 | 表驱动单测,每行一断言 |
| 9 | 单实例(D9):第二个 `daemon start` 检测到活 pid | 复用/退,不双绑 |
| 10 | engine_config 回落(P2.2):`--engine` 缺省 → 读 engine.json | 与显式 `--engine` 等价(纯函数,不污染 ADR 0022 既有测试) |

## 10. 安全威胁模型 + 开放问题(留 Codex 交叉验证 + hostile sub-agent)

**威胁与缓解**:
- **同用户冒充 daemon**(抢绑套接字路径,返"无 findings"):缓解 = token + version 握手 + pid 存活校验;**残余** = 即便冒充成功,只能抑制 ML recall(D2/D7),动不了硬指纹底座。但仍是「ML 防护被静默削弱」,GUI `status` 应能侦测异常。
- **同用户驱动真 daemon 做 oracle**(探测某文本是否触发分类器):token(0600)已挡随机进程;价值本身低(分类器非秘密)。
- **DoS**(灌请求挤垮暖模型/耗尽并发):池上限 + 背压丢弃(软信号可丢);隐私 op 超时封顶,挤不垮 hook(降级硬指纹)。
- **daemon 作为 ledger 写者**(D4 注入 bump risk + 审计):多写者经既有 WAL `BEGIN IMMEDIATE` 纪律(feedback_sqlite_wal_multiwriter);冒充 daemon 至多**抑制或虚增** risk(软信号,过审慎/漏审慎),不击穿门控。

**开放问题(adversarial review 重点拷问)**:
1. **冒充 daemon 的抢绑竞态**:token 在 `daemon.json`(0600)里,冒充者读不到真 token——但它能否抢先绑套接字路径并**自己**写一个 daemon.json,诱使 hook 用它的 token?→ 需:套接字路径与 daemon.json 的**原子绑定 + pid 校验 + 持锁**设计是否真闭合?还是要更强的(如 hook 校验套接字 owner = 当前用户 + 连上后校验 daemon 自报 pid 与 daemon.json 一致 + 该 pid 是 vigil-hub)?
2. **Windows named-pipe ACL**:`interprocess` / 手写的默认 security descriptor 是否真限到当前用户 SID?匿名/network logon SID 是否被排除?(Win 命名管道 ACL 易配错。)
3. **传输选型**:引入 `interprocess` crate(统一 UDS/named-pipe)vs 手写平台分支(`std::os::unix::net` + win32 named-pipe)。新依赖审查(license/维护/攻击面)vs 手写 greenfield 安全边界的出错风险。倾向 `interprocess`,请定夺。
4. **超时默认值 + 可观测性**:1500ms 是否合理?降级时除 stderr warn 外,是否需进审计(「本次工具调用 ML 不可用,走硬指纹」)以便事后审?(注意 untrusted input not in errors:审计零回显。)
5. **token 生命周期**:per-launch 足够,还是需定期轮换 / 连接级 nonce 防重放?(本地单机重放价值低,但请确认。)
6. **`classify_injection` 的 ledger_path 由 hook 传入**:daemon 是否应限制可写 ledger 的路径(防被诱导写任意路径)?还是 daemon 启动期固定自己的 ledger、忽略请求里的路径?(倾向后者更安全。)

## 11. 非 goals(本 ADR 明确不做)

- **新决策/merge 语义**:复用 ADR 0013(merge)/ 0022(引擎是否运行)/ posture(占位符处置)。本 ADR 只管传输 + 生命周期 + 降级。
- **monitor-resolver 实装**(D10):仅保证可容纳,P2 不做。
- **HTTP/远端 daemon**:仅本机同用户 IPC;跨机不在范围。
- **serve/wrap 改用 daemon**:serve 本就长驻持暖模型,无需经 daemon(短期);未来若统一可另案。
- **隐私过滤异步化**:ADR 0023 D1 铁律不变(异步 = 泄漏窗口)。daemon 让隐私**暖载**但仍**同步门控**。

## 12. 关系

- **ADR 0022**:管 `--engine` 是否运行 ML;本 ADR 管 ML 在 **hook 路径**如何经 daemon 运行 + 缺失降级。`hardfp` 下本 ADR 完全不激活。
- **ADR 0023**:管 serve 路径的同步隐私 / 异步注入执行模型;本 ADR 把同一**安全语义**(隐私同步门控、注入软信号异步)落到 **hook + daemon** 拓扑(D3/D4 与 0023 D1/D2 同构)。
- **ADR 0013**:merge 不变量(Hard ⊆ merged)是 D7 fail-closed 成立的**构造基础**。
- **2026-06-16 review**:daemon 真独占价值 = 持 ORT(本 ADR 兑现)+ monitor-resolver(D10 留口)。

## Sources
- 代码:`apps/vigil-hub-cli/src/hook.rs`(`run:479` / 无 ML;基线无条件先跑 `:546-557`;PostToolUse withhold `:1581-1595`)、`main.rs:372`(`From<CliServeArgs>` 已回落 engine_config,P2.2a)、`serve.rs:196-323`(engine 选择)+ `:835-892`/`:974-1035`(ort warm-load 构造,daemon 复用)、`engine_config.rs`(落盘)、`crates/vigil-redaction/src/{engine.rs:610,injection.rs:241}`(Send+Sync)、`merge.rs:199`(Hard ⊆ merged)、`crates/vigil-firewall/src/preflight.rs:92,572`(`PiiScanner` / `ort_scanner_arc_from_env`)、`bootstrap/mod.rs:62-105`(模型 API,**ort-gated**)、`.github/workflows/release.yml`(P2.1 已加 --features ort 变体)
- ADR 0012 / 0013 / 0022 / 0023;feasibility-A1-selectable-hardfp.md;project-vigil-review-2026-06-16

## Revised — hostile sub-agent review(2026-06-25)

**VERDICT = SOUND-WITH-CORRECTIONS**(foreground hostile sub-agent;Codex 二校不可用 = OpenAI key 401)。核心不变量(fail-closed 到硬指纹底座、**永不 fail-open**)经真实代码逐条核实**成立**:hook 基线无条件先跑(`hook.rs:546-557`)、merge Hard ⊆ merged(`merge.rs:199`,golden 矩阵守门)、PostToolUse withhold 独立于 ML op(`hook.rs:1581-1595`)→ 冒充/缺失 daemon **只能抑制 ML recall,动不了硬指纹 deny 与 withhold**。**未发现 Crit fail-open**。以下 must-fix 把 §10 的"开放问题"从"延后"升级为**实施前必决**,已落决策(P2.3 实施按此):

| # | sev | 决策(取代原 open question) |
|---|---|---|
| **R1**(原 Q1)| High | **冒充 daemon 防御 = peer-credential 校验,非仅 token**(token 循环:冒充者自写 daemon.json 自授 token,自洽通过握手)。hook 连上后**必须**:① OS 元数据核 socket/pipe owner == 当前用户;② 取**对端(server)进程凭据**(Linux `SO_PEERCRED`;Win 命名管道 server PID)核对 == `daemon.json.pid` 且该 pid 镜像名 = `vigil-hub`。任一不符 → 当 daemon 不可用 → 硬指纹。 |
| **R2**(原 §6 超时行)| High | **有界超时必须覆盖整段流式读**,非仅 connect。client 设 `set_read_timeout`(`SO_RCVTIMEO`)覆盖**每次 recv** 截止;声明的 body 在截止前未读满 → 丢连接 → 硬指纹。防"握手后挤牙膏"楔死 hook(正是 D8 要避免的"用户卸载")。**新增测试**:stub daemon 握手后扣住 body → hook 预算内降级**不 hang**。 |
| **R3**(原 Q6)| Med | **`classify_injection` 请求体删除 `ledger_path`**;daemon 在 `daemon start --ledger <path>` 启动期**绑定自己的 ledger**,**忽略**任何 per-request 路径(杜绝诱导写客户端指定文件 = 任意写 / 跨 session risk 投毒)。daemon 绝不打开 client 命名的文件。 |
| **R4**(D4)| Med | **fire-and-forget 注入发送 = 非阻塞/短截止**(背压下 `write()` 阻塞会破坏"注入零税")。`EWOULDBLOCK`/短截止 → **丢弃软信号**(0023 D5:软信号可丢)并返回。§7 注入零税补此前提。 |
| **R5**(原 Q4)| Med | **`ml`(严格)在 hook 降级硬指纹时必写持久审计事件**(零回显,沿 0023 untrusted-input 纪律),非仅 stderr(agent CLI 常吞 stderr);**GUI daemon 卡持久显示"ml 已选/daemon 未跑 → 当前硬指纹"**(从 aspirational 升 normative)。残留偏执用户需 hook 侧硬阻断 → 未来 opt-in `--engine ml --strict-hook`(本 P2 非 goal,文档化)。 |
| **R6**(原 Q2)| Low | **Windows named-pipe 显式 DACL**:仅当前用户 SID;**拒** `NETWORK`/`ANONYMOUS`/`Everyone`。**新增 Windows-gated 测试**:第二用户/低完整性 client 被拒。用 `interprocess`(Q3)→ 审其默认 security descriptor,不假设。 |
| **R7**(D1)| Med(citation)| §1 OrtEngine `Send+Sync` 引用更正为 **`engine.rs:610`**(`ort_static_assertions`);`engine.rs:149` 仅断言 Mock/Noop/`Box<dyn RedactionEngine>`,不覆盖 OrtEngine。（本 Revised 已改 §1 + Sources。） |

**§10 状态**:Q1→R1 / Q2→R6 / Q4→R5 / Q6→R3 = **已决**;Q3(interprocess vs 手写)+ Q5(token 轮换,本地重放价值低)= **可接受残余**(实施时定夺,不阻断)。

**§9 测试矩阵追加(进默认矩阵)**:R2 流式读截止降级测试、R6 Windows DACL 拒绝测试、R3 daemon 绑定固定 ledger(忽略请求路径)测试、R1 peer-credential 不符 → 降级测试。

**实施前必决 gate(P2.3)= R1 + R2 + R3 + R5 + R6**(R4/R7 同批落)。评审定论:对"传输+鉴权+fail-closed"这类 ADR,这四问**就是**交付物,必须实施前解决而非延后 —— 已照办。

## Revised 2026-07-06 — 第二客户端(browser native host)+ IPC 抽 crate

- daemon 客户端面从 hook(+ `daemon status`)扩到 **vigil-native-host**(浏览器 paste 守门
  ML 增强;ADR 0009 Revised 2026-07-06)。D2(无状态推理 oracle / merge 留客户端)与
  R1-R3 不变量**原样适用**,零 daemon 端改动。
- protocol / client / transport(客户端侧)/ wire(WireFinding 应用原语)抽至
  `crates/vigil-daemon-ipc`(纯移动;hub-cli `daemon/mod.rs` re-export 保路径);`serve`
  accept 循环归位 `daemon/server.rs`(需 `DaemonCaps`)。
- 长驻客户端新纪律:R2 的 detached-worker 模式假设 one-shot 进程回收;**长驻调用方必须自带
  失败冷却/限流**(native host:60s 冷却)。已注记于 `transport::query_daemon` doc。
