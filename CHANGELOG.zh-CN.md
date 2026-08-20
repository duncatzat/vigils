# 更新日志

Vigils 的所有重要变更记录于此。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/),版本遵循
[语义化版本](https://semver.org/lang/zh-CN/)(0.x 阶段允许接口演进)。

> English version: [CHANGELOG.md](./CHANGELOG.md)

---

## [Unreleased] - 供应链门禁:cargo-deny + 诚实的 MSRV

### Added

- **CI 引入 cargo-deny 供应链门禁**(`deny.toml` + `ci.yml` 新增 `cargo-deny` job)。
  每次 push/PR 检查 advisories(RUSTSEC 漏洞、yanked crate)、license 兼容性、
  重复/外来依赖与依赖来源白名单。此前依赖漏洞盯梢是手工流程(wasmtime 25 -> 41
  那次升级手动修了 15 个 RUSTSEC);现在新披露的漏洞在 CI 下一次运行时即变红。
- **每周漏洞复查 workflow**(`.github/workflows/deny-advisories.yml`)。漏洞披露
  不跟我们的发版节奏走 -- 每周一对 main 分支的 lockfile 复跑扫描,无提交、无发版
  也能发现新披露的漏洞(与 acceptance workflow 防"上游漂移"同思路)。
- **CI 新增 MSRV 编译检查 job**(`ci.yml` 的 `msrv`)。用声明的最低 Rust 版本编译
  workspace 并比对声明一致性,工具链下限不再会悄悄失效。

### Security

- **升级 `h2` 0.4.15 -> 0.4.17(RUSTSEC-2026-0258)**--无边界空 DATA 帧。这是新
  cargo-deny 门禁首跑就抓到的**生产路径漏洞**:`h2` 位于 hyper/reqwest 之下,承载
  MCP HTTP transport。另刷新 yanked 的 `spin` 0.9.8 -> 0.9.9(dev-only,测试专用
  `rsa` crate 的传递依赖)。

### Fixed

- **MSRV 声明已过期** -- `rust-version = "1.80"`,而依赖树(wasmtime 44,修
  RUSTSEC-2026-0114 所需)实际需要 rustc 1.95。旧工具链用户会在依赖深处收到
  难懂的语法错误而非清晰的"Rust 版本过旧"提示。声明现已改为 `1.95`,与事实一致。

## [v0.7.0-beta.2] — 2026-07-22 — 修复:codex hook 在 Windows fail-open(cmd /C 引号陷阱)

### 修复

- **codex hook 在 Windows 上 fail-open,凭据越过防线泄漏。** 真机取证发现 codex 通过
  `cmd.exe /C "<command>"` 执行 hook,而 Vigil 注册的 command 给可执行文件路径加了双引号
  (为 Claude Code 设计的格式)。`cmd /C` 的引号规则:当 command 以 `"` 开头且含多个引号时,
  strip 首尾引号 → 破坏带引号的 exe 路径 → 找不到命令 → exit 1 → codex 判 hook `Failed`
  → **fail-open**,真实 `github_token` 明文抵达模型。三个 codex hook 事件
  (PreToolUse / PostToolUse / UserPromptSubmit)全部受影响。修复让 codex 面 command 的 exe
  路径**不加引号**(仅 Windows + codex;Unix codex 走 `sh -lc`,单引号安全;Claude/Gemini/
  Cursor 保持引号——它们的执行方式兼容引号,真机 Claude 运行仍正确拦截,已实证)。command 首
  字符非引号后,`cmd /C` 不再 strip,其后的 `--ledger "..."` 引号正常保留。端到端验证:修复
  引擎自动生成的 command 让 codex 对有效 token 报 `PreToolUse Blocked`(拦截)而非泄漏。若 exe
  路径本身含空格,codex 的 `cmd /C` 无法可靠执行(此情形无安全的引号格式,是 codex/Windows
  的限制)——Vigil 现在如实警告,并指向 MCP 网关(`vigil-hub wrap`)作为 codex 的替代保护,而非
  静默 fail-open。

## [v0.7.0-beta.1] — 2026-07-21 — MCP wrap 扩容至 12 家、codex trust 诚实化、prompt 侧守门

### 新增

- **五个新的 MCP 网关接入面 —— Gemini CLI、CodeBuddy、Cline、Grok、OpenCode**,
  `setup --mcp` turnkey 覆盖达到 **12 家 agent**。Grok 复用 Codex 同构 TOML 线
  (`[mcp_servers.*]`,以真机 `grok mcp add` 落盘契约实证);OpenCode 走独立 v1
  `mcp.<name>` 专线(`command` 单数组 + `environment`,且对「只有 v2 `opencode.jsonc`
  布局」显式拒绝守门 —— 绝不静默漏保护);CodeBuddy 按官方三路径优先链;Cline 用
  globalStorage 稳定布局 + `VIGIL_CLINE_MCP_PATH` 逃生舱;Gemini 共享 `settings.json`
  安全共写(顶层未知键保留,hook + wrap 两面 TOCTOU stamp)。
- **Codex prompt 侧守门**:Codex hook 面新注册 **UserPromptSubmit** —— 把裸的高置信
  凭据直接贴进 codex 对话框,现在会在抵达模型前被拦下(codex 拒绝契约:exit 0 + 顶层
  `{"decision":"block"}`;其余 CLI 防御性 fail-closed)。prompt 是自由文本,只查硬指纹
  secret —— 不上软规则,不误伤正常粘贴。审计只落 sha256 + 检出类别,绝不记录 prompt
  原文。

### 修复

- **Codex「已保护」可能是假绿 —— 现在如实报 `pending_trust`。** codex(0.144.x)只在
  用户完成一次性交互 `/hooks` 审阅、并把 trust hash 持久化进 `config.toml [hooks.state]`
  后才执行用户级 hook;headless(`codex exec`)从不 trust,未信任的 hook 打印
  `hook: PreToolUse Failed` 后 **fail-open 放行**。此前 Vigil 判 `active` 只看「配置在位
  + exe 存在」,桌面 Aegis 卡与 `setup --json` 在 codex 实际裸奔时仍显示「已保护」。
  Vigil 现在逐字节复刻 codex 的 trust hash 校验(以真机落盘样本为测试锚),把「已注册但
  未信任」的 codex 如实报为 **`pending_trust`**(绝不计入 protected),并给出精确到事件的
  一次性 `/hooks` 引导。设计上 fail-honest:状态不可读 / hash 不符 / hook 被禁用一律降级
  为 `pending_trust`,绝不虚报安全。Vigil 绝不代写 codex managed 配置、绝不替用户绕过
  trust —— 那次审阅属于用户。
- **wrap 面评审修复(codex 对抗评审 7 项)**,最重三条:OpenCode 仅 v2 `.jsonc` 在场时
  被误读为「未配置」= 静默漏保护(现为显式拒绝);派生 server-id 碰撞会让两个 server 在
  审批/审计/pin 中身份塌缩(六个 apply 面写前唯一性预检);TOCTOU stamp 在 12 处调用点
  被静默降级(现为 fail-closed helper,原子写内部文件被删也 abort)。

### 变更

- **桌面 deploy 原子化**:引擎换装走安装互斥 + staging 两阶段替换,旧引擎保活到新 setup
  成功为止 —— 部署失败不再可能把用户留在「零可用引擎」;回滚失败时如实报告磁盘终态。
- `setup --json` 逐 agent 条目新增 `warnings` 数组(只增性 schema 变更),`status` 值域
  新增 `pending_trust`;桌面 Aegis 卡新增黄色「待 codex 信任」标签 + 一次性 `/hooks`
  引导提示(中英)。

## [v0.6.1-beta.1] — 2026-07-20 — 桌面 Deploy Guardian 修复 + 图标圆角柔化

### 修复

- **桌面 `Deploy Guardian` 报 `unexpected argument '--json'` 直接失败**(#91)。桌面控制
  平面通过 `vigil-hub setup --json [--status] --hook-exe <稳定路径>` 驱动捆绑引擎,但公开
  CLI 一直缺这两个 flag —— 点击 `Deploy Guardian` 立即红错。`setup` 现已支持:`--json`
  输出稳定的**逐 agent** 机器可读状态(供 GUI/脚本消费,绝不一盏聚合灯);`--hook-exe
  <path>` 把 agent hook 钉在**稳定启动器**位置(随 app 更新/移动不变,CRIT-1)。install
  时拒绝指向不存在的 `--hook-exe`(hook 启动失败是 fail-open 静默漏);`--status` 则刻意
  放行,把启动器丢失如实报为 `stale` 而非报错吞掉信号。

### 变更

- **桌面图标圆角柔化**(#92)。全部图标资产从设计源重新生成:外形加 Apple 比例圆角遮罩
  (半径 ≈ 边长 22.4%);macOS 的 `icon.icns` 按 Apple HIG 图标网格单独生成(图形占
  824/1024、四周留白),在 Launchpad / Dock / Finder 里不再显得比邻居"更大更方"。
  Windows / Linux / store 资产共用通用圆角源。流水线可复现:`scripts/gen-icons.py` +
  `tauri icon`(见 `apps/desktop/icons/README.md`)。

## [v0.6.0] — 2026-07-18 — 八个 agent、Aegis 桌面与 Intel mac

v0.6.0-beta.1 → beta.4 的稳定汇总,已在三平台真机对已发布产物完成端到端验收
(ML turnkey 安装、daemon 生命周期、功能矩阵 —— 全绿)。

**要点**

- **MCP 网关新增三个接入面 —— Kimi CLI、ZCode、pi** —— turnkey 覆盖达 8 个 agent
  (hook:Claude Code / Codex / Gemini CLI / Cursor;MCP wrap:+ Windsurf / Kimi CLI /
  ZCode / pi),并对接入层系统性加固(CODEX_HOME 分裂修复、托管条目 grammar 统一、
  单一 agent registry + 命名空间门禁、根形状严格校验、status 三态诚实化)。
- **Aegis 指挥舱桌面 UI 落地公开构建** —— 盾徽 hero + 八徽记防御环、逐页重做、常驻守护
  (关窗收托盘、单实例)、一键部署守卫、引擎安全自动下载、引擎/姿态切换、daemon 生命周期
  与 ML 模型安装。
- **macOS Intel(x86_64)构建** —— 桌面 dmg + CLI,交叉编译并走独立 OTA 线(更新器归档带
  架构后缀,两条 mac 线不可能相撞)。ML 变体仍仅 Apple Silicon(上游 onnxruntime 停发
  x86_64 macOS)。

完整细节见下方各 beta 条目。

## [v0.6.0-beta.4] — 2026-07-17 — macOS Intel(x86_64)构建

### 新增

- **macOS Intel(x86_64)构建。** 发布管线现从 arm64 runner 交叉编译并发布:桌面
  `Vigils_<ver>_x64.dmg`(+ OTA 更新器资产与 `latest-darwin-x86_64.json`)与 CLI
  `vigils-cli-macos-x64.tar.gz`。mac 更新器归档现带架构后缀
  (`Vigils-darwin-<arch>.app.tar.gz`),两条 macOS 线不再会在 release 里互相覆盖。
- 已知限制:**ML 引擎变体不支持 Intel mac** —— 上游 onnxruntime 已停发 x86_64 macOS
  wheel(1.24.x 仅 arm64),无 dylib 可捆。Intel mac 使用默认硬指纹引擎;其余防护层完全一致。

## [v0.6.0-beta.3] — 2026-07-17 — Aegis 指挥舱桌面 UI 落地公开构建

> 取代 v0.6.0-beta.2:其桌面 bundle 三平台全部失败(tauri-cli 的 manifest 解析不识别
> `autobins = false`,把仅内部保留的 `src/main.rs` 误判为 crate 名二进制);该 tag/release
> 已在任何桌面资产发出前移除。

### 变更

- **桌面端:Aegis 指挥舱 UI 落地公开构建。** 桌面 UI 整体替换为此前仅内部构建搭载的当前设计线:
  盾徽 hero + 八徽记防御环(双态),活动流 / 审批队列 / 服务器注册 / 会话回放 / 隐私发现逐页重做,
  统一设计语言(窗钮卡片、括号状态胶囊、官方徽记页头、等宽语义上色日志流),官方品牌资产
  (`/brand`),深色优先。
- **桌面端成为常驻守护。** 关闭窗口收起到系统托盘(托盘菜单:打开 / 退出);再次启动只唤起既有
  实例而不再多开进程(单实例插件);Windows release 构建不再闪控制台黑窗。
- **GUI 内置 Deploy Guardian 与引擎控制。** 一键部署防护(逐 agent 状态)、缺失引擎检测 + 安全
  自动下载(HTTPS + SHA-pin + 运行核验,fail-closed)、引擎模式(hardfp/ml/auto)与姿态
  (low/medium/high)切换、常驻 daemon 生命周期与 ML 模型安装 —— GUI 现在驱动与 CLI 同一个
  `vigil-hub` 引擎。
- 审计**检查点锚定**保留:公开版既有的 `Settings → checkpoint` 锚定重新落位到新设置页
  (同一 `anchor_checkpoint` 命令,Aegis 风格卡片)。

## [v0.6.0-beta.1] — 2026-07-17 — 三个新 agent 接入面(Kimi CLI / ZCode / pi)与接入面系统性加固

### 新增

- **MCP 网关新增三个 agent 接入面:Kimi CLI / ZCode / pi。** `setup --mcp` / `setup --all`
  (及 `--doctor`、`--status`、`quickstart`)现可自动探测并保护:
  - **Kimi CLI**(Moonshot)—— `~/.kimi/mcp.json`(标准顶层 `mcpServers`),server-id 命名空间
    `kimi-`。Kimi 的 hook 面**刻意不注册**:该功能为 Beta 且官方 fail-open(hook 崩溃/超时 =
    放行),不满足 Vigils 的强保护语义;GA 后重评。
  - **ZCode**(Z.ai)—— `~/.zcode/cli/config.json` 内嵌套的 `mcp.servers` 键,独立专线
    (契约取证自 vendor 实际发布的应用代码,非第三方资料)。`enabled` 等 GUI 附加字段逐字
    保留;`--apply` 前请关闭 ZCode。命名空间 `zcode-`。工作区级 `.zcode/config.json`(项目内
    文件)与共享 `~/.agents/mcp.json` fallback 刻意不碰。
  - **pi**(badlogic)—— `$PI_AGENT_DIR/mcp.json`(默认 `~/.pi/agent/`,支持
    `PI_CODING_AGENT_DIR`/`PI_AGENT_DIR`),即 pi-mcp-adapter 约定文件;pi 本体无内置 MCP。
    文件不存在即如实报告"无可保护项",绝不代为创建。命名空间 `pi-`。

### 修复

- **agent 接入面系统性加固**(双线对抗性代码评审产出):
  - `CODEX_HOME` 分裂:MCP wrap 面此前硬编码 `~/.codex/config.toml`,而 hook 面尊重
    `$CODEX_HOME` —— 自定义目录的 Codex 安装其 MCP server 全部静默漏保护且
    `--status`/`--doctor` 不可见。现两面共用同一路径解析(带守门测试)。
  - 托管条目 grammar 统一:分类(`AlreadyWrapped`)与还原(`unwrap`)现接受完全一致的 wrap
    grammar(sentinel 必须紧邻 `--`),堵住"计为已保护却无法卸载"的假托管态,以及伪造
    sentinel 逃逸包裹的口子。
  - 受支持 agent 清单 SSOT:清单此前散落 4 处调用点(status 计数 / doctor / apply 编排 /
    quickstart),新增 agent 可能静默漏一处。现收敛为 `all_json_mcp_agents()` 单一 registry +
    受校验前缀构造器(字符集 + `user`/`local`/`codex` 保留命名空间)+ registry 驱动的
    invariant 测试。
  - 根形状严格化:`mcpServers`(JSON)/ `mcp_servers`(TOML)**存在但类型错**此前被静默当作
    "没有 server"(配置在场却完全不受保护、无任何信号)。现按不支持形状 abort;Codex 内联表
    形态顺带获得支持;`--doctor` 输出 `ConfigError` 行。
  - `--status` 诚实化:逐 agent MCP 计数不再把"配置存在但读不了/解析失败"折叠成 `0`,
    改为独立的配置错误状态。
  - preview 与 apply 的 server-id 同源:预览此前手拼 `<prefix>-<name>`,apply 则做
    slug + 哈希规约;现共用同一派生函数。
  - apply 前 PATH 预警(底层程序不可解析)扩展到全部接入面(Claude user+local / Codex /
    ZCode / JSON-agent registry),并按接入面标注。

## [v0.5.0] — 2026-07-08 — 浏览器防线接入控制平面:商店版配对、姿态感知守护、hook 加固

v0.5.0-beta.1 的稳定汇总。浏览器扩展不再是孤岛:Chrome Web Store 版本
([Vigils Browser Guard](https://chromewebstore.google.com/detail/vigils-browser-guard/ffmgaglmcimapacgmoejaobfjdpmopch)
0.3.0,已上架)可与本机安装的 Vigils 引擎配对,桌面端与 CLI 终于能看见浏览器防线,hook 路径
新增两项加固。硬地板不动。

### 新增

- **浏览器 ⇄ 引擎连接**(#57)。native messaging host 成为 daemon 的第二个 ML 客户端:浏览器
  检查获得与 hook 路径一致的本机 ML PII 增强(`engine.json` 门控;daemon 缺席 → fail-closed
  回落硬指纹地板,绝不 fail-open)。
- **扩展首个企业后端**(#58)。选项页可将检查路由到本机 Vigils 引擎(native messaging)——
  权限为可选、仅在显式启用时请求,原文不出设备,host 不可达时阻断而非静默降级。
- **浏览器事件进控制平面**(#59、#60、#62)。事件中心显示浏览器粘贴/输入/发送介入;防护总览
  新增浏览器防线卡:注册与引擎状态 + 近 24 小时检查/拦截/脱敏计数。
- **`setup --status` 浏览器行**(#61)。native host 注册态与 hook、MCP 并列——turnkey 状态
  自此覆盖三条防线。
- **姿态下发**(#62、#64)。host 回报 `posture_tier`/`engine`;strict 姿态下扩展将
  confirm-redact 升级为 block(只收紧,allow/block 恒不动)。
- **Command Guard 文件写入侧翼**(#63)。Write/Edit 工具向 shell rc、crontab、`.git/hooks`
  的持久化落点写入,现与等价 shell 命令同样分类。

### 修复

- **真实富文本编辑器上的内联介入**(#64)。content script 提前到 `document_start`,站点
  capture 监听不再饿死守门;手动输入防抖增加最长等待,框架重渲染心跳无法永久推迟检查;
  引擎判定有风险后弹卡无条件呈现;写回前对当前文本重新检查而非严格快照等值,连续粘贴在
  光标处叠加。
- **事件中心如实化**(#64)。正常放行不再记为「检测到风险」;popup 事件行全部用
  DOM/textContent 构建,不用 innerHTML。
- **hook panic 兜底**(#65)。hook 决策+输出整体包进 `catch_unwind`:未预期 panic 收敛为
  该 CLI 的 Deny 形状(Claude 为 exit 2),而非以 101 退出被 agent 视为 non-blocking
  fail-open。

### 变更

- **扩展 UX**(#64、#66)。品牌化弹卡(盾徽、风险 chip、信任行、tone 色顶边);企业连接区
  改为「价值卡 + 状态徽章 + 三步引导」,替代密集表单。manifest 0.3.0 已在 Chrome Web Store
  上架。
- **配对文档与已落地后端对齐**(#68)。README(中/英)与安装指南给出真实三步配对流程
  (安装引擎 → 以扩展 ID 注册 → 选项页启用),不再是未来式承诺。

## [v0.5.0-beta.1] — 2026-07-07 — 浏览器防线接入控制平面:本机引擎配对、姿态感知守护、hook 加固

浏览器扩展不再是孤岛:Chrome Web Store 版本(0.3.0)可与本机安装的 Vigils 引擎配对,桌面端与
CLI 终于能看见浏览器防线,hook 路径新增两项加固。硬地板不动。

### 新增

- **浏览器 ⇄ 引擎连接**(#57)。native messaging host 成为 daemon 的第二个 ML 客户端:浏览器
  检查获得与 hook 路径一致的本机 ML PII 增强(`engine.json` 门控;daemon 缺席 → fail-closed
  回落硬指纹地板,绝不 fail-open)。
- **扩展首个企业后端**(#58)。选项页可将检查路由到本机 Vigils 引擎(native messaging)——
  权限为可选、仅在显式启用时请求,原文不出设备,host 不可达时阻断而非静默降级。
- **浏览器事件进控制平面**(#59、#60、#62)。事件中心显示浏览器粘贴/输入/发送介入;防护总览
  新增浏览器防线卡:注册与引擎状态 + 近 24 小时检查/拦截/脱敏计数。
- **`setup --status` 浏览器行**(#61)。native host 注册态与 hook、MCP 并列——turnkey 状态
  自此覆盖三条防线。
- **姿态下发**(#62、#64)。host 回报 `posture_tier`/`engine`;strict 姿态下扩展将
  confirm-redact 升级为 block(只收紧,allow/block 恒不动)。
- **Command Guard 文件写入侧翼**(#63)。Write/Edit 工具向 shell rc、crontab、`.git/hooks`
  的持久化落点写入,现与等价 shell 命令同样分类。

### 修复

- **真实富文本编辑器上的内联介入**(#64)。content script 提前到 `document_start`,站点
  capture 监听不再饿死守门;手动输入防抖增加最长等待,框架重渲染心跳无法永久推迟检查;
  引擎判定有风险后弹卡无条件呈现;写回前对当前文本重新检查而非严格快照等值,连续粘贴在
  光标处叠加。
- **事件中心如实化**(#64)。正常放行不再记为「检测到风险」;popup 事件行全部用
  DOM/textContent 构建,不用 innerHTML。
- **hook panic 兜底**(#65)。hook 决策+输出整体包进 `catch_unwind`:未预期 panic 收敛为
  该 CLI 的 Deny 形状(Claude 为 exit 2),而非以 101 退出被 agent 视为 non-blocking
  fail-open。

### 变更

- **扩展 UX**(#64、#66)。品牌化弹卡(盾徽、风险 chip、信任行、tone 色顶边);企业连接区
  改为「价值卡 + 状态徽章 + 三步引导」,替代密集表单。manifest 0.3.0 已提交 Chrome Web Store。

## [v0.4.6] — 2026-07-03 — Command Guard、可独立使用的浏览器扩展、四轮用户级验证

v0.4.6-beta.1 – beta.4 的稳定汇总,外加消费者模式浏览器扩展重构(#32)。两条新防线(hook 路径的
危险命令防护;不依赖桌面端即可使用的浏览器扩展)、一个真实网关修复(OAuth scope 白名单)、以及由
三平台真实二进制上四轮逐特性用户级验证驱动的大批文案/可观测性修正。硬地板未动。

### 新增

- **Command Guard —— hook 路径的危险命令防线**(#53, #54)。hook 路径(Claude Code / Cursor /
  Codex 的 `Bash` 工具)此前只扫密钥 —— 在"放行全部命令"姿态下,跑偏的 agent(意图漂移、提示注入、
  参数事故)可以执行 `rm -rf ~`、`curl … | sh` 或写 crontab 而不触发任何拦截。守卫**按效果分类,
  不猜意图**(denylist,无 ML):灾难级动作(清盘、裸设备写入、fork 炸弹)在任何姿态下一律拒绝 ——
  与裸密钥同级的硬地板;危险级动作(持久化/自启动、远程执行安装、项目根之外的删除、`rm -rf $VAR/`
  空展开事故)按姿态分级 Ask(High=Deny)。项目根感知压低误报。诚实边界:防事故与低成本注入的护栏,
  不是沙箱。
- **浏览器扩展开箱即用 —— 不再依赖桌面端**(#32;Chrome 应用商店
  [Vigils Browser Guard](https://chromewebstore.google.com/detail/vigils-browser-guard/ffmgaglmcimapacgmoejaobfjdpmopch),
  0.2.0)。此前扫描硬绑本机 Native Host,未安装时 fail-closed 全阻断 —— 商店版离开桌面端根本
  没法用。现在检测走 provider 管线:浏览器内消费者扫描器(密钥/token/连接串规则 + 通俗语言提示)
  为默认,企业 provider 保持可插拔,结果按最严合并(`block > confirm_redact > allow`,未知动作
  fail-closed)。保护可扩展到任意网站 —— 宽域名权限为可选、按站点运行时授权。Popup 与设置页围绕
  "当前页面保护状态"重新设计。原文依旧不出浏览器、不落 `chrome.storage`;`nativeMessaging` 不再
  是默认权限。
- **Daemon 暖载可观测**(#55):模型暖载(约 45s)期间 `daemon status` 显示"启动中(正在预热 ML
  模型)"而非"未运行";`daemon status --json` 提供稳定、与语言无关的机读 schema(字段只增不改);
  过期标记自愈。
- **`setup --status` 展示全 agent 的网关覆盖面** —— 如
  `23 server(s) wrapped (Claude Code 2 / Codex 11 / Cursor 10)`。
- **大写/空格/点号的 server 名可保护了**(`setup --mcp` / `--all`):经 slugifier 派生网关 id
  (`Playwright` → `user-playwright-<hash8>`);原本合法的名字保持原 id 不变。
- **CLI 中英双语**(按系统语言)。裸 `posture` / `engine` / `daemon` 默认执行 `show`/`status`;
  `serve --monitor` 为无 GUI 的 headless/e2e 提供观察审计姿态。
- **验证基础设施**:每次发布后三平台无人值守用户级验收 CI(像用户一样下载已发布产物、校验
  sha256 + SLSA 溯源、跑功能/agent 集成/GUI 冒烟)、远程 MCP e2e(在 Streamable HTTP 上游上
  证明保护不变量)、双引擎一致性绊线(hook 路径与 MCP 网关必须同判)、扩展测试接入 CI、每周对
  Latest 的定时验收、以及发布前置门禁(tag 永远不会从 fmt/clippy/test 红的提交上发出)。

### 修复

- **`ScopeNotInAllowList` 策略规则对 OAuth HTTP 上游真正生效了。**网关此前用硬编码的非 OAuth
  scope 上下文评估所有出站 tools/call,配置的 scope 白名单 Deny 规则静默失效。现在 token 的
  scope 集抵达策略评估:白名单外拒绝、空 scope 集 fail-closed、stdio/bearer/none 上游不受影响。
- **桌面端在非英文系统上不再误判 daemon 状态**(#55):机读子进程输出固定
  (`VIGIL_LANG=en`、`--json`);daemon 卡片新增"启动中 · 预热模型"第三态,取代暖载期误导性的
  "已停止"。
- `daemon status` 运行时长不再冻结在 `0s`;`daemon stop` 不再泄漏 OS kill 助手的本地化输出
  (非 UTF-8 代码页乱码)。
- 输出如实化批次:`setup --all` 按 agent 限定范围、"已写入配置"只在真写入时出现;agent CLI 状态
  改说"hook 未注册"而非"未安装";`demo` 指向一键的 `setup --all`;`checkpoint` 提示按平台给出;
  `setup --mcp` 跳过原因本地化;标准构建的 `model --help` 开头即说明需要 ML 构建;姿态级别名
  CLI 与 GUI 一致(宽松 / 适中 / 严格);hook fail-closed 文案不再硬编码 "PreToolUse"。
- 桌面端:未装模型时 daemon 卡片不再承诺 ML 防护;Naive UI 内建文案跟随应用语言。扩展:面向用户
  的文案移除内部规格引用;禁用按钮有禁用观感。

### 文档

- `docs/user-guide/`:移除不存在的命令、纠正默认账本路径、替换过期的 "tools/list 返回空" 说明、
  安装指向 GitHub Releases。
- README + book(中英):扩展改为从 Chrome 应用商店安装;crates.io `vigil-sdk` 为独立节奏的早期
  预览;ML 构建可用性说明更新(自 v0.4.0 起随发布提供)。

## [v0.4.6-beta.4] — 2026-07-03 — hook 路径 Command Guard + daemon 暖载可观测 + GUI locale 误判修复

新增一条防护线的 beta;其余为第四轮逐功能用户级验证(三平台真二进制)收敛的可观测性
与 locale 缺口。硬地板不受影响。

### 新增

- **Command Guard —— hook 路径的危险命令防线**(#53、#54)。MCP 网关路径本就会分类破坏性
  shell 命令,但 hook 路径(Claude Code / Cursor / Codex 的 `Bash` 工具)此前只扫
  secret / 占位符 —— 用户开「允许所有命令」时,agent 因意图漂移 / 提示注入 / 参数事故跑出的
  `rm -rf ~`、`curl … | sh`、写 crontab 等命令会直接穿过。本防线**只判效果、不判意图**
  (denylist,无 ML):灾难级动作(文件系统清除、裸写块设备、fork bomb)任何姿态恒拒 ——
  与明文密钥同级的硬地板;高危动作(持久化 / 自启、远程下载直灌 shell、项目根之外的递归删除、
  `rm -rf $VAR/` 空展开事故)按姿态分级 Ask(High=Deny)。项目根感知压误报:项目内的
  `rm -rf ./node_modules` 放行,同一命令指向 `~` 则被拦。诚实边界:这是防事故与低成本注入的
  护栏,不是沙箱 —— 深度混淆可以绕过。
- **daemon 暖载窗口可观测**(#55):模型暖载最长约 45s,此前这段时间里 `daemon status`
  会在你刚执行 `daemon start` 后报「未运行」。现在 warming 标记让窗口可见:status 报
  「启动中(正在暖载 ML 模型)」,`--json` 增 `reason:"warming"`(字段只增不删),
  陈旧标记自愈。
- **`setup --status` 显示全 agent 网关覆盖**(#55):此前只显示 Claude Code 的计数 ——
  `setup --all` 为 Codex/Cursor 包好二十多个 server 后,status 里无从确认全局覆盖面。
  现在:`已防护 23 个服务器(Claude Code 2 / Codex 11 / Cursor 10)`。

### 修复

- **非英文系统上桌面应用可能恒判 daemon「未运行」**(#55):它解析的是英文人类可读
  `daemon status` 行,而该行随系统语言本地化。现改走 `daemon status --json` 稳定 schema,
  并对机器解析的子进程输出统一钉 `VIGIL_LANG=en`(model status 的 "installed" 行解析存在
  同族隐患,一并根治)。守护卡同时新增第三态「启动中 · 暖载模型」,替代暖载期间误导性的
  「未运行」,并隐藏启动按钮避免 bind 冲突。
- hook fail-closed 消息不再写死「PreToolUse」(同一入口也接 PostToolUse 事件);daemon
  冷态 / stop 文案去掉内部黑话「无 daemon.json」;posture 中文档位词在 CLI help 与 GUI
  之间对齐(宽松 / 适中 / 严格)。

## [v0.4.6-beta.3] — 2026-07-03 — 稳健性打磨:OAuth scope 接线修复、`status --json`、双引擎 parity、远程 MCP e2e

加固向 beta:一个真实网关修复,其余全部是验证覆盖面的加强。

### 修复

- **`ScopeNotInAllowList` 策略规则对 OAuth HTTP upstream 现在真正生效。** 此前网关对所有出站
  tools/call 硬编码非 OAuth scope 上下文,配置了 scope 白名单 Deny 规则的用户以为有保护、
  实际规则静默永不触发(虚假安全感)。token 的 scope 集(attach 期快照)现已进入策略评估:
  越界 scope 拒绝、空 scope 集 fail-closed、非 OAuth 上游(stdio / bearer / 无鉴权)不受影响。
  三个新集成测试锁定三分支。

### 新增

- **`daemon status --json`** —— 稳定、与界面语言无关的机器可读 schema
  (`running`/`pid`/`pii_loaded`/`inj_loaded`/`uptime_secs`/`inflight`;字段只增不删)。
  人类输出不变(仍本地化)。验收脚本优先用它,老版本自动回退钉英文文案。
- **远程 MCP e2e 进入值守验收矩阵**(`http-e2e.mjs`):对已发布二进制实证 Streamable HTTP
  upstream 路径的防护不变量 —— Bearer token 到达上游 `Authorization` 头但绝不出现在客户端
  与审计里、密钥租约四段往返在 HTTP 上成立、SSE(`text/event-stream`)上游响应被折叠并
  再脱敏、裸 secret 不被转发、审计账本无明文。
- **双引擎 parity 守门**(`dual_engine_parity`):hook 路径与 MCP 网关路径喂同一份不可信输入,
  判定必须一致(裸 secret 双拦、干净输入双放、deny 不回显真值)—— 决策核心统一前的漂移警报线。
- **周度定时验收**(每周一 03:23 UTC,对 Latest release):上游 agent hook 协议漂移、
  分发服务变化不必等我们发版即可被发现。

### 文档

- README(双语):crates.io 上的 `vigil-sdk` 是独立节奏的早期预览、落后于本仓库;
  要用最新 API 请从源码构建。

## [v0.4.6-beta.2] — 2026-07-02 — 值守式用户验收 CI(功能 + agent 接入 + GUI),含 beta.1 打磨

本测试版聚焦「逐功能用户级验证」(三平台真二进制走查)发现的问题。不涉及任何安全不变量变更,硬底线不动。

### 新增

- **含大写 / 空格 / 点的 server 名现在可被保护**(`setup --mcp` / `--all`):网关 server-id 经
  slugifier 派生(`Playwright` → `user-playwright-<hash8>`),不再跳过并要求你去改 MCP 配置里的名字。
  本就合法的名字 id 逐字不变(向后兼容);大小写变体不会塌缩成同一身份(哈希后缀)。
- 裸 `vigil-hub posture` / `engine` / `daemon` 现在默认执行 `show` / `status`,不再甩出 help。

### 修复

- `daemon status` 的运行时长恒为 `0s`;现在如实报告已运行时间。`daemon stop` 不再把系统结束进程
  助手的本地化输出漏进用户界面(非 UTF-8 代码页下曾乱码)。
- `setup --all` 输出如实化:`[2/2]` MCP 网关行标注 scope(Claude Code),不再被误读成全局总数;
  「改动写入配置文件」只在真实写盘时出现;agent CLI 状态由易误读的「未安装」改为「hook 未注册」。
- `demo` 结尾改推 `vigil-hub setup --all`(一键路径),不再指向手动 `serve --stdio` 流程。
- `checkpoint` 提示按平台给建议 —— Windows 不再出现 Linux 专属的 `chattr +a`;macOS 建议
  `chflags uappnd`。
- `setup --mcp` 预览的跳过原因在中文输出下本地化;`quickstart` 不再把所有被跳过的 server 统称
  「http/sse」。
- 标准(非 ML)构建的 `model` help 直接标注需 ML 版二进制,不再等到 `model install` 才发现。
- `setup --help` 文本清理内部评审速记。
- 桌面:模型未安装时,守护进程卡不再承诺「启动即开启 ML 防护」(现在说明此时 daemon 以无模型方式
  运行,hook 保持硬指纹底座);Naive UI 内建文案(空表、分页)随应用语言。
- 扩展:用户可见文本清除内部规范编号;禁用按钮有了禁用外观;守护站点文案与 manifest 实际清单一致。

### 文档

- `docs/user-guide/`:移除不存在的命令(`ledger verify` / `ledger query` → `vigil-hub verify` +
  Activity Feed / 直查 SQLite),修正默认账本路径(`%LOCALAPPDATA%\Vigil\ledger.sqlite3` 及各
  平台等价路径,用 `VIGIL_LEDGER_PATH` 对齐),把过时的「Stage 1:`tools/list` 返空」说明替换为
  真实的上游转发行为,并把安装指引指向 GitHub Releases。
- README(中英):ML 变体可用性说明已过时(v0.4.0 起随每个 release 发布);「逐字节还原」措辞
  收敛为经验证的承诺(只删 Vigils 自己的条目,你的配置如实还原)。

### 新增(测试基建)

- **值守式用户验收 CI**(`.github/workflows/acceptance.yml`):每次发布后三平台像用户一样下载已发布产物、校验 sha256 + SLSA 溯源,跑 `user-sim.sh`、`functional-sweep.sh`、`core-e2e.mjs`(真 MCP 网关的隐私过滤 + 密钥租约四段)、`agent-compat.sh`(Claude/Codex/Gemini/Cursor 原生 hook 协议),外加桌面 GUI 冒烟(Windows WebView2 CDP;Linux/macOS 装→启→截图)。ML 模型下载 e2e 留内部真机。
- **`serve --monitor`**(与 `wrap --monitor` 对称):headless/e2e 无 GUI 审批 resolver 时观察放行 + 审计;硬地板不变。

---

## [v0.4.5] — 2026-06-30 — 闭合 `VIGIL-SEC-ML-SKIP`(`secret://` 面):恢复同段 soft-PII 脱敏

### 安全

- **`VIGIL-SEC-ML-SKIP` 闭合(`secret://` 面)。** `MlScrub::augment` 不再因字符串 leaf 含字面
  `secret://` 就整段跳 ML。`secret://<alias>` 占位符由脱敏流程**自产**(逆向替换写入、字节区间已记入
  `protected` 集),`apply_wire_spans` 经区间减法保其不被 ML 切,同段 soft-PII(person / address / email)
  得以正常脱敏 —— 闭合一处 ML-recall gap:攻击者在 soft-PII 旁嵌字面 `secret://x` 即抑制该 leaf 的语义
  脱敏(无泄漏;硬指纹地板始终兜住)。`vigil://redact/` skip 保留(这类 Tier-B token 在 tool_output 中、
  非自产,区间无法可信加入 `protected`);tool_output 中**伪造**的 `secret://…` 同样不在 `protected`,其
  包裹的 PII 仍被 scrub。经对抗式审查、可证伪真机对比(旧二进制抑制 soft-PII vs 修复后 scrub 且
  `secret://` 占位符保留)、端到端验收断言验证。

---

## [v0.4.4] — 2026-06-29 — 深 `$HOME` 下 macOS daemon socket 健壮性(`sun_path` 溢出修复)

macOS 上 daemon 默认 socket 路径(`~/Library/Application Support/Vigil/vigil-daemon.sock`)在深 `$HOME`
下 —— 企业网络 home(`/Network/Servers/…`)或 sandbox 的 `$TMPDIR` —— 可能超出 `sockaddr_un.sun_path`
上限(104 字节),令 `daemon start` 以晦涩 libc 错误失败,并把 ML 防护静默降级到硬指纹地板。

### 修复

- **`VIGIL_DAEMON_SOCKET` env 覆盖** 让 daemon socket 路径可显式指定 —— 深 `$HOME` 部署(及确定性测试
  sandbox)的短、用户私有逃生口。在 `default_socket_name()` 一处解析,经 `daemon.json` 原样流向 hook
  客户端,故 server bind 与 client connect 始终一致。
- **可操作的 bind 时守门。** socket 路径达到或超过 `sun_path` 容量时,以明确指向 `VIGIL_DAEMON_SOCKET`
  的错误拒绝,而非晦涩 libc 消息。不触及单实例 / peer-credential(R1)/ stale-reclaim 任一不变量 ——
  env 只提供它们已消费的字符串。

---

## [v0.4.3] — 2026-06-29 — `VIGIL-SEC-OVERLAP-PH`:受保护区减法消除破碎嵌套占位符

daemon ML pass 跑在已脱敏(含 `[REDACTED …]` 占位符)的文本上。ML span 可能 over-capture 延伸进占位符
并切碎它(`[[REDACTED address]DACTED email]`)。无原值泄漏(被切的是占位符字节;真值已脱敏),但面向模型的
输出畸形。

### 修复

- **`apply_wire_spans` 减去真实占位符区间。** 脱敏流程现在报告它插入的占位符字节区间
  (`scrub_text_with_spans`);hook 把 redact + ML 融合为单遍,把这些**真实**区间 plumb 进
  `apply_wire_spans`,后者从每个 ML span 减去它们、只替换占位符之外的字节。区间来自流程**自产**输出,
  绝不靠正则识别 `[REDACTED …]` 形态 —— 故 tool_output 中伪造的占位符无法遮蔽其包裹的 PII。

---

## [v0.4.2] — 2026-06-26 — GUI 自动安装 ML 引擎变体 + 签名引擎清单(ML 最后一公里)

### 新增

- **桌面 GUI 一键安装 ML 引擎。** 设置页 AI 模型卡下载并换入逐平台 ML 引擎变体(格式无关 zip/tar),
  闭合最后一公里 —— 默认安装无需手动倒腾二进制即可变为 ML 可用。
- **签名引擎清单。** 引擎清单在 CI 中签名(minisign),换引擎前经 GUI 内嵌 pubkey 核验,故被篡改或
  中间人的清单被拒。

### 修复

- 引擎清单默认 URL 指向 GitHub release 资产(此前 `vigils.ai` 镜像对 `/releases/engine/` 返回 SPA
  HTML,破坏 turnkey 路径)。

---

## [v0.4.1] — 2026-06-26 — P1 重叠 span PII 泄漏修复 + v0.4.0 分发 bug 修复

对 v0.4.0 已发布产物的发布验收测试,暴露出一处脱敏路径泄漏与四个打包/分发 bug;此处全部修复。

### 安全

- **P1:重叠 span PII 泄漏(两处)。** 两处独立 span 替换点(`vigil-redaction::build_redacted_text`、
  `vigil-hub-cli::apply_wire_spans`)旧用右→左替换 + 重叠跳过;嵌套 model span(外层前缀是 PII)时泄漏
  外层明文前缀。两处均改写为 **union-merge**(对齐网关 `redact_string`),令任一 span 命中的每个字节都
  落入某替换区间。

### 修复

- **Linux `model install` 超时** —— 固定 30 秒每-chunk 超时短于 48MB chunk 在带宽共享链路上所需,
  turnkey 下载失败;已放宽。
- **macOS daemon R1 / stale socket** —— `peer_creds().pid()` 在 macOS 上为 `None`(R1 改回落 euid
  核验),且文件 socket 在非干净退出后未回收(永久 `EADDRINUSE`);经私有目录文件 socket + stale-reclaim
  在 `transport.rs` 修复。
- **ML 归档缺 `vigil-native-host`** —— 浏览器 native-messaging host 现已捆进 ML 变体归档。
- **Windows `.sha256` CRLF** —— 校验和文件携带 CRLF 行尾时被标记。

---

## [v0.4.0] — 2026-06-26 — 常驻 daemon 把 ML 隐私过滤带上 hook 主防护路径(ADR 0024)+ 模型安装 turnkey + GUI 控制

AI 隐私模型(DeBERTa 注入 + PII NER)现在跑在 **hook 主防护路径**上,而不只是 `serve`/`wrap`。常驻
**daemon** 持有暖载模型,每次 `vigil-hub hook` 经本地 IPC socket 查询、近零额外延迟 —— 若 daemon /
模型 / IPC 缺失或变慢,hook **回落硬指纹地板**(fail-closed,绝不 fail-open)。自内部 R3 移植,脱敏
路径经对抗式审查。

### 新增

- **ML-on-hook 常驻 daemon(ADR 0024)。** `vigil-hub daemon start|status|stop` 跑单实例本地 socket
  服务,一次性暖载 PII scanner + 注入分类器,hook 作瘦 IPC 客户端查询。peer-credential 认证(客户端
  核验 server PID == 记录的 daemon)、流式读截止、daemon 自持审计账本、fire-and-forget 注入分类,
  使其有界且抗篡改。ort-gated;非 ML 构建或模型未缓存 → model-less daemon,hook 留在硬指纹 —— 绝不
  fail-open。
- **`vigil-hub model install|status` turnkey。** 一条命令下载隐私 + 注入模型(HTTPS、16-chunk 并发、
  SHA-256 钉死、不符即 fail-closed)。`model status` 报每个模型缓存态;非 ML 构建报 `unsupported`。
- **`vigil-hub engine show|set`** 落盘引擎模式(`hardfp` / `ml` / `auto`),`serve`/`wrap`/hook 在无
  显式 `--engine` 时回落本配置(由 GUI 控制平面写入)。
- **桌面 GUI 控制卡。** 设置页新增 **守护进程** 卡(运行 / ML 暖载态 + 启停)与 **AI 模型** 卡(已装 /
  不支持态 + 一键安装),经独立进程 shell-out CLI,GUI 自身绝不加载 ort。
- **ML 引擎发行变体。** 逐平台 `vigils-cli-ml-*` 归档(含捆绑 ONNX Runtime 动态库)与默认纯硬指纹
  二进制一并发布。

### 安全

- 硬指纹脱敏地板在任何 daemon 缺失 / 模型缺失 / IPC 超时 / 非 ort 路径上**无条件**生效;ML 严格加性
  叠加其上。经移植 hook 路径的对抗式审查 + 端到端回归测试(ML-only 模式、daemon 缺席 → 地板仍 scrub)验证。

---

## [v0.3.0] — 2026-06-22 — 远端 HTTP/SSE MCP 上游(OAuth/Bearer)+ 防篡改 OAuth 信任链 + 锚定自动核对

首个把**远端 HTTP MCP 服务器**纳入 Vigil 防火墙的版本,外加对新 OAuth 路径的两项审计完整性加固。
每个安全关键改动都经过对抗式审查。

### Added

- **HTTP / SSE MCP 上游(ADR 0021)。** 经 Streamable HTTP(`application/json` 或 `text/event-stream`)
  可达的远端 MCP 服务器,现在流经 Vigil 的传输无关 chokepoint,因而继承与本地 stdio 服务器同等的保障:
  防火墙 default-deny、`secret://` detokenize、结果脱敏、审计。三种鉴权来源,均经一个 sealed planner
  (无法把传入的 `Authorization` 头 passthrough 给上游):`none`(public)、plain **Bearer**
  (`env:`/`keyring:` 静态 token)、**OAuth**(`serve` 启动时从 `add-remote-mcp` 已落库的 token 经授权
  服务器 re-discovery 重建 —— 无需浏览器)。mcp URL **与** OAuth discovery 端点均过 SSRF denylist +
  no-redirect;OAuth 对未 onboard / 异源 / SSRF / issuer 漂移一律 fail-closed。
- **启动时自动核对审计锚定(ADR 0020)。** 防篡改锚点此前已在网关关闭时自动 emit(v0.1.32),但只由手动
  `vigil-hub verify` 命令核对。`serve` 现在启动时也自动核对 checkpoint 锚定(异步、不阻塞、stderr-only、
  warn-only)—— turnkey 用户无需手动运行任何命令,即可在发生整链重写时被告警(补齐了 emit 自动、verify
  却只手动的非对称缺口)。

### Changed(安全)

- **OAuth token metadata 现绑入审计哈希链。** `oauth_token_metadata` 行(issuer / authorization-server /
  resource)是 OAuth token 验证的信任根,此前却在审计链外 —— 本地 DB 攻击者可篡改而不被发现。现在按
  存储的 `event_id` 绑定到一条审计事件,读时校验(`verify_chain` + payload 比对),故 naive 篡改、绑定
  事件删除、伪造 append 均被检出。(诚实定界:达到与账本其余状态同级的篡改**可检测性**;防住完整一致
  重写的篡改**证明**需外部锚定 —— 见 ADR 0020 / `vigil-hub verify`。)

---

## [v0.2.2] — 2026-06-21 — status 报告 MCP-wrap 防护 + ML 引擎错误文案更清晰 + 发布流程加固

v0.2.1 的小幅跟进,来自一次全局代码审计 + 真机 QA:两个面向用户的 CLI 修复、一个 flaky 测试修复,
以及 CI/发布流程加固。防护逻辑本身未变;两个 CLI 修复已在真实 Linux 硬件上从用户视角验证。

### Fixed

- **`vigil-hub setup --status` 现报告 MCP 网关防护。** 此前只检查原生工具 hook,故用 `setup --mcp`
  (只 wrap MCP server、不装 hook)配置防护的用户被误报 `Protection: not installed`。status 现显示
  两层 —— `Native hook:` 与 `MCP gateway: N server(s) wrapped` —— `Protection: ACTIVE` 反映任一层启用。
- **在非 ML 件上请求 ML 引擎时错误更清晰。** 默认件(`vigils-cli-<plat>`)上 `vigil-hub serve --engine ml`
  现引用用户实际所传的 `--engine ml`,并指引下载 ML 变体(`vigils-cli-ml-<plat>`)或 `--features ort`
  重建,不再引用内部 flag。

### Changed(维护者 / CI)

- **发布流程加固。** 发布版本门现还会对陈旧的 inter-crate 版本 pin 与 Tauri Rust/npm minor 不一致
  早失败(二者都在 v0.2.1 发布过程踩过)。GitHub release 现先建为草稿,所有构建 job 成功后才发布,
  故构建失败不再可能留下资产残缺的公开 release。
- de-flake 一个进程内审批唤醒测试(改测唤醒延迟而非总 wall-clock,消除受 CI 负载影响的 flaky)。

---

## [v0.2.1] — 2026-06-21 — ML 脱敏 CLI 变体 + 真机验证修复

发布可选的 ML 脱敏引擎作为预构建 release 产物(`vigils-cli-ml-<plat>`),与默认硬指纹 CLI 并存,
并修复两个只有三平台真机验证才能暴露的 bug。ML CLI 变体及其模型下载路径已在真实 Linux / macOS /
Windows 硬件上端到端验证(onnxruntime 1.24 dylib `dlopen` + 真 PII/DeBERTa 推理);已发布的
`vigils-cli-ml-windows-x64` 与 `vigils-cli-ml-linux-x64` 产物在发布后又做了复测。

### 新增

- **ML CLI 变体 —— `vigils-cli-ml-<plat>`(Linux x64 / macOS arm64 / Windows x64)。** 与默认硬指纹
  `vigils-cli-<plat>` 并存的第二个 CLI 构建,以 `--features ort` 构建,并把 ONNX Runtime 1.24 动态库
  捆在 `vigil-hub` 同目录。运行 `vigil-hub serve --engine ml`(或 `auto`)即在硬指纹规则之上叠加
  OpenAI PII NER 模型 + DeBERTa 提示注入分类器;模型首跑按需下载(~0.8–1.5 GB,Hugging Face 主源 +
  vigils.ai 镜像 fallback,SHA-256 校验)。两引擎并存(按启动选择)。已在真实 Linux / macOS / Windows
  硬件验证(dylib dlopen + 真 PII/DeBERTa 推理)。每个资产同默认 CLI 一样带 `.sha256` + Sigstore
  构建溯源。ML 构建平台地板:Linux glibc ≥ 2.28、macOS ≥ 14。

### 修复

- **模型下载不再在"不支持 HTTP Range 的镜像"上损坏文件。** 16-chunk 并发下载器假设服务端返
  `206 Partial Content`;经 Cloudflare 的镜像对 JSON 做 gzip,对 Range 请求返 `200`(全量),于是每个
  worker 把整文件写进自己的分块槽 → 组装成 16× 损坏 → SHA-256 不匹配。仅 HF 被屏蔽、走 vigils.ai
  镜像 fallback 的用户中招(Hugging Face 永远返 206)。下载器现会探测 Range 支持,镜像不支持时改为
  单流下载。
- **ML smoke 覆盖不再硬断言一个已知且搁置的多语种 gap。** per-label 覆盖测试与精度/召回基准共用
  fixture(已膨胀到 90+ zh/ja/ko/de/it/fr 样本),硬断言了英文中心模型本不应具备的多语种 PII 覆盖;
  现改为只对受支持范围门控,并将多语种召回转为报告。

### 文档

- README(en + zh)与 mdBook 新增"两种脱敏引擎"说明(默认 vs ML、`--engine` 用法、首跑模型下载、
  平台地板);并修正安装表中的 CLI 资产命名。

## [v0.2.0] — 2026-06-20 — 首个正式版:turnkey 健壮性 + 诚实边界

退出 beta 线。本版加固一键接入(`vigil-hub setup`)对真实配置形态的处理,修复一轮真机端到端
测试(Claude Code + Codex 由真实模型驱动、k8s 隔离)发现的状态报告与审计 bug,并诚实陈述防护
边界,让你能正确地依赖 Vigils。每个修复都有单测 + 33 断言端到端套件(对真二进制)验证;风险最高
的修复经 Codex 交叉评审。

本版还包含已合并的社区贡献:桌面 UI 重设计(#5)与 Chrome 扩展更新(#2)。感谢贡献者。

### 修复

- **`setup --status` 不再对自定义 `--ledger` 误报 STALE**。用自定义共享 ledger 安装(文档建议的
  与桌面应用共享审计的方式)后,`setup --status` 会误报 "INSTALLED but STALE / 保护关闭" —— 即便
  保护有效、自检 PASS —— 且其重跑 `setup` 的提示会把账本悄悄改回默认、切断 GUI 共享。staleness 现
  与 ledger 路径无关(用户选的路径不算漂移);binary 路径漂移、缺 PostToolUse 注册、缺 flag 仍报
  STALE。Claude(`settings.json`)与 Codex/Gemini/Cursor(`hooks.json`)两面均修。(#19)
- **`vigil-hub --version` / `-V` 现能打印版本**,不再报 "unexpected argument"。安全 CLI 连版本都
  报不出是真实粗糙点(提 bug、核对升级都需要)。(#20)
- **`vigil-hub verify` 恢复只读**。校验不存在的账本路径会凭空建 221KB 空库(只读审计产生写副作用)
  再误报 "✓ chain internally valid";现诚实报告账本不存在且不创建。
- **`setup --mcp` 处理真实 MCP 配置形态**:单串 `command`(`"npx -y pkg /path"`,即 `claude mcp add`
  写法)拆为 program+args 而非不可运行的单 argv;被 `stdbuf`/`sh`/`env` 前缀包裹的 `vigil-hub wrap`
  保持原样不二次包装;底层程序不在 `PATH` 的被包装 server 给非阻塞 WARNING 而非虚假 "Protected"。
  (#14、#15、#16)
- **Claude Code turnkey 结果脱敏默认开启**,agent 检测不再漏判"已装未首跑"(经 `PATH` 上的
  `claude` 二进制检测,不仅凭 `~/.claude/`)。(#10、#11)
- **还原 `vigil-hub inspect` 命令**(`protection` / `activity` / `search` / `approvals` /
  `verify-chain`)。其 CLI 接线在 v0.1.31 被误删(一次无关的 checkpoint-anchor port 连带删除),而实现
  与 README / 文档引用都还在 —— 照做会撞 "unrecognized subcommand"。现已恢复。(`inspect protection` 的
  头条计数目前反映 MCP 网关路径;`activity` 事件流则展示包括 hook 路径拦截在内的全部事件。把 `protection`
  汇总扩展到 hook 路径的归类留作后续跟进。)

### 文档

- **诚实防护边界**。引言与用户指南现明确陈述 Vigils 能可靠防住什么(13 类指纹的明文凭据泄漏、可逆
  脱敏、防篡改审计、审批、沙箱)与**防不住**什么(蓄意模型可对 secret 编码/分段、或走 Vigils 未
  中介的通道绕过输入侧检测)—— 以及出站代理是路线图上的完整堵法。不制造虚假安全感。
- 修正 agent 接入与 Codex 指引(hook-first 模型;Codex 需 `wire_api=responses`)。

### 验证

- 对新构建的 Linux 二进制跑真机端到端套件(15 组场景、33 断言):内置 `Bash`/`Write`/`Edit` 携裸
  secret 的 hook 拦截(reason 点名凭据类型且不回显);PostToolUse 结果脱敏;MCP wrap 网关真转发上游
  tool call + 完整审计;descriptor pinning 漂移 fail-closed;ledger-agnostic 状态;只读 verify;
  逐字节 uninstall 还原。Workspace 门禁全绿:clippy `-D warnings`、`cargo fmt`、lib 测试。

## [v0.2.0-beta.9] — 2026-06-16 — 二次传播泄漏加固(非边界工具结果 scrub)

来自同一次结构化项目 review、经 Codex 代码审查确认的安全修复。

### 安全

- **结果再脱敏现覆盖所有 native 工具,不再仅限执行边界**。此前 agent 可用 `Bash` 把注入的
  secret 落盘,再用 `Read`/`Grep` 等非边界工具读出 —— 而这些工具的结果不被再脱敏,真值二次
  回流给模型。PostToolUse 再脱敏面现扩到每个 native 工具:边界工具(`Bash`/`shell`)保持对声明
  secret 真值的完整逆替换;非边界 native 工具只跑硬指纹 scrub(不逐结果解析 secret,避免性能/
  审计开销)。MCP 工具(`mcp__*`)排除,因其结果 detokenize 由 MCP 网关负责。诚实标注 scope:
  自定义非硬指纹 secret 经非边界工具读出仍未覆盖 —— 完整覆盖留待 egress 代理。

## [v0.2.0-beta.8] — 2026-06-16 — 注入加固(session-risk DoS 封顶 + 边界注入白名单)

结构化项目 review(双路敌意 sub-agent 审计)发现、经 Codex 两轮代码审查确认的两个安全修复。

### 安全

- **session-risk 升档现按单事件封顶**。此前单条被污染/恶意的工具结果可塞**任意多**元指令短语
  (`delta = 单位 × 命中数`,无上限)→ 单方面把 session 姿态顶到 High,对用户合法 `secret://`
  占位符工具调用制造拒绝服务。现把单事件 delta 封顶到 24(= 升一档阈值),消除与 MCP 网关已封顶
  路径的平行不对称。命中数仍进审计、跨事件累加仍正常升档。
- **执行边界 secret 注入改用字符白名单**。把 `secret://` alias 替换进 shell command 时,resolve
  出的真值若含 shell 元字符,会逃逸占位符所在引号上下文、触发 glob 或空白分词 → 改写实际执行的
  命令。现要求真值匹配 `[A-Za-z0-9-_=.+/:@]`(覆盖 token/key/hex/base64/JWT/URL);其余一律
  fail-closed 拒绝并引导改用环境变量。Codex 审查指出初版黑名单漏 glob/tab/空格 —— 故改用白名单。

## [v0.2.0-beta.7] — 2026-06-16 — Agent 协作 UX(拦截引导 + effect 覆盖)

帮助编码 agent(Claude Code、Codex)理解 Vigil 作为协作式安全治理层的角色,在被拦截时配合,
而非通过换工具、换路径、拆请求来绕过拦截。

### 新增

- **治理 preamble** 注入 MCP `initialize.instructions` 通道(≤512 字节,Codex/Claude Code
  消费):把拦截定性为**终态**策略决定(非可重试错误),引导 agent 向用户报告或在 Vigil 请求
  批准,而非绕过。丢弃 `instructions` 的客户端(web/SDK)由下方拦截消息兜底。
- **终态拦截引导**:firewall 拦截消息与 hook 拦截消息(裸 secret、占位符)现在明确告知
  "等价绕过(换工具/换路径、拆请求)同样会被拒",唯一正确路径是在 Vigil 请求用户批准。
- **更广的 effect 覆盖**:扩展 `is_write_call` 与 path / URL / shell 字段名词表(如
  `remove`/`truncate`/`save`、`filename`/`folder`、`webhook_url`/`cmd`),让命名陌生的第三方
  工具也能被正确分类(Fs/Net/Exec),而非落到 default-deny floor。floor 行为本身不变。

### 安全

- firewall 拦截响应**不再向模型回显内部判定理由**。这些理由可能含请求派生的文件路径与主机名
  (一种 causality laundering 侧信道,让模型借此探测覆盖边界);现在只留在审计账本。enforcement
  行为未变 —— 所有拦截仍是确定性 fail-closed。经敌意 sub-agent 与 Codex 双路独立评审。

## [v0.2.0-beta.6] — 2026-06-15 — detokenize 真值回流防护(MCP 网关)

### 修复 —— hook 与 MCP 网关的逆替换对称性

一次对称性审计(经敌意 agent 交叉评审,并抓出了第一版修复的残留缺口)发现两处平行路径缺口,
MCP 网关落后于 hook 执行边界:

- **HIGH —— detokenize 真值在 tool result 中回流**:当 `secret://<alias>` 被 detokenize 成真实
  tool 参数、上游工具把该真值回吐进 result 时,MCP 网关此前**只**跑硬指纹脱敏(`detect_hard_secret`)。
  来自 `env:`/`keyring:` 的自定义 secret 无固定格式,非指纹真值会原样回流给 LLM 且不审计。网关现在
  对注入真值做**精确逆替换**回 `secret://<alias>`(与 hook 的 `try_result_redaction` 对齐),配
  **无条件 fail-closed 自检**(真值落 object key 位时整体脱敏),并写零回显审计事件。always-on,
  独立于 `--redact-tool-results`。
- **MEDIUM —— result 注入扫描仅 ORT**:上游 result 的提示注入扫描此前被 `--features ort` 门控,
  默认(非 ORT)构建完全不做 result 注入检测。现改为与 descriptor 扫描同款双检测器(启发式
  always-on + 可选 DeBERTa)。

## [v0.2.0-beta.5] — 2026-06-15 — ORT-init 超时对称(privacy filter)

### 修复 —— ORT-init 超时兜底现覆盖两条模型路径

对 beta.4 的交叉评审(hostile sub-agent + Codex,两路独立得出)发现:beta.4 新增的 warm-load
超时/abort 兜底**只**保护了**注入分类器**路径。**privacy filter**(`--enable-privacy-filter`)
经同样的 `load-dynamic` `dlopen` 初始化 ORT,仍可能 hang 在错误/stub `onnxruntime.dll` 上、死握
Windows loader lock —— 这正是 beta.4 要修的故障,却在 privacy-filter 路径上原样残留。

- **共享 `run_ort_init_with_timeout` helper**:两条 ORT init 路径(注入分类器 + privacy filter)
  现在都在工作线程上、同一主线程超时下运行。对称兜底,无路径遗漏。
- **worker panic 与超时区分**:worker panic(channel `Disconnected`)现在映射为干净的 fail-closed
  `OrtInitPanicked` 错误,而非被误判为 loader-lock 超时而 `abort()`。只有真超时(很可能是 loader
  lock)才仍然 abort。
- 超时诊断现在也会指出慢盘/远端盘 cold-load 是可能原因(不再一口咬定 stub dll);移除了一处过时
  文档引用;`set_var` 时序不变量已注释;新增 2 个回归守门测试。

## [v0.2.0-beta.4] — 2026-06-14 — 注入分类器部署加固

### 修复 / 加固 —— DeBERTa ORT 部署(问题 B)

DeBERTa 分类器用 ORT `load-dynamic`,运行时经系统 loader 解析 `onnxruntime.dll`。Windows 上可能
命中系统路径的错误/stub `onnxruntime.dll`(如 System32 的 2.8 KB 占位)→ ORT init 静默 hang,死握
Windows loader lock 到进程都杀不掉。

- **ORT_DYLIB_PATH 自动定位**:serve 启动时若未设 `ORT_DYLIB_PATH`,Vigil 自动指向 exe 同目录
  合理大小(>1 MB)的 `onnxruntime` dylib,绕开系统 loader 的 stub-dll 陷阱;同时保护 privacy filter。
- **warm-load 超时 + abort**:模型装载放工作线程,主线程 45s 超时。超时后 `abort()`(内核级
  `__fastfail`)立即终止进程 —— 优雅 `return Err` 会在 hang 线程持的 loader lock 上死锁。

> **部署注意(deberta,opt-in `--features ort`)**:ORT 用 `load-dynamic`(build 不链接 ORT ——
> 避开 `ort-sys` 的 ureq build bug 与 MSVC 静态链接 ABI 不匹配两个坑)。请在可执行文件同目录提供
> 匹配的 **ORT 1.24** `onnxruntime.dll` / `.so` / `.dylib`,或设 `ORT_DYLIB_PATH`。(若改用
> `download-binaries`,还需额外 `tls-*` feature + 兼容的 MSVC 工具链。)

## [v0.2.0-beta.3] — 2026-06-12 — DeBERTa 注入分类器(serve 路径)

### 新增 —— DeBERTa 提示注入分类器(opt-in,serve 路径)

beta.2 的启发式注入防护现在有了可选的**第二检测器**:微调的 DeBERTa 序列分类器
(`protectai/deberta-v3-base-prompt-injection-v2`,Apache-2.0),抓住 5 条正则漏掉的自然语言越狱
(实测 recall 较纯启发式 **+0.28**)。它作为 **MCP 网关 serve 路径上的 warm-session 软信号**运行,
绝不进短生命周期的 hook(738 MB 模型无法每次 hook spawn 重载)。

- **opt-in,默认零痕迹**:需要 `--features ort` 编译*且* `vigil-hub serve --enable-injection-classifier`。
  默认构建零 ORT 依赖。模型(738 MB FP32)首次启动时拉取一次(16 chunk 并发 + sha256 校验)。
- **两个扫描点**:工具描述(descriptor pin 时)与工具结果,各自与启发式检测器融合。命中时提升
  session 风险分(启发式 + DeBERTa delta **取 max,非累加**)+ 写零回显审计事件。**仍是纯软信号——
  绝不 deny、绝不改写 result**(改写仅属凭据脱敏路径)。
- **fail-closed 接线**:`--enable-injection-classifier` 但未 `--features ort` 会中止启动(绝不静默
  降级),与 privacy filter 的契约一致。

### 修复

- **`check_existing` 重下载 bug**:模型缓存就绪检查只认 OpenAI 的 `model_q4f16.onnx` 文件名,
  DeBERTa 的 `model.onnx` 缓存恒 miss → 每次 `serve` 启动重下载 738 MB。修复:抽共享
  `is_onnx_artifact` SSOT(下载 assign + 就绪检查共用一个匹配器),加端到端 + 单元回归守门。

> **部署注意(ORT)**:`ort` feature 用 `load-dynamic`——需要正确版本的 `onnxruntime.dll`
> (ORT 1.24)能被可执行文件找到(同目录 / PATH)。系统路径上其它位置的错误版本 DLL 会让初始化卡住。
> 这是 ORT 既有要求(与 privacy filter 共享),非分类器特有。

## [v0.2.0-beta.2] — 2026-06-12 — 提示注入防护

### 新增 —— 提示注入防护(P0)

Vigil 现在能检测并遏制工具输出与 MCP 工具描述里的**恶意指令注入**——这是 secret 外泄防护的互补另一半。

- **元指令检测(软信号)**:启发式扫描工具结果里的提示注入语句("ignore previous instructions"、
  角色重设、数据外泄祈使句)。刻意做成**软信号——绝不 deny**(语义、高误报);只提升 session 风险分,
  与硬 secret 的 deny 路径严格分离。
- **数据标记(Claude)**:被判注入嫌疑的工具结果会被 nonce 标签包裹为不可信数据(`updatedToolOutput`),
  让模型当数据而非指令。Codex / Gemini / Cursor 降级为仅审计(无改写输出能力)。
- **会话风险升档**:元指令命中在会话内累积,越阈后有效姿态自动升档(Low → Medium → High),收紧后续
  工具调用。升档**只会更严**——基础姿态与决策表不变。
- **MCP 工具投毒扫描**:在 descriptor 审批关扫描 tool 的 description 与 schema 的元指令,让投毒在审批时
  可见(软信号、不阻断)。

安全:零明文回显(审计/reason 只含 sha256 + 计数)、全程 fail-safe、已对抗式审查。

## [v0.2.0-beta.1] — 2026-06-11 — Hook-first 数据流控制平面(公开测试版)

> **首个公开测试版。** Vigil 从"仅 MCP 网关"成长为本地**数据流控制平面**:`vigil-hub hook`
> 把 secret 防护扩到 agent CLI 的**原生**工具调用(Bash / Edit / …),覆盖
> Claude Code + Codex + Gemini + Cursor —— 不再局限于 MCP server。我们以 beta 形式发布以收集
> 真实反馈:跑 `vigil-hub setup`、试试三档姿态,把任何意外告诉我们。欢迎提 bug。

### ⚠️ 行为变更(影响默认行为)

- **默认安装面现在是 hook。** `vigil-hub setup`(无 flag)默认注册 agent CLI hook(Claude 为
  主面,外加检测到的 Codex / Gemini / Cursor),不再默认 MCP wrap。**MCP wrap 降级为显式
  `setup --mcp`**(代码与行为完全保留 —— 只想保护 MCP 工具流时用它)。`setup --all` 仍一步两者全做。
- **默认姿态为 Low。** 到达原生工具的 `secret://` 占位符在 Low 档**放行**(α1 时是恒 deny)。
  三档:**Low**(仅拦最高风险 —— 裸硬指纹 secret;账本篡改档位已在决策表预留但检测尚未接线)/
  **Medium**(+ 占位符 *ask*)/
  **High**(= 旧 enforce,全量 deny)。**裸真凭据在任何档位恒 deny**(不可降级的硬底线)。
  用 `vigil-hub posture set|show` 切换。
- **hook 的 `ask` 现在是共同批准。** Medium 档下,占位符的 *ask* 进入 Vigil 审批队列有界等待;
  **Vigil(desktop / CLI)与工具链自身 UI 两边都能批准** —— 先批者生效(审批状态机原子仲裁),
  超时回退工具链提示。MCP wrap 的审批队列行为不变。

### 新增

- **多 agent hook adapter**(`hook.rs`):归一层,把事件名与字段名跨 Claude / Codex / Gemini /
  Cursor 归一,再按 CLI 分流响应(Claude `deny` = exit 2 + stderr;Codex / Gemini / Cursor =
  exit 0 + 各自 JSON 契约)。裸 secret 在**任何**工具(含 `mcp__*`)恒 deny —— 唯一的纵深防御线。
- **多 agent hook 注册**(`setup_hooks.rs`):Codex(`$CODEX_HOME/hooks.json`)、Gemini
  (`~/.gemini/settings.json`)、Cursor 各面,均幂等,`--uninstall` 仅删 Vigil 自有 entry。若
  Codex `config.toml` 含 `[features] hooks = false`,setup **仅警告、绝不改写**。Claude 面完整化
  (PreToolUse + **PostToolUse** + timeout)。
- **`vigil-hub posture show|set <low|medium|high>`**:三档姿态的 turnkey 入口(原子写配置 +
  每次变更一条审计事件)。
- **执行边界注入(α2)**:PreToolUse 时,边界工具(Bash / shell)内的 `secret://<alias>` 占位符
  经 lease 授权解析为真值,**内联重写**进 `updatedInput` 交宿主执行 —— **模型 transcript 始终只见
  占位符**。仅 Claude(实证支持 `updatedInput`)。真值绝不进审计 / stderr / note(仅 sha256 指纹)。
- **PostToolUse 结果再脱敏**:边界工具结果回 LLM 前,声明 secret 的真值经**逆向替换**回
  `secret://<alias>`(+ 硬指纹 scrub 作纵深防御),经 Claude `updatedToolOutput` 改写。声明的
  secret 无法解析、或自检发现残留 → **fail-closed 裁剪**。

### 安全不变量

- **fail-closed by construction**:hook 永不返错或 panic;解析失败、注入失败、再脱敏失败、缺
  ledger 一律收敛为 deny 或裁剪(`deny` 走 exit 2 —— exit 1 是 fail-open,绝不用作拦截)。
- **零明文**:真值仅在单点暴露,直达注入目的地 / 再脱敏替换;审计、reason、note、stderr 全程
  只含 alias 名 + sha256。字节级 E2E 验证真值不落盘。

### 已知范围边界(本测试版)

- 再脱敏**仅**覆盖边界工具的**直接**结果;不追踪 secret 的**二次传播**(边界命令落盘 → 非边界
  工具读出)。完整覆盖需 egress 侧(模型 API 代理)拦截。
- inject / re-redact 走 OS keyring 真值后端,但 **keyring 填充尚无 turnkey CLI 入口**(下一增量);
  注入当前需手动用 `--inject --secrets` 注册 hook 命令。
- 完整真机**双 CLI**(Claude Code + Codex 实跑)inject / re-redact 往返 E2E 待受控环境验证;
  二进制层与单测已覆盖全部决策与协议形状。

### 本版同时包含 —— bug 修复

- **DEF-004:firewall 项目边界从未真正生效 —— 新增 `--project-root` flag,缺省为网关工作目录。**
  真机测试中发现。
  - **bug 本体**:所有生产入口(`serve` / `wrap` / demo / 桌面 embed)启动 firewall 时项目根
    集合为**空**,而 policy 引擎的 `Outside` 条件对空集合恒判 true —— 内置规则
    `deny-outside-project`(priority 150)把**整个文件系统**判成"项目外",对称的
    `approve-repo-write`(priority 80)永不匹配,Inside/Outside 边界语义整体反转:凡被识别为
    文件写的调用在**所有姿态**被硬 deny(monitor 只降级 default-deny *floor*,不降级显式
    Deny 规则),且审计 reason 谎报"writes OUTSIDE project"。长期未暴露是因为多数被 wrap 的
    第三方工具名不在 effect 提取词表内 —— 提取不出 FsWrite,规则根本不触发,调用落 floor
    被 monitor 观察放行。
  - **policy 引擎 fail-safe 守门**:空 roots 时 `Outside` 不再断言"项目外"(返不匹配),写操作
    落 default-deny floor —— 仍 fail-closed,且 reason 诚实为 "no rule matched" 而非伪造的
    越界。风险评分器同语义(空 roots 不再 +30 "越界写"评分),其根匹配在 Windows 下补齐
    大小写不敏感,与 policy 引擎对齐。
  - **`serve` / `wrap` 新增可重复的 `--project-root <DIR>`**;省略时缺省 = 进程工作目录
    (agent 在项目目录里启动网关,与 git/cargo 的目录语义一致)。根按路径提取器同款 POSIX
    形式归一(canonicalize、`\` → `/`、剥 `\\?\` 前缀)—— 否则 Windows 下前缀比较静默不
    匹配,边界形同虚设。
  - **enforce 姿态下的可见变更**:边界**内**的写操作现在走 `approve-repo-write` 审批通道
    (此前被硬 deny);边界**外**的写仍被 `deny-outside-project` 拦截,reason 如实指向真实
    越界路径。
  - **启动 banner 打印绑定的边界根**(`project boundary -> <roots>` / `NONE`),从错误目录
    spawn 的网关一眼可见。
  - SDK `FirewallBuilder::project_roots` 在 `build()` 时同样归一,消费者传 `C:\proj` 原生
    形式也能正确前缀比较。
  - demo / 桌面 embed **有意**保持空 roots(自包含模拟 / GUI 无工作目录语义),由引擎守门
    兜底。已通过对抗式审查。

## [v0.1.34] — 2026-06-09

真机测试 Claude Code / Codex 接入时发现的缺陷修复。

- **桌面 Activity Feed 现在能反映 CLI 写入的事件**(DEF-001)。根因是账本路径不一致:接入指南
  指向 `ledger.sqlite`,而桌面读 `ledger.sqlite3`,导致 CLI 与桌面用了两个不同文件、Feed 一直空
  (实时监听本身正常)。已订正双语接入指南;`serve`/`wrap` 启动时打印解析后的账本绝对路径,使用
  内存账本(桌面看不到)时响亮警告。
- **`setup --mcp` 不再嵌套 wrap Vigil 自身的 server**(DEF-002)。文档里的 `vigil-hub serve`
  自指条目曾被误判为可包裹,产生 wrap 套 serve 的嵌套网关。`setup` 现在跳过 Vigil 自身的 serve/wrap
  条目,且"已包裹"检测不再依赖二进制文件名(改名/带版本号的二进制写出的 wrap 不会被二次包裹)。
  可经 `--uninstall` 还原。已对抗审查。

生产防护路径(firewall / redaction / audit)无变更。每个产物照例带 build provenance + 校验和。

## [v0.1.33] — 2026-06-08

引导首跑:`vigil-hub quickstart`。

### 新增

- **`vigil-hub quickstart` —— 一屏告诉新用户该做什么。** 装完之后先跑什么并不显然。`quickstart`
  来回答,且**只读**(它不改任何东西):它检测你机器上的 AI agent(Claude Code、Codex、Cursor、
  Windsurf),统计各自的 MCP server 数,并显示有几个已在 Vigil 保护下、几个还没保护 —— 然后给出
  三步:看它工作(`vigil-hub demo`)、一条可逆命令保护全部(`vigil-hub setup --all`,或先
  `setup --mcp` 预览)、查看/验证(`setup --mcp --doctor`、`vigil-hub verify`,或桌面应用)。
  检测复用了 `setup --mcp` 同一套**只读** preview,因此从不改写配置 —— 真正接入仍需你显式跑
  `setup --all`。

## [v0.1.32] — 2026-06-08

审计 checkpoint 锚点(v0.1.31)现在自动生效。

### 变更

- **网关在关闭时自动锚定审计链。** v0.1.31 加入了 `vigil-hub checkpoint` 来把防篡改账本锚定起来、
  对抗整链重写,但 turnkey 用户(只跑 `setup --all` / `setup --mcp`、从不手动调用)永远不会有锚点
  —— 那项保护对他们形同虚设。现在 `vigil-hub serve` 与 `vigil-hub wrap` 在网关关闭时**自动** emit 一个
  checkpoint,于是每次 agent 会话都会自动留下锚点,无需任何手动步骤。它是 best-effort、**绝不阻断
  关闭**(写操作在独立线程上跑、有 5 秒上界,wedged 或网络文件系统也卡不住退出),仅在有新事件时才写,
  且输出到 stderr(绝不污染 MCP 通道)。随时可跑 `vigil-hub verify` 校验链内一致性 + 锚点。(要完全
  闭合该威胁,请把 `<ledger>.checkpoints` 文件设为 append-only 或异地同步 —— 见 ADR 0020。)

## [v0.1.31] — 2026-06-08

审计 checkpoint 锚定 —— 检出防篡改账本的整链重写。

### 新增

- **`vigil-hub checkpoint` 与 `vigil-hub verify` —— 对抗整链重写的外部锚定。** 审计账本的 SHA-256
  哈希链能让*部分*篡改可见,但持完整数据库写权限的攻击者可一致重写*整条*链并仍通过内部校验
  (审计 threat #7)。`vigil-hub checkpoint` 现把当前链头记入一份与数据库**分离**的 append-only
  sidecar(`<ledger>.checkpoints`);`vigil-hub verify` 同时校验链内一致性**与**每个锚点是否仍匹配
  —— 只要 checkpoint 文件完好,仅改数据库的整链重写即被检出,发现任何篡改即非零退出。诚实边界:
  这**不是**对持完整文件系统写权限者的 tamper-proof 保证 —— 为此请把 `.checkpoints` 设为
  append-only(`chattr +a`)或异地同步;无锚点时校验报告 `Unanchored`(绝不报 "verified")。可嵌入的
  `vigil-audit` 新增 `CheckpointLog` API。既有哈希链摘要与 `verify_chain` 不变(纯增量)。详见
  [ADR 0020](https://github.com/duncatzat/vigils/blob/main/docs/adr/0020-audit-checkpoint-anchor.md)。

### 新增

- **`setup --mcp --doctor` 现在覆盖全部四个 agent 接入面。** 这个只读的启动健康预检 —— 回答"wrap 之后,
  每个 MCP server 的底层程序在本环境还能起来吗" —— 此前只查 Claude Code 的 server。现在一次过查 Claude
  (user + 各项目)、Codex、Cursor、Windsurf,每行按 agent 标注。`--doctor --probe` 同样对四个面的 server
  做真实 MCP 握手测试。它看穿 Vigil 的包裹 —— 检查的是底层程序(如 `npx` / `uvx` / `python`)而非
  `vigil-hub` 自身。这直接回应 `setup --all` 后最常见的担忧:"wrap 之后我的工具是不是被弄坏了?"

### 修复 / 安全

- 非 Claude agent 的配置坏了(无法解析 或 读不了),现在会作为**计入失败**的 doctor 项报告,并给出准确成因
  (解析失败 vs 权限/IO 错误),而不再被静默跳过 —— 这样 `--doctor` 不会在某个 agent 面整个没被检查到的情况下
  仍宣称"所有 server 都可解析"。所有诊断输出(含配置路径)在打印前都经脱敏。

## [v0.1.29] — 2026-06-07

Cursor 与 Windsurf 现在也受保护 —— 一条命令覆盖四个 agent 接入面。

### 新增

- **`setup --mcp` 现在也保护 Cursor 与 Windsurf,不再只限 Claude Code 与 Codex。** `vigil-hub setup
  --mcp`(预览 / `--apply` / `--uninstall`)与一键的 `setup --all`,现在还会检测并包裹 Cursor
  `~/.cursor/mcp.json` 与 Windsurf `~/.codeium/windsurf/mcp_config.json` 里的 stdio MCP server。一条命令
  现在覆盖你可能拥有的全部四个 agent 接入面。两者复用**完全相同**的网关包裹(结果脱敏 + 裸 secret 拦截 +
  防篡改审计,默认 monitor 姿态),可逆 —— `--uninstall` 还原原样。每个 server 用 `cursor-<name>` /
  `windsurf-<name>` 网关 id,与 Claude 的 `user-`/`local-`、Codex 的 `codex-` 命名空间不相交 —— 跨 agent
  的同名 server 在共享审计账本里绝不串身份。

### 安全

- Cursor 与 Windsurf 用与 Claude user scope **完全相同**的 JSON `mcpServers` 形态,故新代码复用**同一个**
  分类器与安全编辑机制(sentinel 精确匹配、危险字符拒绝、非 stdio 跳过、server-id 校验、原子写 + 备份)。
  对共享路径两处加固:用 Windsurf 的 `serverUrl` 字段(而非 `url`)声明的远程 server,现在被正确跳过而非误
  当 stdio 包裹;以及一个**存在但读不到**的配置文件(如权限错误),现在会如实报错,而不是被静默当成"未配置"
  —— 让不可访问的配置绝不被悄悄漏保护。已经对抗审查。

## [v0.1.28] — 2026-06-07

一条命令现在也保护 Codex —— 不再只是 Claude Code。

### 新增

- **`setup --mcp` 现在也保护 Codex CLI 的 MCP server,不再只限 Claude Code。** `vigil-hub setup --mcp`
  (预览 / `--apply` / `--uninstall`)与一键的 `setup --all`,现在除 Claude Code 的 `~/.claude.json` 外,
  还会检测并包裹 Codex `~/.codex/config.toml` 里(`[mcp_servers.*]` 表)的 stdio MCP server。一条命令
  保护你拥有的每个 agent 接入面。每个 Codex server 被改写为经 Vigil 网关启动(结果脱敏 + 裸 secret 拦截 +
  防篡改审计,默认 monitor 姿态),可逆 —— `--uninstall` 还原原样。改写**保留格式**:只改被包裹条目的
  `command`/`args`;你的注释、键序、`env` 表、以及其它设置(model、approval policy……)逐字不动。Codex
  server 用 `codex-<name>` 网关 id,与 Claude 的 `user-`/`local-` 命名空间不相交 —— 跨 agent 的同名 server
  在共享审计账本里绝不串身份。

### 安全

- Codex 路径复用与 Claude 路径**完全相同**的分类器与安全机制(sentinel 精确匹配保证幂等、危险字符拒绝、
  非 stdio 跳过、server-id 校验、配置损坏即 abort 且原子写 + 备份)—— 单一真源,绝不漂移。`env` 的值
  从不被复制进改写后的命令行(只含键名)、也从不打印。经两轮对抗审查:uninstall 拒绝对任何被手改条目做
  lossy 还原;Claude 侧已应用后 Codex 步若失败,会如实报告并给出恢复指引。

## [v0.1.27] — 2026-06-07

可验证的供应链,以及终于能对真实 MCP server 做风险分类的防火墙。

### 新增

- **每个发布产物都带 build-provenance 证明。** CLI 压缩包、桌面安装包、扩展 zip 现在都附带密码学
  SLSA build-provenance 证明(经 GitHub OIDC + Sigstore,无需自管密钥)。用
  `gh attestation verify <文件> --repo duncatzat/vigils` 校验任一下载:确认产物**由官方 CI 从本仓库构建**,
  关闭"release 被替换/篡改"的缺口(单凭校验和无法关闭)。见[安装](./README.zh-CN.md#安装)。
- **Effect 目录 —— tool-call 防火墙现在对真实 MCP server 做风险分类。** 此前防火墙只从调用**参数**推断
  效应,故对那些风险由工具**身份**隐含的第三方 server(`github` 的 `create_issue`、`fetch`)只看到
  "无效应",重型策略机器空转。现在内置目录按身份为常见 server(filesystem、github、fetch、git、
  brave-search、slack、postgres)预置 baseline 效应 —— 每个工具实际做什么(读写文件、网络、用 secret、
  对外发消息)现在都在审计账本可见,`--enforce` 可据此 gate。它**结构性 fail-safe**:目录只会**抬高**
  可见性/严重度(绝不掩盖真实效应),且**不改**默认 monitor 姿态 —— 不新增任何审批弹窗。

## [v0.1.26] — 2026-06-07

Linux CLI 现在能在近十年几乎任何 glibc Linux 上运行 —— 不再只限较新发行版。

### 变更

- **Linux CLI 二进制改为 glibc 2.17 地板(覆盖几乎所有发行版)。** 此前已发布的 Linux CLI 在
  Ubuntu 22.04 构建、要求 `GLIBC_2.34`,因而在更老但常见的发行版上 `version 'GLIBC_2.xx' not found`
  起不来 —— Ubuntu ≤20.04、Debian ≤11、RHEL/CentOS 7–8、Amazon Linux 2 全中招。现在发布流程改用
  [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) 以 `x86_64-unknown-linux-gnu.2.17`
  为目标构建 Linux CLI,把所需 glibc 符号下沉到 2.17(manylinux2014 同款地板,覆盖近十年几乎所有 glibc
  Linux)。**功能完全不变** —— 二进制行为一致,只是链接到更老的 glibc 符号。发布管线还新增 `objdump`
  守门:glibc 地板一旦回升超过 2.17 即构建失败。macOS 与 Windows 构建保持不变。(真实 CI 已验证:
  `vigil-hub` 与 `vigil-native-host` 现在最高均为 `GLIBC_2.17`,低于原 `GLIBC_2.34`。)

## [v0.1.25] — 2026-06-07

桌面应用现在以**保护成效概览**为首屏 —— 一眼看到 Vigil 为你拦下了什么,与 CLI 的
`vigil-hub inspect protection` 同源信息。

### 新增

- **桌面"保护成效概览"页(新的默认落地页)。** 此前只有 CLI 能展示"Vigil 拦下了什么"
  (`vigil-hub inspect protection`)。桌面应用现在直接以保护成效概览为首屏,从本地审计账本展示:
  输入侧拦截的裸密钥、检测到的工具结果泄漏、withheld 的 secret:// 别名、覆盖多少 session 审计了多少
  事件、防篡改审计链是否仍校验通过,以及一组最近的(已脱敏)保护事件。它只读,并随 Vigil 记录活动
  实时刷新。若审计链校验失败,最近事件明细会被隐藏(只保留计数)—— 被篡改的日志否则可能显示注入文本。

## [v0.1.24] — 2026-06-07

新增深度健康检查:真启动每个 MCP server 确认它能跑 —— 而不只是确认其程序已安装。

### 新增

- **`vigil-hub setup --mcp --doctor --probe` —— 验证每个 MCP server 真能起来。** 现有 `--doctor` 是
  静态的:只检查每个 server 的程序(如 `npx`、`uvx`)能否在 `PATH` 解析。但最常见的静默失败是程序
  *已安装*却在运行时起不来 —— 包拉不动、server 启动即崩、或不说 MCP —— 而你的 agent 只是静默地看不到
  它的任何工具。`--probe` 更进一步:对每个通过静态检查的 server,它会**短暂启动该 server 并完成一次真
  实的 MCP `initialize` 握手**,随后停止,并逐 server 报告 `[OK]` / `FAILED to initialize`。它是可选
  开启的,因为会执行每个 server 的启动代码;不带 `--probe` 的 `--doctor` 保持纯静态、无副作用。
  (`npx`/`uvx` server 首次探测可能因下载包而超时 —— 暖缓存后重跑即可。)

### 安全

- 探测从不转发被启动 server 的 stderr(故一个在启动时回显配置 secret 的 server 不会经 doctor 泄漏),
  把配置的精确 env 值从任何失败信息里遮蔽,并对不可信的协议版本串做指纹化而非原样打印。

## [v0.1.23] — 2026-06-06

修复 secret 以 `KEY=value` 形式出现时,脱敏占位符可能畸形的问题(外观损坏但 secret 本身始终被
完整移除——从不泄漏,只是 `[REDACTED …]` 标记被打碎)。

### 修复

- **secret 赋值给变量时脱敏占位符现在良构。** 最常见的形态——secret 在 `=` 右侧,如工具结果里的
  `api_token=ghp_…`——会让两条检测规则重叠(一条匹配整段 `key=value`,一条匹配内层 token)。网关脱敏器
  此前逐条规则在**已替换文本**上依次替换,第二条规则匹配进了第一条留下的 `[REDACTED …]` 标记,把它打碎成
  `[REDACTED env_assignment] github_token]`(括号不配对)。每种情况下原始 secret 都已被移除——从不泄漏——
  但标记看起来是坏的。脱敏器现在对原文扫描一遍,把重叠匹配合并为单一覆盖区间,输出一个干净的
  `[REDACTED …]` 标记。(由在真实机器上的完整端到端 turnkey 运行发现;已审查泄漏安全性——按**并集**合并
  重叠区间,保证任何 secret 字节都不会遗留。)

## [v0.1.22] — 2026-06-06

修复全新机器上的首次受保护运行 —— 审计账本现在会自建数据目录,而不是开库失败。

### 修复

- **全新机器上的首次运行不再因打不开审计账本而失败。** 在一台 Vigil 从未写过数据目录的机器上
  (Linux 为 `~/.local/share/Vigil/`,Windows 为 `%LOCALAPPDATA%\Vigil\`),首次受保护的工具调用
  会尝试在一个父目录尚不存在的路径打开审计账本,并以 `unable to open database file` 失败。现在账本
  会在打开前自建所有缺失的父目录,因此 turnkey 流程在全新安装、无需手动 `mkdir` 的情况下即可工作。
  (由在全新机器上端到端运行完整的 `setup --all` → 包装后的 MCP server → 审计闭环时发现 —— 开发者
  机器上该目录总是已存在,故此前没有任何测试暴露过它。)

## [v0.1.21] — 2026-06-06

修复 Linux CLI,使其在 Ubuntu 22.04 LTS、Debian 12 及多数现行发行版上真正能跑 —— 此前的 Linux 构建
静默要求了比这些系统更新的 glibc 版本。

### 修复

- **Linux CLI 现在在 glibc 2.35+(Ubuntu 22.04 LTS、Debian 12……)上可运行。** `vigils-cli-linux-x64`
  二进制此前在最新 CI runner(Ubuntu 24.04)上构建,因而要求 `GLIBC_2.39`,在更老系统上启动即报
  `version 'GLIBC_2.39' not found` 而失败 —— 包括开发者最常用的 Ubuntu 22.04 LTS。现在 Linux CLI 改在
  Ubuntu 22.04(glibc 2.35)上构建,可在 22.04、24.04、Debian 12 及多数现行发行版运行。(由在真实机器上
  端到端运行已发布二进制时发现 —— 正是构建主机上的测试永远暴露不出的打包问题。)完全静态(musl)的
  "任何 Linux 都能跑"构建作为后续 release 的跟踪项。

## [v0.1.20] — 2026-06-06

`vigil-hub setup --all` 一条命令全保护 —— 闭合"download → 直接得到保护"的最后一个缺口(此前全保护需跑两条
分开的命令)。

### 新增

- **`vigil-hub setup --all` —— 一条命令全保护。** 此前全保护要跑两条命令:`setup`(原生工具 PreToolUse
  hook,拦截工具**输入**里的裸 secret)**和** `setup --mcp --apply`(把每个 MCP server 经 Vigil 网关做
  结果脱敏 + 审计)。`--all` 一次完成两者。`--all --uninstall` 撤销两者;`--all --dry-run` 预览两者不写盘。
  两步写不同文件,各自原子写 + 备份 + 可逆。完成后:`vigil-hub inspect protection` 看 Vigil 拦下了什么。
- **诚实的部分失败报告。** 若 hook 步成功但 MCP 步失败(或反之),CLI 会明确告诉你哪一步已应用、如何只撤销
  那一步 —— 绝不用笼统的"失败"掩盖半应用状态。`--all` 与只读的 `--status` / `--doctor` / `--mcp` 组合时
  在 parse 期即被拒绝,故它绝不会把只读检查静默变成写操作。

## [v0.1.19] — 2026-06-06

新增 `vigil-hub setup --mcp --doctor` 预检:在你运行 agent **之前**就告诉你每个被包裹的 MCP server 能否
真正启动 —— 静默坏掉的 server 不再像是"Vigil 弄坏了我的配置"。

### 新增

- **`vigil-hub setup --mcp --doctor` —— MCP server 启动可行性预检。** 对配置里每个 MCP server(含已被
  Vigil 包裹的),检查其底层程序能否在你的 `PATH` 中解析,用的是**网关 spawn 时同款**的解析逻辑。逐 server
  给出 `[OK]` / `[FAIL] 程序不在 PATH` / `[skip]`(远程 server),并附可操作提示(如 `npx` 缺失时提示"装
  Node.js")。这回答了最常见的一键接入失败 —— "哪个 server 起不来、为什么?" —— 此前它只表现为 agent 里
  工具静默消失。纯静态、只读:只解析程序,**不启动**任何 server。有任一 server 起不来则退出码非 0,可用于
  脚本。对已包裹的条目,检查的是**真实**被包裹的 server 程序,而非 `vigil-hub` 自身。

## [v0.1.18] — 2026-06-06

新增 `vigil-hub inspect protection` 命令,一眼看清 Vigil 实际保护了什么 —— 让"monitor 模式仍在保护你"
的承诺**可见**,而非只是声称。

### 新增

- **`vigil-hub inspect protection` —— 基于审计账本的保护成效汇总视图。** 统计:输入侧被拦的裸 secret 数、
  tool result 里被检测到的 secret 泄漏数(开启结果脱敏时即被脱敏 —— `setup --mcp`/`wrap` 默认开)、
  被扣留的 `secret://` 别名数、跨 session 的审计事件总量、防篡改哈希链是否仍校验通过 —— 外加最近若干条
  保护事件(仅已脱敏摘要)。这让可逆脱敏的价值**可见**:用 Vigil 跑过你的 MCP 工具后,能确切看到它拦下了
  什么。只读;`--json` 供脚本使用。措辞刻意**诚实** —— 报告**已观察到**的保护,不夸大成"已阻止的威胁"。
- 汇总**fail-closed**:若审计链未通过校验,则**扣留**最近事件明细(被篡改账本里存储的摘要不可信),
  但仍给出整数计数 + 清晰的"链校验失败"警告。

## [v0.1.17] — 2026-06-06

`vigil-hub setup --mcp` 现在默认 **monitor** 姿态,包裹你已有的 MCP server 不再把它们打挂 —— 一键
"下载 → 受保护"开箱即用,同时所有硬保护照常生效。

### 变更

- **`setup --mcp` 默认姿态改为 monitor,而非 enforce。** 这条命令包裹的是你自己的第三方 MCP server
  (filesystem、git 等)。Vigil 防火墙只能分类它识别的工具的 effect,第三方工具提取不出 effect ——
  在旧的 `enforce` 默认下撞上 default-deny 兜底而被**拦截**。实际后果是:一键接入可能让你现有的 server
  停止工作。monitor 姿态让 server 保持可用,同时仍强制每一道**硬地板**:裸 secret 输入仍被拦截,工具
  结果仍被脱敏(可逆往返 —— 模型只看到占位符),显式拒绝规则仍拒绝,变更/漂移的工具 descriptor 仍不被
  自动批准,每一次调用仍写入防篡改审计账本。研究支持这一取舍:约 93% 的审批提示被未读即批,故确定性
  脱敏比"反正会被点批"的阻塞门更能保护你。
- **新增 `--enforce` 标志,启用硬化的 default-deny 姿态。** 若你要严格守门 —— 例如已知/固定的工具集、
  自建的 server、或高保障环境 —— 运行 `vigil-hub setup --mcp --apply --enforce`。预览
  (`vigil-hub setup --mcp`)与 apply 输出现在都会明示将要写入的确切姿态,monitor 还是 enforce 一目了然。

可逆性与此前一致:`vigil-hub setup --mcp --uninstall` 会逐字节还原你的原始配置。

## [v0.1.16] — 2026-06-06

让被包裹的 MCP server 在 monitor 模式下真正可用,外加安全加固 —— 由对真实第三方 MCP server 的端到端
测试发现。

### 修复

- **被包裹的 MCP server 现在在 monitor 模式下可用了。** 此前用 `vigil-hub wrap --monitor` 包裹的
  server(没有桌面审批端时推荐的姿态)大部分工具会被**拒绝** —— 防火墙无法分类的第三方工具撞上
  default-deny 兜底,而 monitor 只自动放行"需审批"的调用、不放行兜底拒绝。现在 monitor 把
  **default-deny 兜底**降级为观察放行(并完整审计),被包裹的 filesystem/git 等 server 开箱即用。
  这**只**影响未分类的兜底:显式拒绝规则、裸 secret 拦截、结果脱敏全部仍然强制,默认的 `enforce`
  姿态不变(仍是默认安全)。
- **monitor 模式不再自动批准"已变更(漂移)"的工具 descriptor。** descriptor 漂移是篡改 / 供应链
  信号;现在 monitor 下漂移的 descriptor 会落到审批路径(无 GUI 的一键场景下被拒绝)而非被静默放行,
  保持 descriptor-pinning 信任锚完整。
- **`vigil-hub setup --mcp` 跳过名字无法作为合法网关 id 的 server。** 含大写字母、空格、点或斜杠的
  server 名此前会被成功改写、但包裹后的网关启动时失败。现在它被跳过并清晰提示改名。
- **`vigil-hub` 启动 banner 显示真实发布版本**(如 `vigil-hub v0.1.16`)而非内部构建标记。

## [v0.1.15] — 2026-06-06

`vigil-hub setup --mcp` 现在也保护 **local scope(按项目)** 的 MCP server —— 闭合了 `claude mcp add`
(默认就写 local/project scope)留下 server 不受保护的常见情况。

### 变更

- **`setup --mcp` 默认同时保护 user scope 与 local scope 的 MCP server。** 此前它只包裹 user scope
  (`~/.claude.json` 顶层 `mcpServers`),遇到 local scope(`projects.*.mcpServers`)的 server 会拒绝。
  而 `claude mcp add` **默认写 local scope**,导致典型配置反而裸奔。现在 `--apply` 两者都包裹;
  `--user-scope-only` 可显式跳过 local scope 并诚实报告留下多少 server 不受保护;`--uninstall` 还原
  两个 scope。你仓库里**已提交**的 `.mcp.json`(与队友共享)仍然绝不触碰。
- **local scope 的 server 获得项目限定、抗碰撞的网关身份。** 名为 `filesystem` 的 server 可能存在于
  多个项目;若都用同一身份包裹,一个项目的批准会悄悄授权另一个项目的同名 server。现在每个 local scope
  server 都用命名空间不相交的 id 包裹(`local-<项目哈希>-<名字>`,与 user scope 的 `user-<名字>` 不相交),
  使跨项目同名 server 在共享账本里保持各自独立的审计/审批状态。

### 新增

- **`setup --mcp` 预览现在同时列出两个 scope**,在你执行 `--apply` 前明确展示 user scope 与各项目
  配置里将被包裹的内容。

## [v0.1.14] — 2026-06-05

为 **MCP 服务器**提供一键保护:把 Vigils 的防火墙、脱敏、审批与审计放在你的 AI agent 与任意 MCP
工具服务器之间 —— 只需改一行配置,或交给 `vigil-hub setup --mcp` 自动完成。

### 新增

- **`vigil-hub wrap` —— 透明 MCP 网关 shim。** 包裹任意 stdio MCP server 命令,使每一次
  `tools/list` 与 `tools/call` 在抵达真实 server 前都经过 Vigils 网关(default-deny 防火墙、
  硬指纹 secret 脱敏、审批、防篡改审计)。你的 agent 像直连原 server 一样连接 `wrap`。用法:
  `vigil-hub wrap --server-id <名> -- npx -y @modelcontextprotocol/server-filesystem /data`
  (在 agent 的 MCP 配置里把 `command` 改为 `vigil-hub`,args 前缀
  `["wrap", "--server-id", "<名>", "--", ...原命令]`)。Secret 处理安全:子进程仅收到你用
  `--env-key` 显式传入的 env 键(默认不转发任何其它内容),工具结果里的 secret 在回到模型前被脱敏。
- **`vigil-hub setup --mcp` —— 自动包裹你的 Claude Code MCP 服务器。** 枚举 Claude Code 配置
  (`~/.claude.json`,user scope)中的 stdio MCP server,逐个改写为经过 `vigil-hub wrap`。单用
  `--mcp` 是**只读预览**;`--mcp --apply` 真正写入(原子写 + 备份,完全可逆);`--mcp --uninstall`
  还原。改写是自描述、逐字保真的 —— 你的原始命令、args、env 都被逐字保留,卸载时精确重建。若某个
  project/local-scope server 会被遗漏不保护,`--apply` 会 fail-closed 拒绝,除非你传 `--user-scope-only`。
- **Monitor 姿态(`vigil-hub wrap --monitor`)。** 可选、非阻塞:风险工具调用被自动放行**并**完整
  审计(而非暂停等待审批),适合没有桌面审批端的一键场景。裸 secret 仍被拦截、工具结果仍被脱敏;
  仅"人工审批"这道门被降级为观察+记录。默认仍为 **enforce**。

### 安全

- **call 时的 descriptor oracle 改为账本支撑。** MCP 网关在 `tools/call` 时查询
  `RegistryDescriptorOracle`,因此工具的首见 / 漂移状态会在强制点对审计账本重新核对。一个到达
  call 路径却没有匹配的已批准 descriptor pin 的工具,会降级为首见 / 漂移(需审批)而非被静默放行
  —— 在 `tools/list` 暴露门之上再加一层纵深防御。
- **日志/审计中绝无裸 secret 或不可信输入。** 上游 stderr、MCP 握手错误、审批记录在写入或展示前
  都经硬指纹脱敏;上游错误消息以指纹(SHA-256)呈现而非原样回显。

## [v0.1.13] — 2026-06-05

一个小而收尾的补丁:`vigil-hub setup` 之后,你现在可以**零额外配置**直接看到保护在工作。

### 变更

- **`vigil-hub inspect` 默认指向共享审计账本。** 省略 `--db-path` 时,`inspect` 现在打开
  **与** `vigil-hub setup` / hook 写入的**同一个**账本(`VIGIL_LEDGER_PATH` → `<本机数据目录>/Vigil/ledger.sqlite3`),
  而非空的内存数据库。于是 `vigil-hub setup` 之后,`vigil-hub inspect activity` 直接显示 Vigil 实际拦了
  什么——无需任何参数。setup 的输出现在也会提示你这条命令。

## [v0.1.12] — 2026-06-05

一键保护:下载 release,跑一条命令,你的 Claude Code 工具调用就受保护。这是从 GitHub 下载到真实防护的最快路径。

### 新增

- **`vigil-hub setup` —— 一键 turnkey 保护 Claude Code。** 检测 Claude Code 并把 Vigils 注册为
  `PreToolUse` hook(覆盖全工具,含 `mcp__*`)写入 `~/.claude/settings.json`,无需手动改配置。
  天生安全:读 → 解析 → 幂等合并 → 原子写 + 备份;遇到非法 / 形状异常的配置宁可 abort 也不动它;
  只管自己的条目(用专属 `--vigil-managed` 标记识别),你其它的 hook/设置不受影响。`--status` 诚实
  报告保护状态(active / stale / 未安装)并跑内置自检;`--uninstall` 只干净移除 Vigils 自己的条目;
  `--dry-run` 只预览不写盘。含 shell 元字符 / 形状异常的路径会被拒绝以防命令注入。
- **`vigil-hub hook` —— Claude Code PreToolUse adapter(原生工具 secret 守门)。** 拦截裸凭据与未解析的
  `secret://` / `vigil://` 占位符流入 Claude Code 的原生工具调用(Bash/Edit/Write/Read/Grep)并审计每次
  拦截,fail-closed by construction(deny=硬拦截;任何 读/解析/内部错误都拒)。裸 secret 在 MCP 工具里
  也拦(纵深防御);MCP 工具里的占位符交给 MCP 网关。错误与审计**绝不回显** secret。

### 修复

- **`vigil-hub inspect` 恢复。** 命令行查审计账本(`activity`、`search`、`approvals`、`verify-chain`……)——
  文档里到处引用——在 v0.1.10 移植时从 CLI 二进制里掉了(变成无人引用的孤儿源文件),现已重新接上。
  复用 desktop 的 dispatch/render 逻辑,**不**拉 GUI/Tauri 依赖。

### 变更

- `serde_json` 现保留对象键顺序(`preserve_order`),让 `vigil-hub setup` 不重排你 `settings.json` 的键。
  审计哈希不受影响(走 JCS 规范化)。
- README 顶部新增 **"一键保护 Claude Code"** 区。

## [v0.1.11] — 2026-06-05

质量补丁:桌面应用不再反复提示更新,`vigil-hub demo` 在所有终端都能正常显示。防火墙、脱敏、审计核心无功能变更。

### 修复

- **桌面 OTA 不再循环更新。** 打包进应用的版本号落后于已发布版本,导致已安装的桌面端每次轮询都把更新清单
  视为"比自己新",反复下载同一个版本。现已将应用版本号钉死到发布版本,安装到最新后更新器即停止。
- **`vigil-hub demo` 在所有终端正常显示。** demo 的边框与状态符号此前用了制表符 / 箭头 / 破折号 / 叉号等
  字符,在非 UTF-8 控制台(如中文 Windows cp936、传统 cp437)会乱码。现已全部改为 ASCII,首次体验在任何
  终端都干净。仅显示层变更 —— demo 仍驱动真实运行时代码,其不变量自检逻辑不变(两个冒烟测试仍通过)。

## [v0.1.10] — 2026-06-05

零设置的 `vigil-hub demo` 首次体验,以及工具边界的可逆 secret 脱敏。已安装版本经 OTA 自动升级。

### 新增

- **`vigil-hub demo` —— 60 秒看到价值,零设置。** 一条命令让一个 planted 场景跑过 Vigils 的**真实运行时
  代码**(防火墙 · 可逆脱敏 · 防篡改审计),不联系任何 LLM、不需账号/key/网络:agent 直传裸 secret 被拒;
  改传 `secret://alias` 占位符后往返 —— 远端模型只见占位符,而本地工具收到真值;工具结果泄漏的 secret 被
  再脱敏;审计账本被证明零明文。`--tamper` 篡改账本一行,真实 verify-chain 检测到 —— 你亲手跑的可证伪。
- **可逆脱敏 —— 工具边界 `secret://alias` detokenize。** 在 upstream 配置里声明 secret alias
  (`env:`/`keyring:`,限定 server);agent 传 `secret://<alias>`(远端模型从不见真值),Vigils 只在本地工具
  执行边界替换成真值。未声明/跨 server/alias 里塞裸 secret 一律 fail-closed(拒)。工具结果泄漏 secret 在回
  模型前被再脱敏(opt-in `--redact-tool-results`)。不可信 alias 文本绝不回显进错误。

### 变更

- README 顶部新增 **"60 秒体验"** 区。

## [v0.1.9] — 2026-06-04

Chrome 扩展新增手动输入脱敏守门,并改进 release 下载体验。已安装版本经 OTA 自动升级。

### 新增

- **Chrome 扩展:手动输入脱敏守门** —— 防抖 `input` 监听现在会检查手动**输入**的字段文本(不止
  粘贴/提交),命中即原地脱敏。属尽力而为的事后清理;粘贴(写入前 preventDefault)与提交仍是硬守门。
  不新增任何扩展权限。
- **Release:Chrome 扩展现为可下载产物** —— `vigils-chrome-extension.zip`(解压后在 `chrome://extensions`
  load unpacked)。

### 修复

- **脱敏误报** —— `env_assignment` 规则的裸 key 形态现在要求 `=`(不收 `:`),故 `token://…` 之类 URI
  scheme 与 YAML `token:` 上下文不再被误脱敏。`token=secret` 仍正常脱敏。(修复了一处泄漏守门回归。)

### 变更

- **Release 文件名 + 下载指引** —— CLI 压缩包改用友好平台名(`vigils-cli-linux-x64` / `-macos-arm64` /
  `-windows-x64`),不再用 Rust target triple;release notes 新增简短的"该下载哪个?"指引(桌面 app vs
  CLI 网关 vs 浏览器扩展)。

---

## [v0.1.8] — 2026-06-04

MCP 网关修复 —— 接入 `npx` / `uvx` 类上游 MCP server(filesystem、GitHub 等)现已端到端可用。此前
网关可能从这类 server 聚合到**零个**工具,导致 agent 把 Vigils 看作 0 工具的 server。已在 Linux 上对
真实 `@modelcontextprotocol/server-filesystem` 验证(14 个工具浮现、防火墙拦截该调用、审计链校验通过)。
不改公开 API / SDK surface;已安装版本经 OTA 自动升级。

### 修复

- **stdio 上游 env 政策** —— 用户配置的上游启动器(`npx` / `uvx` / `node`)此前沿用沙箱 runner 的
  完全 `env_clear`,会剥掉 `PATH` / `HOME`,使启动器找不到解释器或包管理器 cache 而**根本起不来**——
  网关随之聚合到零个工具。上游现改用专用 env 政策:`env_clear` + 一份精选的**非敏感**运行时变量白名单
  (`PATH` / `HOME` / `APPDATA` / locale 等)+ 批准的逐工具 secret。白名单刻意排除密钥类与代码注入类
  变量,故父进程的 API key / token 仍绝不会到达上游;沙箱 runner 保持不变。([ADR 0007](docs/adr/0007-sandbox-runner.md) 修订)
- **MCP initialize 握手** —— 网关现在会在列出上游工具前,按协议要求完成 MCP 客户端生命周期握手
  (`initialize` → `notifications/initialized`),从而支持那些在初始化前拒绝 `tools/list` 的严格 MCP
  SDK server。协商出的协议版本会被校验(不支持的版本 fail-closed)。坏 / 慢的上游是非致命的 —— 会被
  记录、其工具暂不可用,而不会拖垮整个网关。

### 文档

- Agent 接入指南:工具命名空间记法更正为真实的 `__`(双下划线)分隔符 —— `fs__read_file`,而非
  `fs/read_file`。

---

## [v0.1.7] — 2026-06-03

安全加固。将项目首次全面安全审计(OWASP Top 10 + STRIDE + 供应链;评分 **9.9/10,0 Critical /
0 High**)的修复移植进公开发布。不改公开 API / SDK surface;已安装版本经 OTA 自动升级。

### 安全

- **审计账本哈希链 v2**(VIGIL-SEC-001)—— 防篡改 SHA-256 链现额外绑定 `session_id`、
  `event_type`、`redacted_text`,堵住"拥有数据库写权限的本地攻击者可无痕改写这些列"的缺口。
  版本化且向后兼容:历史 v1 事件仍可校验,新事件用 v2,`verify_chain` 强制版本单调(拒绝 v2→v1
  降级)。详见 [ADR 0002](docs/adr/0002-audit-ledger.md)。
- **描述符哈希校验**(VIGIL-SEC-004)—— MCP 描述符 oracle 对格式非法的传入哈希 fail-closed 为
  `FirstSeen`(需审批),而非信任它。
- **保留 allowlist 键守门**(VIGIL-SEC-005)—— firewall 保护一**组**保留策略键,而非单个字面量。
- **浏览器扩展发送方校验**(VIGIL-SEC-006)—— 后台 service worker 对入站消息校验
  `sender.id === chrome.runtime.id`。

完整报告:[docs/security/SECURITY-AUDIT-2026-06-03.md](docs/security/SECURITY-AUDIT-2026-06-03.md)。

---

## [v0.1.6] — 2026-06-03

应用内品牌一致性。桌面 UI 此前在标题、侧栏标题、若干说明文字里显示单数 "Vigil",而产品名是
"Vigils"。这些用户可见文案现已统一为 "Vigils"。

### 变更

- 桌面 UI 文案统一使用产品名 "Vigils" —— 窗口 / 文档标题、侧栏标题("Vigils Desktop" /
  "Vigils 桌面")、隐私发现说明。无功能变更;CLI 二进制(`vigil-hub`、`vigil-native-host`)与代码
  标识符不受影响。

---

## [v0.1.5] — 2026-06-03

桌面可执行文件命名修复。安装后的桌面程序现在叫 `vigils`,不再是看不出含义的 `gui` —— 此前进程名与
磁盘上的可执行文件都叫 `gui.exe` / `gui`,完全看不出是什么程序。窗口标题、安装目录、macOS app
包早已是 "Vigils",唯独二进制名落后。

### 变更

- 桌面二进制由 `gui` 改名 `vigils`(`mainBinaryName`、Cargo bin、源文件一并改)。安装后:Windows
  为 `Vigils/vigils.exe`、Linux 为 `vigils`、macOS 为 `Vigils.app/Contents/MacOS/vigils`;进程显示
  为 `vigils`。产品名("Vigils")、安装包文件名、自动更新流程均不变 —— 已安装版本会经 OTA 自动升级到
  改名后的二进制。

### 修复

- 用户指南文档引用的 `vigil-desktop-gui.exe` 自 v0.1.2 单二进制修复后早已不存在;现已指向 `vigils.exe`。

---

## [v0.1.4] — 2026-06-02

首个 crate 线版本。此前 0.1.x 均为桌面打包修复;本次将可嵌入 SDK(`vigil-sdk`)发布到
crates.io,为 MCP 网关新增第二个漂移维度,并将所有 crate、桌面应用与已发布 SDK 统一到 0.1.4。

### 新增

- **`vigil-sdk` 嵌入式 facade。** `FirewallBuilder` 一次调用即装配出可用防火墙(审计账本 +
  策略引擎 + 默认规则集),且默认 fail-closed —— 未配置的工具绝不被无条件放行。
  `SdkFirewall::decide` / `decide_call` 提供一次调用的决策 API,便于把 Vigil 安全运行时嵌入
  自有宿主应用。SDK 及其依赖 crate 已发布至 crates.io。
- **stdio MCP server 的 resolved-program 漂移检测。** 被 pin 的 server 的*解析后可执行路径*
  现作为独立追踪维度(与参数漂移正交):一旦变化,网关在该变更经复核批准前拒绝拉起该 server。
  检测在 spawn 前执行(fail-closed)、对并发 attach 串行化,并作为可复核的漂移事件记入审计账本。

### 变更

- 隐私过滤模型改为从公开 Hugging Face 端点下载(`huggingface.co/openai/privacy-filter`,
  Apache-2.0);可设 `VIGIL_MODEL_MIRROR` 指向自有镜像。文件大小与 SHA-256 摘要不变(与原源
  字节一致)。
- workspace、桌面应用与已发布 SDK 版本对齐到 `0.1.4`。桌面构建通过其后端 crate 获得 MCP 漂移
  加固;本次无桌面 UI 变更。

### 安全

- Wasmtime 升级 `44.0.1` → `44.0.2`,清除沙箱 advisory RUSTSEC-2026-0149。

---

## [v0.1.3] — 2026-06-01

桌面 GUI 渲染修复。桌面应用现在能真正渲染界面。v0.1.2 修好了"安装包装 GUI 而非 CLI",但 GUI
打开仍是空白/黑屏:vue-i18n 在运行时用 `new Function` 编译多语言消息,被应用的严格 CSP
(`script-src 'self'`,无 `'unsafe-eval'`)拦截,导致渲染中断。

### 修复

- 桌面 GUI 不再打开空白/黑屏窗口。给 vue-i18n 注入 CSP 安全的自定义 `messageCompiler`(纯
  `{named}` 插值,无 `eval` / `new Function`),使 UI 在不放宽严格 CSP 的前提下正常渲染。此问题
  只影响打包/安装的应用 —— `tauri dev` 用宽松 CSP,故在 v0.1.2 让 GUI 首次可安装前一直未暴露。

### 变更

- workspace 与桌面应用版本 `0.1.2` → `0.1.3`。

---

## [v0.1.2] — 2026-06-01

桌面安装包修复。Windows / macOS / Linux 三平台桌面安装包现在装的是真正的 GUI 应用。v0.1.0 与
v0.1.1 的桌面安装包误打入了无窗口的 CLI 二进制 —— 双击安装后的应用只闪一下控制台便退出,而不
打开窗口。CLI 二进制本身正常,仅桌面安装包受影响。

### 修复

- 桌面安装包现在装 GUI 而非 CLI。`apps/desktop` 原有第二个 `[[bin]]`(`vigil-desktop` 调试
  CLI);`cargo tauri build` 会构建全部二进制(`cargo build --bins`)并把错误的那个打成应用主
  程序。现 desktop crate 仅保留 `gui` 一个二进制,打包器只能打 GUI。

### 变更

- 移除 `vigil-desktop` 调试 CLI;其查账本能力整合进主 CLI 的 `vigil-hub inspect` 子命令
  (`activity` / `search` / `approvals` / `session` / `servers` / `sandbox` / `verify-chain`;
  单行 JSON 输出,便于脚本化)。
- workspace 与桌面应用版本 `0.1.1` → `0.1.2`。

---

## [v0.1.1] — 2026-06-01

打包补全版本。在既有 NSIS / DMG / DEB / AppImage 之外新增 Windows MSI 与 Linux RPM 安装包,并
将 workspace 与桌面应用版本号对齐公开发布线。无库或运行时行为变更。

### 新增

- Windows MSI 安装包与 Linux RPM 包纳入发布产物。

### 变更

- workspace 与桌面应用版本 `0.0.1` → `0.1.1`,对齐公开发布 tag。
- README 安装表补全各平台完整安装包清单。

---

## [v0.1.0] — 2026-06-01

Vigils 首个公开版本 —— 面向 AI Agent 的本地优先控制平面。

### 新增

- **审计账本** —— SQLite、SHA-256 哈希链、FTS5 全文检索、逐事件完整性。
- **防火墙与审批** —— 默认拒绝工具门禁、按 Agent 策略、人在回路的范围化审批队列。
- **脱敏引擎** —— 硬指纹规则 + 可选 ML 集成的密钥/PII 检测,配 fail-closed 合并层。
- **凭据租约 broker** —— 短时凭据租约;明文永不落盘。
- **沙箱 runner** —— Wasm(Wasmtime)与 native 执行、Linux Landlock LSM 文件系统隔离,默认
  fail-closed。
- **MCP 网关** —— stdio 与 HTTP 双传输、descriptor pinning + 漂移检测、OAuth scope 白名单。
- **桌面应用**(Tauri 2 + Vue 3)—— 审批队列、活动流、服务器注册、会话回放、隐私发现;键盘
  快捷键、主题切换、实时更新、中英双语 UI。
- **浏览器扩展**(Chrome MV3)—— 在 AI 站点粘贴/提交前脱敏密钥/PII。

采用 Apache-2.0 许可证。
