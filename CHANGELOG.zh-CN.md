# 更新日志

Vigils 的所有重要变更记录于此。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/),版本遵循
[语义化版本](https://semver.org/lang/zh-CN/)(0.x 阶段允许接口演进)。

> English version: [CHANGELOG.md](./CHANGELOG.md)

---

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
