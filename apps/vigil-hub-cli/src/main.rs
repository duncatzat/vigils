//! Vigil Hub CLI binary —— clap entrypoint,lib 层是 `vigil_hub_cli` crate。
//!
//! I00-I09:占位。
//! I10b-β:`add-remote-mcp` 子命令,串联 PRM discover + loopback OAuth + token persist。
//! v0.3 Stage 1(2026-04-24):`serve` 子命令 —— 把 Hub 暴露为 MCP stdio server,
//! 供 CLI agent(Claude Code / Codex / Cursor / Zed 等)通过 stdio transport 连接。

use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use vigil_hub_cli::daemon;
use vigil_hub_cli::demo::{self, DemoArgs};
use vigil_hub_cli::engine_config;
use vigil_hub_cli::hook::{self, HookArgs};
use vigil_hub_cli::i18n::{self, Lang};
use vigil_hub_cli::inspect::{self, InspectArgs};
use vigil_hub_cli::model;
use vigil_hub_cli::posture;
use vigil_hub_cli::quickstart;
use vigil_hub_cli::serve::{self, ServeArgs};
use vigil_hub_cli::setup::{self, SetupArgs};
use vigil_hub_cli::setup_hooks;
use vigil_hub_cli::setup_mcp::{self, McpServerClass};
use vigil_hub_cli::wrap::{self, WrapArgs};
use vigil_hub_cli::{add_remote, AddRemoteArgs};

/// Vigil Hub CLI(I10b-β:含 `add-remote-mcp`)。
#[derive(Parser, Debug)]
#[command(name = "vigil-hub", version, about = "Vigil Hub local proxy + CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 注册并为一个远程 HTTP MCP server 完成 OAuth(loopback redirect)。
    AddRemoteMcp(CliAddRemoteArgs),
    /// 把 Vigil Hub 暴露为 MCP stdio server;CLI agent 可通过 stdio transport 连接。
    ///
    /// 典型用法(在 agent 侧 MCP 配置):
    /// ```json
    /// {"vigil": {"command": "vigil-hub", "args": ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]}}
    /// ```
    Serve(CliServeArgs),
    /// 零设置首次体验:一条命令看完 default-deny 防护 + 可逆脱敏往返 + 防篡改审计。
    ///
    /// 走 Vigil 真实运行时代码(firewall / 脱敏 / 审计),只模拟外部 model/tool;不联系任何 LLM,
    /// 不需账号/key/网络。`--tamper` 额外演示篡改账本被检测(可证伪)。
    Demo(CliDemoArgs),
    /// agent CLI `PreToolUse` hook adapter(guard-only):从 stdin 读 PreToolUse 事件,
    /// 对带 secret 的**原生**工具调用 fail-closed deny 并审计;干净调用放行(exit 0)。
    /// 支持 Claude Code(默认,deny=exit 2+stderr)与 Codex/Gemini/Cursor
    /// (`--cli <kind>`,deny=exit 0+stdout JSON 决策)。
    ///
    /// Claude settings.json 注册示例(matcher `*` = **所有**工具 —— 裸 secret 纵深防御需覆盖
    /// `mcp__*`,故不要把 matcher 限定到 `Bash|Edit|...`,否则 hook 对 MCP 工具根本不触发):
    /// ```json
    /// {"hooks":{"PreToolUse":[{"matcher":"*",
    ///   "hooks":[{"type":"command","command":"vigil-hub hook --ledger C:\\Vigil\\ledger.sqlite"}]}]}}
    /// ```
    /// 注:hook 对**每个**工具调用触发(含 Read);干净调用零开销放行。占位符替换在后续增量加入。
    Hook(CliHookArgs),
    /// 一键接入:把 Vigil 保护写进已装 AI agent 配置,让"下载 → 运行一次 → 直接受保护"成立。
    ///
    /// v1 = 检测 Claude Code → 注册 PreToolUse hook(全工具 secret 守门 + 本地审计)。
    /// `--uninstall` 干净移除;`--status` 报告 + 自检;`--dry-run` 只预览不写盘。
    Setup(CliSetupArgs),
    /// 透明 stdio MCP shim:把一个已存在的 MCP server 命令套上 Vigil 网关(firewall + 脱敏 +
    /// 审批 + 审计)。agent 像直连原 server 一样连 wrap,中间被守护。
    ///
    /// 用法:`vigil-hub wrap -- npx -y @modelcontextprotocol/server-filesystem /data`
    /// (在 agent 的 MCP 配置里把 `command` 改为 `vigil-hub`、args 前缀 `["wrap","--", ...原命令]`)。
    Wrap(CliWrapArgs),
    /// 锚定审计链头(ADR 0020):把当前链头快照写入与账本分离的 append-only sidecar
    /// (`<ledger>.checkpoints`)。周期运行(或 cron)即可检出**整链重写**——哈希链单独检不出的篡改。
    ///
    /// 安全建议:把 `.checkpoints` 设为 OS append-only(Linux:`chattr +a`;macOS:`chflags uappnd`)
    /// 或异地同步(含 Windows 均适用),锚点才能完全闭合"持完整本地写权限者整链重写"。
    Checkpoint(CliCheckpointArgs),
    /// 校验审计链:先链内一致性(防篡断裂),再比对 checkpoint 锚点(防整链重写)。三态如实输出。
    Verify(CliVerifyArgs),
    /// 引导首跑(**只读**):检测你机器上的 AI agent + MCP server 与保护状态,并给出
    /// 「看 demo → 一键保护 → 验证」三步。**不改任何配置**(检测=只读 preview)。
    Quickstart,
    /// 查看 / 切换安全姿态档位(三档:low / medium / high)。控制**占位符 × 原生工具**的处置:
    /// low=放行(默认) / medium=共同批准(ask) / high=拦截。裸 secret 在**任何**档位恒拦(硬底线不可降级)。
    ///
    /// 用法:`vigil-hub posture show` / `vigil-hub posture set medium`。
    Posture(CliPostureArgs),
    /// 只读查看 Vigil 拦了什么(基于已持久化审计账本的聚合):protection 汇总 / activity 事件流 /
    /// search 全文检索 / approvals 队列 / verify-chain 链校验 —— 用过 agent 后"看见保护"。
    ///
    /// 用法:`vigil-hub inspect protection` / `vigil-hub inspect activity`。
    Inspect(InspectArgs),
    /// 查看 / 切换 AI 引擎模式(ADR 0022 三态:hardfp / ml / auto)的**落盘配置**。
    /// GUI(控制平面)经本命令读写;serve/wrap 未显式 `--engine` 时回落本配置(消费侧增量接线)。
    /// `ml`/`auto` 实际跑 ML 仍需 ML 引擎变体(`--features ort`)。
    /// 用法:`vigil-hub engine show` / `vigil-hub engine set ml`。
    Engine(CliEngineArgs),
    /// 启 / 查常驻 daemon(ADR 0024):暖载 ML 模型供 hook 主路径低延迟查询(瘦客户端经本地 IPC)。
    /// `start` 前台运行(单实例:已运行则退出);`status` 查运行态。ort 构建 + 模型已缓存则暖载真
    /// PII scanner,否则 model-less(hook 落硬指纹)。
    Daemon(CliDaemonArgs),
    /// 安装 / 查 ML 模型(隐私 PII + 注入分类器,各 ~700MB)。turnkey:`model install` →
    /// `daemon start`(暖载)→ `engine set ml` → hook 走 ML。ort-gated(非 ML 变体报错指向变体)。
    /// 用法:`vigil-hub model install` / `vigil-hub model status`。
    Model(CliModelArgs),
}

#[derive(clap::Args, Debug)]
struct CliPostureArgs {
    /// 省略子命令 = `show`(裸 `vigil-hub posture` 直接给当前值,不甩 help;F-11)。
    #[command(subcommand)]
    command: Option<PostureCommand>,
}

#[derive(Subcommand, Debug)]
enum PostureCommand {
    /// 显示当前档位(读 posture 配置;文件缺失 = 默认 low)。
    Show,
    /// 切换到指定档位(原子写配置 + 审计变更事件)。
    Set {
        /// 目标档位:low / medium / high。
        #[arg(value_enum)]
        profile: posture::PostureProfile,
        /// 审计账本路径(记录 posture 变更;默认 `<本机数据目录>/Vigil/ledger.sqlite3`,与 hook 同账本)。
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
}

#[derive(clap::Args, Debug)]
struct CliEngineArgs {
    /// 省略子命令 = `show`(同 posture;F-11)。
    #[command(subcommand)]
    command: Option<EngineCommand>,
}

#[derive(Subcommand, Debug)]
enum EngineCommand {
    /// 显示当前引擎模式(读 engine 配置;文件缺失 = 未配置,显示默认 hardfp)。
    Show,
    /// 切换到指定引擎模式(原子写配置)。`ml`/`auto` 实际生效仍需 ML 引擎变体(`--features ort`)。
    Set {
        /// 目标模式:hardfp / ml / auto。
        #[arg(value_enum)]
        mode: serve::EngineMode,
    },
}

#[derive(clap::Args, Debug)]
struct CliDaemonArgs {
    /// 省略子命令 = `status`(裸 `vigil-hub daemon` 报运行态;`start`/`stop` 仍需显式;F-11)。
    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Subcommand, Debug)]
enum DaemonCommand {
    /// 前台启动 daemon(bind 本地 socket + 写 daemon.json + serve)。单实例:已运行则失败退出。
    Start,
    /// 查 daemon 状态(读 daemon.json + 连接 query live Status,经 R1 peer-cred)。
    Status {
        /// 机器可读 JSON 输出(schema 稳定、与界面语言无关;供脚本/CI 断言)
        #[arg(long)]
        json: bool,
    },
    /// 停止 daemon(R1+token 验存活后杀 daemon.json.pid;不响应则只清陈旧 json,防 pid 重用误杀)。
    Stop,
}

#[derive(clap::Args, Debug)]
struct CliModelArgs {
    #[command(subcommand)]
    command: ModelCommand,
}

#[derive(Subcommand, Debug)]
enum ModelCommand {
    /// 下载 ML 模型。`--privacy` / `--injection` 选装;都不给 = 都装。已缓存则幂等秒回(ETag 304)。
    Install {
        /// 只装隐私 PII 模型。
        #[arg(long)]
        privacy: bool,
        /// 只装注入分类器模型。
        #[arg(long)]
        injection: bool,
    },
    /// 查两个模型本地是否已缓存(daemon 暖载 / `--engine auto` best-effort 的前提)。
    Status,
}

#[derive(clap::Args, Debug)]
struct CliCheckpointArgs {
    /// 审计账本路径(默认 `<本机数据目录>/Vigil/ledger.sqlite3`,与 setup/hook/wrap 同一个)。
    #[arg(long)]
    ledger: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct CliVerifyArgs {
    /// 审计账本路径(默认同上)。
    #[arg(long)]
    ledger: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct CliDemoArgs {
    /// 额外演示可证伪:篡改一条账本行后真 verify_chain 检测到篡改(失败)。
    #[arg(long)]
    tamper: bool,
}

#[derive(clap::Args, Debug)]
struct CliHookArgs {
    /// 审计账本路径(与 `serve --ledger` 同一文件以保持审计链连续)。
    /// 省略 = 不审计(仍做安全决策;stderr 提示)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// 事件来源 CLI(决定事件名归一映射与 deny 输出形状:claude=exit 2+stderr;
    /// codex/gemini/cursor=exit 0+stdout JSON 决策)。省略 = claude(向后兼容既有注册)。
    #[arg(long, value_enum, default_value_t = hook::CliKind::Claude)]
    cli: hook::CliKind,
    /// 由 `vigil-hub setup` 写入的托管标记(被本命令**忽略**;仅供 setup 识别/卸载其托管条目)。
    #[arg(long = "vigil-managed", hide = true)]
    #[allow(dead_code)]
    // clap 解析后不读取;存在只为接受该 flag,不让 Claude Code 调用报未知参数
    vigil_managed: bool,
    /// 开启 α2 执行边界注入(TASK-005):Bash 等边界工具里的 `secret://<alias>` 占位符,
    /// 经 lease 授权解析为真值后写回 `updatedInput`(仅 Claude 支持;模型 transcript 仍见占位符)。
    /// 仅在该 CLI 支持 `updatedInput` 且版本达标时由 setup 写入;省略 = 不注入(占位符落三档姿态)。
    #[arg(long)]
    inject: bool,
    /// 注入用 alias→secret_ref 映射文件(JSON 对象 `{"<alias>": "<secret_ref>"}`)。
    /// **仅含映射,不含真值**(真值在 OS Keychain,按 secret_ref 取);未声明的 alias 注入时 fail-closed deny。
    /// 与 `--inject` 配套;`--inject` 开但本文件缺失/损坏 → 空映射(任何占位符都 undeclared → deny,诚实暴露误配)。
    #[arg(long = "secrets")]
    secrets: Option<PathBuf>,
    /// 注入 lease 的 TTL(秒)。hook 是 one-shot,mint→resolve 微秒级,短 TTL 即可。默认 300。
    #[arg(long = "inject-ttl-secs", default_value_t = 300)]
    inject_ttl_secs: i64,
    /// PostToolUse 结果硬指纹 secret 脱敏(#12):把工具结果里的 ghp_/AKIA/sk- 等硬指纹 secret
    /// 替换为 `[REDACTED <rule>]` 再返回模型 —— **无状态、独立于 `--inject`**(无需声明 secret)。
    /// 仅 Claude 生效(需 updatedToolOutput);由 `vigil-hub setup` 默认为 Claude 写入。
    #[arg(long = "redact-results")]
    redact_results: bool,
}

#[derive(clap::Args, Debug)]
struct CliWrapArgs {
    /// 审计账本路径(默认 `<本机数据目录>/Vigil/ledger.sqlite3`,与 setup/hook 同一个)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// 该被包裹 server 的稳定身份 id(= agent 配置里的 server 名)。缺省由命令 argv 派生(并警告)。
    #[arg(long = "server-id")]
    server_id: Option<String>,
    /// **显式**转发给子进程的 env 键(可重复;= 该 server 配置的 `env{}` 的键)。默认不转发任何 secret。
    #[arg(long = "env-key")]
    env_key: Vec<String>,
    /// 逃生舱:透传 wrap 进程的**全部** env 给子进程(仅确知该 server 本就该拿全量继承 env 时用)。
    #[arg(long = "inherit-env")]
    inherit_env: bool,
    /// **Monitor posture**(opt-in,非阻塞):风险调用自动放行 + 审计,不阻塞(turnkey 无 desktop
    /// resolver 时推荐;否则风险工具阻塞 ~300s 看似卡死)。默认 enforce(阻塞人审批)。
    #[arg(long)]
    monitor: bool,
    /// 项目边界根(可重复):firewall `deny-outside-project` / `approve-repo-write` 的判定基准。
    /// 省略 = 当前工作目录(CWD)。
    #[arg(long = "project-root")]
    project_root: Vec<PathBuf>,
    /// 由 `vigil-hub setup --mcp` 写入的托管标记(被本命令**忽略**;仅供 setup 识别其托管的 wrap 条目)。
    #[arg(long = "vigil-managed-mcp", hide = true)]
    #[allow(dead_code)]
    vigil_managed_mcp: bool,
    /// 被包裹的 MCP server 命令,放在 `--` 之后(例:`-- npx -y <pkg> /data`)。
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct CliSetupArgs {
    /// 移除 Vigil 托管配置(仅 Vigil 自己的条目,不动你其它配置)。
    #[arg(long)]
    uninstall: bool,
    /// 报告当前保护状态 + 自检(含合成 fake token 跑真 hook 断言被拦的 smoke test)。
    #[arg(long)]
    status: bool,
    /// 只打印将要做的改动,不写盘。
    #[arg(long)]
    dry_run: bool,
    /// 覆盖审计账本路径(默认 `<本机数据目录>/Vigil/ledger.sqlite3`)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// **MCP turnkey**:把 Claude Code(`~/.claude.json`)的 stdio MCP server 改写为 `vigil-hub wrap`
    /// 网关(**默认 monitor 姿态**)。**默认保护 user scope(顶层 mcpServers)+ local scope(`projects.*`,
    /// `claude mcp add` 默认写这里)**;local scope 用项目限定 server-id 防跨项目同名身份塌缩。
    /// `--mcp` 单用 = **只读预览**;`--mcp --apply` 真改写;`--mcp --uninstall` 还原(两 scope);
    /// `--dry-run` 只算不写。
    #[arg(long)]
    mcp: bool,
    /// 配合 `--mcp`:真正改写 `~/.claude.json`(否则 `--mcp` 仅预览)。原子写 + 备份 + 可逆。
    #[arg(long)]
    apply: bool,
    /// 配合 `--mcp --apply`:**只**保护 user scope,显式跳过 local scope(`projects.*`)的 server
    /// (让它们**不被保护**;CLI 会诚实报告被跳过的数量)。默认两个 scope 都保护。
    #[arg(long = "user-scope-only")]
    user_scope_only: bool,
    /// 配合 `--mcp`:把 wrap 网关姿态从默认 **monitor** 升级为 **enforce**(default-deny 硬拦)。
    ///
    /// **为何默认 monitor 而非 enforce**:被 wrap 的是用户自配的**第三方** MCP server,其工具名不在
    /// Vigil 的 effect 提取词表内 → 提取不出 effect → enforce 下一律 default-deny = 真实 server **全部
    /// 不可用**(turnkey 一键接入直接打挂用户现有工作流 = 采用毒药)。monitor 姿态保留全部硬地板
    /// (裸 secret 拦截 + 结果脱敏可逆往返 + 显式 Deny + descriptor drift),只把 default-deny **地板**
    /// 降级为观察放行 —— 实际交付的价值(脱敏 + 审计 + 输入拦截)全在,且 server 可用。业界研究也一致:
    /// 绝大多数审批弹窗被未读即批,拦截式审批容易沦为形式,而确定性脱敏保护始终生效。
    /// 想要硬拦语义(已知工具集 / 自建 server / 高保障场景)再显式 `--enforce`。
    #[arg(long)]
    enforce: bool,
    /// 配合 `--mcp`:**健壮性预检**。对每个 MCP server(含已被 Vigil 包裹的)检查其底层 stdio 程序能否
    /// 在 PATH 解析(用网关同款解析逻辑)→ 逐 server ✓/✗ + 可操作原因。回答"我的接入是否能跑 / 哪个
    /// server 起不来、为什么"(最常见失败 = 程序没装 / 不在 PATH)。**纯静态、只读、不启动任何 server**。
    #[arg(long)]
    doctor: bool,
    /// 配合 `--doctor`:**深度探测**。对静态判定可启动的 server**真启动**其底层程序 + 完成 MCP
    /// `initialize` 握手(逐 server 有超时上界),再立即关停。回答静态档答不了的"程序在 PATH 但**运行时**
    /// 真能起来 + 说 MCP 吗"——抓"装了 Node 但 npx 包拉不动 / server 启动即崩 / 不说 MCP"这类静默失败
    /// (agent 表现为该 server **零工具**)。**有副作用**:会真启动每个 server 进程片刻(执行其 init 代码),
    /// 故 opt-in;默认 `--doctor` 保持纯静态无副作用。`npx`/`uvx` server **首次**探测可能因下包慢而超时
    /// (同 agent 首启;暖缓存后重跑即 OK)。
    #[arg(long, requires = "doctor")]
    probe: bool,
    /// **一条命令全保护**:同时接入 hook(原生工具输入侧 secret 拦截)**和** MCP 网关 wrap(脱敏 +
    /// 审计 + 审批 + descriptor pin),兑现"download → 直接得到保护"。等价于 `setup` + `setup --mcp
    /// --apply` 两步合一(两者写不同文件、互不冲突)。`--all --uninstall` 撤销两者;`--all --dry-run`
    /// 预览两者;MCP 侧默认 monitor 姿态(加 `--enforce` 升级硬拦)。
    ///
    /// 与只读操作 `--status` / `--doctor` **互斥**(否则 `--all --status` 会因 `--all` 优先而
    /// **变成写操作**,破坏只读预期)—— 该组合在解析期即被拒绝,避免意外写入。
    /// 也与 `--mcp` 互斥(`--all` 已包含 MCP wrap,叠加 `--mcp` 会被静默忽略造成歧义;
    /// 请二选一:`--all` 或 `--mcp`)。
    #[arg(long, conflicts_with_all = ["status", "doctor", "mcp"])]
    all: bool,
}

#[derive(clap::Args, Debug)]
struct CliAddRemoteArgs {
    /// 远程 MCP server 的 base URL,例如 `https://mcp.example.com/`
    #[arg(long)]
    url: String,
    /// OAuth client_id(公共 client,无 secret;I10c 再加 confidential)
    #[arg(long)]
    client_id: String,
    /// 请求的 scope 列表,逗号分隔(例如 `mcp:tools.read,mcp:tools.write`)
    #[arg(long, value_delimiter = ',')]
    scopes: Vec<String>,
    /// SQLite Ledger 路径(默认 `./vigil.db`)
    #[arg(long, default_value = "vigil.db")]
    ledger: PathBuf,
    /// 等 loopback callback 的超时秒数(默认 60)
    #[arg(long, default_value_t = 60u64)]
    timeout_secs: u64,
}

impl From<CliAddRemoteArgs> for AddRemoteArgs {
    fn from(c: CliAddRemoteArgs) -> Self {
        AddRemoteArgs {
            url: c.url,
            client_id: c.client_id,
            scopes: c.scopes,
            ledger: c.ledger,
            timeout_secs: c.timeout_secs,
        }
    }
}

#[derive(clap::Args, Debug)]
struct CliServeArgs {
    /// 使用 stdio transport(v0.3 Stage 1 唯一支持;HTTP 留后续)。必须显式开启。
    #[arg(long)]
    stdio: bool,
    /// SQLite Ledger 持久化路径。省略 = 内存 ledger(仅 smoke 测试用,跨连接不保留审计)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Upstream MCP server 配置 JSON。schema:`{"upstreams":[{"name":..., "argv":[...]}]}`。
    /// Stage 1 仅校验 JSON 格式,实际 attach 留 Stage 2 完成 register_server + approve_server。
    #[arg(long = "upstream-config")]
    upstream_config: Option<PathBuf>,
    /// 开发模式:tools/list 首次见到的 descriptor 自动批准(生产务必保持 false)。
    #[arg(long)]
    auto_approve_first_seen: bool,
    /// 开发模式:注入 "catch-all → Approve" 兜底 policy 规则,让无 EffectKind
    /// 匹配的纯计算工具走 ApprovalBroker 路径而非 default-deny。
    /// **生产必须关闭**(否则零信任 fail-safe 失守)。
    #[arg(long)]
    dev_permissive_firewall: bool,
    /// ISS-008 Phase 2:启用 T0 Privacy Filter(ORT 真模型推理)。
    /// 需要编译期 `--features ort` + 运行期 `VIGIL_PRIVACY_FILTER_MODEL_DIR` 环境变量。
    /// flag on + feature off → 启动失败 `ServeError::PrivacyFilterUnavailable`;
    /// flag off → 走 v0.4 默认 NoopEngine(向后兼容)。
    #[arg(long = "enable-privacy-filter")]
    enable_privacy_filter: bool,
    /// 可逆脱敏 Slice 1:上游工具响应命中硬指纹 secret 时,in-band 脱敏 result 后再返回
    /// agent/LLM(默认 off = 既有 out-of-band 仅审计)。堵住工具输出把 secret 回吐给远端 LLM。
    #[arg(long = "redact-tool-results")]
    redact_tool_results: bool,
    /// 项目边界根(可重复):firewall `deny-outside-project` / `approve-repo-write` 的判定基准。
    /// 省略 = 当前工作目录(CWD)。DEF-004 之前生产入口边界为空,这两条规则形同虚设。
    #[arg(long = "project-root")]
    project_root: Vec<PathBuf>,
    /// **Monitor 姿态**(与 `wrap --monitor` 对称):无 GUI 审批 resolver 时,把本应人审批的
    /// 风险调用**自动放行 + 完整审计**(不阻塞 approval_wait ~300s),而非看似卡死。硬地板不变
    /// (裸 secret 拦截 + 结果脱敏 + 显式 Deny + descriptor drift 仍在),只把 default-deny **地板**
    /// 降级为观察放行。默认 off = enforce(default-deny + 阻塞审批)。turnkey / headless / e2e 场景用。
    #[arg(long)]
    monitor: bool,
    /// P0 注入防护 Slice D:启用 DeBERTa prompt-injection 软信号检测(serve warm session)。
    /// 需编译期 `--features ort`。flag on + feature off → 启动失败 InjectionClassifierUnavailable;
    /// flag off → 不加载。命中只 bump risk + 审计,绝不 deny。
    #[arg(long = "enable-injection-classifier")]
    enable_injection_classifier: bool,
    /// ADR 0022:引擎选择 `--engine <hardfp|ml|auto>`。省略 = legacy(由裸 `--enable-*` 决定)。
    /// `hardfp`=仅硬指纹(默认发行件行为);`ml`=严格启用 ML(缺 feature/模型/dylib 则拒启);
    /// `auto`=仅当模型已缓存 + onnxruntime dylib 就位才启用 ML,否则降级硬指纹(永不触发下载)。
    #[arg(long, value_enum)]
    engine: Option<serve::EngineMode>,
}

impl From<CliServeArgs> for ServeArgs {
    fn from(c: CliServeArgs) -> Self {
        // P2.2:显式 `--engine` 缺省时回落持久化 engine.json(GUI 控制平面写的全局偏好);
        // 持久化 = standing 偏好 → best-effort(缺 ort/模型响亮降级硬指纹而非拒启;ADR 0024 D8)。
        let persisted =
            engine_config::default_engine_path().map(|p| engine_config::load_engine(&p));
        if let Some(w) = persisted.as_ref().and_then(|l| l.warning.as_deref()) {
            eprintln!("vigil-hub serve: {w}");
        }
        let (effective, ml_best_effort) =
            engine_config::effective_engine(c.engine, persisted.and_then(|l| l.mode));
        // ADR 0022:把生效 engine + 裸 --enable-* 解析成最终两开关(`auto` 含只读 fs 探测,不下载)。
        let sel = serve::resolve_engine_args(
            effective,
            c.enable_privacy_filter,
            c.enable_injection_classifier,
        );
        ServeArgs {
            ledger_path: c.ledger,
            upstreams_config: c.upstream_config,
            auto_approve_first_seen: c.auto_approve_first_seen,
            dev_permissive_firewall: c.dev_permissive_firewall,
            enable_privacy_filter: sel.enable_privacy_filter,
            enable_injection_classifier: sel.enable_injection_classifier,
            ml_best_effort,
            redact_tool_results: c.redact_tool_results,
            // 默认 enforce(default-deny + 阻塞审批);`--monitor` 显式转观察放行(headless/turnkey/e2e)。
            monitor: c.monitor,
            project_roots: serve::resolve_project_roots(&c.project_root),
        }
    }
}

fn main() -> std::process::ExitCode {
    // i18n:按系统语言(VIGIL_LANG 覆盖 → 系统 locale → En 回落)选择输出语言;在 parse 前用
    // builder 把帮助文案整体改写为贴切、本地化文本 —— **只改展示**,绝不动子命令名 / flag 解析契约。
    let lang = Lang::detect();
    let matches = i18n::help::localize(Cli::command(), lang).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    match cli.command {
        None => {
            // 真实 crate 版本(编译期 CARGO_PKG_VERSION),非内部迭代标记 —— 用户看到的是
            // 发布版本号(如 v0.1.15),既不误导也不泄漏内部 `I0x` 迭代术语。文案按系统语言本地化。
            eprintln!(
                "{}",
                i18n::t(
                    lang,
                    i18n::Msg::NoCommandHint {
                        version: concat!("v", env!("CARGO_PKG_VERSION")),
                    },
                )
            );
            std::process::ExitCode::SUCCESS
        }
        Some(Command::AddRemoteMcp(args)) => {
            let args: AddRemoteArgs = args.into();
            match add_remote::run(args) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => fail_cmd(lang, "add-remote-mcp", e),
            }
        }
        // 还原 v0.1.31 误删的 inspect 接线(`feat(audit): checkpoint anchor` 从无 inspect 的内部仓
        // port 时连带删了 Command::Inspect;inspect.rs 实现一直在 + README/docs 仍引用)。
        Some(Command::Inspect(args)) => inspect::run(args),
        Some(Command::Serve(args)) => {
            // stdio flag 必须显式给,防止用户误以为能默认启 HTTP
            if !args.stdio {
                eprintln!("{}", i18n::t(lang, i18n::Msg::ServeNeedsStdio));
                return std::process::ExitCode::FAILURE;
            }
            let args: ServeArgs = args.into();
            // NOTE:stderr 打印启动提示;stdout 交给 MCP 协议,**不得污染**
            eprintln!(
                "{}",
                i18n::t(
                    lang,
                    i18n::Msg::ServeStarted {
                        pid: std::process::id(),
                    },
                )
            );
            match serve::run(args) {
                Ok(()) => {
                    eprintln!("{}", i18n::t(lang, i18n::Msg::ServeStopped));
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => fail_cmd(lang, "serve", e),
            }
        }
        Some(Command::Demo(args)) => {
            let demo_args = DemoArgs {
                tamper: args.tamper,
            };
            match demo::run(&demo_args, lang) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => fail_cmd(lang, "demo", e),
            }
        }
        Some(Command::Hook(args)) => {
            // agent CLI PreToolUse adapter:stdin 读事件 → 决策 → 按 CLI 分流输出。
            // Claude deny 必须 exit 2(blocking;exit 1 是 non-blocking fail-open,绝不能用作拦截);
            // Codex/Gemini/Cursor deny 走 exit 0 + stdout JSON 决策。形状映射在 hook::respond
            // (纯函数,进默认测试矩阵),这里只做 IO。
            // posture_path / co_approval_wait_secs 走默认(canonical 路径 + 按 CLI 预算);
            // 显式覆盖仅测试注入用。
            // α2 注入配置:仅 `--inject` 时构造(否则 None = 占位符落三档姿态,无行为回归)。
            // engine.json(GUI 控制平面写的全局偏好)决定 hook 是否经常驻 daemon 走 ML PII 增强
            // (ADR 0024)。持久化 = standing 偏好 → best-effort(daemon 缺则降级硬指纹;D8)。hook 由
            // agent 以固定注册参数调起,无 `--engine` flag → 仅读 engine.json(显式覆盖留 serve/wrap)。
            // 纵深兜底(审核 P1):决策 + 输出整体经 exit_code_guarded —— 任何未预期 panic
            // (含 broken-pipe 下 println! panic)收敛为本 CLI 的 Deny 形状(Claude=exit 2),
            // 绝不 unwind 成 exit 101(Claude 视非 2 退出为 non-blocking fail-open)。
            let cli = args.cli;
            let code = hook::exit_code_guarded(cli, || {
                let loaded_engine =
                    engine_config::default_engine_path().map(|p| engine_config::load_engine(&p));
                if let Some(w) = loaded_engine.as_ref().and_then(|l| l.warning.as_deref()) {
                    eprintln!("vigil-hook: {w}");
                }
                let engine = loaded_engine.and_then(|l| l.mode);
                let injection = build_injection_config(
                    args.inject,
                    args.secrets.as_deref(),
                    args.inject_ttl_secs,
                );
                let hook_args = HookArgs {
                    ledger_path: args.ledger,
                    cli,
                    injection,
                    redact_results: args.redact_results,
                    engine,
                    ..HookArgs::default()
                };
                let stdin = std::io::stdin();
                let mut reader = stdin.lock();
                let outcome = hook::run(&hook_args, &mut reader);
                let resp = hook::respond(&outcome, cli);
                if let Some(out) = &resp.stdout {
                    println!("{out}");
                }
                if let Some(err) = &resp.stderr {
                    eprintln!("{err}");
                }
                resp.exit_code
            });
            std::process::ExitCode::from(code)
        }
        Some(Command::Setup(args)) => {
            if args.all {
                // 一条命令全保护:hook + MCP wrap 一次完成(兑现 download→直接保护)。
                match run_setup_all(lang, &args) {
                    Ok(code) => code,
                    Err(e) => fail_cmd(lang, "setup --all", e),
                }
            } else if args.mcp {
                // MCP turnkey:--apply 改写 / --uninstall 还原 / 默认只读预览。
                match setup_mcp_dispatch(lang, &args) {
                    Ok(code) => code,
                    Err(e) => fail_cmd(lang, "setup --mcp", e),
                }
            } else {
                let setup_args = SetupArgs {
                    uninstall: args.uninstall,
                    status: args.status,
                    dry_run: args.dry_run,
                    ledger: args.ledger,
                };
                match setup::run(&setup_args) {
                    Ok(report) => {
                        // ISS-20260621-002:status 还需报告 MCP-wrap 保护层(只看 hook 会误报
                        // `--mcp` turnkey 用户未保护)。逐 agent 统计(F-6:只报 Claude 会让
                        // setup --all 保护的 Codex/Cursor 覆盖面在 status 里不可见)。
                        let mcp_counts = dirs::home_dir()
                            .map(|h| setup_mcp::wrapped_server_counts_all_agents(&h))
                            .unwrap_or_default();
                        let code = print_setup_report(lang, &setup_args, &report, &mcp_counts);
                        // 其余 agent 的 hook 注册面(Codex/Gemini/Cursor):检测到才注册,逐面诚实
                        // 报告。ledger 用 Claude 面已解析出的同一路径(审计链单账本)。
                        let op = if setup_args.status {
                            setup_hooks::AgentHookOp::Status
                        } else if setup_args.uninstall {
                            setup_hooks::AgentHookOp::Uninstall {
                                dry_run: setup_args.dry_run,
                            }
                        } else {
                            setup_hooks::AgentHookOp::Install {
                                dry_run: setup_args.dry_run,
                            }
                        };
                        run_agent_hook_legs(lang, &report.ledger, op, code)
                    }
                    Err(e) => fail_cmd(lang, "setup", e),
                }
            }
        }
        Some(Command::Wrap(args)) => {
            // 透明 stdio MCP shim:stdout 是给 agent 的 MCP 协议通道,**不得污染**(提示走 stderr)。
            let wrap_args = WrapArgs {
                command: args.command,
                ledger: args.ledger,
                server_id: args.server_id,
                env_keys: args.env_key,
                inherit_env: args.inherit_env,
                monitor: args.monitor,
                project_roots: args.project_root,
            };
            match wrap::run(&wrap_args) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => fail_cmd(lang, "wrap", e),
            }
        }
        Some(Command::Checkpoint(args)) => run_checkpoint(lang, args.ledger),
        Some(Command::Verify(args)) => run_verify(lang, args.ledger),
        Some(Command::Quickstart) => {
            // 只读引导:检测需要 home(找各 agent 配置)+ exe(preview 构造 wrap argv;本命令不显示)。
            let Some(home) = dirs::home_dir() else {
                eprintln!("{}", i18n::t(lang, i18n::Msg::QuickstartNoHome));
                return std::process::ExitCode::FAILURE;
            };
            let exe = std::env::current_exe().ok();
            let exe_str = exe
                .as_deref()
                .and_then(|p| p.to_str())
                .unwrap_or("vigil-hub");
            match quickstart::run(&home, exe_str, lang) {
                0 => std::process::ExitCode::SUCCESS,
                _ => std::process::ExitCode::FAILURE,
            }
        }
        Some(Command::Posture(args)) => run_posture(lang, args),
        Some(Command::Engine(args)) => run_engine(lang, args),
        Some(Command::Daemon(args)) => run_daemon(lang, args),
        Some(Command::Model(args)) => run_model(lang, args),
    }
}

/// 统一打印「某子命令失败」(本地化)并返回 [`ExitCode::FAILURE`](std::process::ExitCode::FAILURE)。
/// `command` 为展示名(如 `serve` / `setup --all`),`error` 为底层错误。
fn fail_cmd(lang: Lang, command: &str, error: impl std::fmt::Display) -> std::process::ExitCode {
    eprintln!(
        "{}",
        i18n::t(
            lang,
            i18n::Msg::CommandFailed {
                command,
                error: &error.to_string(),
            },
        )
    );
    std::process::ExitCode::FAILURE
}

/// 按语言取静态文案(中 / 英并排)。供 `setup` 系列人类可读报告本地化;复杂插值 / 词序差异的句子
/// 用 `match lang` 直接写整句。`--json` 是机器契约,**不**走本地化(键值恒英文)。
fn tr(lang: Lang, en: &'static str, zh: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// `vigil-hub engine show|set`:查看 / 切换 AI 引擎模式的落盘配置(ADR 0022)。镜像 [`run_posture`]
/// 纪律(原子写;配置目录定位失败 = fail-soft 错误退出)。消费侧(serve/wrap 回落本配置)是后续
/// 增量;本命令只读写配置,不改任何决策路径。
fn run_engine(lang: Lang, args: CliEngineArgs) -> std::process::ExitCode {
    let Some(path) = engine_config::default_engine_path() else {
        eprintln!(
            "{}",
            i18n::t(
                lang,
                i18n::Msg::ConfigDirNotFound {
                    component: "engine",
                },
            )
        );
        return std::process::ExitCode::FAILURE;
    };
    match args.command.unwrap_or(EngineCommand::Show) {
        EngineCommand::Show => {
            let loaded = engine_config::load_engine(&path);
            if let Some(w) = &loaded.warning {
                eprintln!("vigil-hub engine: {w}");
            }
            // 未配置(None)= 默认 hardfp(与发行二进制实际行为一致);纯值输出,刻意不本地化。
            println!("{}", loaded.mode.unwrap_or_default().as_str());
            std::process::ExitCode::SUCCESS
        }
        EngineCommand::Set { mode } => {
            let old = engine_config::load_engine(&path).mode.unwrap_or_default();
            match engine_config::store_engine(&path, mode) {
                Ok(()) => {
                    println!(
                        "{}",
                        i18n::t(
                            lang,
                            i18n::Msg::EngineChanged {
                                old: old.as_str(),
                                new: mode.as_str(),
                            },
                        )
                    );
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        i18n::t(
                            lang,
                            i18n::Msg::ConfigStoreFailed {
                                component: "engine",
                                error: &e.to_string(),
                            },
                        )
                    );
                    std::process::ExitCode::FAILURE
                }
            }
        }
    }
}

/// `vigil-hub daemon start|status`(ADR 0024):前台启动 / 查询常驻 daemon。逻辑在
/// [`daemon::lifecycle`];本处只做分发 + ExitCode 映射。
fn run_daemon(lang: Lang, args: CliDaemonArgs) -> std::process::ExitCode {
    let result = match args
        .command
        .unwrap_or(DaemonCommand::Status { json: false })
    {
        DaemonCommand::Start => daemon::lifecycle::run_start(lang),
        DaemonCommand::Status { json } => daemon::lifecycle::run_status(lang, json),
        DaemonCommand::Stop => daemon::lifecycle::run_stop(lang),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => fail_cmd(lang, "daemon", e),
    }
}

/// `vigil-hub model install|status`(「安装模型支持」turnkey 入口):下载 / 查 ML 模型。逻辑在
/// [`model`];本处只做分发 + ExitCode 映射。ort-gated(非 ML 变体 `install` 返错指向 ML 变体)。
fn run_model(lang: Lang, args: CliModelArgs) -> std::process::ExitCode {
    let result = match args.command {
        ModelCommand::Install { privacy, injection } => {
            model::run_install(lang, privacy, injection)
        }
        ModelCommand::Status => model::run_status(lang),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => fail_cmd(lang, "model", e),
    }
}

/// `vigil-hub posture show|set`:查看 / 切换三档安全姿态。
/// `set` 走 [`posture::store_posture`](原子写)+ best-effort 审计(default ledger 或 `--ledger`;
/// 仅档位真变化时记录)。配置目录定位失败 = fail-soft 错误退出(不影响既有保护:hook 端
/// 文件缺失自落默认 low)。
fn run_posture(lang: Lang, args: CliPostureArgs) -> std::process::ExitCode {
    let Some(path) = posture::default_posture_path() else {
        eprintln!(
            "{}",
            i18n::t(
                lang,
                i18n::Msg::ConfigDirNotFound {
                    component: "posture",
                },
            )
        );
        return std::process::ExitCode::FAILURE;
    };
    match args.command.unwrap_or(PostureCommand::Show) {
        PostureCommand::Show => {
            let loaded = posture::load_posture(&path);
            if let Some(w) = &loaded.warning {
                eprintln!("vigil-hub posture: {w}");
            }
            // 纯值输出(low / medium / high),供脚本解析 —— 刻意不本地化。
            println!("{}", loaded.profile.as_str());
            std::process::ExitCode::SUCCESS
        }
        PostureCommand::Set { profile, ledger } => {
            let old = posture::load_posture(&path).profile;
            match posture::store_posture(&path, profile) {
                Ok(()) => {
                    // 审计 best-effort,仅档位真变化时记录(default ledger 或 --ledger 覆盖)。
                    if old != profile {
                        if let Some(lp) = ledger.or_else(setup::default_ledger_path) {
                            posture::audit_posture_switch(&lp, old, profile);
                        }
                    }
                    println!(
                        "{}",
                        i18n::t(
                            lang,
                            i18n::Msg::PostureChanged {
                                old: old.as_str(),
                                new: profile.as_str(),
                            },
                        )
                    );
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        i18n::t(
                            lang,
                            i18n::Msg::ConfigStoreFailed {
                                component: "posture",
                                error: &e.to_string(),
                            },
                        )
                    );
                    std::process::ExitCode::FAILURE
                }
            }
        }
    }
}

/// `setup --mcp` 分发:`--uninstall` 还原 / `--apply` 改写 / 默认只读预览。
fn setup_mcp_dispatch(
    lang: Lang,
    args: &CliSetupArgs,
) -> Result<std::process::ExitCode, setup::SetupError> {
    let home = dirs::home_dir().ok_or(setup::SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe()
        .map_err(|_| setup::SetupError::MissingCurrentExe)?
        .to_string_lossy()
        .to_string();
    // wrap 网关姿态:默认 monitor(观察放行+脱敏+审计+裸 secret 拦截);`--enforce` 升级为 default-deny
    // 硬拦。第三方 server 工具名不在 effect 词表 → enforce 一律 default-deny = server 全不可用,故默认 monitor
    // 让 turnkey 接入即可用且仍守全部硬地板(详见 CliSetupArgs::enforce doc)。
    let monitor = !args.enforce;
    if args.doctor {
        // 健壮性预检:默认纯静态只读;`--probe` 升级为深度探测(真 spawn + MCP initialize 握手,
        // 有副作用,见 CliSetupArgs::probe doc)。先于 uninstall/apply,doctor 优先。
        let probe_timeout = if args.probe {
            // Codex D18 R2 Low:probe 真执行每个配置 server 的启动代码 —— 动手**前**(run_doctor 内即
            // 开始 spawn)在 stderr 明确告警,而非仅 help 文案 / 事后表头。
            match lang {
                Lang::En => eprintln!(
                    "[vigil-hub] --probe will briefly START each configured MCP server (Claude / Codex / \
                     Cursor / Windsurf) — running its startup code — to test a real MCP handshake, then \
                     stop it. Ctrl-C to abort."
                ),
                Lang::Zh => eprintln!(
                    "[vigil-hub] --probe 会短暂启动每个已配置的 MCP 服务器(Claude / Codex / Cursor / \
                     Windsurf)—— 执行其启动代码 —— 以测试真实 MCP 握手,随后停止它。Ctrl-C 可中止。"
                ),
            }
            Some(setup_mcp::DOCTOR_PROBE_TIMEOUT)
        } else {
            None
        };
        let rows = setup_mcp::run_doctor(&home, probe_timeout)?;
        Ok(print_mcp_doctor(lang, &rows))
    } else if args.uninstall {
        // 所有 agent 接入面都还原:Claude + Codex + Cursor + Windsurf(各独立文件,逐一诚实报告)。
        let rep = setup_mcp::run_uninstall(&home, args.dry_run)?;
        let mut code = print_mcp_apply(lang, &rep, "uninstall");
        code = run_codex_leg(
            lang,
            setup_mcp::run_codex_uninstall(&home, args.dry_run),
            "uninstall",
            code,
        );
        for agent in json_mcp_agents(&home) {
            code = run_json_agent_leg(
                lang,
                setup_mcp::run_json_agent_uninstall(&agent, args.dry_run),
                agent.display_name,
                "uninstall",
                code,
            );
        }
        Ok(code)
    } else if args.apply {
        // 所有面都保护(turnkey:一条命令覆盖用户全部 agent 接入面)。
        // #16:apply 前先查底层程序在 PATH 是否可解析(apply 后条目变 AlreadyWrapped 不再可查)。
        let unresolvable = setup_mcp::unresolvable_wrappables(&home);
        let rep = setup_mcp::run_apply(&home, &exe, args.dry_run, args.user_scope_only, monitor)?;
        let mut code = print_mcp_apply(lang, &rep, "apply");
        // #16:非阻塞 WARN —— 底层程序找不到的 server 仍被 wrap(配置正确),但会在 agent 启动时静默
        // 失败,故诚实告知(避免"Protected"虚假安全感)。
        for (name, prog) in &unresolvable {
            match lang {
                Lang::En => eprintln!(
                    "  WARNING: MCP server '{name}' command '{prog}' not found on PATH; once wrapped it \
                     will fail when the agent starts it (install it or fix the path in your config)"
                ),
                Lang::Zh => eprintln!(
                    "  警告:MCP 服务器 '{name}' 的命令 '{prog}' 不在 PATH 中;一旦被 wrap,agent 启动它时 \
                     会失败(请安装它,或在配置里修好路径)"
                ),
            }
        }
        code = run_codex_leg(
            lang,
            setup_mcp::run_codex_apply(&home, &exe, args.dry_run, monitor),
            "apply",
            code,
        );
        for agent in json_mcp_agents(&home) {
            code = run_json_agent_leg(
                lang,
                setup_mcp::run_json_agent_apply(&agent, &exe, args.dry_run, monitor),
                agent.display_name,
                "apply",
                code,
            );
        }
        Ok(code)
    } else {
        let rep = setup_mcp::run_preview(&home, &exe, monitor)?;
        let code = print_mcp_preview(lang, &rep);
        // 预览只读:某 agent 配置 malformed 不硬 abort(什么都没写),优雅降级为一行提示而非突兀报错。
        match setup_mcp::run_codex_preview(&home, &exe, monitor) {
            Ok(codex) => print_codex_preview(lang, &codex),
            Err(e) => {
                println!();
                println!(
                    "  {}{}",
                    tr(lang, "Codex CLI config: ", "Codex CLI 配置:"),
                    setup_mcp::codex_config_path(&home).display()
                );
                match lang {
                    Lang::En => println!(
                        "  (could not read it: {e} -- fix the file to preview/protect Codex MCP servers)"
                    ),
                    Lang::Zh => println!(
                        "  (无法读取:{e} —— 修好该文件以预览 / 保护 Codex 的 MCP 服务器)"
                    ),
                }
            }
        }
        for agent in json_mcp_agents(&home) {
            match setup_mcp::run_json_agent_preview(&agent, &exe, monitor) {
                Ok(r) => print_json_agent_preview(lang, &r),
                Err(e) => {
                    println!();
                    match lang {
                        Lang::En => println!(
                            "  {} config: {}",
                            agent.display_name,
                            agent.config_path.display()
                        ),
                        Lang::Zh => println!(
                            "  {} 配置:{}",
                            agent.display_name,
                            agent.config_path.display()
                        ),
                    }
                    match lang {
                        Lang::En => println!(
                            "  (could not read it: {e} -- fix the file to preview/protect its MCP servers)"
                        ),
                        Lang::Zh => println!(
                            "  (无法读取:{e} —— 修好该文件以预览 / 保护其 MCP 服务器)"
                        ),
                    }
                }
            }
        }
        Ok(code)
    }
}

/// turnkey 覆盖的"JSON `mcpServers` 形态"agent 列表(Cursor + Windsurf)。新增同形态 agent 只在此扩列。
fn json_mcp_agents(home: &std::path::Path) -> [setup_mcp::JsonMcpAgent; 2] {
    [
        setup_mcp::JsonMcpAgent::cursor(home),
        setup_mcp::JsonMcpAgent::windsurf(home),
    ]
}

/// 运行 Codex 接入面的一步(apply/uninstall)并**诚实处理半应用状态**(Codex review #7 MEDIUM):
/// 成功 → 打印 Codex 报告,返回 Claude 侧退出码;失败(如 Codex 配置 malformed)→ **不吞错也不在成功
/// 文案后突兀 `?` 报错**:明确告知 Claude 侧已生效 + Codex 步失败原因 + 恢复指引,返回 FAILURE。
/// 对齐既有 `--all` 的 `McpAfterHook` 部分失败诚实哲学(报告每步状态 + 如何恢复,而非笼统失败)。
fn run_codex_leg(
    lang: Lang,
    res: Result<setup_mcp::CodexApplyReport, setup::SetupError>,
    op: &str,
    claude_code: std::process::ExitCode,
) -> std::process::ExitCode {
    match res {
        Ok(codex) => {
            print_codex_apply(lang, &codex, op);
            claude_code
        }
        Err(e) => {
            match lang {
                Lang::En => eprintln!(
                    "  [Codex] the {op} step FAILED (the Claude side already completed): {e}"
                ),
                Lang::Zh => {
                    eprintln!("  [Codex] {op} 步失败(Claude 侧已完成):{e}")
                }
            }
            if op == "uninstall" {
                match lang {
                    Lang::En => eprintln!(
                        "  The Claude side was restored. Fix ~/.codex/config.toml, then re-run: \
                         vigil-hub setup --mcp --uninstall"
                    ),
                    Lang::Zh => eprintln!(
                        "  Claude 侧已还原。修好 ~/.codex/config.toml 后重跑:\
                         vigil-hub setup --mcp --uninstall"
                    ),
                }
            } else {
                match lang {
                    Lang::En => eprintln!(
                        "  The Claude side IS applied. Fix ~/.codex/config.toml and re-run; or undo \
                         the Claude side with: vigil-hub setup --mcp --uninstall"
                    ),
                    Lang::Zh => eprintln!(
                        "  Claude 侧已应用。修好 ~/.codex/config.toml 后重跑;或撤销 Claude 侧:\
                         vigil-hub setup --mcp --uninstall"
                    ),
                }
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// 运行一个 JSON-agent 接入面(Cursor / Windsurf)的一步并**诚实处理半应用状态**(同 [`run_codex_leg`])。
/// 成功 → 打印报告,返回 `prior_code`(保留前面 leg 可能的 FAILURE);失败 → 打印该 agent 步失败 +
/// 恢复指引(其它 agent 面互不影响),返回 FAILURE。`prior_code` 链式传递 → 任一 leg 失败则总退出码 FAILURE。
fn run_json_agent_leg(
    lang: Lang,
    res: Result<setup_mcp::JsonAgentApplyReport, setup::SetupError>,
    agent_name: &str,
    op: &str,
    prior_code: std::process::ExitCode,
) -> std::process::ExitCode {
    match res {
        Ok(r) => {
            print_json_agent_apply(lang, &r, op);
            prior_code
        }
        Err(e) => {
            match lang {
                Lang::En => {
                    eprintln!(
                        "  [{agent_name}] the {op} step FAILED (other agent surfaces unaffected): {e}"
                    );
                    eprintln!("  Fix {agent_name}'s MCP config, then re-run the same command.");
                }
                Lang::Zh => {
                    eprintln!("  [{agent_name}] {op} 步失败(其它 agent 接入面不受影响):{e}");
                    eprintln!("  修好 {agent_name} 的 MCP 配置后,重跑同一命令。");
                }
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// `vigil-hub checkpoint`(ADR 0020):锚定当前审计链头到 append-only sidecar(`<ledger>.checkpoints`)。
fn run_checkpoint(lang: Lang, ledger: Option<PathBuf>) -> std::process::ExitCode {
    let Some(path) = ledger.or_else(setup::default_ledger_path) else {
        eprintln!(
            "vigil-hub checkpoint: {}",
            i18n::t(lang, i18n::Msg::LedgerNotFound)
        );
        return std::process::ExitCode::FAILURE;
    };
    let ledger = match vigil_audit::Ledger::open(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "vigil-hub checkpoint: {}",
                i18n::t(
                    lang,
                    i18n::Msg::LedgerOpenFailed {
                        error: &e.to_string(),
                    },
                )
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let log = vigil_audit::CheckpointLog::sidecar_for(&path);
    match log.emit(&ledger) {
        Ok(Some(cp)) => {
            // event_hash 必为 64-hex,取前 12 仅作展示。
            let head = cp.event_hash.get(..12).unwrap_or(&cp.event_hash);
            println!(
                "{}",
                i18n::t(
                    lang,
                    i18n::Msg::CheckpointAnchored {
                        event_id: cp.event_id,
                        head,
                        path: &log.path().display().to_string(),
                    },
                )
            );
            eprintln!("{}", i18n::t(lang, i18n::Msg::CheckpointTip));
            std::process::ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("{}", i18n::t(lang, i18n::Msg::CheckpointNothing));
            std::process::ExitCode::SUCCESS
        }
        Err(e) => fail_cmd(lang, "checkpoint", e),
    }
}

/// `vigil-hub verify`(ADR 0020):链内一致性(防篡断裂)+ checkpoint 锚点(防整链重写),三态如实输出。
/// 任何检出的篡改/损坏 → 非零退出(可脚本化);Verified / Unanchored → 0。
fn run_verify(lang: Lang, ledger: Option<PathBuf>) -> std::process::ExitCode {
    let Some(path) = ledger.or_else(setup::default_ledger_path) else {
        eprintln!(
            "vigil-hub verify: {}",
            i18n::t(lang, i18n::Msg::LedgerNotFound)
        );
        return std::process::ExitCode::FAILURE;
    };
    // verify 是**只读**审计:账本不存在时诚实报告且**绝不创建**。否则 `Ledger::open` 的 create-if-missing
    // 会在 typo 的路径上凭空生成一个空账本,再误报"✓ chain internally valid"——给虚假安全感(把"查了个
    // 不存在的账本"伪装成"审计有效"),还污染文件系统。存在性检查先于 open。
    if !path.exists() {
        eprintln!(
            "vigil-hub verify: {}",
            i18n::t(
                lang,
                i18n::Msg::LedgerMissingForVerify {
                    path: &path.display().to_string(),
                },
            )
        );
        return std::process::ExitCode::FAILURE;
    }
    let ledger = match vigil_audit::Ledger::open(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "vigil-hub verify: {}",
                i18n::t(
                    lang,
                    i18n::Msg::LedgerOpenFailed {
                        error: &e.to_string(),
                    },
                )
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let log = vigil_audit::CheckpointLog::sidecar_for(&path);
    match log.verify_anchored(&ledger) {
        Ok(vigil_audit::Anchored::Verified {
            checkpoints,
            through_event_id,
        }) => {
            println!(
                "{}",
                i18n::t(
                    lang,
                    i18n::Msg::VerifyValidAnchored {
                        checkpoints,
                        through: through_event_id,
                    },
                )
            );
            // 诚实框定(ADR §3):不冒充 tamper-proof。
            println!("{}", i18n::t(lang, i18n::Msg::VerifyAnchorNote));
            std::process::ExitCode::SUCCESS
        }
        Ok(vigil_audit::Anchored::Unanchored) => {
            println!("{}", i18n::t(lang, i18n::Msg::VerifyValidUnanchored));
            println!("{}", i18n::t(lang, i18n::Msg::VerifyRunCheckpointHint));
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            match &e {
                vigil_audit::AuditError::ChainBroken { event_id } => eprintln!(
                    "{}",
                    i18n::t(
                        lang,
                        i18n::Msg::VerifyChainBroken {
                            event_id: *event_id,
                        },
                    )
                ),
                vigil_audit::AuditError::CheckpointMismatch { event_id } => eprintln!(
                    "{}",
                    i18n::t(
                        lang,
                        i18n::Msg::VerifyCheckpointMismatch {
                            event_id: *event_id,
                        },
                    )
                ),
                vigil_audit::AuditError::CheckpointStoreCorrupt { reason } => eprintln!(
                    "{}",
                    i18n::t(
                        lang,
                        i18n::Msg::VerifyStoreCorrupt {
                            reason: reason.as_str(),
                        },
                    )
                ),
                other => eprintln!(
                    "{}",
                    i18n::t(
                        lang,
                        i18n::Msg::CommandFailed {
                            command: "verify",
                            error: &other.to_string(),
                        },
                    )
                ),
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// 构造 α2 注入配置(`vigil-hub hook --inject`)。
///
/// - `inject=false` → `None`:不注入,占位符落三档姿态决策(默认,无行为回归)。
/// - `inject=true` → `Some`:真值后端固定 [`KeyringSecretStore`](service `"vigil"`,与
///   `serve`/`add-remote-mcp` 同一 keychain 命名空间);alias→secret_ref 映射从 `secrets_path`
///   的 JSON 对象加载。**fail-closed 误配语义**:文件缺失/读失败/非对象/值非字符串一律降级为
///   **空映射**(enabled 仍 true)—— 任何 `secret://<alias>` 都成"未声明"→ hook deny,把误配
///   响亮暴露,绝不静默放过未解析占位符。映射文件**只含 alias→ref,不含真值**(真值在 keychain)。
fn build_injection_config(
    inject: bool,
    secrets_path: Option<&std::path::Path>,
    ttl_secs: i64,
) -> Option<hook::InjectionConfig> {
    use std::collections::HashMap;
    use std::sync::Arc;

    if !inject {
        return None;
    }

    // 加载 alias→secret_ref 映射(best-effort;任何异常 → 空映射 + 警告,fail-closed deny)。
    let mut secrets: HashMap<String, String> = HashMap::new();
    if let Some(path) = secrets_path {
        match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(serde_json::Value::Object(map)) => {
                    for (alias, v) in map {
                        match v.as_str() {
                            Some(secret_ref) => {
                                secrets.insert(alias, secret_ref.to_string());
                            }
                            // 值非字符串 = 形状不符;跳过该条(该 alias 注入时会 fail-closed deny)。
                            None => eprintln!(
                                "vigil-hook: secrets entry `{alias}` is not a string secret_ref; ignored"
                            ),
                        }
                    }
                }
                Ok(_) => eprintln!(
                    "vigil-hook: secrets file is not a JSON object; injection will deny all aliases (fail-closed)"
                ),
                Err(e) => eprintln!(
                    "vigil-hook: secrets file parse failed ({e}); injection will deny all aliases (fail-closed)"
                ),
            },
            Err(e) => eprintln!(
                "vigil-hook: secrets file read failed ({e}); injection will deny all aliases (fail-closed)"
            ),
        }
    } else {
        eprintln!(
            "vigil-hook: --inject set without --secrets; injection will deny all aliases (fail-closed)"
        );
    }

    // 真值后端:OS Keychain(service "vigil",与 serve/add-remote-mcp 同命名空间)。
    let store: Arc<dyn vigil_lease::SecretStore> =
        Arc::new(vigil_lease::KeyringSecretStore::new("vigil"));

    Some(hook::InjectionConfig {
        enabled: true,
        secrets,
        store,
        ttl_secs,
    })
}

/// `setup --all`:一条命令同时接入 hook + MCP 网关 wrap(兑现 download→直接保护)。
/// `--uninstall` 撤销两者;`--dry-run` 预览两者;MCP 侧默认 monitor(`--enforce` 升级硬拦)。
fn run_setup_all(
    lang: Lang,
    args: &CliSetupArgs,
) -> Result<std::process::ExitCode, setup::SetupError> {
    let home = dirs::home_dir().ok_or(setup::SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe().map_err(|_| setup::SetupError::MissingCurrentExe)?;
    // ledger:`--ledger` 覆盖 → 否则默认(`VIGIL_LEDGER_PATH` / `<data 目录>/Vigil/ledger.sqlite3`)。
    let ledger = args
        .ledger
        .clone()
        .or_else(setup::default_ledger_path)
        .ok_or(setup::SetupError::MissingDataDir)?;
    let monitor = !args.enforce;
    let op = if args.uninstall {
        "uninstall"
    } else if args.dry_run {
        "preview"
    } else {
        "apply"
    };
    match setup_mcp::run_all_with(
        &home,
        &exe,
        &ledger,
        args.uninstall,
        args.dry_run,
        args.user_scope_only,
        monitor,
    ) {
        Ok((hook_rep, mcp_rep)) => {
            let mut code = print_setup_all(lang, &hook_rep, &mcp_rep, op);
            // 其余接入面:Codex + Cursor + Windsurf。各独立文件,hook + Claude-MCP 成功后逐一做;失败经
            // `run_*_leg` **诚实半应用报告**(不回滚已应用面 —— 各面独立、各自可逆)。op 在 dry-run 时为
            // "preview";各步只认 apply/uninstall(dry 措辞由报告里 dry_run 决定)。
            let exe_str = exe.to_string_lossy().to_string();
            let mcp_op = if args.uninstall { "uninstall" } else { "apply" };
            let codex_res = if args.uninstall {
                setup_mcp::run_codex_uninstall(&home, args.dry_run)
            } else {
                setup_mcp::run_codex_apply(&home, &exe_str, args.dry_run, monitor)
            };
            code = run_codex_leg(lang, codex_res, mcp_op, code);
            for agent in json_mcp_agents(&home) {
                let res = if args.uninstall {
                    setup_mcp::run_json_agent_uninstall(&agent, args.dry_run)
                } else {
                    setup_mcp::run_json_agent_apply(&agent, &exe_str, args.dry_run, monitor)
                };
                code = run_json_agent_leg(lang, res, agent.display_name, mcp_op, code);
            }
            // 其余 agent CLI 的 hook 注册面(Codex/Gemini/Cursor 原生工具输入侧守门),
            // 与上面 MCP wrap 面正交(hook 拦原生工具,wrap 管 MCP server)。
            let hook_op = if args.uninstall {
                setup_hooks::AgentHookOp::Uninstall {
                    dry_run: args.dry_run,
                }
            } else {
                setup_hooks::AgentHookOp::Install {
                    dry_run: args.dry_run,
                }
            };
            code = run_agent_hook_legs(lang, &ledger, hook_op, code);
            Ok(code)
        }
        // hook 步就失败 → 什么都没改(hook 写盘前 gate,失败即未写):诚实"nothing changed"。
        Err(setup_mcp::AllError::Hook(e)) => {
            match lang {
                Lang::En => {
                    eprintln!("vigil-hub setup --all: hook step failed -- nothing was changed: {e}")
                }
                Lang::Zh => {
                    eprintln!("vigil-hub setup --all:第一步(注册 hook)失败 —— 未改动任何配置:{e}")
                }
            }
            Ok(std::process::ExitCode::FAILURE)
        }
        // hook 成功、MCP 步失败 → **半应用**:诚实告知 hook 已应用 + 如何单独撤销(Codex D13 HIGH)。
        Err(setup_mcp::AllError::McpAfterHook { hook, source }) => {
            let did = if op == "uninstall" {
                if hook.changed {
                    tr(lang, "removed", "已移除")
                } else {
                    tr(lang, "nothing to remove", "无需移除")
                }
            } else if hook.changed {
                tr(lang, "applied", "已应用")
            } else {
                tr(lang, "already up to date", "已是最新")
            };
            let hook_label = tr(
                lang,
                "hook (PreToolUse input-secret guard)",
                "hook(PreToolUse 输入侧密钥守卫)",
            );
            match lang {
                Lang::En => println!(
                    "Vigil setup --all --{op}: PARTIAL (the hook step completed, the MCP step did not)"
                ),
                Lang::Zh => println!(
                    "Vigil setup --all --{op}:只完成了一半(原生 hook 已装好,MCP 网关未装上 —— 当前仅 hook 在生效)"
                ),
            }
            println!("  [1/2] {hook_label}: {did}");
            match lang {
                Lang::En => eprintln!("  [2/2] MCP gateway step FAILED: {source}"),
                Lang::Zh => eprintln!("  [2/2] MCP 网关这一步失败:{source}"),
            }
            if op == "uninstall" {
                // 不声称"hook 已移除"(若 changed=false 则本就没东西可移除,会过度陈述;Codex D13 R2 nit)。
                match lang {
                    Lang::En => eprintln!("  The hook step completed (see above); MCP wrap entries may remain. Retry: vigil-hub setup --mcp --uninstall"),
                    Lang::Zh => eprintln!("  hook 这一步已完成(见上);MCP wrap 条目可能仍在。重试:vigil-hub setup --mcp --uninstall"),
                }
            } else {
                match lang {
                    Lang::En => {
                        eprintln!("  The hook above IS applied. Undo just the hook with: vigil-hub setup --uninstall");
                        eprintln!("  (or fix the cause and re-run: vigil-hub setup --all)");
                    }
                    Lang::Zh => {
                        eprintln!("  上面的 hook 已应用。仅撤销 hook:vigil-hub setup --uninstall");
                        eprintln!("  (或修复原因后重跑:vigil-hub setup --all)");
                    }
                }
            }
            Ok(std::process::ExitCode::FAILURE)
        }
    }
}

/// 其余 agent CLI 的 hook 注册面(Codex/Gemini/Cursor):逐面执行 + 诚实打印。单面失败不
/// 中断其它面(各面独立文件、各自可逆),但最终退出码降级 FAILURE(诚实半应用,同 `run_codex_leg`
/// 模式)。未检测到的 agent 一行说明后跳过,不为不存在的 agent 创建配置。
fn run_agent_hook_legs(
    lang: Lang,
    ledger: &std::path::Path,
    op: setup_hooks::AgentHookOp,
    mut code: std::process::ExitCode,
) -> std::process::ExitCode {
    let (home, exe) = match (dirs::home_dir(), std::env::current_exe()) {
        (Some(h), Ok(e)) => (h, e),
        // Claude 面能跑到这里说明 home/exe 可解析;此分支仅防御性兜底。
        _ => {
            eprintln!("  agent hooks: cannot resolve home/exe; skipped");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!();
    println!(
        "{}",
        tr(
            lang,
            "Other agent CLIs (hook registration):",
            "其它 agent CLI(hook 注册):",
        )
    );
    for spec in setup_hooks::all_agent_specs(&home) {
        let display = spec.display_name;
        match setup_hooks::run_agent_hook(&spec, &exe, ledger, op) {
            Ok(rep) => {
                if !rep.detected {
                    println!(
                        "  {display}: {}",
                        tr(lang, "not detected -- skipped", "未检测到 —— 已跳过")
                    );
                    continue;
                }
                use setup::ProtectionState;
                let verdict = match op {
                    setup_hooks::AgentHookOp::Status => match rep.state {
                        ProtectionState::Active => tr(lang, "ACTIVE", "已激活(ACTIVE)").to_string(),
                        ProtectionState::Stale => tr(
                            lang,
                            "INSTALLED but STALE (re-run `vigil-hub setup` to refresh)",
                            "已安装但已失效(重跑 `vigil-hub setup` 刷新)",
                        )
                        .to_string(),
                        // 「hook 未注册」而非「未安装」—— 本段说的是 Vigil hook 的注册态;
                        // 「未安装」会被读成"该 agent CLI 没装"(F-5:机器上明明装着 Codex)。
                        ProtectionState::NotInstalled => {
                            tr(lang, "hook not registered", "hook 未注册").to_string()
                        }
                    },
                    setup_hooks::AgentHookOp::Install { dry_run } => {
                        let did = if !rep.changed {
                            tr(lang, "already up to date", "已是最新")
                        } else if dry_run {
                            tr(
                                lang,
                                "[dry-run] would register hook",
                                "[dry-run] 将注册 hook",
                            )
                        } else {
                            tr(lang, "hook registered", "已注册 hook")
                        };
                        format!("{did} ({})", rep.config_path.display())
                    }
                    setup_hooks::AgentHookOp::Uninstall { dry_run } => {
                        let did = if !rep.changed {
                            tr(lang, "nothing to remove", "无需移除")
                        } else if dry_run {
                            tr(
                                lang,
                                "[dry-run] would remove Vigil hook",
                                "[dry-run] 将移除 Vigil hook",
                            )
                        } else {
                            tr(lang, "Vigil hook removed", "已移除 Vigil hook")
                        };
                        format!("{did} ({})", rep.config_path.display())
                    }
                };
                println!("  {display}: {verdict}");
                for w in &rep.warnings {
                    println!("    {}{w}", tr(lang, "WARNING: ", "警告:"));
                }
            }
            Err(e) => {
                // 单面失败:诚实报告 + 继续其它面(各面独立);退出码降级让脚本可感知。
                eprintln!("  {display}: {} {e}", tr(lang, "FAILED --", "失败 ——"));
                code = std::process::ExitCode::FAILURE;
            }
        }
    }
    code
}

/// 打印 `setup --all` 合并报告(ASCII-safe)。两段(hook / mcp)各自诚实陈述 + 末尾下一步。
fn print_setup_all(
    lang: Lang,
    hook: &setup::SetupReport,
    mcp: &setup_mcp::McpApplyReport,
    op: &str,
) -> std::process::ExitCode {
    let dry = if hook.dry_run { " (dry-run)" } else { "" };
    match lang {
        Lang::En => {
            println!("Vigil setup --all --{op}{dry}: native-tool hook + MCP gateway in one step")
        }
        Lang::Zh => {
            println!("Vigil setup --all --{op}{dry}:原生工具 hook + MCP 网关一步到位")
        }
    }

    // [1/2] hook(原生工具输入侧 secret 拦截)
    let hook_label = tr(
        lang,
        "hook (PreToolUse input-secret guard)",
        "hook(PreToolUse 输入侧密钥守卫)",
    );
    if !hook.claude_detected {
        match lang {
            Lang::En => println!(
                "  [1/2] hook: Claude Code not detected (claude not on PATH; neither ~/.claude nor ~/.claude.json found) -- hook step skipped"
            ),
            Lang::Zh => println!(
                "  [1/2] hook:未检测到 Claude Code(claude 不在 PATH;~/.claude 与 ~/.claude.json 都不存在)—— 跳过 hook 步"
            ),
        }
    } else if op == "uninstall" {
        let did = if hook.changed {
            tr(lang, "removed", "已移除")
        } else {
            tr(lang, "nothing to remove", "无需移除")
        };
        println!("  [1/2] {hook_label}: {did}");
    } else {
        let did = if hook.changed {
            tr(lang, "registered", "已注册")
        } else {
            tr(lang, "already up to date", "已是最新")
        };
        println!("  [1/2] {hook_label}: {did}");
    }

    // [2/2] MCP 网关 wrap(脱敏 + 审计 + 审批 + descriptor pin)。
    // 标注 scope(Claude Code):本计数只含 Claude 的 user+local server;Codex/Cursor/Windsurf
    // 各有独立段落 —— 不标注会让用户误以为这就是全局总数(F-6:真机 22 个被读成 1 个)。
    let total = mcp.total_changed();
    match lang {
        Lang::En => {
            let verb = if op == "uninstall" {
                "restored"
            } else {
                "wrapped"
            };
            println!("  [2/2] MCP gateway (Claude Code): {verb} {total} server(s); other agents follow below");
        }
        Lang::Zh => {
            let verb = if op == "uninstall" {
                "已还原"
            } else {
                "已防护"
            };
            println!("  [2/2] MCP 网关(Claude Code):{verb} {total} 个服务器;其它 agent 见下方各段");
        }
    }
    if mcp.local_skipped > 0 {
        match lang {
            Lang::En => println!(
                "        NOTE: {} local-scope server(s) left unprotected (--user-scope-only).",
                mcp.local_skipped
            ),
            Lang::Zh => println!(
                "        注意:有 {} 个项目级(local scope)服务器未受保护(--user-scope-only)。",
                mcp.local_skipped
            ),
        }
    }

    // 下一步 / 撤销
    println!();
    if op == "preview" {
        println!(
            "  {}",
            tr(
                lang,
                "Preview only -- nothing written. Apply with: vigil-hub setup --all",
                "仅预览 —— 未写任何东西。应用:vigil-hub setup --all",
            )
        );
    } else if op == "uninstall" {
        println!(
            "  {}",
            tr(
                lang,
                "Vigil protection removed (hook + MCP gateway). Restart your agent.",
                "已移除 Vigil 防护(hook + MCP 网关)。请重启你的 agent。",
            )
        );
    } else {
        match lang {
            Lang::En => {
                println!(
                    "  Protected. Restart your agent to activate. Confirm: vigil-hub setup --status  ·  See what Vigil catches: vigil-hub demo"
                );
                println!("  Undo everything with: vigil-hub setup --all --uninstall");
            }
            Lang::Zh => {
                println!(
                    "  已保护。重启 agent 使其生效。确认:vigil-hub setup --status  ·  看 Vigil 能拦什么:vigil-hub demo"
                );
                println!("  全部撤销:vigil-hub setup --all --uninstall");
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

/// 打印 `setup --mcp --doctor` 健壮性预检结果(ASCII-safe,cp936/cp437 不乱码)。返回退出码:
/// 有任一 server 起不来(ProgramNotFound/Malformed)→ 退出码 1(脚本可据此判失败);否则 0。
///
/// **truth-in-labeling**(Codex D12 nit):解析用**本进程当前 PATH**,= 网关 spawn 时同款 `resolve_program`
/// (SSOT);但若 agent 启动 `vigil-hub wrap` 的 PATH 与此不同,verdict 可能偏差 → 文案明示"在本环境"。
/// **hygiene**(Codex D12 nit):所有展示字段(name/scope/program/resolved)过 `scrub_text` 再输出 ——
/// argv[0]/路径通常无 secret,但纵深防御统一遵守"绝不把可能含敏感串的值原样进 UI/日志"(与 preview 一致)。
fn print_mcp_doctor(lang: Lang, rows: &[setup_mcp::McpDoctorRow]) -> std::process::ExitCode {
    use setup_mcp::{DoctorStatus, ProbeOutcome};
    let scrub = vigil_redaction::scrub_text;
    // 是否处于深度探测档(任一行带 probe 结果)—— 决定表头/表尾措辞与失败语义。
    let probing = rows.iter().any(|r| r.probe.is_some());
    match lang {
        Lang::En => {
            println!("Vigil setup --mcp --doctor: can each MCP server's program be launched in THIS environment?");
            println!("  (resolves argv[0] in the current PATH, exactly as the gateway does at spawn time)");
        }
        Lang::Zh => {
            println!("Vigil setup --mcp --doctor:每个 MCP 服务器的程序在**当前环境**能否启动?");
            println!(
                "  (按当前 PATH 查找每个服务器的启动命令,和 Vigil 实际拉起它们时的查找方式一致)"
            );
        }
    }
    if probing {
        // Codex D18 R2 Low:probe 会真执行每个 server 的启动代码 —— 在动手前明确告知(非仅 help 文案)。
        match lang {
            Lang::En => {
                println!("  --probe: WARNING — this briefly STARTS each configured server (runs its startup code)");
                println!("           to complete a real MCP initialize handshake, then stops it. Direct child is killed;");
                println!("           a misbehaving npx/uvx grandchild may survive briefly.");
            }
            Lang::Zh => {
                println!("  --probe:警告 —— 这会短暂启动每个已配置的服务器(执行其启动代码)");
                println!(
                    "           以完成一次真实的 MCP initialize 握手,随后停止它。直接子进程会被杀;"
                );
                println!("           行为异常的 npx/uvx 孙进程可能短暂存活。");
            }
        }
    }
    if rows.is_empty() {
        println!(
            "  {}",
            tr(
                lang,
                "No MCP servers found across Claude / Codex / Cursor / Windsurf (nothing to check).",
                "Claude / Codex / Cursor / Windsurf 均未找到 MCP 服务器(无需检查)。",
            )
        );
        return std::process::ExitCode::SUCCESS;
    }
    let mut failed = 0usize;
    for r in rows {
        // scope 标注:Claude user / Claude 项目路径(local) / 其它 agent(Codex/Cursor/Windsurf)。
        // 三个 agent 名是本程序固定字面量(非用户输入),据此与 Claude 的 user/local-path 区分。wrapped
        // 标注是否已受 Vigil 保护。全部过 scrub。
        let name = scrub(&r.name);
        let scope = match r.scope.as_str() {
            "user" => "user".to_string(),
            "Codex" | "Cursor" | "Windsurf" => r.scope.clone(),
            other => format!("local:{}", scrub(other)),
        };
        let guard = if r.wrapped { " [vigil-wrapped]" } else { "" };
        match &r.status {
            DoctorStatus::Launchable { program, resolved } => {
                println!(
                    "  [OK]   {name} ({scope}){guard}: {} -> {}",
                    scrub(program),
                    scrub(resolved)
                );
                // 深度探测结果(--probe):静态可解析但运行时起不来 = 真失败(agent 会零工具)。
                match &r.probe {
                    // 措辞:probe 验的是**底层 server** 能起 + 说 MCP;对 vigil-wrapped 条目,真实
                    // 网关启动还会额外强制 descriptor drift gate,故不等同"agent 一定见到工具"(Codex R2 M3)。
                    Some(ProbeOutcome::Initialized) => match lang {
                        Lang::En => println!("           probe: the underlying server initialized OK (started + MCP handshake succeeded)"),
                        Lang::Zh => println!("           probe:底层服务器初始化成功(已启动 + MCP 握手成功)"),
                    },
                    Some(ProbeOutcome::Failed { reason }) => {
                        failed += 1;
                        // reason 已在 setup_mcp 侧 value-aware 脱敏 + scrub;此处直接展示。
                        match lang {
                            Lang::En => {
                                println!("           probe: FAILED to initialize: {reason}");
                                println!("           -> the program runs but did not complete an MCP handshake; your agent will see no tools from it.");
                                println!("           -> if it's an npx/uvx server on first run, packages may still be downloading; re-run --probe once warm.");
                            }
                            Lang::Zh => {
                                println!("           probe:初始化失败:{reason}");
                                println!("           -> 程序能跑,但没完成 MCP 握手;你的 agent 会看不到它的任何工具。");
                                println!("           -> 若是首次运行的 npx/uvx 服务器,包可能还在下载;暖缓存后重跑 --probe。");
                            }
                        }
                    }
                    None => {}
                }
            }
            DoctorStatus::ProgramNotFound { program } => {
                failed += 1;
                match lang {
                    Lang::En => println!(
                        "  [FAIL] {name} ({scope}){guard}: program `{}` not found in PATH",
                        scrub(program)
                    ),
                    Lang::Zh => println!(
                        "  [FAIL] {name} ({scope}){guard}:程序 `{}` 不在 PATH 中",
                        scrub(program)
                    ),
                }
                // 可操作提示:最常见两类运行时。
                let hint = match (lang, program.as_str()) {
                    (Lang::En, "npx" | "node") => {
                        "  -> install Node.js (npx/node), then restart your agent"
                    }
                    (Lang::En, "uvx" | "uv") => "  -> install uv (uvx/uv), then restart your agent",
                    (Lang::En, _) => {
                        "  -> install this program or fix its PATH, then restart your agent"
                    }
                    (Lang::Zh, "npx" | "node") => "  -> 安装 Node.js(npx/node),然后重启你的 agent",
                    (Lang::Zh, "uvx" | "uv") => "  -> 安装 uv(uvx/uv),然后重启你的 agent",
                    (Lang::Zh, _) => "  -> 安装该程序或修好它的 PATH,然后重启你的 agent",
                };
                println!("{hint}");
            }
            DoctorStatus::Skipped { reason } => {
                // reason 可能含路径(如配置错误行)→ scrub(secrets 绝不进 UI;Codex D29 #5)。
                println!("  [skip] {name} ({scope}): {}", scrub(reason));
            }
            DoctorStatus::Malformed => {
                failed += 1;
                match lang {
                    Lang::En => println!(
                        "  [FAIL] {name} ({scope}){guard}: Vigil-managed entry is malformed (cannot determine the underlying program)"
                    ),
                    Lang::Zh => println!(
                        "  [FAIL] {name} ({scope}){guard}:Vigil 托管条目格式损坏(无法确定底层程序)"
                    ),
                }
            }
            // 整个 agent 配置坏了(malformed / 读不了)→ 计入失败(server 可能存在却对 doctor 不可见;
            // doctor 不能因此谎称"全部正常")。reason 含路径 → scrub(Codex D29 #5/#6/#8)。
            DoctorStatus::ConfigError { reason } => {
                failed += 1;
                println!("  [FAIL] {name} ({scope}): {}", scrub(reason));
            }
        }
    }
    println!();
    if failed == 0 {
        match lang {
            Lang::En => {
                if probing {
                    println!("  All checked servers resolve AND their underlying program completes an MCP handshake here.");
                    println!("  (probe checks the underlying server; for vigil-wrapped entries the live gateway also enforces descriptor drift.)");
                } else {
                    println!("  All checked servers resolve in this environment.");
                }
                println!(
                    "  Note: your agent must launch vigil-hub with the same PATH for this to hold."
                );
            }
            Lang::Zh => {
                if probing {
                    println!("  所有被检查的服务器都能解析,且其底层程序在此都能完成 MCP 握手。");
                    println!("  (probe 验的是底层服务器;对 vigil-wrapped 条目,真实网关启动还会强制 descriptor drift。)");
                } else {
                    println!("  所有被检查的服务器在此环境都能解析。");
                }
                println!("  注意:你的 agent 必须用相同的 PATH 启动 vigil-hub,本结论才成立。");
            }
        }
        std::process::ExitCode::SUCCESS
    } else {
        match lang {
            Lang::En => {
                let what = if probing {
                    "will not start / initialize"
                } else {
                    "will not start"
                };
                println!(
                    "  {failed} server(s) {what} in this environment. Fix the above, then re-run --doctor."
                );
            }
            Lang::Zh => {
                let what = if probing {
                    "无法启动 / 初始化"
                } else {
                    "无法启动"
                };
                println!("  有 {failed} 个服务器在此环境{what}。修好上面的问题后,重跑 --doctor。");
            }
        }
        std::process::ExitCode::from(1)
    }
}

/// 打印 `setup --mcp --apply/--uninstall` 结果(ASCII-safe)。
fn print_mcp_apply(lang: Lang, r: &setup_mcp::McpApplyReport, op: &str) -> std::process::ExitCode {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = match (lang, r.dry_run) {
        (Lang::En, true) => "would",
        (Lang::En, false) => "did",
        (Lang::Zh, true) => "将",
        (Lang::Zh, false) => "已",
    };
    let what = match (lang, op == "uninstall") {
        (Lang::En, true) => "restore",
        (Lang::En, false) => "wrap",
        (Lang::Zh, true) => "还原",
        (Lang::Zh, false) => "防护",
    };
    let total = r.total_changed();
    // 「改动写入配置文件」只在真写盘时声称(0 改动 / dry-run 未写文件,措辞失实 = F-6c)。
    let wrote = total > 0 && !r.dry_run;
    match lang {
        Lang::En => println!(
            "Vigil setup --mcp --{op}{dry}: {verb} {what} {total} MCP server(s){}",
            if wrote {
                format!(" in {}", r.claude_json.display())
            } else {
                format!(" ({} untouched)", r.claude_json.display())
            }
        ),
        Lang::Zh => println!(
            "Vigil setup --mcp --{op}{dry}:{verb}{what} {total} 个 MCP 服务器{}",
            if wrote {
                format!(",改动写入配置文件 {}", r.claude_json.display())
            } else {
                format!("(配置文件 {} 未改动)", r.claude_json.display())
            }
        ),
    }
    // 分 scope 报告:local scope(projects.*)用**项目限定 server-id**(跨项目同名不串账本)。
    if r.local_changed > 0 {
        match lang {
            Lang::En => println!(
                "  ({} user-scope + {} local-scope/per-project)",
                r.changed, r.local_changed
            ),
            Lang::Zh => println!(
                "  (其中 {} 个用户级、{} 个项目级)",
                r.changed, r.local_changed
            ),
        }
    }
    if let Some(b) = &r.backup {
        println!(
            "  {}{}",
            tr(lang, "backup of the previous config: ", "原配置备份:"),
            b.display()
        );
    }
    if total == 0 && !r.dry_run {
        match lang {
            Lang::En => println!("  (nothing to {what} -- no matching servers)"),
            Lang::Zh => println!("  (无需{what} —— 无匹配服务器)"),
        }
    }
    // `--user-scope-only` 跳过了可保护的 local scope server → 诚实提示它们仍未受保护。
    if r.local_skipped > 0 {
        match lang {
            Lang::En => println!(
                "  NOTE: {} local-scope (per-project) MCP server(s) left UNPROTECTED (--user-scope-only).",
                r.local_skipped
            ),
            Lang::Zh => println!(
                "  注意:有 {} 个项目级(local scope)MCP 服务器未受保护(--user-scope-only)。",
                r.local_skipped
            ),
        }
    }
    if op == "apply" && total > 0 && !r.dry_run {
        println!(
            "  {}",
            tr(
                lang,
                "Restart Claude Code to pick up the change. Undo with: vigil-hub setup --mcp --uninstall",
                "重启 Claude Code 使改动生效。撤销:vigil-hub setup --mcp --uninstall",
            )
        );
    }
    std::process::ExitCode::SUCCESS
}

/// 打印 `setup --mcp` 只读预览(ASCII-safe,cp936/cp437 不乱码)。返回退出码。
/// 渲染单个 server 分类的预览行(user / local / Codex scope 各调一次)。`derive_id` 由调用方注入
/// scope 专属的 server-id 派生(user-/local-/codex-,disjoint 命名空间),让 WRAP 渲染逻辑单一真源。
fn print_mcp_server_preview(
    lang: Lang,
    exe: &str,
    derive_id: impl Fn(&str) -> String,
    class: &McpServerClass,
    monitor: bool,
) {
    match class {
        McpServerClass::Wrappable {
            name,
            command,
            args,
            env_keys,
        } => {
            // server-id 由调用方注入的 scope 派生器产出(各 scope 加 disjoint 前缀防身份塌缩)。
            let wrap_id = derive_id(name);
            let argv = setup_mcp::wrapped_argv(exe, &wrap_id, command, args, env_keys, monitor);
            println!("  [WRAP] {name}");
            // 预览里的 command/args 可能含用户内联的 token(如 `--api-key sk-...`)。过硬指纹 scrub
            // 再展示,守"secrets 绝不进 UI/日志"不变量(Codex setup_mcp review hygiene)。
            let from_disp = vigil_redaction::scrub_text(&format!("{} {}", command, args.join(" ")));
            let to_disp = vigil_redaction::scrub_text(&argv.join(" "));
            println!("         {}{from_disp}", tr(lang, "from: ", "原: "));
            println!("         {}{to_disp}", tr(lang, "to:   ", "改: "));
            if !env_keys.is_empty() {
                println!(
                    "         {}{}",
                    tr(
                        lang,
                        "env (key-only, values never copied): ",
                        "env(仅键名,绝不复制值):",
                    ),
                    env_keys.join(", ")
                );
            }
        }
        McpServerClass::AlreadyWrapped { name } => {
            println!(
                "  [OK]   {name} {}",
                tr(
                    lang,
                    "-- already Vigil-managed (skipped)",
                    "—— 已是 Vigil 托管(跳过)",
                )
            );
        }
        McpServerClass::Skipped { name, reason } => {
            // reason 是 setup_mcp 产出的英文分类码;zh 输出按已知前缀映射中文,未知则原样
            // (F-4:英文整句混进中文预览)。
            match lang {
                Lang::En => println!("  [SKIP] {name} -- {reason}"),
                Lang::Zh => println!("  [SKIP] {name} —— {}", skip_reason_zh(reason)),
            }
        }
    }
}

/// 把 `setup_mcp` 的英文 Skip 分类码按**稳定前缀**映射为中文(未知原样返回,fail-open 到英文)。
/// 分类码是 `&'static str` 且仅在 setup_mcp 内定义 —— 前缀匹配足够稳,免为文案引入枚举 ripple。
fn skip_reason_zh(reason: &str) -> String {
    const MAP: &[(&str, &str)] = &[
        (
            "appears already wrapped under a wrapper prefix",
            "疑似已被 wrapper 前缀(stdbuf/sh/env…)包裹 —— 跳过,避免嵌套",
        ),
        (
            "Vigil's own server/gateway entry",
            "Vigil 自身的 server/网关条目 —— 绝不包裹(会自我嵌套)",
        ),
        (
            "remote (http/sse) server",
            "远程(http/sse)server —— HTTP MCP 的包裹在后续版本支持",
        ),
        (
            "non-stdio or malformed `type`",
            "非 stdio 或 `type` 字段异常 —— 当前版本不包裹",
        ),
        (
            "`args` is present but not an array",
            "`args` 存在但不是数组(形状异常)—— 原样未动",
        ),
        (
            "entry has no `command`",
            "条目缺 `command`(形状异常)—— 原样未动",
        ),
        (
            "`args` has a non-string element",
            "`args` 含非字符串元素(形状异常)—— 原样未动",
        ),
        (
            "`command` is a single shell string with quotes",
            "`command` 是含引号的单条 shell 字符串;请在 MCP 配置里拆成 `command` + `args` 数组后再保护",
        ),
        (
            "single-string `command` is itself a vigil-hub invocation",
            "单串 `command` 本身就是一次 vigil-hub 调用 —— 跳过,避免二次包裹",
        ),
    ];
    for (prefix, zh) in MAP {
        if reason.starts_with(prefix) {
            return (*zh).to_string();
        }
    }
    reason.to_string()
}

fn print_mcp_preview(lang: Lang, r: &setup_mcp::McpPreviewReport) -> std::process::ExitCode {
    println!(
        "{}",
        tr(
            lang,
            "Vigil setup --mcp (PREVIEW ONLY -- nothing is changed)",
            "Vigil setup --mcp(仅预览 —— 不改动任何东西)",
        )
    );
    println!(
        "  {}{}",
        tr(lang, "Claude Code config: ", "Claude Code 配置:"),
        r.claude_json.display()
    );
    if !r.exists {
        println!(
            "  {}",
            tr(
                lang,
                "(no ~/.claude.json found -- Claude Code not configured, or no MCP servers yet)",
                "(未找到 ~/.claude.json —— Claude Code 未配置,或尚无 MCP 服务器)",
            )
        );
        return std::process::ExitCode::SUCCESS;
    }
    println!("  vigil-hub: {}", r.exe);
    println!();
    if r.servers.is_empty() && r.local_servers.is_empty() {
        println!(
            "  {}",
            tr(
                lang,
                "No MCP servers found (user scope or per-project local scope).",
                "未找到 MCP 服务器(用户级 user 或各项目本地 local 都没有)。",
            )
        );
        return std::process::ExitCode::SUCCESS;
    }
    // user scope(顶层 mcpServers)
    if !r.servers.is_empty() {
        match lang {
            Lang::En => println!(
                "  User scope (top-level mcpServers) -- {} can be protected:",
                r.wrappable_count()
            ),
            Lang::Zh => println!(
                "  User scope(顶层 mcpServers)—— {} 个可保护:",
                r.wrappable_count()
            ),
        }
        for s in &r.servers {
            print_mcp_server_preview(lang, &r.exe, setup_mcp::user_scope_server_id, s, r.monitor);
        }
    }
    // local scope(projects.<path>.mcpServers)—— claude mcp add 默认写这里
    if !r.local_servers.is_empty() {
        println!();
        match lang {
            Lang::En => {
                println!(
                    "  Local scope (per-project mcpServers) -- {} can be protected:",
                    r.local_wrappable_count()
                );
                println!(
                    "  (wrapped with a project-scoped server-id so same-named servers across projects"
                );
                println!("   don't share audit/approval identity)");
            }
            Lang::Zh => {
                println!(
                    "  Local scope(按项目 mcpServers)—— {} 个可保护:",
                    r.local_wrappable_count()
                );
                println!("  (用项目限定的 server-id 防护,使跨项目的同名服务器");
                println!("   不共享审计 / 审批身份)");
            }
        }
        for (proj, s) in &r.local_servers {
            print_mcp_server_preview(
                lang,
                &r.exe,
                |n| setup_mcp::local_scope_server_id(proj, n),
                s,
                r.monitor,
            );
        }
    }
    println!();
    // 姿态提示反映将落盘的真实姿态(默认 monitor;`--enforce` 升级硬拦)。
    if r.monitor {
        match lang {
            Lang::En => {
                println!(
                    "  Default posture: MONITOR (servers stay usable; result redaction + raw-secret"
                );
                println!(
                    "  block + tamper-evident audit always on; add --enforce for default-deny gating)."
                );
            }
            Lang::Zh => {
                println!("  默认姿态:MONITOR 观察模式(服务器保持可用;结果脱敏 + 明文密钥拦截");
                println!("  + 防篡改审计始终开启;加 --enforce 可改用「默认拒绝放行」的严格模式)。");
            }
        }
    } else {
        match lang {
            Lang::En => {
                println!(
                    "  Posture: ENFORCE (default-deny; third-party tools without known effects are"
                );
                println!(
                    "  blocked -- use only for known/self-built servers). Omit --enforce for monitor."
                );
            }
            Lang::Zh => {
                println!("  姿态:ENFORCE 严格模式(默认拒绝放行;Vigil 识别不出用途的第三方工具会被");
                println!(
                    "  一律拦截 —— 仅建议用于你了解或自建的服务器)。省略 --enforce 即观察模式。"
                );
            }
        }
    }
    match lang {
        Lang::En => println!(
            "  Apply with:  vigil-hub setup --mcp --apply{}",
            if r.monitor { "" } else { " --enforce" }
        ),
        Lang::Zh => println!(
            "  应用:  vigil-hub setup --mcp --apply{}",
            if r.monitor { "" } else { " --enforce" }
        ),
    }
    println!(
        "  {}",
        tr(
            lang,
            "(protects user + local scope; --user-scope-only skips local; --uninstall reverts).",
            "(同时保护用户级与项目级;--user-scope-only 只跳过项目级;--uninstall 还原)。",
        )
    );
    std::process::ExitCode::SUCCESS
}

/// 打印 Codex 接入面只读预览(ASCII-safe)。附在 Claude 预览之后,作为第二个受保护配置面。
/// 复用 [`print_mcp_server_preview`](注入 `codex-` server-id 派生),WRAP 渲染单一真源。
fn print_codex_preview(lang: Lang, r: &setup_mcp::CodexPreviewReport) {
    println!();
    println!(
        "  {}{}",
        tr(lang, "Codex CLI config: ", "Codex CLI 配置:"),
        r.codex_config.display()
    );
    if !r.exists {
        println!(
            "  {}",
            tr(
                lang,
                "(no ~/.codex/config.toml found -- Codex not configured, or no MCP servers yet)",
                "(未找到 ~/.codex/config.toml —— Codex 未配置,或尚无 MCP 服务器)",
            )
        );
        return;
    }
    if r.servers.is_empty() {
        println!(
            "  {}",
            tr(
                lang,
                "No MCP servers found in Codex [mcp_servers].",
                "Codex [mcp_servers] 中未找到 MCP 服务器。",
            )
        );
        return;
    }
    match lang {
        Lang::En => println!(
            "  Codex scope ([mcp_servers]) -- {} can be protected:",
            r.wrappable_count()
        ),
        Lang::Zh => println!(
            "  Codex scope([mcp_servers])—— {} 个可保护:",
            r.wrappable_count()
        ),
    }
    for s in &r.servers {
        print_mcp_server_preview(lang, &r.exe, setup_mcp::codex_scope_server_id, s, r.monitor);
    }
}

/// 打印 Codex 接入面 apply/uninstall 结果(ASCII-safe)。附在 Claude 结果之后。
fn print_codex_apply(lang: Lang, r: &setup_mcp::CodexApplyReport, op: &str) {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = match (lang, r.dry_run) {
        (Lang::En, true) => "would",
        (Lang::En, false) => "did",
        (Lang::Zh, true) => "将",
        (Lang::Zh, false) => "已",
    };
    let what = match (lang, op == "uninstall") {
        (Lang::En, true) => "restore",
        (Lang::En, false) => "wrap",
        (Lang::Zh, true) => "还原",
        (Lang::Zh, false) => "防护",
    };
    let wrote = r.changed > 0 && !r.dry_run;
    match lang {
        Lang::En => println!(
            "Vigil setup --mcp --{op}{dry} (Codex): {verb} {what} {} MCP server(s){}",
            r.changed,
            if wrote {
                format!(" in {}", r.codex_config.display())
            } else {
                format!(" ({} untouched)", r.codex_config.display())
            }
        ),
        Lang::Zh => println!(
            "Vigil setup --mcp --{op}{dry}(Codex):{verb}{what} {} 个 MCP 服务器{}",
            r.changed,
            if wrote {
                format!(",改动写入配置文件 {}", r.codex_config.display())
            } else {
                format!("(配置文件 {} 未改动)", r.codex_config.display())
            }
        ),
    }
    if let Some(b) = &r.backup {
        println!(
            "  {}{}",
            tr(lang, "backup of the previous config: ", "原配置备份:"),
            b.display()
        );
    }
    if r.changed == 0 && !r.dry_run {
        match lang {
            Lang::En => println!("  (nothing to {what} in Codex -- no matching servers)"),
            Lang::Zh => println!("  (Codex 中无需{what} —— 无匹配服务器)"),
        }
    }
    if op == "apply" && r.changed > 0 && !r.dry_run {
        println!(
            "  {}",
            tr(
                lang,
                "Restart Codex to pick up the change. Undo with: vigil-hub setup --mcp --uninstall",
                "重启 Codex 使改动生效。撤销:vigil-hub setup --mcp --uninstall",
            )
        );
    }
}

/// 打印 JSON-agent 接入面(Cursor / Windsurf)只读预览(ASCII-safe)。附在前面各面预览之后。
/// 复用 [`print_mcp_server_preview`](注入 `<prefix>-` server-id 派生,与 apply 真改写一致)。
fn print_json_agent_preview(lang: Lang, r: &setup_mcp::JsonAgentPreviewReport) {
    println!();
    match lang {
        Lang::En => println!("  {} config: {}", r.display_name, r.config_path.display()),
        Lang::Zh => println!("  {} 配置:{}", r.display_name, r.config_path.display()),
    }
    if !r.exists {
        match lang {
            Lang::En => println!(
                "  (not found -- {} not configured, or no MCP servers yet)",
                r.display_name
            ),
            Lang::Zh => println!("  (未找到 —— {} 未配置,或尚无 MCP 服务器)", r.display_name),
        }
        return;
    }
    if r.servers.is_empty() {
        println!(
            "  {}",
            tr(
                lang,
                "No MCP servers found in mcpServers.",
                "mcpServers 中未找到 MCP 服务器。",
            )
        );
        return;
    }
    match lang {
        Lang::En => println!(
            "  {} scope (mcpServers) -- {} can be protected:",
            r.display_name,
            r.wrappable_count()
        ),
        Lang::Zh => println!(
            "  {} scope(mcpServers)—— {} 个可保护:",
            r.display_name,
            r.wrappable_count()
        ),
    }
    // server-id 派生须与 apply 一致(`<prefix>-<name>`)。prefix 是 &'static str,闭包捕获。
    let prefix = r.id_prefix;
    for s in &r.servers {
        print_mcp_server_preview(lang, &r.exe, |n| format!("{prefix}-{n}"), s, r.monitor);
    }
}

/// 打印 JSON-agent 接入面 apply/uninstall 结果(ASCII-safe)。附在前面各面结果之后。
fn print_json_agent_apply(lang: Lang, r: &setup_mcp::JsonAgentApplyReport, op: &str) {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = match (lang, r.dry_run) {
        (Lang::En, true) => "would",
        (Lang::En, false) => "did",
        (Lang::Zh, true) => "将",
        (Lang::Zh, false) => "已",
    };
    let what = match (lang, op == "uninstall") {
        (Lang::En, true) => "restore",
        (Lang::En, false) => "wrap",
        (Lang::Zh, true) => "还原",
        (Lang::Zh, false) => "防护",
    };
    let wrote = r.changed > 0 && !r.dry_run;
    match lang {
        Lang::En => println!(
            "Vigil setup --mcp --{op}{dry} ({}): {verb} {what} {} MCP server(s){}",
            r.display_name,
            r.changed,
            if wrote {
                format!(" in {}", r.config_path.display())
            } else {
                format!(" ({} untouched)", r.config_path.display())
            }
        ),
        Lang::Zh => println!(
            "Vigil setup --mcp --{op}{dry}({}):{verb}{what} {} 个 MCP 服务器{}",
            r.display_name,
            r.changed,
            if wrote {
                format!(",改动写入配置文件 {}", r.config_path.display())
            } else {
                format!("(配置文件 {} 未改动)", r.config_path.display())
            }
        ),
    }
    if let Some(b) = &r.backup {
        println!(
            "  {}{}",
            tr(lang, "backup of the previous config: ", "原配置备份:"),
            b.display()
        );
    }
    if r.changed == 0 && !r.dry_run {
        match lang {
            Lang::En => println!(
                "  (nothing to {what} in {} -- no matching servers)",
                r.display_name
            ),
            Lang::Zh => println!("  ({} 中无需{what} —— 无匹配服务器)", r.display_name),
        }
    }
    if op == "apply" && r.changed > 0 && !r.dry_run {
        match lang {
            Lang::En => println!(
                "  Restart {} to pick up the change. Undo with: vigil-hub setup --mcp --uninstall",
                r.display_name
            ),
            Lang::Zh => println!(
                "  重启 {} 使改动生效。撤销:vigil-hub setup --mcp --uninstall",
                r.display_name
            ),
        }
    }
}

/// 打印 setup/status 的人类可读报告(ASCII-safe,cp936/cp437 不乱码)。返回退出码。
fn print_setup_report(
    lang: Lang,
    args: &SetupArgs,
    r: &setup::SetupReport,
    mcp_counts: &[(&'static str, usize)],
) -> std::process::ExitCode {
    use setup::ProtectionState;
    let mcp_wrapped: usize = mcp_counts.iter().map(|(_, n)| n).sum();
    if args.status {
        let self_test = setup::doctor_self_test();
        println!("{}", tr(lang, "Vigil status", "Vigil 状态"));
        println!(
            "  Claude Code:   {}",
            if r.claude_detected {
                tr(lang, "detected", "已检测到")
            } else {
                tr(
                    lang,
                    "not detected (neither ~/.claude nor ~/.claude.json found)",
                    "未检测到(~/.claude 与 ~/.claude.json 都不存在)",
                )
            }
        );
        // 总体保护 = 原生 hook 活跃 **或** 至少一个 MCP server 被 Vigil 网关 wrap(ISS-20260621-002:
        // 两层任一即受保护;此前只看 hook 的 ProtectionState,致 `setup --mcp` turnkey 用户被误报未保护)。
        // 诚实分级:hook Active 仅当托管条目存在且 command 未漂移且 exe 存在(Codex R1 HIGH)。
        let hook_active = r.state == ProtectionState::Active;
        let overall_active = hook_active || mcp_wrapped > 0;
        if overall_active {
            println!(
                "  {}",
                tr(lang, "Protection:    ACTIVE", "防护状态:    已激活(ACTIVE)")
            );
        } else if r.state == ProtectionState::Stale {
            println!(
                "  {}",
                tr(
                    lang,
                    "Protection:    INSTALLED but STALE",
                    "防护状态:    已安装但已失效(STALE)"
                )
            );
        } else {
            println!(
                "  {}",
                tr(lang, "Protection:    not installed", "防护状态:    未安装")
            );
        }
        // 分层明细:两条防护面各自可见(原生工具输入侧 hook + MCP 网关逐 server wrap)。
        println!(
            "  {}{}",
            tr(lang, "Native hook:   ", "原生 hook:    "),
            match r.state {
                ProtectionState::Active => tr(lang, "active", "活跃"),
                ProtectionState::Stale => tr(
                    lang,
                    "STALE - points at a different binary/ledger; re-run `vigil-hub setup`",
                    "已失效 —— Vigil 程序或账本路径变了(可能升级 / 移动过),请重跑 `vigil-hub setup` 修复",
                ),
                ProtectionState::NotInstalled => tr(lang, "not installed", "未安装"),
            }
        );
        println!(
            "  {}{}",
            tr(lang, "MCP gateway:   ", "MCP 网关:     "),
            if mcp_wrapped > 0 {
                // 逐 agent 明细(只列非零项):用户能一眼确认 setup --all 的全局覆盖面。
                let detail = mcp_counts
                    .iter()
                    .filter(|(_, n)| *n > 0)
                    .map(|(name, n)| format!("{name} {n}"))
                    .collect::<Vec<_>>()
                    .join(" / ");
                match lang {
                    Lang::En => format!("{mcp_wrapped} server(s) wrapped ({detail})"),
                    Lang::Zh => format!("已防护 {mcp_wrapped} 个服务器({detail})"),
                }
            } else {
                tr(lang, "no servers wrapped", "尚未防护任何服务器").to_string()
            }
        );
        // 浏览器防线(可选层):native host 注册态。直调 install::status(纯文件/注册表
        // 只读,与桌面 Protection Overview 卡同源判定 is_registered,防重实现漂移)。
        println!(
            "  {}{}",
            tr(lang, "Browser guard: ", "浏览器防线:  "),
            match vigil_native_host::install::status(None) {
                Ok(s) if s.is_registered() => tr(
                    lang,
                    "native host registered (pick it in the extension's enterprise settings)",
                    "native host 已注册(在扩展企业设置选择本机引擎后生效)",
                ),
                Ok(_) => tr(
                    lang,
                    "not registered (optional; see the Browser extension docs)",
                    "未注册(可选;见浏览器扩展文档)",
                ),
                Err(_) => tr(lang, "status unknown", "状态未知"),
            }
        );
        if hook_active {
            println!(
                "  {}{}",
                tr(lang, "Hook command:  ", "Hook 命令:    "),
                r.hook_command
            );
        }
        println!(
            "  {}{}",
            tr(lang, "Audit ledger:  ", "审计账本:    "),
            r.ledger.display()
        );
        println!(
            "  {}{}",
            tr(lang, "Self-test:     ", "自检:        "),
            if self_test {
                tr(
                    lang,
                    "PASS - a synthetic fake credential was blocked by the hook logic",
                    "通过 —— 用一条伪造的测试密钥验证,已被成功拦截",
                )
            } else {
                tr(
                    lang,
                    "FAIL - the hook did NOT block a synthetic credential (please report)",
                    "失败 —— hook 未能拦截合成凭据(请反馈)",
                )
            }
        );
        if !overall_active && r.claude_detected {
            match lang {
                Lang::En => println!(
                    "\n  Run `vigil-hub setup` (native-tool hook) or `vigil-hub setup --mcp --apply` (MCP gateway) to turn on protection."
                ),
                Lang::Zh => println!(
                    "\n  运行 `vigil-hub setup`(原生工具 hook)或 `vigil-hub setup --mcp --apply`(MCP 网关)开启防护。"
                ),
            }
        }
        // self-test 失败是真问题 → 非零退出
        return if self_test {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }

    if args.uninstall {
        println!("Vigil setup --uninstall");
        if r.changed {
            println!(
                "  {}",
                tr(
                    lang,
                    "Removed Vigil's PreToolUse hook from Claude Code settings.",
                    "已从 Claude Code 设置中移除 Vigil 的 PreToolUse hook。",
                )
            );
            if let Some(b) = &r.backup_path {
                println!(
                    "  {}{}",
                    tr(lang, "Backup:        ", "备份:        "),
                    b.display()
                );
            }
        } else {
            println!(
                "  {}",
                tr(
                    lang,
                    "Nothing to remove (Vigil hook was not present).",
                    "无需移除(Vigil hook 本就不存在)。",
                )
            );
        }
        return std::process::ExitCode::SUCCESS;
    }

    // install
    println!("Vigil setup");
    if !r.claude_detected {
        match lang {
            Lang::En => {
                println!("  Claude Code:   not detected (claude not on PATH; neither ~/.claude nor ~/.claude.json found)");
                println!("  Nothing to do. Install Claude Code, then re-run `vigil-hub setup`.");
                println!(
                    "  (For other agents (Codex/Gemini/Cursor), run `vigil-hub setup --all`.)"
                );
            }
            Lang::Zh => {
                println!("  Claude Code:   未检测到(claude 不在 PATH;~/.claude 与 ~/.claude.json 都不存在)");
                println!("  无事可做。请先安装 Claude Code,再重跑 `vigil-hub setup`。");
                println!("  (其它 agent(Codex/Gemini/Cursor)请用:`vigil-hub setup --all`。)");
            }
        }
        return std::process::ExitCode::SUCCESS;
    }
    println!(
        "  {}",
        tr(lang, "Claude Code:   detected", "Claude Code:   已检测到")
    );
    if r.dry_run {
        match lang {
            Lang::En => {
                println!("  [dry-run] would register Vigil's PreToolUse hook in:");
                println!("            {}", r.settings_path.display());
                println!("  [dry-run] hook command: {}", r.hook_command);
                println!("  [dry-run] audit ledger: {}", r.ledger.display());
                println!("  (no changes written)");
            }
            Lang::Zh => {
                println!("  [dry-run] 将把 Vigil 的 PreToolUse hook 注册到:");
                println!("            {}", r.settings_path.display());
                println!("  [dry-run] hook 命令:{}", r.hook_command);
                println!("  [dry-run] 审计账本:{}", r.ledger.display());
                println!("  (未写入任何改动)");
            }
        }
        return std::process::ExitCode::SUCCESS;
    }
    if r.changed {
        match lang {
            Lang::En => {
                println!("  Protection:    PreToolUse hook registered (all tools)");
                println!("  Hook command:  {}", r.hook_command);
                println!("  Audit ledger:  {}", r.ledger.display());
            }
            Lang::Zh => {
                println!("  防护状态:    已注册 PreToolUse hook(覆盖所有工具)");
                println!("  Hook 命令:    {}", r.hook_command);
                println!("  审计账本:    {}", r.ledger.display());
            }
        }
        if let Some(b) = &r.backup_path {
            match lang {
                Lang::En => println!("  Backup:        {}  (your previous settings)", b.display()),
                Lang::Zh => println!("  备份:        {}  (你之前的设置)", b.display()),
            }
        }
        println!();
        match lang {
            Lang::En => {
                println!("  Your Claude Code tool calls are now guarded by Vigil: raw secrets are");
                println!("  blocked from Bash/Edit/Write/etc., and every block is recorded in a");
                println!("  tamper-evident local audit ledger.");
                println!();
                println!("  Verify:  vigil-hub setup --status");
                println!("  Undo:    vigil-hub setup --uninstall");
                println!(
                    "  Restart Claude Code (or start a new session) for the hook to take effect."
                );
            }
            Lang::Zh => {
                println!("  你的 Claude Code 工具调用现已受 Vigil 守护:明文密钥会被挡在");
                println!("  Bash/Edit/Write 等工具之外,且每一次拦截都记入防篡改的本地审计账本。");
                println!();
                println!("  验证:  vigil-hub setup --status");
                println!("  撤销:  vigil-hub setup --uninstall");
                println!("  重启 Claude Code(或开新会话)使 hook 生效。");
            }
        }
    } else {
        match lang {
            Lang::En => {
                println!("  Protection:    already active (no change).");
                println!("  Verify:  vigil-hub setup --status");
            }
            Lang::Zh => {
                println!("  防护状态:    已激活(无改动)。");
                println!("  验证:  vigil-hub setup --status");
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// localize 必须能命中**真实** Cli 树的每个 mut_subcommand / mut_arg —— `mut_arg` 对未定义
    /// id 会 panic,故 arg id 一旦写错,线上**每次**启动(main 在 parse 前都会 localize)都会崩。
    /// 本测试在真实 Cli 上跑两语言 localize + clap 结构自检,守住这条必经路径(mirror 测试在
    /// i18n::help 里只是近似,本测试才是权威)。
    #[test]
    fn localize_applies_to_real_cli_both_langs() {
        for lang in [Lang::En, Lang::Zh] {
            i18n::help::localize(Cli::command(), lang).debug_assert();
        }
    }

    /// 真实 root 帮助按语言渲染(同时验证 mut_subcommand 命中 + 文案确实生效)。term_width 调大
    /// 关闭折行,保证目标短语逐字保留。
    #[test]
    fn real_root_help_is_localized() {
        let mut zh_cmd = i18n::help::localize(Cli::command(), Lang::Zh).term_width(10_000);
        let zh = zh_cmd.render_long_help().to_string();
        assert!(
            zh.contains("Vigil 位于你的 AI 编码 agent"),
            "ZH root long help should be localized:\n{zh}"
        );
        let mut en_cmd = i18n::help::localize(Cli::command(), Lang::En).term_width(10_000);
        let en = en_cmd.render_long_help().to_string();
        assert!(
            en.contains("Vigil sits between your AI coding agents"),
            "EN root long help should be localized:\n{en}"
        );
    }
}
