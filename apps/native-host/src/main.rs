//! Vigil Chrome Native Messaging Host(I09a + I09b-β1)。
//!
//! 原 I09a 职责:Chrome service worker 通过 `connectNative("com.vigil.host")` 建立长连接,
//! 本进程从 stdin 读 framing + JSON,调 `vigil-browser::classify`,stdout 回写。
//!
//! I09b-β1 新增:CLI 子命令 `install` / `uninstall` / `status`,实现三平台
//! Chrome Native Messaging Host 注册(Windows HKCU 注册表 + macOS/Linux Manifest 文件)。
//!
//! **Chrome 启动 Host 会传 argv**(Chrome Native Messaging 文档):
//!   - Linux/macOS:`argv[1] = <calling extension origin, 如 "chrome-extension://<id>/">`
//!   - Windows:Linux/macOS 同上 + `argv[2] = --parent-window=<HWND>`
//!
//! 这些 argv **不能被 clap 解析** —— clap 会把非预定义 subcommand 判为错误 exit 2,
//! 导致 Chrome onDisconnect "Specified native messaging host not found"。
//!
//! 解决:`dispatch_argv()` 手工预判 argv[1] —— 仅 `install`/`uninstall`/`status`/
//! `--help`/`-h`/`-V`/`--version` 走 clap,**其它(含 Chrome 传来的 origin) 全部直走 run**。
//! 这样 Chrome exec 路径永远进 stdin/stdout 循环,管理员 CLI 路径走子命令。
//!
//! 安全契约延续 ADR 0009:
//! - §I-9.1:原文仅在内存停留,分类完立即 drop;不入 SQLite / log / tracing
//! - §I-9.2:audit payload 字段白名单固定
//! - §I-9.3:特权 scheme → OriginDenied
//! - §I-9.5:length prefix > 1 MB → too_large
//! - §I-9.6:redact 兜底 re-scan
//!
//! β1 install 额外守门:
//! - extension_id 必须 32 chars `a-p`(Chrome 扩展 ID alphabet)
//! - exe_path 必须绝对(**Vigil 项目策略**;Chrome 本身只在 Linux/macOS 强制绝对,Windows
//!   允许相对 manifest 目录,Vigil 一律收紧为绝对避免本地/CI 路径歧义)

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vigil_audit::Ledger;
use vigil_native_host::install::{self, InstallConfig};

#[derive(Parser)]
#[command(
    name = "vigil-native-host",
    about = "Vigil Chrome Native Messaging Host(默认无参即进入 run 循环供 Chrome exec)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 注册 Native Host(三平台:Windows HKCU + macOS/Linux manifest 文件)。
    Install {
        /// Chrome 扩展 ID(32 chars in a-p)。从 `chrome://extensions/` 复制。
        #[arg(long, value_name = "ID")]
        extension_id: String,
        /// vigil-native-host 可执行文件绝对路径;默认取当前进程位置。
        #[arg(long, value_name = "PATH")]
        exe_path: Option<PathBuf>,
        /// Host manifest description 字段。
        #[arg(long, default_value = "Vigil browser native messaging host")]
        description: String,
        /// 允许 `exe_path` 指向不存在的文件(用于"先写 manifest 后构建"流程)。
        #[arg(long)]
        allow_missing_exe: bool,
    },
    /// 卸载 Native Host(幂等;不存在不报错)。
    Uninstall,
    /// 打印当前注册状态。
    Status,
}

fn main() -> ExitCode {
    // R1 BLOCKER 修复:Chrome exec 本 binary 时 argv[1] 是扩展 origin(形如
    // "chrome-extension://<id>/"),不能走 clap 否则判为未知 subcommand exit 2。
    // **仅** 预定义 subcommand 字面量走 clap;其它(含 Chrome origin / --parent-window /
    // 无参)直走 run_stdio_loop。判断逻辑抽到 lib 为纯函数 + 单测守门,见
    // `vigil_native_host::is_admin_subcommand`。
    let args: Vec<String> = std::env::args().collect();
    if !vigil_native_host::is_admin_subcommand(&args) {
        // Chrome 启动路径(argv[1] 是 origin / Windows 下 argv[2] 是 --parent-window)
        // 或无参;统一进 stdin/stdout 循环。未预定义的 argv 被有意忽略(Chrome 契约
        // 不要求 host 解读 origin;分类审计已走 BrowserCheckRequest.origin 字段)。
        return run_stdio_loop();
    }

    // 管理员 CLI:解析子命令
    let cli = Cli::parse();
    match cli.command {
        None => run_stdio_loop(), // 理论不可达(上方 is_admin_subcmd 已保证 argv[1] 是已知 subcmd),兜底
        Some(Cmd::Install {
            extension_id,
            exe_path,
            description,
            allow_missing_exe,
        }) => cmd_install(extension_id, exe_path, description, allow_missing_exe),
        Some(Cmd::Uninstall) => cmd_uninstall(),
        Some(Cmd::Status) => cmd_status(),
    }
}

// ─────────────────────────── default subcommand: run(Chrome exec) ─────────────────────

fn run_stdio_loop() -> ExitCode {
    // Ledger 路径(审核 P1 EXT-01 修复):VIGIL_LEDGER_PATH(全产品 canonical)→
    // VIGIL_DB_PATH(历史别名)→ 默认 <data_local_dir>/Vigil/ledger.sqlite3(与 CLI/桌面
    // 同账本,浏览器审计事件从此桌面 Activity Feed 可见)。解析为纯函数进 lib 单测守门。
    let db_path = vigil_native_host::resolve_ledger_path(
        std::env::var("VIGIL_LEDGER_PATH").ok().as_deref(),
        std::env::var("VIGIL_DB_PATH").ok().as_deref(),
        dirs::data_local_dir(),
    );
    // 持久账本打不开(锁/权限/目录建不出)→ 降级 in-memory 并继续服务:分类防护优先于
    // 审计持久化(与 hook/daemon 的 audit best-effort 先例一致),绝不因审计初始化失败
    // 拒绝守门。警告走 stderr(Chrome 收集到扩展日志;stdout 是 framing 通道,禁止字面量)。
    let ledger = match db_path {
        Some(p) => {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Ledger::open(&p).or_else(|e| {
                eprintln!(
                    "vigil-native-host: persistent ledger unavailable at {} ({e}); \
                     falling back to in-memory audit (protection unaffected)",
                    p.display()
                );
                Ledger::open_in_memory()
            })
        }
        None => Ledger::open_in_memory(),
    };
    let ledger = match ledger {
        Ok(l) => l,
        Err(_) => {
            // 不能在 stdout 打字面字符串(Chrome 会以 u32 length prefix 解析成天文数字长度)
            // 直接 silent exit 非 0;扩展可在 onDisconnect 里观察到
            return ExitCode::from(2);
        }
    };
    let session_id = match ledger.start_session("browser_host", None) {
        Ok(s) => s,
        Err(_) => return ExitCode::from(3),
    };

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    // daemon ML 探针:engine.json 门控 + 失败冷却;daemon 缺席 → 行为恒等纯硬指纹(fail-closed)。
    let ml = vigil_native_host::DaemonProbe::new();
    match vigil_native_host::run(&mut stdin, &mut stdout, &ledger, &session_id, &ml) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

// ─────────────────────────── install / uninstall / status 子命令 ─────────────────────

fn cmd_install(
    extension_id: String,
    exe_path_arg: Option<PathBuf>,
    description: String,
    allow_missing_exe: bool,
) -> ExitCode {
    // 默认 exe_path = 当前进程位置;Chrome 读 manifest 后会 exec 该路径
    let exe_path = match exe_path_arg {
        Some(p) => p,
        None => match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("install failed: unable to resolve current_exe(); pass --exe-path");
                return ExitCode::from(11);
            }
        },
    };
    let cfg = InstallConfig {
        extension_id,
        exe_path,
        description,
    };
    match install::install(&cfg, allow_missing_exe, None) {
        Ok(out) => {
            println!("[OK] Vigil Native Host installed");
            println!("  manifest: {}", out.manifest_path.display());
            if let Some(reg) = out.registry_key {
                println!("  registry: {reg}");
            }
            println!(
                "  extension: chrome-extension://{}/",
                cfg_extension_id_for_display(&cfg)
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("install failed: {err}");
            ExitCode::from(10)
        }
    }
}

fn cmd_uninstall() -> ExitCode {
    match install::uninstall(None) {
        Ok(()) => {
            println!("[OK] Vigil Native Host uninstalled (manifest / registry cleared, 幂等)");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("uninstall failed: {err}");
            ExitCode::from(12)
        }
    }
}

fn cmd_status() -> ExitCode {
    match install::status(None) {
        Ok(s) => {
            println!("Vigil Native Host status:");
            println!("  manifest path    : {}", s.manifest_path.display());
            println!(
                "  manifest exists  : {}",
                if s.manifest_exists { "yes" } else { "no" }
            );
            match s.registry_present {
                Some(true) => println!("  registry (HKCU)  : present"),
                Some(false) => println!("  registry (HKCU)  : missing"),
                None => println!("  registry         : n/a (non-Windows)"),
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("status query failed: {err}");
            ExitCode::from(13)
        }
    }
}

/// 小助手:install 成功分支打印用;从 `cfg` 取 extension_id(`cfg` 已被 `install()` 消费的字段引用)。
fn cfg_extension_id_for_display(cfg: &InstallConfig) -> &str {
    &cfg.extension_id
}
