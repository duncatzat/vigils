//! Native runner env 政策(ADR 0007 §I-7.1 helper)+ `ScrubCallback` type alias。
//!
//! 从 `vigil-runner/src/native.rs` 抽出(ADR 0018 v0.13)。0 vigil deps,可
//! 独立 publish + 被 `vigil-mcp` / `vigil-ui-protocol` 直接 path-dep。
//!
//! `default_scrub` 不在本模块(它依赖 `vigil-redaction::scrub_text`),仍由
//! `vigil-runner` 主 crate 提供。`ScrubCallback` type alias 在此,允许
//! consumer 在不拉 vigil-redaction 的情况下构造自己的 scrub。

use std::sync::Arc;

/// 脱敏回调:接受任意字符串,返回脱敏后字符串(同长度或更短)。
///
/// 默认实现 `default_scrub` 用 `vigil_redaction::scrub_text`(在 `vigil-runner`
/// 主 crate),consumer 也可注入 identity / 更严格的实现。
pub type ScrubCallback = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Windows 下会被 runner 自动注入的最小系统 env 集合 —— caller 通过
/// `bind_tool_secret` 声明的 `env_var_name` **不允许**命中这些保留名字,
/// 否则 runner 的 defense-in-depth 会让系统 env 在注入顺序上早于用户 env,
/// 语义变得难以预期。registry 层应在 `bind_tool_secret` 入口做大小写不敏感拒绝。
pub const RESERVED_SYSTEM_ENV_KEYS: &[&str] = &[
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "WINDIR",
    "SystemDrive",
    "SYSTEMDRIVE",
];

/// 判定一个 env key 是否属于 Windows 保留系统 env(大小写不敏感)。
/// Linux/macOS 亦按保守口径拒绝(保持跨平台一致 binding)。
pub fn is_reserved_env_key(key: &str) -> bool {
    RESERVED_SYSTEM_ENV_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
}

/// I07.5+ (ADR 0007 §I-7.1 helper 抽取承诺兑现):统一 Native spawn 的 env 政策。
///
/// **原子三步**(不可改序,不可在中间插其他 `cmd` 操作):
/// 1. `env_clear()`(AGENTS §7 / §I-7.3)
/// 2. **仅 Windows**:注入 `RESERVED_SYSTEM_ENV_KEYS`(`SystemRoot` / `windir` / `SystemDrive`
///    及其大小写变体)—— 让 cmd.exe / ping 等系统命令能解析 System32 DLL;`env_clear` 后
///    缺失它们会让绝大部分 Windows 系统命令以 exit=1 退出;这些 env 本身非敏感。
///    Linux/macOS 不做此注入(/bin/sh 不依赖 env 查 DLL)
/// 3. `envs(user_env)` —— 用户批准的 env 最后注入,顺序最后保证优先级最高(即使
///    registry 漏检也压过 system 保留键;registry 层已通过 `is_reserved_env_key`
///    主动拒绝 binding 使用这些名字)
///
/// **§I-7.3 compliance**:本函数是**原子单元**,内部三步无 log / audit / Debug 调用。
/// 调用方应在**取得 user_env 后立即**调用本函数,之间不插入任何其他 cmd 操作(典型:
/// `cmd.arg()` / `cmd.current_dir()` 等应**先于**本函数,stdio/stdin 配置可后于)。
///
/// **I07.5+ 动机**:此前 `spawn_native` 和 `vigil_mcp::StdioUpstream::spawn` 各自实现
/// env 政策,存在 Windows SystemRoot 注入漂移(StdioUpstream 缺失)。抽共享 helper
/// 消除漂移,同时兑现 ADR 0007 §I-7.1 承诺。
pub fn apply_native_env_policy<I, K, V>(cmd: &mut std::process::Command, user_env: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    cmd.env_clear();
    #[cfg(windows)]
    for key in RESERVED_SYSTEM_ENV_KEYS {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd.envs(user_env);
}

/// MCP stdio upstream 可继承的**非敏感运行时** env 白名单(deny-by-default)。
///
/// 仅收录"让 node / python 启动器(`npx` / `uvx` / `node` / `python`)能跑起来"必需的
/// OS / locale / 包管理器-cache 类变量;**刻意不含**任何密钥类(API key / token /
/// `*_SECRET` / `*_TOKEN` / `NPM_TOKEN` / 云凭证)。父进程 env 里的密钥因此**仍不泄漏**给
/// upstream —— 隔离从"全清"收窄为"清掉白名单外的一切",边界方向是收紧而非放开。
///
/// 跨平台合并(`std::env::var` 在缺失键上返 `Err` → 自动跳过,故 Unix 键在 Windows、
/// Windows 键在 Unix 都安全地不命中)。新增启动器若需别的非敏感运行时变量,在此登记。
///
/// **已接受风险(Codex review SHOULD-FIX 记录)**:`PATH`(及 `PATHEXT`/`ComSpec`)是必需的,但它是
/// 一个代码**选择**面 —— 若攻击者能控制 Vigil 父进程的 `PATH`,launcher 内部解析(如 shebang
/// `/usr/bin/env node`)可能定位到不同的解释器。这**不同于** `LD_PRELOAD`/`NODE_OPTIONS` 类代码**注入**
/// (那些刻意不在白名单),且 upstream 的 `argv[0]` 在 spawn 前已由 `resolve_program` 解析 + V1.1
/// resolved-program drift gate 钉死。残余的"launcher 依赖解析仍受 PATH 影响"是有意接受的取舍:
/// upstream 本就是用户配置的可信启动器,其 PATH 即用户自身环境。
pub const MCP_UPSTREAM_ENV_ALLOWLIST: &[&str] = &[
    // 通用:解释器/二进制定位 + locale(正确文本编码)+ 时区
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    // Unix:HOME(~/.npm·~/.npmrc·~/.cache)、临时目录、身份、XDG cache/config
    "HOME",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    // Windows:用户目录、npm/uv cache+config、临时、系统(System32 DLL/cmd.exe/扩展名解析)
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "SystemRoot",
    "windir",
    "SystemDrive",
    "PATHEXT",
    "ComSpec",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "NUMBER_OF_PROCESSORS",
];

/// MCP stdio upstream **专用** env 政策(区别于沙箱 runner 的 `apply_native_env_policy`)。
///
/// **为何与沙箱 runner 不同**(ADR 0007 §I-7.1 amendment / ADR 0018):
/// `apply_native_env_policy` 为隔离**不可信沙箱代码**做完全 `env_clear()`。但 MCP stdio
/// upstream 是**用户显式配置的可信 MCP server**(典型 `npx -y <pkg>` / `uvx <pkg>`),本质是
/// node/python **启动器**,内部要靠 `PATH` 定位解释器、靠 `HOME`/`APPDATA` 访问包管理器 cache。
/// 完全 `env_clear` 会让 npx/uvx **根本起不来**(Linux + Windows 实测:`mcp-server-filesystem:
/// not found`,子进程永不打印 "running on stdio")→ Hub 聚合 0 工具 → 网关核心价值(代理工具)失效。
///
/// **三步**(与 native 同构,差别仅在第 2 步注入白名单而非仅 Windows 保留键):
/// 1. `env_clear()`
/// 2. 注入 `MCP_UPSTREAM_ENV_ALLOWLIST` 里**当前进程实际存在**的键(非敏感运行时 env)
/// 3. `envs(user_env)` —— 用户批准的 env(含经 lease broker 的 secret)最后注入,优先级最高
///
/// **安全**:白名单是 deny-by-default 且不含任何密钥类键,父进程的 API key/token **不泄漏**给
/// upstream。这是对 §I-7.1 "stdio upstream 与 native spawn 共享 env 政策"的**有意分叉**:两者
/// 威胁模型不同(沙箱跑不可信代码 vs upstream 是可信启动器),不再强制同构。
pub fn apply_mcp_upstream_env_policy<I, K, V>(cmd: &mut std::process::Command, user_env: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    cmd.env_clear();
    for key in MCP_UPSTREAM_ENV_ALLOWLIST {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd.envs(user_env);
}

#[cfg(test)]
mod mcp_upstream_env_tests {
    use super::apply_mcp_upstream_env_policy;
    use std::collections::HashMap;

    /// 取 `Command` 实际会注入的 env 覆盖(`env_clear` 后只剩显式 set 的键)。
    fn collected_envs(cmd: &std::process::Command) -> HashMap<String, String> {
        cmd.get_envs()
            .filter_map(|(k, v)| {
                v.map(|vv| {
                    (
                        k.to_string_lossy().into_owned(),
                        vv.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect()
    }

    /// 白名单内且当前进程存在的运行时 env(PATH)被继承;非白名单 env(cargo 测试注入的
    /// `CARGO_MANIFEST_DIR`,代表"父进程里不该泄漏给 upstream 的非白名单变量")被剥离;
    /// 用户批准 env 注入。—— 这是 Issue B 修复的核心不变量:upstream 能跑起来,但隔离仍 deny-by-default。
    #[test]
    fn allows_runtime_env_strips_non_allowlisted_and_injects_user_env() {
        let mut cmd = std::process::Command::new("dummy-not-spawned");
        apply_mcp_upstream_env_policy(
            &mut cmd,
            [("MY_APPROVED_SECRET".to_string(), "v1".to_string())],
        );
        let envs = collected_envs(&cmd);

        // 用户批准 env 必须注入
        assert_eq!(
            envs.get("MY_APPROVED_SECRET").map(String::as_str),
            Some("v1"),
            "用户批准 env 应注入 upstream"
        );

        // PATH 几乎必然存在于父进程,且在白名单 → 应被继承(否则 npx 找不到 node)
        if std::env::var("PATH").is_ok() {
            assert!(
                envs.contains_key("PATH"),
                "白名单内的 PATH 应被继承给 upstream"
            );
        }

        // CARGO_MANIFEST_DIR 由 cargo 在测试运行时注入但不在白名单 → 必须被剥离
        // (代表父进程里"非白名单、潜在敏感"的变量不泄漏给 upstream;deny-by-default 不变量)
        if std::env::var("CARGO_MANIFEST_DIR").is_ok() {
            assert!(
                !envs.contains_key("CARGO_MANIFEST_DIR"),
                "非白名单 env(CARGO_MANIFEST_DIR)不得泄漏给 upstream —— 隔离边界被破坏"
            );
        }
    }

    /// 批准的 `user_env` 必须**覆盖**白名单继承来的同名键(注入顺序:allowlist 在前、user_env 在后)。
    /// 用 PATH 验证:它几乎必然存在于父进程(故 allowlist 步骤会先注入真实 PATH),user_env 再用
    /// 自定义值覆盖 —— 证明 secret-lease 批准值始终压过继承的运行时 env(Codex review SHOULD-FIX)。
    #[test]
    fn user_env_overrides_allowlisted_inherited_key() {
        if std::env::var("PATH").is_err() {
            return; // 父进程无 PATH(极罕见)→ 无从验证覆盖,跳过
        }
        let mut cmd = std::process::Command::new("dummy-not-spawned");
        apply_mcp_upstream_env_policy(
            &mut cmd,
            [("PATH".to_string(), "VIGIL_USER_OVERRIDE_PATH".to_string())],
        );
        let envs = collected_envs(&cmd);
        assert_eq!(
            envs.get("PATH").map(String::as_str),
            Some("VIGIL_USER_OVERRIDE_PATH"),
            "批准的 user_env 应覆盖白名单继承的 PATH(注入顺序 user_env 最后,优先级最高)"
        );
    }
}
