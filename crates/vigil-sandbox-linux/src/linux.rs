//! Linux-only Landlock 实装。本文件仅在 `cfg(target_os = "linux")` 下编译。
//!
//! # 架构(I07.5 R2 REJECT 修订后)
//!
//! Landlock 集成分两阶段,显式划分父/子进程责任:
//!
//! **父进程(`LandlockPolicy::install_into`)**:
//! - 查 kernel ABI(不支持 → 立即 `LandlockError::NotSupported`)
//! - 打开所有路径 `PathFd`(O_PATH | O_CLOEXEC;不存在 → `PathOpenFailed`)
//! - 构造 `RulesetCreated`(`Ruleset::default().handle_access().create().add_rule()×N`);
//!   任一步失败 → `RulesetBuildFailed { step }`
//! - 所有可预见的 landlock 失败都在此阶段上报,映射到 `RunnerError::Rejected { Sandbox }`
//!
//! **子进程(pre_exec 闭包)**:
//! - 只调 `RulesetCreated::restrict_self()` + `RulesetStatus::FullyEnforced` 校验
//! - `restrict_self` 文档明确实现只做 `prctl(PR_SET_NO_NEW_PRIVS)` + `landlock_restrict_self`
//!   syscall —— 两者均 async-signal-safe
//! - 闭包**绝不分配**、绝不 `format!` / `to_string()` —— 所有错误用
//!   `io::Error::from_raw_os_error(libc::EPROTO)`(来自静态 const,不触堆)
//! - 父进程在 `spawn_native` 的 spawn 失败路径上检测 `raw_os_error == EPROTO`,映射到
//!   `Rejected { Sandbox, landlock_restrict_failed }` —— 闭环 fail-closed 审计契约

use std::path::{Path, PathBuf};

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus, ABI as LandlockABI,
};
use thiserror::Error;

/// Landlock ruleset 构造 / 应用期错误(**父进程**阶段 —— install_into 返回)。
///
/// 子进程 pre_exec 的 `restrict_self` 失败另行通过 `io::Error(EPROTO)` 信号传回
/// `spawn_native` —— 详见模块头"架构"说明。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LandlockError {
    /// 内核不支持 Landlock(< 5.13 / 未启编译选项 / 未启用 LSM)。
    #[error("kernel does not support landlock (ABI v1 not available)")]
    NotSupported,

    /// 声明的路径无法打开(不存在 / 权限不足 / 非 dir)。
    #[error("open path failed: {0}")]
    PathOpenFailed(PathBuf),

    /// Ruleset 构造失败(父进程阶段 —— handle_access / create / add_rule)。
    #[error("ruleset build failed at step: {step}")]
    RulesetBuildFailed {
        /// 失败步骤:`"handle_access"` / `"create"` / `"add_rule_read"` / `"add_rule_write"`
        step: &'static str,
    },
}

/// pre_exec 闭包向父进程传递 landlock 特定失败的 errno(EPROTO)。
///
/// 父进程 `spawn_native` 在 `Command::spawn` 失败时比对 `raw_os_error() == LANDLOCK_PRE_EXEC_ERRNO`
/// 区分"landlock restrict 失败"与"普通 spawn 失败",映射到 `Rejected { Sandbox }`。
pub const LANDLOCK_PRE_EXEC_ERRNO: i32 = libc::EPROTO;

/// 内核是否支持 Landlock ABI v1(最低需求:Linux 5.13)。
///
/// landlock 0.4 **明确禁止** runtime 根据运行内核动态创建 ABI(见 compat.rs 源码
/// 注释:"ABI should not be dynamically created ... to avoid inconsistent behaviors
/// and non-determinism")。正确做法:静态 target ABI::V1,内核不支持由
/// `Ruleset::create()` syscall 失败检测。
pub fn kernel_supports_landlock() -> bool {
    Ruleset::default()
        .handle_access(AccessFs::from_all(LandlockABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

/// Landlock 访问策略 —— 包含允许读 / 允许写 / 允许 cwd 列表,由 caller 在 spawn 前构造。
///
/// **使用模式**:
/// ```ignore
/// let policy = LandlockPolicy::from_dirs(&read_dirs, &write_dirs);
/// let mut cmd = std::process::Command::new(argv[0]);
/// policy.install_into(&mut cmd)?;       // 父进程构建 ruleset + 注入 pre_exec
/// let child = cmd.spawn()?;             // 子进程 fork 后 exec 前 restrict_self
/// ```
pub struct LandlockPolicy {
    /// 允许读(只读)。exec 后子进程对这些目录 + 子树可 read / stat / readdir。
    read_paths: Vec<PathBuf>,
    /// 允许读+写。I07 `SandboxProfile.write_dirs` 隐含读写双权限。
    write_paths: Vec<PathBuf>,
}

impl std::fmt::Debug for LandlockPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LandlockPolicy")
            .field("read_paths_count", &self.read_paths.len())
            .field("write_paths_count", &self.write_paths.len())
            .finish_non_exhaustive()
    }
}

impl LandlockPolicy {
    /// 从路径列表构造策略(不做 IO)。
    ///
    /// - `read_paths`:子进程可读目录(递归子树)
    /// - `write_paths`:子进程可读+可写目录
    pub fn from_dirs(
        read_paths: impl IntoIterator<Item = impl Into<PathBuf>>,
        write_paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        Self {
            read_paths: read_paths.into_iter().map(Into::into).collect(),
            write_paths: write_paths.into_iter().map(Into::into).collect(),
        }
    }

    /// 把策略注入到 `std::process::Command::pre_exec`。
    ///
    /// **父进程阶段**:打开 FD + 构造 RulesetCreated + add_rule × N。任一失败即返
    /// `LandlockError`,caller(`spawn_native`)映射到 `Rejected { Sandbox }`。
    ///
    /// **子进程阶段**:pre_exec 闭包只调 `restrict_self` + status 校验,async-signal-safe。
    ///
    /// # TOCTOU
    ///
    /// `plan.validate()` 先做 canonicalize,`install_into` 再用原路径 `PathFd::new`,
    /// 中间理论上存在 symlink-swap 窗口。当前用两点缓解:
    /// 1. `PathFd::new` 使用 `O_PATH | O_CLOEXEC`(landlock crate 默认),不跟随 symlink
    ///    本身的 target 做额外 open —— 但 `O_NOFOLLOW` 未设置,最终 open 的仍是 symlink
    ///    target
    /// 2. 窗口极短(validate → spawn 在同一函数内)
    ///
    /// 彻底消除需要 `openat2` + `RESOLVE_NO_SYMLINKS` + fstat inode 校验,landlock 0.4
    /// crate 未暴露此 API —— 留待后续迭代 / 升 landlock 0.5+。
    #[allow(unsafe_code)] // pre_exec 是 unsafe API —— 本 crate 唯一 unsafe 出现点
    pub fn install_into(&self, cmd: &mut std::process::Command) -> Result<(), LandlockError> {
        // 阶段 1:静态 target ABI::V1(最低 Linux 5.13)。landlock 0.4 禁止 runtime
        // 动态创建 ABI(见 kernel_supports_landlock 注释),内核不支持由下方 create()
        // syscall 失败检测 → 映射到 LandlockError::NotSupported。
        let abi = LandlockABI::V1;

        // 阶段 2:父进程打开 FD(失败 → PathOpenFailed)
        let read_fds: Vec<PathFd> = self
            .read_paths
            .iter()
            .map(|p| open_path_fd(p))
            .collect::<Result<_, _>>()?;
        let write_fds: Vec<PathFd> = self
            .write_paths
            .iter()
            .map(|p| open_path_fd(p))
            .collect::<Result<_, _>>()?;

        // 阶段 3:父进程构造 RulesetCreated(失败 → RulesetBuildFailed)
        let mut ruleset: RulesetCreated = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|_| LandlockError::RulesetBuildFailed {
                step: "handle_access",
            })?
            // create() 是 landlock 0.4 唯一真正触发 syscall 的点,失败 = 内核不支持
            // (kernel < 5.13 / landlock LSM 未启用 / 容器禁用)→ NotSupported
            .create()
            .map_err(|_| LandlockError::NotSupported)?;

        let read_access = AccessFs::from_read(abi);
        let write_access = AccessFs::from_all(abi);
        for fd in &read_fds {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access))
                .map_err(|_| LandlockError::RulesetBuildFailed {
                    step: "add_rule_read",
                })?;
        }
        for fd in &write_fds {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, write_access))
                .map_err(|_| LandlockError::RulesetBuildFailed {
                    step: "add_rule_write",
                })?;
        }

        // 阶段 4:注入 pre_exec(子进程只做 restrict_self + status 校验)。
        //
        // SAFETY:pre_exec 闭包必须 async-signal-safe。本实装仅:
        // - `Option::take()`:内部是指针 swap,不分配
        // - `RulesetCreated::restrict_self()`:内部仅调 `prctl(PR_SET_NO_NEW_PRIVS)` +
        //   `landlock_restrict_self` syscall,async-signal-safe
        // - `io::Error::from_raw_os_error(LANDLOCK_PRE_EXEC_ERRNO)`:静态 errno 常量
        //   (libc::EPROTO),不分配字符串,不 panic
        //
        // 保留 FD 生命周期由 ruleset Option::Some(...) 持有;fork 时子进程继承 FD,
        // ruleset add_rule 阶段 landlock crate 通过 landlock_add_rule syscall 把
        // PathBeneath 转为内核内部引用,restrict_self 只需 ruleset fd 本身。
        let mut ruleset_opt: Option<RulesetCreated> = Some(ruleset);
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                let rs = ruleset_opt
                    .take()
                    .ok_or_else(|| std::io::Error::from_raw_os_error(LANDLOCK_PRE_EXEC_ERRNO))?;
                let status = rs
                    .restrict_self()
                    .map_err(|_| std::io::Error::from_raw_os_error(LANDLOCK_PRE_EXEC_ERRNO))?;
                match status.ruleset {
                    RulesetStatus::FullyEnforced => Ok(()),
                    _ => Err(std::io::Error::from_raw_os_error(LANDLOCK_PRE_EXEC_ERRNO)),
                }
            });
        }
        // FD 容器可以在此 drop —— `add_rule` 阶段 landlock crate 已通过 landlock_add_rule
        // syscall 把规则登记进 ruleset 内核表,后续只依赖 ruleset fd 本身(在 `ruleset_opt`
        // 里由闭包捕获)。显式 `drop` 让生命周期意图清晰(非功能需要)。
        drop(read_fds);
        drop(write_fds);
        Ok(())
    }
}

fn open_path_fd(path: &Path) -> Result<PathFd, LandlockError> {
    PathFd::new(path).map_err(|_| LandlockError::PathOpenFailed(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_from_dirs_stores_paths_without_io() {
        let policy = LandlockPolicy::from_dirs(
            vec!["/nonexistent/read"],
            vec!["/nonexistent/write1", "/nonexistent/write2"],
        );
        assert_eq!(policy.read_paths.len(), 1);
        assert_eq!(policy.write_paths.len(), 2);
    }

    #[test]
    fn kernel_support_check_is_stable() {
        let _ = kernel_supports_landlock();
    }

    #[test]
    fn install_into_nonexistent_path_returns_path_open_failed() {
        if !kernel_supports_landlock() {
            return;
        }
        let policy =
            LandlockPolicy::from_dirs(vec!["/definitely/does/not/exist/read"], Vec::<&str>::new());
        let mut cmd = std::process::Command::new("/bin/true");
        // crate 级 clippy::unwrap_used = warn(CI -D warnings 升 deny);直接 matches! 断言 Err,
        // 不用 unwrap_err。
        assert!(matches!(
            policy.install_into(&mut cmd),
            Err(LandlockError::PathOpenFailed(_))
        ));
    }

    #[test]
    fn install_into_on_unsupported_kernel_returns_not_supported() {
        if kernel_supports_landlock() {
            return;
        }
        let policy = LandlockPolicy::from_dirs(Vec::<&str>::new(), Vec::<&str>::new());
        let mut cmd = std::process::Command::new("/bin/true");
        assert!(matches!(
            policy.install_into(&mut cmd),
            Err(LandlockError::NotSupported)
        ));
    }

    #[test]
    fn pre_exec_errno_is_eproto() {
        // 固定契约:pre_exec 失败时 io::Error 的 raw_os_error == libc::EPROTO
        // 父进程 spawn_native 依赖此常量区分 landlock 失败 vs 通用 spawn 失败
        assert_eq!(LANDLOCK_PRE_EXEC_ERRNO, libc::EPROTO);
    }
}
