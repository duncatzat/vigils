//! Vigil Hub CLI — lib 面。
//!
//! 把 `add_remote::run_with_deps` + `Deps` 暴露给 **同 crate integration test**
//! (`tests/cli_add_remote.rs`)使用,同时保持 main binary 不变。
//!
//! 生产路径入口仍是 `main.rs` 的 clap parser;本 lib 不对外 crate 依赖。

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]
#![allow(missing_docs)]

pub mod add_remote;
pub mod inspect;
pub mod serve;

use std::path::PathBuf;
use std::time::Duration;

/// `add-remote-mcp` 的参数 —— 与 `main.rs` 的 clap `Args` 结构同构,
/// integration test 可直接构造。
#[derive(Debug, Clone)]
pub struct AddRemoteArgs {
    pub url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub ledger: PathBuf,
    pub timeout_secs: u64,
}

pub fn duration_secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
