//! Codex prompt guard 的一次性放行与限时暂停状态。
//!
//! 状态只保存 prompt SHA-256、规则名与过期时间，绝不保存 prompt 原文。所有修改在
//! 跨进程 lock-file 内完成；读取、解析或加锁失败时，hook 必须继续执行原有拦截。

use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const VIGIL_SUBDIR: &str = "Vigil";
const STATE_FILENAME: &str = "prompt-guard.json";
const STATE_VERSION: u64 = 1;
pub const ALLOW_ONCE_TTL_SECS: u64 = 60;
pub const DEFAULT_PAUSE_SECS: u64 = 300;
pub const MAX_PAUSE_SECS: u64 = 900;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedPrompt {
    pub prompt_sha256: String,
    pub session_id: Option<String>,
    pub finding: String,
    pub blocked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AllowOnce {
    prompt_sha256: String,
    session_id: Option<String>,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateFile {
    version: u64,
    #[serde(default)]
    pause_until: Option<u64>,
    #[serde(default)]
    allow_once: Option<AllowOnce>,
    #[serde(default)]
    last_blocked: Option<BlockedPrompt>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            pause_until: None,
            allow_once: None,
            last_blocked: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PromptGuardStatus {
    pub paused_until: Option<u64>,
    pub allow_once_expires_at: Option<u64>,
    pub last_blocked: Option<BlockedPrompt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptDecision {
    Enforce,
    AllowOnce,
    Paused,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn default_state_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join(VIGIL_SUBDIR).join(STATE_FILENAME))
}

fn read_state(path: &Path) -> std::io::Result<StateFile> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let state: StateFile = serde_json::from_str(&raw).map_err(|_| {
                Error::new(ErrorKind::InvalidData, "prompt guard state is malformed")
            })?;
            if state.version != STATE_VERSION {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "prompt guard state version is unsupported",
                ));
            }
            Ok(state)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(StateFile::default()),
        Err(e) => Err(e),
    }
}

fn write_state(path: &Path, state: &StateFile) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut rendered = serde_json::to_string_pretty(state)?;
    rendered.push('\n');
    let tmp = path.with_extension("json.vigil-tmp");
    if let Err(e) = std::fs::write(&tmp, rendered) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

struct StateLock {
    path: PathBuf,
    _file: File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_lock(path: &Path) -> std::io::Result<StateLock> {
    let lock_path = path.with_extension("json.lock");
    if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    for _ in 0..50 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => {
                return Ok(StateLock {
                    path: lock_path,
                    _file: file,
                });
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::WouldBlock,
        "prompt guard state is busy",
    ))
}

fn with_locked_state<T>(
    path: &Path,
    f: impl FnOnce(&mut StateFile) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let _lock = acquire_lock(path)?;
    let mut state = read_state(path)?;
    let result = f(&mut state)?;
    write_state(path, &state)?;
    Ok(result)
}

pub fn status(path: &Path, now: u64) -> std::io::Result<PromptGuardStatus> {
    let state = read_state(path)?;
    Ok(PromptGuardStatus {
        paused_until: state.pause_until.filter(|until| *until > now),
        allow_once_expires_at: state
            .allow_once
            .as_ref()
            .map(|permit| permit.expires_at)
            .filter(|until| *until > now),
        last_blocked: state.last_blocked,
    })
}

pub fn record_blocked(
    path: &Path,
    prompt_sha256: &str,
    session_id: Option<&str>,
    finding: &str,
    now: u64,
) -> std::io::Result<()> {
    with_locked_state(path, |state| {
        state.last_blocked = Some(BlockedPrompt {
            prompt_sha256: prompt_sha256.to_string(),
            session_id: session_id.map(str::to_string),
            finding: finding.to_string(),
            blocked_at: now,
        });
        Ok(())
    })
}

pub fn allow_last_blocked(path: &Path, now: u64) -> std::io::Result<PromptGuardStatus> {
    with_locked_state(path, |state| {
        let blocked = state.last_blocked.clone().ok_or_else(|| {
            Error::new(ErrorKind::NotFound, "there is no blocked prompt to allow")
        })?;
        state.allow_once = Some(AllowOnce {
            prompt_sha256: blocked.prompt_sha256,
            session_id: blocked.session_id,
            expires_at: now.saturating_add(ALLOW_ONCE_TTL_SECS),
        });
        Ok(PromptGuardStatus {
            paused_until: state.pause_until.filter(|until| *until > now),
            allow_once_expires_at: Some(now.saturating_add(ALLOW_ONCE_TTL_SECS)),
            last_blocked: state.last_blocked.clone(),
        })
    })
}

pub fn pause(path: &Path, now: u64, seconds: u64) -> std::io::Result<PromptGuardStatus> {
    if seconds == 0 || seconds > MAX_PAUSE_SECS {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("pause must be between 1 and {MAX_PAUSE_SECS} seconds"),
        ));
    }
    with_locked_state(path, |state| {
        state.pause_until = Some(now.saturating_add(seconds));
        Ok(PromptGuardStatus {
            paused_until: state.pause_until,
            allow_once_expires_at: state.allow_once.as_ref().map(|p| p.expires_at),
            last_blocked: state.last_blocked.clone(),
        })
    })
}

pub fn resume(path: &Path, _now: u64) -> std::io::Result<PromptGuardStatus> {
    with_locked_state(path, |state| {
        state.pause_until = None;
        state.allow_once = None;
        Ok(PromptGuardStatus {
            paused_until: None,
            allow_once_expires_at: None,
            last_blocked: state.last_blocked.clone(),
        })
    })
}

pub fn check_and_consume(
    path: &Path,
    prompt_sha256: &str,
    session_id: Option<&str>,
    now: u64,
) -> std::io::Result<PromptDecision> {
    with_locked_state(path, |state| {
        if state.pause_until.is_some_and(|until| until > now) {
            return Ok(PromptDecision::Paused);
        }
        state.pause_until = None;

        let matches = state.allow_once.as_ref().is_some_and(|permit| {
            permit.expires_at > now
                && permit.prompt_sha256 == prompt_sha256
                && permit.session_id.as_deref() == session_id
        });
        if matches {
            state.allow_once = None;
            return Ok(PromptDecision::AllowOnce);
        }
        if state
            .allow_once
            .as_ref()
            .is_some_and(|permit| permit.expires_at <= now)
        {
            state.allow_once = None;
        }
        Ok(PromptDecision::Enforce)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_once_matches_exact_hash_and_session_then_is_consumed() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("prompt-guard.json");
        record_blocked(&path, "a", Some("s1"), "env_assignment", 100).unwrap();
        allow_last_blocked(&path, 101).unwrap();

        assert_eq!(
            check_and_consume(&path, "a", Some("other"), 102).unwrap(),
            PromptDecision::Enforce
        );
        assert_eq!(
            check_and_consume(&path, "a", Some("s1"), 102).unwrap(),
            PromptDecision::AllowOnce
        );
        assert_eq!(
            check_and_consume(&path, "a", Some("s1"), 102).unwrap(),
            PromptDecision::Enforce
        );
    }

    #[test]
    fn expired_permit_does_not_allow() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("prompt-guard.json");
        record_blocked(&path, "a", None, "github_token", 100).unwrap();
        allow_last_blocked(&path, 100).unwrap();
        assert_eq!(
            check_and_consume(&path, "a", None, 161).unwrap(),
            PromptDecision::Enforce
        );
    }

    #[test]
    fn pause_expires_and_resume_clears_bypasses() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("prompt-guard.json");
        pause(&path, 100, 300).unwrap();
        assert_eq!(
            check_and_consume(&path, "anything", None, 399).unwrap(),
            PromptDecision::Paused
        );
        assert_eq!(
            check_and_consume(&path, "anything", None, 400).unwrap(),
            PromptDecision::Enforce
        );
        pause(&path, 500, 300).unwrap();
        resume(&path, 501).unwrap();
        assert_eq!(
            check_and_consume(&path, "anything", None, 502).unwrap(),
            PromptDecision::Enforce
        );
    }

    #[test]
    fn malformed_state_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("prompt-guard.json");
        std::fs::write(&path, "not-json").unwrap();
        assert!(check_and_consume(&path, "a", None, 1).is_err());
    }
}
