//! EffectExtractor trait + 7 个内置实装。
//!
//! 每个 extractor 负责把 `ToolInvocation.args` 中属于自己领域的结构化字段解出,
//! 并合并到 `EffectVector`。多个 extractor 的结果以**合并**的方式叠加 —— 一次
//! tool call 可能同时触发 fs / net / secret / comm 等多种效应。

use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use url::Url;
use vigil_types::{EffectKind, EffectVector, ToolInvocation};

/// 抽取器统一接口。
pub trait EffectExtractor: Send + Sync {
    /// 人读名称,用于审计与日志。
    fn name(&self) -> &'static str;
    /// 从一次调用中抽取效应,叠加到 `out`。**不得**清空已有字段。
    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector);
}

/// Path 抽取器 —— 处理文件读写。
///
/// 输入形态(按优先级查找):
/// - `args.path` 字符串
/// - `args.paths` 字符串数组
/// - `args.src` / `args.dst` / `args.file` / `args.target` 等常见别名
///
/// 写/读由 tool_name 启发或 `args.mode` 决定:
/// - tool_name 含 `write` / `create` / `edit` / `patch` / `delete` / `unlink` / `rm` → 写
/// - 默认(或含 `read` / `cat` / `show` / `list`)→ 读
///
/// 规范化:相对路径基于 `project_roots[0]`(若提供),绝对路径走 `dunce::canonicalize`
/// 尝试真实解析;解析失败(文件不存在时)至少做 `..` 展开与 POSIX 化。
#[derive(Debug)]
pub struct PathExtractor {
    /// 用作相对路径基准与跨平台 canonicalization 的参考根。
    pub project_roots: Vec<PathBuf>,
}

impl PathExtractor {
    /// 构造。`project_roots` 可空(此时所有相对路径被标为"无法定位",仍然会被
    /// 下游策略的 Outside 条件视为越界)。
    pub fn new(project_roots: Vec<PathBuf>) -> Self {
        Self { project_roots }
    }

    fn collect_paths(&self, args: &Value) -> Vec<String> {
        let mut out = Vec::new();
        const KEYS: &[&str] = &[
            "path",
            "paths",
            "file",
            "files",
            "src",
            "source",
            "dst",
            "destination",
            "target",
            "input",
            "output",
        ];
        for k in KEYS {
            match args.get(*k) {
                Some(Value::String(s)) => out.push(s.clone()),
                Some(Value::Array(a)) => {
                    for v in a {
                        if let Value::String(s) = v {
                            out.push(s.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn canonicalize(&self, raw: &str) -> String {
        let p = Path::new(raw);
        let abs: PathBuf = if p.is_absolute() {
            p.to_path_buf()
        } else if let Some(root) = self.project_roots.first() {
            root.join(p)
        } else {
            p.to_path_buf()
        };
        // 先尝试真实解析 —— 若文件存在,解出符号链接 / `..`;不存在时退回手工 `..` 展开
        let normalized = dunce::canonicalize(&abs).unwrap_or_else(|_| manual_normalize(&abs));
        to_posix(&normalized)
    }
}

/// 判定一次调用是读还是写(启发式)。
fn is_write_call(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    for kw in [
        "write", "create", "edit", "patch", "delete", "unlink", "rm", "move", "rename", "append",
        "chmod", "chown", "mkdir",
    ] {
        if lower.contains(kw) {
            return true;
        }
    }
    false
}

impl EffectExtractor for PathExtractor {
    fn name(&self) -> &'static str {
        "PathExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        let paths = self.collect_paths(&call.args);
        if paths.is_empty() {
            return;
        }
        let norm: Vec<String> = paths.iter().map(|p| self.canonicalize(p)).collect();
        if is_write_call(&call.tool_name) {
            out.effects.push(EffectKind::FsWrite);
            out.paths_write.extend(norm);
        } else {
            out.effects.push(EffectKind::FsRead);
            out.paths_read.extend(norm);
        }
    }
}

/// URL 抽取器 —— 网络出站。
#[derive(Debug)]
pub struct UrlExtractor;

impl EffectExtractor for UrlExtractor {
    fn name(&self) -> &'static str {
        "UrlExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        let mut hosts = Vec::new();
        for k in ["url", "endpoint", "uri"] {
            if let Some(Value::String(s)) = call.args.get(k) {
                if let Ok(u) = Url::parse(s) {
                    if let Some(h) = u.host_str() {
                        hosts.push(h.to_ascii_lowercase());
                    }
                }
            }
        }
        // 也看 urls/[]
        if let Some(Value::Array(a)) = call.args.get("urls") {
            for v in a {
                if let Value::String(s) = v {
                    if let Ok(u) = Url::parse(s) {
                        if let Some(h) = u.host_str() {
                            hosts.push(h.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
        if !hosts.is_empty() {
            out.effects.push(EffectKind::NetOutbound);
            out.network_hosts.extend(hosts);
        }
    }
}

/// SQL 抽取器 —— 识别破坏性语句。
///
/// 不做完整 SQL 解析,只做**关键词**检测。`args.sql` / `args.query` / `args.statement`
/// 中若含 `DELETE`、`DROP`、`TRUNCATE`、`ALTER`、`UPDATE` 任一关键字(且不是 `SELECT`
/// 子句),置 `DbWrite + destructive`。
#[derive(Debug)]
pub struct SqlExtractor;

static DESTRUCTIVE_SQL: Lazy<Regex> = Lazy::new(|| {
    // 行首或 ';' 后的首词,排除在 SELECT ... FROM 子查询内
    Regex::new(r"(?i)\b(DELETE|DROP|TRUNCATE|ALTER|UPDATE|REPLACE)\b").expect("regex")
});

static READ_ONLY_SQL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*(SELECT|SHOW|DESCRIBE|EXPLAIN|WITH)\b").expect("regex"));

impl EffectExtractor for SqlExtractor {
    fn name(&self) -> &'static str {
        "SqlExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        for k in ["sql", "query", "statement"] {
            if let Some(Value::String(s)) = call.args.get(k) {
                if READ_ONLY_SQL.is_match(s) && !DESTRUCTIVE_SQL.is_match(s) {
                    out.effects.push(EffectKind::DbRead);
                } else if DESTRUCTIVE_SQL.is_match(s) {
                    out.effects.push(EffectKind::DbWrite);
                    out.destructive = true;
                } else {
                    // 非显式识别的 SQL:保守视为 DbWrite 不破坏
                    out.effects.push(EffectKind::DbWrite);
                }
            }
        }
    }
}

/// Shell 抽取器 —— `argv` 与命令行字符串,识别破坏性二进制与保护路径命中。
///
/// 输入:
/// - `args.argv`: `Vec<String>`(首选)
/// - `args.command`: `String`(POSIX 字符串,由 shlex 分词)
///
/// 行为:
/// - 识别到破坏性二进制 → `destructive=true` + push `ExecNative`
/// - 识别 shell metacharacter → `requires_shell=true`,也置 `destructive=true`
///   (ADR 0003 §D2:模糊路径 fail-closed)
/// - 否则 push `ExecNative`(但不 destructive)
#[derive(Debug)]
pub struct ShellExtractor;

/// 破坏性二进制(按 argv[0] basename 比较,去扩展名前的形式)。
const DESTRUCTIVE_BINARIES: &[&str] = &[
    "rm", "rmdir", "shred", "mkfs", "fdisk", "format", "del", "dd", "srm", "erase",
];

/// **包装 shell** 类二进制 —— 当它们作为 argv[0] 且携带 "-c" 类参数时,
/// 我们无法在不展开整条 shell 脚本的前提下安全判定,**一律 fail-closed destructive**。
/// 与 ADR 0003 §D2 "不做完整 shell 解析" 一致。
const SHELL_WRAPPERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "dash",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

/// wrapper 常见的"后跟字符串即执行"选项。出现这些中的任何一个即 fail-closed。
const SHELL_EVAL_FLAGS: &[&str] = &["-c", "-lc", "-Command", "/c", "/C", "-Cmd", "--command"];

/// 高危路径前缀(命中即 destructive)。
const PROTECTED_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/usr",
    "/var",
    "/bin",
    "/sbin",
    "/boot",
    "/sys",
    "/proc",
    "~",
    "~/.ssh",
    "~/.config",
    "~/.aws",
    "~/.docker",
    "C:\\",
    "C:\\Windows",
    "%SystemRoot%",
    "%USERPROFILE%\\.ssh",
];

const SHELL_METACHARS: &[&str] = &[
    "&&", "||", "|", "&", ";", ">", ">>", "<", "<<", "$(", "`", "\\\n",
];

impl EffectExtractor for ShellExtractor {
    fn name(&self) -> &'static str {
        "ShellExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        // 提取 argv
        let argv: Vec<String> = if let Some(Value::Array(a)) = call.args.get("argv") {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(Value::String(s)) = call.args.get("command") {
            // shlex 分词;分词失败按含 metachar 处理
            match shlex::split(s) {
                Some(v) if !v.is_empty() => v,
                _ => {
                    // 分词失败 → fail-closed
                    out.effects.push(EffectKind::ExecNative);
                    out.destructive = true;
                    return;
                }
            }
        } else {
            return;
        };

        if argv.is_empty() {
            return;
        }

        out.effects.push(EffectKind::ExecNative);

        // 1) 检查是否含 shell metachar(任何一处命中即 destructive)
        let full = argv.join(" ");
        let has_meta = SHELL_METACHARS.iter().any(|m| full.contains(m));

        // 2) wrapper + -c/-Command 形式的"嵌套 shell":一律 fail-closed
        //    (ADR 0003 §D2:"模糊 shell 一律 destructive")
        let bin_lower = basename(&argv[0]).to_ascii_lowercase();
        let strip_ext = |s: &str| -> String { s.strip_suffix(".exe").unwrap_or(s).to_string() };
        let bin_noexe = strip_ext(&bin_lower);
        let is_wrapper = SHELL_WRAPPERS
            .iter()
            .any(|w| strip_ext(w) == bin_noexe || *w == bin_lower);
        let has_eval_flag = argv
            .iter()
            .skip(1)
            .any(|a| SHELL_EVAL_FLAGS.iter().any(|f| a == f));
        // wrapper 后任何含空格的字符串参数也视作"嵌套脚本"(如 cmd 的 /c)
        let wrapper_with_script = is_wrapper
            && (has_eval_flag
                || argv
                    .iter()
                    .skip(1)
                    .any(|a| a.contains(' ') || a.contains('\n')));

        // 3) 检查破坏性二进制
        let is_destructive_bin = DESTRUCTIVE_BINARIES
            .iter()
            .any(|d| bin_noexe == *d || bin_lower == *d);
        let rm_dangerous =
            is_destructive_bin && argv.iter().any(|a| a == "-rf" || a == "-fr" || a == "-r");

        // 4) 检查保护路径
        let hits_protected = argv
            .iter()
            .any(|a| PROTECTED_PATHS.iter().any(|p| path_hits_protected(a, p)));

        if has_meta || wrapper_with_script || is_destructive_bin || rm_dangerous || hits_protected {
            out.destructive = true;
        }
    }
}

/// Email / comm 抽取器。
#[derive(Debug)]
pub struct EmailExtractor;

impl EffectExtractor for EmailExtractor {
    fn name(&self) -> &'static str {
        "EmailExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        let mut recipients = Vec::new();
        for k in ["to", "cc", "bcc", "recipients"] {
            match call.args.get(k) {
                Some(Value::String(s)) => recipients.push(s.clone()),
                Some(Value::Array(a)) => {
                    for v in a {
                        if let Value::String(s) = v {
                            recipients.push(s.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        if !recipients.is_empty() {
            out.effects.push(EffectKind::CommSend);
            out.recipients.extend(recipients);
        }
    }
}

/// Secret ref 抽取器 —— 识别 `secret://...` 引用。
#[derive(Debug)]
pub struct SecretRefExtractor;

static SECRET_REF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"secret://[A-Za-z0-9._\-/]+").expect("regex"));

impl EffectExtractor for SecretRefExtractor {
    fn name(&self) -> &'static str {
        "SecretRefExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        let s = call.args.to_string(); // 对整个 args JSON 扫描
        let mut refs = Vec::new();
        for m in SECRET_REF_RE.find_iter(&s) {
            refs.push(m.as_str().to_string());
        }
        if !refs.is_empty() {
            out.effects.push(EffectKind::SecretUse);
            out.secret_refs.extend(refs);
        }
    }
}

/// 浏览器动作抽取器。
#[derive(Debug)]
pub struct BrowserActionExtractor;

impl EffectExtractor for BrowserActionExtractor {
    fn name(&self) -> &'static str {
        "BrowserActionExtractor"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        // 输入形态:args.action = "submit"|"click"|...; args.origin = "https://..."
        let is_browser_tool = call.tool_name.to_ascii_lowercase().contains("browser");
        let action = call.args.get("action").and_then(Value::as_str);
        if is_browser_tool {
            match action {
                Some("submit") | Some("fill_form") | Some("post") => {
                    out.effects.push(EffectKind::BrowserSubmit);
                    if let Some(Value::String(origin)) = call.args.get("origin") {
                        if let Ok(u) = Url::parse(origin) {
                            if let Some(h) = u.host_str() {
                                out.network_hosts.push(h.to_ascii_lowercase());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// ---------------- 辅助 ----------------

fn basename(p: &str) -> &str {
    // 不用 std::path::Path —— 要把 Windows `\` 和 POSIX `/` 都当分隔符
    let idx_slash = p.rfind('/').map(|i| i + 1).unwrap_or(0);
    let idx_back = p.rfind('\\').map(|i| i + 1).unwrap_or(0);
    let start = idx_slash.max(idx_back);
    &p[start..]
}

fn path_hits_protected(arg: &str, protected: &str) -> bool {
    // 简化匹配:arg 去掉引号后,与 protected 相等或以 protected + "/" 开头
    let a = arg.trim_matches(|c| c == '\'' || c == '"');
    let p = protected;
    a == p || a.starts_with(&format!("{}/", p)) || a.starts_with(&format!("{}\\", p))
}

/// DEF-004:把 project root 归一成与 [`PathExtractor`] 输出同款的 POSIX 风格规范化字符串。
///
/// serve/wrap CLI 入口用它处理 `--project-root`(含 CWD 缺省),保证 root 与 effect
/// 提取出的 `paths_write` 前缀**可比**:Windows 下 `dunce::canonicalize` 解出真实
/// 盘符/大小写 + 剥 `\\?\` 前缀 + `\`→`/`。不经此归一,`is_under` 的前缀比较会因
/// 分隔符/前缀差异静默不匹配 → 边界配置形同虚设(这是 DEF-004 最易错处)。
///
/// 相对路径先基于 CWD 变绝对(canonicalize 失败时退手工 `..` 展开,不强求目录存在)。
///
/// 边界情形:root 真实存在时 canonicalize 会**解出 symlink**,而新建文件的写目标走
/// `manual_normalize`(不解 symlink)—— 经 symlink 访问的项目根可能导致项目内写被误判
/// Outside(false-deny,fail-closed 方向,非绕过)。此时请把真实路径传给 `--project-root`。
pub fn normalize_project_root(p: &Path) -> String {
    let abs: PathBuf = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let normalized = dunce::canonicalize(&abs).unwrap_or_else(|_| manual_normalize(&abs));
    to_posix(&normalized)
}

fn manual_normalize(p: &Path) -> PathBuf {
    use std::path::Component::*;
    let mut out: Vec<std::path::Component> = Vec::new();
    for comp in p.components() {
        match comp {
            CurDir => {}
            ParentDir => {
                // 不允许越过 Prefix(Windows 盘符) / RootDir。
                // 之上的 `..` 视为 no-op:`/../x` → `/x`,对应 POSIX `realpath` 语义。
                match out.last() {
                    None | Some(Prefix(_)) | Some(RootDir) => {}
                    Some(ParentDir) => out.push(ParentDir), // 一串未解析的 ..,保留
                    _ => {
                        out.pop();
                    }
                }
            }
            _ => out.push(comp),
        }
    }
    if out.is_empty() {
        return PathBuf::from(".");
    }
    out.iter().collect()
}

fn to_posix(p: &Path) -> String {
    let s = p.to_string_lossy();
    // 剥除 Windows 长路径前缀
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_call(tool: &str, args: Value) -> ToolInvocation {
        ToolInvocation {
            invocation_id: "t".into(),
            session_id: "s".into(),
            server_id: "srv".into(),
            tool_name: tool.into(),
            args,
            descriptor_hash: "hash".into(),
            requested_at: 0,
        }
    }

    #[test]
    fn path_extractor_write_vs_read() {
        let e = PathExtractor::new(vec![PathBuf::from("/proj")]);
        let mut ev = EffectVector::default();
        e.extract(
            &mk_call("fs_read_file", json!({"path": "src/main.rs"})),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::FsRead));
        assert!(ev
            .paths_read
            .iter()
            .any(|p| p.ends_with("/proj/src/main.rs")));

        let mut ev = EffectVector::default();
        e.extract(
            &mk_call("fs_write_file", json!({"path": "README.md"})),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::FsWrite));
        assert!(ev
            .paths_write
            .iter()
            .any(|p| p.ends_with("/proj/README.md")));
    }

    #[test]
    fn path_extractor_resolves_dot_dot() {
        let e = PathExtractor::new(vec![PathBuf::from("/proj")]);
        let mut ev = EffectVector::default();
        e.extract(
            &mk_call("fs_read_file", json!({"path": "../../etc/passwd"})),
            &mut ev,
        );
        assert!(ev.paths_read.iter().any(|p| p == "/etc/passwd"));
    }

    #[test]
    fn url_extractor_detects_host() {
        let mut ev = EffectVector::default();
        UrlExtractor.extract(
            &mk_call(
                "http_get",
                json!({"url": "https://api.github.com/users/me"}),
            ),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::NetOutbound));
        assert_eq!(ev.network_hosts, vec!["api.github.com"]);
    }

    #[test]
    fn sql_destructive_vs_read() {
        let mut ev = EffectVector::default();
        SqlExtractor.extract(
            &mk_call("db_query", json!({"sql": "DELETE FROM users WHERE id=1"})),
            &mut ev,
        );
        assert!(ev.destructive);
        assert!(ev.effects.contains(&EffectKind::DbWrite));

        let mut ev = EffectVector::default();
        SqlExtractor.extract(
            &mk_call("db_query", json!({"sql": "SELECT * FROM t"})),
            &mut ev,
        );
        assert!(!ev.destructive);
        assert!(ev.effects.contains(&EffectKind::DbRead));
    }

    #[test]
    fn shell_rm_rf_is_destructive() {
        let mut ev = EffectVector::default();
        ShellExtractor.extract(
            &mk_call(
                "shell_run",
                json!({"argv": ["rm", "-rf", "/home/user/Downloads"]}),
            ),
            &mut ev,
        );
        assert!(ev.destructive);
        assert!(ev.effects.contains(&EffectKind::ExecNative));
    }

    #[test]
    fn shell_metacharacter_fails_closed() {
        let mut ev = EffectVector::default();
        ShellExtractor.extract(
            &mk_call("shell_run", json!({"command": "ls && rm -rf /"})),
            &mut ev,
        );
        assert!(
            ev.destructive,
            "shell metachar 必须 fail-closed 标 destructive"
        );
    }

    #[test]
    fn shell_protected_path_triggers() {
        let mut ev = EffectVector::default();
        ShellExtractor.extract(
            &mk_call("shell_run", json!({"argv": ["cat", "/etc/shadow"]})),
            &mut ev,
        );
        assert!(ev.destructive, "保护路径命中应标 destructive");
    }

    #[test]
    fn shell_safe_ls_not_destructive() {
        let mut ev = EffectVector::default();
        ShellExtractor.extract(
            &mk_call("shell_run", json!({"argv": ["ls", "-la"]})),
            &mut ev,
        );
        assert!(!ev.destructive);
        assert!(ev.effects.contains(&EffectKind::ExecNative));
    }

    #[test]
    fn email_extractor_collects_recipients() {
        let mut ev = EffectVector::default();
        EmailExtractor.extract(
            &mk_call(
                "send_email",
                json!({"to": "bob@example.com", "cc": ["alice@example.com"]}),
            ),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::CommSend));
        assert_eq!(ev.recipients.len(), 2);
    }

    #[test]
    fn secret_ref_extractor_finds_alias() {
        let mut ev = EffectVector::default();
        SecretRefExtractor.extract(
            &mk_call(
                "github_create_issue",
                json!({"auth": "secret://github/repo-write", "title": "x"}),
            ),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::SecretUse));
        assert_eq!(ev.secret_refs, vec!["secret://github/repo-write"]);
    }

    #[test]
    fn browser_submit_detected() {
        let mut ev = EffectVector::default();
        BrowserActionExtractor.extract(
            &mk_call(
                "browser_action",
                json!({"action": "submit", "origin": "https://chatgpt.com"}),
            ),
            &mut ev,
        );
        assert!(ev.effects.contains(&EffectKind::BrowserSubmit));
        assert_eq!(ev.network_hosts, vec!["chatgpt.com"]);
    }
}
