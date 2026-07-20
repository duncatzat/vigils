//! `vigil-hub quickstart` —— 引导首跑(**只读**,不改任何配置)。
//!
//! 目的(M0 "5 分钟看到价值"):新用户装完不知道先跑什么。本命令一屏内回答三件事:
//! ①你机器上有哪些 AI agent、有多少 MCP server、几个已被 Vigil 保护(**真实检测**,复用
//! `setup --mcp` 的只读 preview 分类);②怎么 30 秒看到 Vigil 拦一次密钥外泄;③一条命令保护全部 +
//! 怎么查看/验证。**绝不改配置**(检测=只读 preview;真正接入仍须用户显式 `setup --all`)。
//!
//! 文案按系统语言本地化(i18n):静态行用 [`tr`] 中 / 英并排,带插值的行内联 `match lang`。

use std::path::Path;

use crate::i18n::Lang;
use crate::setup_mcp::{self, McpServerClass};

/// 单 agent 的 MCP server 分类计数。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    /// 已是 Vigil 托管(`AlreadyWrapped`)。
    protected: usize,
    /// stdio、可保护但尚未保护(`Wrappable`)。
    unprotected: usize,
    /// 非 stdio(http/sse)或形状异常,v1 不 wrap(`Skipped`)。
    skipped: usize,
}

impl Counts {
    fn total(&self) -> usize {
        self.protected + self.unprotected + self.skipped
    }
    fn add(self, o: Counts) -> Counts {
        Counts {
            protected: self.protected + o.protected,
            unprotected: self.unprotected + o.unprotected,
            skipped: self.skipped + o.skipped,
        }
    }
}

/// 收 `&McpServerClass` 迭代器(故 user-scope `Vec` 与 local-scope `(name, class)` 元组都能直接数,
/// 无需 clone)。
fn count_servers<'a>(servers: impl IntoIterator<Item = &'a McpServerClass>) -> Counts {
    let mut c = Counts::default();
    for s in servers {
        match s {
            McpServerClass::AlreadyWrapped { .. } => c.protected += 1,
            McpServerClass::Wrappable { .. } => c.unprotected += 1,
            McpServerClass::Skipped { .. } => c.skipped += 1,
        }
    }
    c
}

/// 按语言取静态文案(中 / 英并排;无插值的行用它,无额外分配)。
fn tr<'a>(lang: Lang, en: &'a str, zh: &'a str) -> &'a str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// 渲染一行 agent 摘要。`configured=false` → "not configured"(无配置文件 / 空 mcpServers)。
fn agent_line(lang: Lang, label: &str, configured: bool, c: Counts) -> String {
    if !configured || c.total() == 0 {
        return format!("    {label:<13} {}", tr(lang, "not configured", "未配置"));
    }
    let total = c.total();
    let mut parts = vec![match lang {
        Lang::En => format!("{total} MCP server{}", if total == 1 { "" } else { "s" }),
        Lang::Zh => format!("{total} 个 MCP 服务器"),
    }];
    parts.push(match lang {
        Lang::En => format!("{} protected", c.protected),
        Lang::Zh => format!("{} 个已保护", c.protected),
    });
    if c.unprotected > 0 {
        parts.push(match lang {
            Lang::En => format!("{} unprotected", c.unprotected),
            Lang::Zh => format!("{} 个未保护", c.unprotected),
        });
    }
    if c.skipped > 0 {
        // `Skipped` 含多种原因(http/sse 远程、配置形状异常等)—— 不再统称 http/sse
        // (F-4b:曾把「名字不合法」的 stdio server 错标成 http/sse,与 setup --mcp 预览矛盾)。
        parts.push(match lang {
            Lang::En => format!(
                "{} not wrappable (http/sse or unusual shape; see `vigil-hub setup --mcp`)",
                c.skipped
            ),
            Lang::Zh => format!(
                "{} 个暂不可保护(http/sse 或形状异常;详见 vigil-hub setup --mcp)",
                c.skipped
            ),
        });
    }
    format!("    {label:<13} {}", parts.join(" · "))
}

/// 一行"读取配置失败"提示(本地化)。
fn could_not_read(lang: Lang, label: &str, e: impl std::fmt::Display) -> String {
    match lang {
        Lang::En => format!("    {label:<13} could not read config ({e})"),
        Lang::Zh => format!("    {label:<13} 无法读取配置({e})"),
    }
}

/// 引导首跑主入口。始终返回 0(纯信息命令,不做判定)。
pub fn run(home: &Path, exe: &str, lang: Lang) -> i32 {
    println!();
    println!("  {}", tr(lang, "Vigil quickstart", "Vigil 快速上手"));
    println!("  {}", tr(lang, "────────────────", "──────────────"));
    match lang {
        Lang::En => {
            println!("  Vigil keeps secrets & PII out of your AI agents — locally, with a");
            println!("  tamper-evident audit. Here's where you stand and what to do next.");
        }
        Lang::Zh => {
            println!("  Vigil 把密钥与隐私数据挡在 AI agent 之外 —— 全程本地,并带防篡改审计。");
            println!("  下面是你当前的状况,以及接下来该做什么。");
        }
    }
    println!();

    // ── 1) 真实检测(只读 preview;绝不改配置)────────────────────────────
    println!(
        "  {}",
        tr(
            lang,
            "1) Your agents  (read-only — nothing was changed)",
            "1) 你的 agent  (只读 —— 未改动任何东西)",
        )
    );
    let mut total_unprotected = 0usize;
    // monitor 仅影响 preview 生成的 wrap argv(本命令不用,只数分类),传 true 任意。
    let monitor = true;

    // Claude Code:user scope + local scope(`projects.*`)都算。
    match setup_mcp::run_preview(home, exe, monitor) {
        Ok(r) => {
            // user scope(`servers`)+ local scope(`projects.*` 的 `local_servers`)都算。
            let c = count_servers(&r.servers)
                .add(count_servers(r.local_servers.iter().map(|(_, sv)| sv)));
            println!("{}", agent_line(lang, "Claude Code", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("{}", could_not_read(lang, "Claude Code", e)),
    }

    // Codex(`$CODEX_HOME/config.toml`)。生产 env 快照只在此入口读一次(库函数注入式)。
    let agent_env = setup_mcp::AgentEnv::from_process_env();
    match setup_mcp::run_codex_preview(home, agent_env.codex_home.as_deref(), exe, monitor) {
        Ok(r) => {
            let c = count_servers(&r.servers);
            println!("{}", agent_line(lang, "Codex", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("{}", could_not_read(lang, "Codex", e)),
    }

    // ZCode(`~/.zcode/cli/config.json` 嵌套 `mcp.servers` 专线)。
    match setup_mcp::run_zcode_preview(home, exe, monitor) {
        Ok(r) => {
            let c = count_servers(&r.servers);
            println!("{}", agent_line(lang, "ZCode", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("{}", could_not_read(lang, "ZCode", e)),
    }

    // Grok(`~/.grok/config.toml` TOML 专线,与 Codex 同构)。
    match setup_mcp::run_grok_preview(home, exe, monitor) {
        Ok(r) => {
            let c = count_servers(&r.servers);
            println!("{}", agent_line(lang, "Grok CLI", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("{}", could_not_read(lang, "Grok CLI", e)),
    }

    // OpenCode(`~/.config/opencode/opencode.json` `mcp.<name>` 数组形态专线)。
    match setup_mcp::run_opencode_preview(home, exe, monitor) {
        Ok(r) => {
            let c = count_servers(&r.servers);
            println!("{}", agent_line(lang, "OpenCode", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("{}", could_not_read(lang, "OpenCode", e)),
    }

    // 全部 JSON `mcpServers` 形态 agent(registry SSOT:Cursor / Windsurf / Kimi / pi /
    // Gemini / CodeBuddy / Cline)。
    for agent in setup_mcp::all_json_mcp_agents(home, &agent_env) {
        match setup_mcp::run_json_agent_preview(&agent, exe, monitor) {
            Ok(r) => {
                let c = count_servers(&r.servers);
                println!("{}", agent_line(lang, agent.display_name, c.total() > 0, c));
                total_unprotected += c.unprotected;
            }
            Err(e) => println!("{}", could_not_read(lang, agent.display_name, e)),
        }
    }
    println!();
    if total_unprotected > 0 {
        match lang {
            Lang::En => println!(
                "     → {total_unprotected} MCP server{} are NOT yet protected by Vigil (firewall + redaction + audit).",
                if total_unprotected == 1 { "" } else { "s" }
            ),
            Lang::Zh => println!(
                "     → 有 {total_unprotected} 个 MCP 服务器还没受 Vigil 保护(防火墙 + 脱敏 + 审计)。"
            ),
        }
    } else {
        match lang {
            Lang::En => println!(
                "     → No unprotected stdio MCP servers detected. (Run the demo anyway to see how it works.)"
            ),
            Lang::Zh => println!(
                "     → 没检测到未受保护的 stdio MCP 服务器。(也可以跑下 demo 看看它怎么工作。)"
            ),
        }
    }
    println!();

    // ── 2) 看它工作 ───────────────────────────────────────────────────
    println!(
        "  {}",
        tr(
            lang,
            "2) See it work  (≈30s, no setup, contacts no LLM)",
            "2) 看它工作  (约 30 秒,零配置,不联系任何 LLM)",
        )
    );
    println!("       vigil-hub demo");
    println!();

    // ── 3) 保护(显式;quickstart 自身从不改配置)────────────────────────
    println!(
        "  {}",
        tr(
            lang,
            "3) Protect every detected agent  (one command, reversible)",
            "3) 保护检测到的每个 agent  (一条命令,可逆)",
        )
    );
    println!("       vigil-hub setup --all");
    println!(
        "     {}",
        tr(
            lang,
            "Preview the exact changes first, without writing anything:",
            "想先看清具体会改什么、且不写任何文件:",
        )
    );
    println!("       vigil-hub setup --mcp");
    println!();

    // ── 4) 查看 / 验证 ────────────────────────────────────────────────
    println!("  {}", tr(lang, "4) Watch & verify", "4) 查看与验证"));
    println!(
        "       vigil-hub setup --mcp --doctor    # {}",
        tr(
            lang,
            "health-check every agent",
            "检查每个 agent 的接入是否正常",
        )
    );
    println!(
        "       vigil-hub verify                  # {}",
        tr(
            lang,
            "verify the audit log is intact and untampered",
            "验证审计记录完整、未被篡改",
        )
    );
    println!(
        "     {}",
        tr(
            lang,
            "…or open the Vigils desktop app for the live Protection Overview.",
            "…或打开 Vigils 桌面应用查看实时「防护总览」。",
        )
    );
    println!();
    println!(
        "  {}",
        tr(
            lang,
            "Everything runs on your machine. Nothing leaves it.",
            "全程在你的机器上运行。数据不外泄。",
        )
    );
    println!();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_servers_classifies_each_variant() {
        let servers = vec![
            McpServerClass::AlreadyWrapped { name: "a".into() },
            McpServerClass::Wrappable {
                name: "b".into(),
                command: "npx".into(),
                args: vec![],
                env_keys: vec![],
            },
            McpServerClass::Skipped {
                name: "c".into(),
                reason: "non-stdio",
            },
            McpServerClass::Wrappable {
                name: "d".into(),
                command: "uvx".into(),
                args: vec![],
                env_keys: vec![],
            },
        ];
        let c = count_servers(&servers);
        assert_eq!(c.protected, 1);
        assert_eq!(c.unprotected, 2);
        assert_eq!(c.skipped, 1);
        assert_eq!(c.total(), 4);
    }

    #[test]
    fn agent_line_renders_not_configured_for_empty() {
        // En:既有英文断言不变(传 Lang::En)。
        let line = agent_line(Lang::En, "Codex", false, Counts::default());
        assert!(line.contains("not configured"), "got: {line}");
        // 即便 configured=true 但全 0 也算 not configured(无 server)。
        let line2 = agent_line(Lang::En, "Codex", true, Counts::default());
        assert!(line2.contains("not configured"), "got: {line2}");
        // Zh:对应中文文案。
        let zh = agent_line(Lang::Zh, "Codex", false, Counts::default());
        assert!(zh.contains("未配置"), "got: {zh}");
    }

    #[test]
    fn agent_line_renders_protection_breakdown() {
        let c = Counts {
            protected: 1,
            unprotected: 3,
            skipped: 0,
        };
        let line = agent_line(Lang::En, "Claude Code", true, c);
        assert!(line.contains("4 MCP servers"), "got: {line}");
        assert!(line.contains("1 protected"), "got: {line}");
        assert!(line.contains("3 unprotected"), "got: {line}");
        // Zh:同一计数的中文渲染。
        let zh = agent_line(Lang::Zh, "Claude Code", true, c);
        assert!(zh.contains("4 个 MCP 服务器"), "got: {zh}");
        assert!(zh.contains("1 个已保护"), "got: {zh}");
        assert!(zh.contains("3 个未保护"), "got: {zh}");
    }
}
