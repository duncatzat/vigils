<!-- 本文件与 README.md(英文,权威源)逐节对齐;若两者不一致,以 README.md 为准。 -->

<div align="center">

# Vigils

### 面向 AI Agent 的本地优先控制平面 —— 看见它们做了什么、审批要紧的、把凭据挡在外面。

[![CI](https://github.com/duncatzat/vigils/actions/workflows/ci.yml/badge.svg)](https://github.com/duncatzat/vigils/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/duncatzat/vigils?sort=semver&color=blue)](https://github.com/duncatzat/vigils/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#安装)

[官网](https://vigils.ai) · [快速开始](#快速开始) · [架构](#架构) · [安全模型](#安全模型) · [文档](#文档)

[English](./README.md) | **简体中文**

</div>

---

AI Agent(Claude Code、Cursor、Zed、MCP 客户端、浏览器助手)会代你调用工具、读文件、请求
API、往网页里粘贴。这种能力很有用 —— 也有风险。**Vigils 位于你的 Agent 与它们所触及的
工具/数据之间**,且是 *本地优先* 的:你的 prompt、密钥与审计记录永不离开本机。

```
   AI agent ──▶  ┌─────────────────── Vigils ───────────────────┐  ──▶  tools / data
 (MCP client)    │  redact → firewall → approve → sandbox → audit │       (MCP servers,
                 └───────────────────────────────────────────────┘        files, APIs, web)
```

## 为什么选 Vigils

四项保证,全部在本地强制执行:

| 保证 | 如何实现 |
|---|---|
| **看见 Agent 做了什么** | 每次工具调用都记入防篡改的 **SHA-256 哈希链账本**,支持全文检索。 |
| **高危动作先审批** | 破坏性 / 敏感调用在 **Approval Queue** 暂停,交人工审核,支持按 Agent 策略与范围化授权。 |
| **凭据不进 prompt / 日志 / UI** | **脱敏引擎**在文本抵达模型、日志或屏幕*之前*,剥离密钥与 PII(硬指纹规则 + 可选 ML 集成)。 |
| **隔离与回滚** | 账本端到端可追溯,**沙箱 runner 默认 fail-closed**(Wasm + native + Linux Landlock)。 |

## 特性

- **🔒 防篡改审计账本** —— SQLite + SHA-256 哈希链;每个事件链接到前一个,篡改即可被检测。
  对脱敏后的轨迹做 FTS5 全文检索。
- **🛡️ 默认拒绝防火墙** —— 工具调用由 Rust 策略 DSL 门禁;按 Agent 规则;远程 MCP 走 OAuth
  scope 白名单。未经允许什么都不会执行。
- **✅ 人在回路审批** —— 高风险副作用(写文件、联网、破坏性操作)暂停审核。授权可范围化
  (本次 / 本会话)。
- **🙈 密钥与 PII 脱敏** —— 对 13+ 类凭据做硬指纹检测(GitHub PAT、Stripe key、Google/GitLab
  token、数据库 URL …),外加可选的多语言 ML 集成;由 fail-closed 合并层决定遮蔽什么。
- **🎟️ 凭据租约 broker** —— 短时凭据租约只注入到真正需要它的子进程;明文永不落盘。
- **📦 沙箱 runner** —— 在 Wasm(Wasmtime)或 native 进程中一次性执行工具,配 **Linux Landlock
  LSM** 文件系统隔离与 `env_clear`,子进程不继承你的环境。默认 fail-closed。
- **🔌 MCP 网关** —— 位于 MCP server 之前,支持 **stdio 与 HTTP**;descriptor pinning + 漂移
  检测(工具定义变化时告警);裸命令 stdio upstream(`npx`/`node`/`python`)在沙箱化前经
  宿主 PATH 解析。
- **🖥️ 桌面应用**(Tauri 2 + Vue 3)—— 审批队列、活动流、服务器注册、会话回放、隐私发现;
  键盘快捷键、浅色/深色/跟随系统主题、实时更新、中英双语 UI。
- **🌐 浏览器扩展**(Chrome MV3)—— 在 AI 站点(ChatGPT、Claude、Gemini、Perplexity)粘贴或
  提交*之前*脱敏密钥/PII。

## 架构

Vigils 是一个由聚焦单一职责的 crate 组成的 Rust workspace,外加三个 app。每一层都可独立
测试,由 **Hub**(MCP 网关)组合。

| 层 | Crate | 职责 |
|---|---|---|
| **审计** | `vigil-audit` | SQLite 账本、SHA-256 哈希链、FTS5 检索、脱敏扫描记录 |
| **策略** | `vigil-policy` | Rust 策略 DSL + 规则引擎(默认拒绝) |
| **防火墙** | `vigil-firewall` | 工具门禁、按 Agent 规则、OAuth scope 白名单 |
| **审批** | `vigil-mcp`(broker) | 人在回路、范围化授权、跨进程解析 |
| **脱敏** | `vigil-redaction` | 密钥/PII 检测(硬指纹 + ML 集成)、fail-closed 合并 |
| **租约** | `vigil-lease` | 短时凭据租约、预备子进程环境(RAII 撤销) |
| **Runner** | `vigil-runner` / `vigil-runner-types` | Native + Wasm 执行、环境策略、fail-closed |
| **沙箱** | `vigil-sandbox-linux` | Linux Landlock LSM 文件系统隔离 |
| **网关** | `vigil-mcp` | MCP Hub:stdio + HTTP upstream、descriptor pinning + 漂移 |
| **远程鉴权** | `vigil-http-auth` / `vigil-http-transport` | OAuth(JWT + opaque)、token 刷新(singleflight)、真 TLS |
| **UI 协议** | `vigil-ui-protocol` | 桌面 UI 的强类型命令/响应契约 |
| **浏览器** | `vigil-browser` | 扩展桥接的脱敏分类器 + 审计 |
| **SDK** | `vigil-sdk` | 引擎之上的瘦封装、SemVer 稳定 |

**App 与二进制:**

| 二进制 | Crate | 它是什么 |
|---|---|---|
| `vigil-hub` | `vigil-hub-cli` | CLI MCP 网关:`vigil-hub serve --stdio`、`add-remote-mcp`、`inspect`、… |
| `gui` | `apps/desktop` | Tauri 2 桌面应用(内嵌 Vue 3 UI + 进程内 Hub) |
| `vigil-native-host` | `apps/native-host` | Chrome 扩展的 native-messaging 桥 |
| — | `extensions/chrome-mv3` | Chrome MV3 扩展(纯 vanilla JS,零 npm 依赖) |

## 安装

每个 [GitHub Release](https://github.com/duncatzat/vigils/releases) 都附带 **Windows、macOS、
Linux** 的预构建安装包与二进制:

| 平台 | 桌面应用 | CLI |
|---|---|---|
| **Windows** | `.exe`(NSIS)/ `.msi` | `vigil-hub.exe`(在 `vigils-cli-…-windows-msvc.zip` 内) |
| **macOS** | `.dmg` | `vigil-hub`(在 `vigils-cli-…-apple-darwin.tar.gz` 内) |
| **Linux** | `.AppImage` / `.deb` / `.rpm` | `vigil-hub`(在 `vigils-cli-…-linux-gnu.tar.gz` 内) |

> 早期版本未签名;首次运行时系统可能弹出 Gatekeeper / SmartScreen 提示。

**Chrome 扩展**在 `extensions/chrome-mv3/` —— 经 `chrome://extensions` → *开发者模式* →
*加载已解压的扩展程序* 以未打包方式载入(它与 `vigil-native-host` 通信)。

## 快速开始

### 一键保护 Claude Code(turnkey)

下载 release 后,只跑**一条命令**。Vigils 把自己注册为 Claude Code 的 `PreToolUse` hook,于是
**每一次工具调用**(Bash、Edit、Write、Read、MCP 工具……)在执行前都先被检查:真实凭据流入工具会被
**fail-closed 拦截**,并记入本地防篡改审计账本。无需手动改配置——你既有的设置会被备份,只新增 Vigils
自己的条目。

```bash
vigil-hub setup             # 检测 Claude Code → 注册守门(备份 ~/.claude/settings.json)
vigil-hub setup --status    # 校验保护已 ACTIVE + 跑内置自检
vigil-hub setup --uninstall # 干净移除(仅 Vigils 自己的条目;你的 hook 不动)
```

重启 Claude Code(或开新会话),agent 的原生工具调用即受保护。这是从 GitHub 下载到真实防护的最快路径。

### 先用 60 秒看价值(零设置)

```bash
vigil-hub demo            # 默认拒绝 → 占位符往返 → 真值只到本地工具 → 审计零明文
vigil-hub demo --tamper   # 另演示:篡改账本一行,看 verify-chain 检测到(可证伪)
```

### 作为 MCP 网关(CLI)

把 Vigils 放在你的 MCP server 前面,让每次工具调用都经过防火墙、审批与审计:

```bash
# 作为 MCP endpoint 供你的 agent 连接(stdio)
vigil-hub serve --stdio --upstream-config ./upstreams.json

# upstreams.json —— 裸命令自动经 PATH 解析
# { "upstreams": [ { "name": "fs", "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"] } ] }

# 注册一个远程(HTTP)MCP server 并完成 OAuth onboarding
vigil-hub add-remote-mcp https://mcp.example.com/

# 从命令行查询本地审计账本(stdout 为单行 JSON,便于 | jq)
vigil-hub inspect --db-path ./vigil.db activity --limit 20
```

把你的 agent(Claude Code / Cursor / Zed)指向 `vigil-hub` 而非原始 MCP server 即可。各 agent 配置
与"如何验证它在管控"见 **[Agent 接入与测试指南](https://duncatzat.github.io/vigils/getting-started/agent-integration.zh-CN.html)**。

### 桌面应用

启动桌面应用,实时观察与控制 agent:**审批队列**(批准 / 拒绝 / 批量)、**活动流**(实时审计
流)、**服务器注册**、**会话回放**、**隐私发现**。

## 从源码构建

要求:近期的 **stable Rust** 工具链(见 `rust-toolchain.toml`)与用于桌面 UI 的 **Node.js 20+**。
在 Linux 上,Tauri 需要 GTK/WebKit dev 包。

```bash
# workspace 测试 / lint(默认不含 GPU 或模型依赖)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# CLI 网关
cargo build --release -p vigil-hub-cli --bin vigil-hub

# 桌面 UI + 应用(`gui` feature 内嵌已构建的 UI)
cd apps/desktop/ui && npm ci && npm run build && cd -
cargo build --release -p vigil-desktop --features gui --bin gui
```

> crate 名沿用历史 `vigil-*` 前缀;产品与项目名为 **Vigils**。

## 安全模型

- **本地优先** —— prompt、密钥与审计账本都留在你的机器上。
- **默认拒绝** —— 除非策略明确允许,防火墙会阻止工具调用。
- **Fail-closed** —— 当某项保证无法强制执行时(如 Landlock 不支持、脱敏引擎被请求但不可用),
  Vigils 选择拒绝,而非静默降级。
- **防篡改** —— 审计账本是 SHA-256 哈希链;桌面应用可校验整条链。
- **原文不落盘** —— 脱敏只存 label / count / fingerprint 元数据;明文凭据永不写入账本。
- **最小权限派生** —— 子进程获得清空后的环境,外加仅经批准的环境变量与短时密钥租约;
  Linux 上额外加 Landlock 文件系统隔离。

发现漏洞?请私下上报 —— 见 [SECURITY.md](./SECURITY.md)。请勿用公开 issue 提交安全报告。

## 项目结构

```
crates/          # 15 个库 crate(audit、policy、firewall、mcp、redaction、runner、
                 #   lease、sandbox-linux、http-auth/transport、ui-protocol、browser、sdk、types)
apps/
  desktop/       # Tauri 2 + Vue 3 桌面应用(bin: gui)
  native-host/   # Chrome native-messaging 桥(bin: vigil-native-host)
  vigil-hub-cli/ # CLI MCP 网关(bin: vigil-hub)
extensions/
  chrome-mv3/    # Chrome MV3 扩展(vanilla JS)
docs/
  adr/           # 架构决策记录(ADR)
  book/          # 用户指南(mdBook)
  threat-model/  # 安全威胁模型
```

## 文档

- **用户指南**(mdBook):[`docs/book/`](./docs/book)
- **架构决策记录(ADR)**:[`docs/adr/`](./docs/adr)
- **威胁模型**:[`docs/threat-model/`](./docs/threat-model)
- **SDK 表面**:[`docs/sdk-shallow-api.md`](./docs/sdk-shallow-api.md)

## 贡献

欢迎 issue 与 pull request。提交前请确保:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

每次 PR,CI 都会在 Linux 上跑同样的门禁,并构建 UI。

### 文档(双语)

Vigils 同时服务中文社区与国际社区,因此**面向用户的文档采用双语**。新增或修改指南 / 教程 / 说明类
文档时,评估是否需要双语——需要则写一份英文页 **+ 一份独立中文页**(绝不逐句中英交错),如
`foo.md` + `foo.zh-CN.md`,顶部互链。参考 / ADR / 内部文档可只保留英文。

## 许可证

[Apache-2.0](./LICENSE) © Vigils Authors · [vigils.ai](https://vigils.ai)
