# Vigil 用户指南

本地运行的 **AI Agent 控制平面**。一句话描述:帮你守住 LLM Agent(ChatGPT / Claude / Gemini / Cursor / Claude Code 等)**不把 secret 粘出去、不越权调工具、审计留痕、沙箱隔离**。

## 文档导航

1. **[Installation](installation.md)** — 装三平台 binary + Chrome 扩展
2. **[Getting Started](getting-started.md)** — 5 分钟跑通 3 个核心场景
3. **[Agent Integration](agent-integration.md)** — ★ Claude Code / Codex / OpenCode / Cursor / Zed 接入 vigil-hub
4. **[Troubleshooting](troubleshooting.md)** — 常见问题

## 产品能力速览

| 能力 | 场景 |
|---|---|
| **Secret 拦截** | 在 ChatGPT 粘贴 `ghp_...` → 扩展显示 "blocked" + 内容不进对话框 |
| **审批闭环** | Agent 调未批工具 → Desktop Approval Queue 待批 → 点 approve 后放行 |
| **审计链** | 每次 tool call / 用户粘贴都写 SQLite ledger(SHA256 hash chain,防篡改) |
| **Sandbox** | Agent 工具进程受限于只读/读写白名单目录(Linux Landlock / Windows job 限权) |
| **HTTP MCP Auth** | 连 SaaS MCP server(GitHub / Anthropic 等)自动 OAuth + token 刷新 + scope 校验 |
| **本地优先** | 所有 secret / token / ledger 都在本机,零云端上报 |

## 防护边界(请先读 — 不制造虚假安全感)

Vigil 的定位是**纵深防御**:大幅降低**意外**泄密、给每个动作留**防篡改审计**、让 secret 以**可逆占位符**参与工作流。它**不是**对抗"蓄意外泄 agent"的密封屏障。把边界说清,你才能正确地依赖它。

### ✅ 能可靠防住

| 类别 | 说明 |
|---|---|
| **明文凭据意外泄漏** | 13 类硬指纹(AWS key / GitHub token / Google API key / Slack webhook / Stripe key / 私钥 PEM / 含密 DB URL 等)以**原文**出现在 tool call、浏览器粘贴、工具结果里 → 拦截 / 脱敏 |
| **可逆脱敏往返** | 远端只见 `secret://<alias>` 占位符,真值只在**本地执行边界**注入;模型 / 日志 / 审计永不见明文 |
| **防篡改审计** | 每次 tool call / 粘贴写 SQLite 账本(SHA256 hash-chain),`vigil-hub verify` 可证伪 |
| **越权动作审批** | 高风险工具先进 Approval Queue,人批准后放行 |
| **沙箱隔离** | 工具进程受限于只读 / 读写白名单目录(Linux Landlock / Windows job 限权) |

### ⚠️ 防不住(蓄意规避)

输入侧的指纹检测,**本质上可被蓄意混淆绕过**。一个被指示要外泄的模型可以:

- **编码 / 变形**真值再外传:base64、hex、`String.fromCharCode(...)`、分段拼接 —— 原文指纹此时不命中
- **借 Vigil 未中介的通道**外泄:如用 Playwright 驱动浏览器**逐字符**输入、或写进一个不经 hook / gateway 的 sink
- **跨多次调用拆分**,任何单次都不足以触发

Vigil 会**抬高门槛**并**留下审计痕迹**,但**不保证**拦住一个蓄意外泄的 agent。**不要**把"接了 Vigil"当成"可以放心让不可信 agent 直接接触真凭据"的理由。

### 🛣️ 完整堵法(路线图)

输入侧检测的根本补全是**出站代理(egress proxy)**:中介 agent 的**所有**外发网络 / 数据流、在出口侧检测 —— 这样编码 / 分段也能在"真值离开机器前"被发现。这是后续版本方向,**当前版本尚未提供**。在它落地前,请把 Vigil 当作**审计 + 意外泄漏防护 + 可逆脱敏**,而非密封的外泄屏障。

## 本发行版(v0.2)交付

**三平台 Tauri GUI + CLI**(全部 portable binary,见 `dist/v0.2/`):

| 平台 | Desktop GUI | CLI |
|---|---|---|
| Windows x86_64 | `vigil-desktop-gui.exe` 12.1 MiB(**GUI**)| `vigil-desktop.exe`(CLI)+ `vigil-hub.exe` + `vigil-native-host.exe` |
| Linux x86_64(Ubuntu 22.04+)| `vigil-desktop-gui` ELF(**GUI**)| `vigil-desktop`(CLI)+ `vigil-hub` + `vigil-native-host` |
| macOS arm64(Apple Silicon)| `vigil-desktop-gui` Mach-O(**GUI**)| `vigil-desktop`(CLI)+ `vigil-hub` + `vigil-native-host` |

**Chrome MV3 扩展**:`vigil-chrome-mv3-v0.1.zip`(平台无关)

**本版未包含**(v0.3 或之后):
- MSI / DMG / AppImage / deb 打包(portable 二进制可直接用,但发行需 `.ico`/`.icns` 图标)
- 代码签名(Authenticode / notarization)
- macOS x86_64(Intel)二进制(arm64 可通过 Rosetta,原生需自行编译)

## 对谁有用

- **个人 AI 开发者**:用 Claude Code / Cursor 等 agent 工具时希望"粘贴时敏感内容不外泄 + 工具调用有审计"
- **企业合规 / 安全团队**:需要本地 MCP hub + 审计链,满足"AI agent 行为可追溯"合规要求
- **Red-team / 内审**:用 `docs/test-cases/scenarios/` 的场景验证 agent 不绕过策略

## 不做什么

- 不做云端同步 / 团队审计聚合(**by design,本地优先**)
- 不替代 EDR / DLP(Vigil 是 agent 控制平面,不是终端防护)
- 不劫持 HTTPS(不装根证书,不动浏览器安全模型 — 扩展只在用户主动粘贴/提交时介入)

---

继续读 **[installation.md](installation.md)** 开始装。
