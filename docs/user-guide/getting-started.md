# Getting Started — 5 分钟跑通 Vigil

假设你已按 [installation.md](installation.md) 装好:**Vigils** 桌面应用(可执行文件 `vigils.exe`)可双击启动,Chrome 扩展已加载并注册 Native Host。

## 场景 1:粘贴 token 被拦截(最直观)

### 步骤

1. 打开 `https://chatgpt.com`(或 `claude.ai` / `gemini.google.com` / `perplexity.ai`)
2. 在输入框粘贴:
   ```
   my github PAT is ghp_1234567890abcdef1234567890abcdef12345678
   ```
3. **预期行为**:
   - 粘贴瞬间,页面顶部出现 toast:**"Blocked: github_token"**(红色警告条)
   - 输入框**实际被替换**为 `[REDACTED github_token]`(而非原文)
   - 扩展 popup(点 Chrome 右上角 Vigil 图标)能看到最近 findings 记录

### 如果不工作

- 顶部无 toast → 扩展没加载或 Native Host 没注册 → 回 [installation.md §3.4](installation.md)
- 粘贴还是原文 → 检查 `chrome://extensions` → Vigil → service worker Console 是否红色 error

## 场景 2:Desktop GUI 看审计链

### 步骤

1. 启动 **Vigils** 桌面应用(Windows 上可执行文件为 `vigils.exe`)
2. 左侧 4 Tab:
   - **Activity Feed**:刚才场景 1 的粘贴事件应在列表里(event_type = `browser.paste.redacted`,findings = `[github_token]`)
   - **Approval Queue**:v0.2 仅 Desktop 内 UI;若 agent 调未批工具会进这里(需要场景 3)
   - **Server Registry**:还没配 MCP server 时是空
   - **Session Replay**:展开 session 看完整时间线
3. 点 Activity Feed 里任一事件 → 打开 Event Detail Modal
4. **验证**:Modal 的 payload JSON 不应含 `ghp_1234567890abcdef1234567890abcdef12345678` 原文(应只显示 `[REDACTED github_token]`)

## 场景 3:CLI Agent 通过 vigil-hub 连接(v0.3 Stage 1)

Vigil 的核心能力之一是**作为 MCP 代理**插在 Agent(Claude Code / Codex / OpenCode / Cursor / Zed)和上游 MCP server 之间。

### 3.1 在任一 Agent 侧配置 Vigil

完整配置模板 + 6 种 agent 具体写法见 **[`agent-integration.md`](agent-integration.md)**。这里以 **Claude Code** 为例(最常用):

`.mcp.json`(项目根)或 `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "C:\\Vigil\\vigil-hub.exe",
      "args": ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]
    }
  }
}
```

### 3.2 启动 agent,观察连接

启动 Claude Code 后,在 `/mcp` 面板能看到 `vigil` 已连接。stderr 日志中应有:

```
vigil-hub serve: started stdio MCP server (PID 12345)
```

### 3.3 在 Desktop UI 看到 session

启动 **Vigils** 桌面应用(`vigils.exe`):
- Activity Feed 应有 `session.started` 事件(source = `vigil-hub-serve`)

### 3.4 Stage 1 边界说明

**当前版本(v0.3 Stage 1)**:agent 能连上 vigil-hub,`tools/list` 返空(零 upstream attach)。**真实 upstream MCP server 的转发留 Stage 2**。

所以:agent 连上后暂时看不到任何工具。这一步的价值是**验证通路**:
- Vigil 作为 MCP stdio server 协议实现正确
- Agent 能识别 `vigil` 连接
- 所有 agent 活动(即使 handshake 阶段)进入 Vigil 的 session / audit 链

Stage 2 会补全上游 attach。如需立即接入真实 MCP server 做评测,请绕过 vigil 直连(但失去审计/审批)。

## 场景 4:查看审计链

```powershell
# ledger 位置(Windows)
dir $env:APPDATA\Vigil\*.sqlite

# 用任意 sqlite 客户端打开,或:
.\vigil-hub.exe ledger query --last 10
# 产品角度:看 event 顺序 + 每条的 prev_hash,无断链
```

审计链不变量:每条 event 都含 `prev_hash`,指向上一条的 SHA256。**任何中间被篡改会在重启时 fail-closed 拒启**(v0.1 scenario RT-05 验证)。

## 场景 5:性能观察

```bash
# 在本仓库根
bash scripts/test-local/bench.sh
# 查 dist/test-results/bench-summary.txt
```

**基线**(本机 Windows 参考值,见 `docs/test-strategy/S1-DELIVERY.md`):
- 100 KB 文本 scrub:**~32 µs**
- Ledger append(冷/10万条后):**54 / 24 µs**

如果你的机器数值偏离基线 >2x,可能是 SSD / CPU / AV 干扰,参考 [troubleshooting.md](troubleshooting.md)。

## 场景 6:agent CLI 原生工具 secret 防护(hook,默认安装面)

场景 3 的 MCP 网关只看得到 **MCP 工具**。但 agent 跑 `Bash`、读写文件用的是**原生工具**——这些**绕过** MCP
网关直接进 LLM。`vigil-hub hook` 把 secret 防护扩到这些原生工具,是 **`setup` 的默认安装面**。

### 6.1 一键注册(默认 = hook)

```bash
# 默认安装面 = agent CLI hook(Claude 主面 + 检测到的 Codex/Gemini/Cursor 自动注册)
vigil-hub setup
# 只想保护 MCP 工具流?显式用 MCP wrap(场景 3 的网关):
vigil-hub setup --mcp --apply
# 两者都要(hook + MCP wrap 一步合一):
vigil-hub setup --all
```

`setup` 写各 agent 的 hook 配置(Claude `~/.claude/settings.json` 等),注册 `PreToolUse`(输入守门)+
`PostToolUse`(结果再脱敏面)。重复跑幂等;`setup --uninstall` 干净移除(只删 Vigil 自有 entry)。

### 6.2 预期行为

- **裸真凭据进任何工具调用 → 拦截**(最高价值):让 agent 跑 `echo ghp_…`(真 token 形态),hook
  **deny**,reason 只说 `github_token`(**绝不回显真值**)。**任何姿态档位恒拦**(硬底线)。
- **`secret://<alias>` 占位符 × 原生工具**:由**三档安全姿态**决定处置:
  - **Low(默认)= 放行**:只拦极高风险,占位符当普通数据放行(最小干扰)。
  - **Medium = 共同批准(ask)**:进 Vigil approval queue,desktop/CLI 与 agent 原生 UI **两边都能批准,先批者生效**。
  - **High = 拦截**:占位符 × 原生工具一律 deny。
  - 切换:`vigil-hub posture set medium`(`posture show` 看当前档)。

### 6.3 执行边界注入 + 结果再脱敏(α2,进阶)

把声明的 `secret://<alias>` 在 **PreToolUse 注入真值**进实际执行的命令(模型 transcript 仍只见占位符),
命令结果回 LLM 前在 **PostToolUse 逆向脱敏**回占位符——**模型上下文任何阶段只见占位符,真值零落审计**。

> **当前边界**:注入走 OS keyring 真值后端,**录入 secret 的 turnkey CLI 入口仍在路上**(下一增量);
> 现阶段需手动给 hook 命令带 `--inject --secrets <map.json>`。仅 **Claude**(实证支持 `updatedInput`/
> `updatedToolOutput`)启用注入与再脱敏。再脱敏仅覆盖边界工具**直接**结果(二次落盘传播见
> `docs/research/privacy-interception-architecture.md`)。

## 下一步

- 读 [troubleshooting.md](troubleshooting.md) 看常见问题解法
- 读 [`docs/test-cases/scenarios/`](../test-cases/scenarios/) 的 `PS-*` 了解产品级场景
- 读 [`docs/adr/`](../adr/) 每个 ADR 的"决策"部分理解 Vigil 的设计思路

**你的反馈**:用过一轮后,把 [UAT checklist](../test-cases/uat/v0.1-checklist.md) 填一遍,告诉我们哪里卡住 / 哪里惊艳。
