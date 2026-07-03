# Vigils Browser Guard

[English](README.md) | [中文](README.zh-CN.md)

## 简介

Vigils Browser Guard 是一个 Chrome MV3 扩展，用来在你把密钥、token、连接串等敏感内容粘贴、输入或发送到 AI 网站时做本地检查。

默认的普通模式不需要安装 Native Host、不需要桌面应用、不需要终端命令。检测在浏览器内完成，命中风险时，页面会提示你选择“脱敏后继续”或“阻断”。

## 核心特点

- **面向普通用户**: 安装扩展后即可使用，不需要配置本机服务。
- **浏览器内检测**: 默认使用本地 JavaScript 规则扫描常见密钥和 token。
- **粘贴与发送守门**: 覆盖 paste、防抖 input、submit 和常见 contenteditable Enter 场景。
- **贴近输入框提示**: 风险提示会优先出现在输入框附近，而不是藏在页面角落。
- **一键保护网站**: Popup 会显示当前页面保护状态，并支持添加自定义 HTTPS 网站。
- **安全事件记录**: Popup 只展示风险类型、网站和处理结果，不保存原文。
- **企业接口预留**: 后续可接入 Native Host、localhost agent、企业 HTTPS API 或 Wasm provider。

## 适用场景

Vigils 适合经常把代码、配置、日志或环境变量粘贴到 AI 工具里的用户，例如：

- 向 ChatGPT、Claude、Gemini、Perplexity 等工具提问时，避免误发 GitHub Token、OpenAI API Key、数据库连接串。
- 粘贴 `.env`、日志、配置片段时，自动发现可能包含的敏感值。
- 在普通用户模式下获得“本地检查 + 明确确认”的低门槛保护。

## 当前支持的网站

扩展默认注入以下网站：

- ChatGPT
- Claude
- Gemini
- Perplexity
- DeepSeek
- 豆包
- Kimi
- 通义 / 千问
- 智谱
- 腾讯元宝
- 文心一言
- 讯飞星火

你也可以在扩展设置中添加其他 HTTPS 网站。添加后，Vigils 会请求对应站点权限，并动态注入通用守门脚本。

## 可检测的风险类型

当前普通模式支持检测和脱敏：

- OpenAI API Key
- Anthropic API Key
- Google API Key
- GitHub Token
- GitLab Personal Access Token
- Slack Webhook
- Stripe Secret Key
- AWS Access Key ID
- JWT
- 数据库连接串
- `.env` 风格变量
- PEM 私钥
- 高级设置中配置的自定义前缀风险类型

其中，大多数 token 和连接串会提示“脱敏后继续”；PEM 私钥等高风险内容会直接阻断。

粘贴和发送检查会在原文写入或发送前执行。手动输入检查会在短暂防抖后执行，属于尽力清理层；如果页面在防抖结束前立即读取输入内容，仍可能先看到原文。

## 隐私与安全承诺

普通模式遵守以下约束：

- 原文不写入 `chrome.storage`
- 原文不写入 `console.log`
- 原文不挂到 `window.*` 等页面全局对象
- Popup 最近事件只保存风险类型、网站、时间和处理结果等元数据
- 页面提示使用 DOM API 和 `textContent` 渲染，不使用 `innerHTML`
- 未知或异常的风险决策按 fail-closed 处理，默认阻断

企业模式是预留能力，不是普通用户默认路径。Native Host 只是未来企业 provider 的一种实现方式。

## 安装与体验

当前版本适合开发模式加载：

1. 打开 Chrome `chrome://extensions/`
2. 开启 Developer mode
3. 点击 Load unpacked
4. 选择本目录：`extensions/chrome-mv3/`
5. 打开受保护的 AI 网站
6. 粘贴一段测试 token，例如：

```text
token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
```

预期行为：

- 输入框附近出现风险提示
- 可选择“脱敏后继续”或“阻断”
- 脱敏后写入的文本不会包含原始 token

## Popup

Popup 面向普通用户，重点展示：

- 当前页面是否已保护
- 当前页面是否需要授权
- “保护当前网站”按钮
- 最近安全事件
- 首次使用说明

不会默认展示 Native Host、provider、策略档位等高级概念。

## Options

Options 默认只保留普通用户需要的内容：

- 推荐保护
- 已保护网站
- 添加自定义网站
- 隐私说明

企业连接、自定义风险类型、扩展 ID、权限技术清单位于“高级设置”中。

## 项目结构

```text
extensions/chrome-mv3/
├── icons/
├── manifest.json
├── background.js
├── content-script.js
├── custom-sites.js
├── popup.html
├── popup.js
├── popup.css
├── options.html
├── options.js
├── options.css
├── redaction-rules.js
├── risk-decision.js
├── scanner-pipeline.js
├── providers/
│   ├── consumer-js-provider.js
│   └── enterprise-provider.js
└── tests/
```

核心分层：

- `content-script.js`: 监听页面 paste、防抖 input、submit 和 contenteditable Enter，并显示页面内风险提示。
- `background.js`: 负责消息编排、模式管理、自定义网站权限和安全事件缓存。
- `custom-sites.js`: 规范化用户添加的 HTTPS 自定义保护域名。
- `redaction-rules.js`: 浏览器内扫描、脱敏规则和自定义前缀风险类型。
- `risk-decision.js`: 将扫描结果转为 `allow`、`confirm_redact` 或 `block`。
- `scanner-pipeline.js`: 普通 provider 与企业 provider 的组合入口。

## 开发与测试

运行 Chrome 扩展相关测试：

```bash
node --test extensions/chrome-mv3/tests/*.test.mjs
```

当前扩展没有前端构建步骤，使用原生 MV3、HTML、CSS 和 JavaScript。

## 企业 Provider 预留

普通用户不需要企业 provider。企业模式后续可以接入：

- Native Host
- localhost agent
- 企业 HTTPS API
- 浏览器内 Wasm
- 其他受管 provider

设计目标是让企业用户可以把扫描和策略判断迁移到受控环境，同时保留普通用户的零配置体验。

## 路线图

- 增加更多 token 和云服务凭证类型
- 补充更多 AI 网站的深度输入框适配
- 增加更完整的 E2E 测试
- 改进安全事件说明和风险解释
- 接入企业 provider 示例
- 打包发布到 Chrome Web Store

## 许可

请以仓库根目录的 License 为准。
