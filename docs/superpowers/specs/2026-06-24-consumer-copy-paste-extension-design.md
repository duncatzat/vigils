# 面向普通用户的复制粘贴 Chrome 插件设计

日期：2026-06-24

## 目标

把现有 Chrome MV3 扩展改造成面向普通用户的复制粘贴守门插件。用户安装扩展后即可使用，不需要注册 Native Host，不需要安装 Vigils 桌面应用，也不需要运行终端命令。

同一个扩展仍然要保留清晰的企业路径。企业用户后续可以在设置中开启企业模式，并通过多种技术接入企业 provider，例如 Native Host、localhost 本机 agent、企业 HTTPS API、浏览器内 Wasm，或其他受管 provider。Native Host 只是企业 provider 的一种实现方式，不再是普通用户的必需步骤。

## 非目标

- 本设计阶段不实现新行为。
- 不要求普通用户安装桌面应用、运行终端命令，或注册 `com.vigil.host`。
- 第一版不实现完整企业 provider registry。第一版只需要定义接口和配置形状，企业 provider 可以是 `disabled` 或 mock 状态。
- 第一版 UI 不暴露复杂的企业策略链配置。

## 当前上下文

现有扩展已经有不少可复用的浏览器侧能力：

- `content-script.js` 已监听 paste、防抖 input、submit、contenteditable Enter 等路径。
- `background.js` 已管理受保护站点、自定义站点注册、最近 findings、档位选择，以及 Native Host 请求路由。
- `popup.js` 已展示最近 findings 和当前页面保护状态。
- `options.js` 已管理自定义保护网站，但当前也会展示 Native Host 安装命令。

当前普通用户体验的主要摩擦点是：`background.js` 把真实扫描硬绑定到了 `chrome.runtime.connectNative("com.vigil.host")`。如果 Native Host 未安装或连接断开，扩展会 fail-closed 到 `block`。这对安全是正确的，但对普通用户太重，导致扩展安装后无法自然使用。

## 推荐方案

采用“双模式 provider 架构”。

普通模式是默认模式，使用浏览器本地 JavaScript 扫描器。企业模式启用 scanner pipeline，在本地扫描器之后可继续调用企业 provider。pipeline 合并多个 provider 的结果时，始终取更严格的动作。

```text
content-script
  监听 paste / input / submit
  收集 text + origin + event_kind

background
  接收 vigil_check
  读取当前模式和 provider 配置
  调用 scannerPipeline.check(request)

scannerPipeline
  普通模式：
    consumerJsProvider
  企业模式：
    consumerJsProvider + enterpriseProvider
  按严格程度合并结果

content-script
  对风险展示页面内确认弹窗
  执行脱敏或阻断
```

## 架构

### 模块边界

`background.js`

- 负责 Chrome runtime 消息入口。
- 负责受保护站点检查、自定义站点同步、findings log、popup/options 消息，以及模式状态。
- 调用 `scannerPipeline.check()`，不再直接调用 `connectNative`。
- 不关心当前 provider 到底是 JS、Native Host、localhost、HTTPS API 还是 Wasm。

`scanner-pipeline.js`

- 接收标准化 scan request。
- 根据扩展模式选择 provider 链。
- 执行 provider，并处理超时和错误。
- 合并 provider 结果。
- 返回 content script 可直接消费的标准化结果。

`providers/consumer-js-provider.js`

- 浏览器本地轻量扫描器。
- 不依赖 Native Host，不访问网络，不依赖桌面应用。
- 使用本地正则规则和脱敏 helper。

`providers/enterprise-provider.js`

- 企业 provider 抽象入口。
- 第一版可以是 disabled 或 mock-backed。
- 后续可路由到 Native Host、localhost agent、企业 API、浏览器 Wasm，或其他 provider。

`redaction-rules.js`

- 定义 JavaScript 检测规则和脱敏函数。
- 规则必须确定、可测试。
- 不把 raw matched span 存入持久化存储。

`risk-decision.js`

- 把 findings 映射成动作建议。
- 判断哪些 findings 可以脱敏，哪些只能阻断。
- 生成用户可读的风险标签，但不暴露原始命中值。

### Scan Request

```js
{
  request_id: string,
  origin: string,
  event_kind: "paste" | "input" | "submit",
  text: string
}
```

### Scan Result

```js
{
  request_id: string,
  action: "allow" | "confirm_redact" | "block",
  findings: [
    {
      kind: string,
      severity: "medium" | "high",
      redactable: boolean
    }
  ],
  redacted_text?: string,
  source: "consumer_js" | "enterprise" | "pipeline",
  error?: string
}
```

现有 Rust 协议使用 `allow`、`redact`、`block`。普通用户扩展内部应使用 `confirm_redact`，让 content script 明确知道：这是“需要用户确认后再应用脱敏”的动作。如果企业 provider 返回 `redact`，pipeline 默认把它归一化成 `confirm_redact`；只有策略明确允许企业 provider 自动脱敏时，才可以跳过用户确认。

## 普通用户体验

普通模式是自动保护。用户安装扩展、打开受支持 AI 网站后即可获得保护，不需要终端步骤或桌面应用设置。

### 默认行为

- 无 finding：放行原事件。
- 可脱敏 finding：展示页面内确认弹窗，主按钮是“脱敏后继续”。
- 高危 finding：展示页面内弹窗解释风险并阻断事件，不提供直接继续动作。

第一版应包含本次讨论确认的两条交互规则：

1. 普通可脱敏风险的主按钮是“脱敏后继续”。
2. 高危内容不提供直接继续动作。

“本次允许”不进入第一版核心流程。后续可以在二次确认和更强策略控制下再加入。

### 页面内确认弹窗

content script 应优先在当前输入框附近展示页面内确认 UI；如果锚定输入框不可靠，则回退到页面角落的 fixed 弹窗。

可脱敏 findings 的文案示例：

```text
Vigils 发现风险内容
检测到：API key、数据库连接串
原文未离开你的浏览器。

[脱敏后继续] [阻断]
```

高危 findings 的文案示例：

```text
Vigils 已阻断高危内容
检测到：私钥
这类密钥不应发送到 AI 网站。

[关闭]
```

如果扩展可以生成脱敏文本，但无法安全写回页面输入框，应阻断原事件，并提供“复制脱敏文本”动作。

### Popup

popup 保持轻量：

- 展示当前模式：普通保护、企业保护、企业异常。
- 展示当前页面是否受保护。
- 展示最近 findings 元数据：时间、origin、动作、finding 类型。
- 不展示原文或原始命中值。
- 提供进入设置页的入口。

### Options 页

options 页不再把 Native Host 安装命令作为默认路径展示。

推荐分区：

- 保护模式：
  - 普通模式，默认开启。
  - 企业模式，默认关闭。
- 普通模式：
  - 说明检测在浏览器内完成，文本不会离开浏览器。
  - 管理受保护站点和自定义站点。
- 企业连接：
  - 企业模式开启前隐藏或折叠。
  - provider 类型选择器预留 Native Host、localhost、HTTPS API、Wasm、custom 等选项。第一版可以显示为尚未配置。
  - 数据策略：`local_only`、`metadata_only`、`raw_allowed`。

## 扫描规则

第一版普通 provider 应覆盖常见、高置信度风险。

可脱敏 findings：

- OpenAI API key。
- Anthropic API key。
- Google API key。
- GitHub token。
- GitLab token。
- Slack webhook。
- Stripe secret key。
- AWS access key id。
- JWT。
- `.env` 风格 secret assignment。
- 含 `user:password@` 的数据库 URL。

只能阻断的 findings：

- PEM private key。
- 脱敏失败。
- 脱敏后复扫仍命中扫描规则。
- 企业 provider 返回 `block`。

JS 扫描器有意比现有 Rust 扫描器轻。它的目标是移除普通用户安装门槛，不是完整替代企业级检测。

## Pipeline 语义

动作严格程度：

```text
block > confirm_redact > allow
```

普通模式：

```text
request -> consumerJsProvider -> result
```

企业模式：

```text
request -> consumerJsProvider -> enterpriseProvider -> 合并更严格结果
```

如果 provider 之间结果不一致，取更严格结果。provider 可以追加 findings，但持久化 UI 和日志只能保存 finding 元数据，不能保存原始命中值。

## 企业 Provider 接口

企业模式不应被设计成“Native Host 模式”，而应被设计成 provider 接口。

未来计划支持的 provider 类型：

- `native_host`：Chrome Native Messaging，包括当前 `com.vigil.host` 路径。
- `localhost`：暴露在 localhost 的本机 app 或 agent。
- `https_api`：企业管理的服务。
- `wasm`：浏览器本地高级扫描器。
- `disabled`：第一版没有配置企业 provider 时的显式状态。

企业数据策略：

- `local_only`：不把 raw text 发出浏览器。只允许本地 provider。
- `metadata_only`：只发送 origin、event kind、长度桶、本地 finding 类型和策略元数据；不发送 raw text。
- `raw_allowed`：企业 provider 可以接收 raw text。UI 必须在开启前明确提示。

第一版应保存企业设置，但真实 provider 实现可以保持 disabled。关键是让 background 和 pipeline 代码保持 provider-neutral。

## 错误处理

普通模式：

- JS provider 异常：阻断当前事件，并提示“本地检测异常，为安全起见已阻断”。
- 脱敏失败：阻断。
- 脱敏后复扫仍有风险：阻断。
- 无法把脱敏文本写回输入框：阻断原事件；如果已有脱敏文本，则提供复制脱敏文本动作。

企业模式：

- 企业 provider 未配置：继续使用普通模式，并在 popup/options 显示“企业未配置”。
- 企业 provider 已配置但不可用：第一版默认 fail-closed，阻断事件。
- 企业 provider 超时：阻断，并记录 `provider_timeout` 元数据。
- 企业 provider 违反配置的数据策略：不调用 provider；企业模式下阻断，并展示配置错误。

## 隐私与存储

普通模式不得把 raw text 发送到设备外。

扩展存储可以包含：

- 模式。
- 受保护站点元数据。
- 企业 provider 配置。
- 数据策略。
- finding log 元数据。

扩展存储不得包含：

- 页面原文。
- 脱敏后全文。
- 原始命中值。
- 可能被字典攻击反查的全文 hash。

内存中的最近 findings log 继续只保存 timestamp、origin、event kind、action 和 finding kinds。

## 迁移计划

1. 新增 scanner pipeline 和 provider 模块。
2. 新增普通模式 JS 规则和脱敏 helper。
3. 把 background 中直接 Native Host check 的路径替换成 `scannerPipeline.check()`。
4. 将 consumer JS provider 设为默认。
5. 在 content script 中增加页面内确认行为。
6. 将 options 页从 Native Host 安装助手改为模式和企业设置。
7. 更新 popup，展示普通/企业模式状态。
8. 第一版保留企业 provider 为 disabled 或 mock-backed。
9. 保留仓库中的现有 Native Host 代码，但不再让它成为普通扩展使用的必要条件。

## 测试

纯函数测试：

- 每条普通模式规则的检测和脱敏。
- 脱敏后复扫仍命中时 fail-closed。
- risk decision 将 PEM private key 映射为 block-only。
- pipeline 合并规则使用 `block > confirm_redact > allow`。
- 企业数据策略在不允许发送 raw text 时确实不会传出 `text`。

Background 测试：

- 普通模式不调用 `chrome.runtime.connectNative`。
- 普通模式从 JS provider 返回 allow、confirm_redact 或 block。
- 企业模式 + disabled provider 符合失败策略。
- findings log 不含 raw text 或 redacted text。
- 模式和 provider 设置在使用前经过校验。

Content script 测试或手工场景：

- 在受保护站点粘贴 token，出现确认弹窗，点击后脱敏写回。
- 提交含 token 的文本，提交继续前出现确认弹窗。
- 粘贴 PEM private key，事件被阻断，且不出现继续动作。
- 脱敏写回失败时阻断原事件。
- 自定义保护站点仍能注入 content script。

## 已确认决策

- 第一版使用同一个扩展，不拆普通版和企业版两个扩展。
- 普通模式默认开启。
- 普通模式优先使用浏览器本地 JS 规则。
- 扩展保留企业 provider 接口，供未来集成。
- 第一版用户确认流程包含：可脱敏风险“脱敏后继续”，高危风险只能阻断。
- “本次允许”延后。

