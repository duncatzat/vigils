# Popup 单一推荐策略设计

## 背景

当前 Chrome 插件已经转向普通用户默认可用的浏览器本地复制粘贴守门能力。普通模式不需要 Native Host、不需要 Vigils Desktop，也不需要终端注册步骤。

现有 popup 和 options 暴露了三档守门策略：

- `strict`
- `balanced`
- `recall-first`

其中 `recall-first` 的语义偏企业场景：企业外发、工单、邮件、多类 PII 命中时更谨慎阻断。它对普通用户不直观，也会让 popup 从“状态面板”变成“安全策略控制台”。

## 设计目标

普通用户界面采用单一默认策略：**推荐保护**。

用户不需要理解或选择 `strict / balanced / recall-first`。插件默认做正确的事：

- 安全文本直接放行。
- 常见可脱敏 secret、token、JWT、`.env`、数据库连接串等命中后，提示“脱敏后继续 / 阻断”。
- 高风险内容，例如 PEM 私钥，直接阻断。

## 非目标

- 不在本轮设计企业策略编辑器。
- 不把 `recall-first` 设计成普通用户可见选项。
- 不增加 allow-once、临时豁免、站点级绕过等放行能力。
- 不要求普通用户理解 Native Host、企业 provider 或数据策略。

## 用户界面

### Popup

Popup 定位为普通用户状态面板，展示“现在是否在保护我”和“最近发生了什么”。

保留：

- 标题：Vigils
- 状态：保护中
- 模式：普通保护
- 最近记录数量
- 刷新
- 清空
- 选项入口
- 最近检测记录列表
- 隐私说明：普通模式在浏览器内检测，原文不写入 storage、console 或页面全局对象。

移除：

- `strict / balanced / recall-first` 三档按钮
- 档位切换中的 loading / error 状态
- `vigilTier` 相关 popup 文案

### Options

Options 继续用于配置模式和网站权限，但普通用户不再看到“守门档位”区域。

移除：

- “守门档位” section
- `strict / balanced / recall-first` 单选项
- 档位说明和档位保存状态

保留：

- 普通模式 / 企业模式选择
- 企业连接预留区域
- 自定义保护网站
- 权限 / 守门清单

## 策略行为

普通模式固定使用推荐策略，行为等同当前 `balanced`：

- `allow` 保持放行。
- `confirm_redact` 交给页面内弹窗确认，用户只能选择“脱敏后继续”或“阻断”。
- `block` 保持阻断。

后续企业模式可以重新引入策略接口，但应作为企业 provider / policy 的一部分，而不是普通 popup 的快捷按钮。

## 架构边界

实现已移除 UI 层的档位入口，并让后台固定走推荐策略。

普通用户路径不再保留 `tier-decision.js`、`vigil_get_tier`、`vigil_set_tier` 或 `vigilTier` 的 runtime 支持。已有历史 `vigilTier` storage 值会被忽略，不影响当前推荐策略。

后续如果企业模式重新引入策略接口，应作为企业 provider / policy 的独立实现回归，而不是恢复普通 popup 的档位切换能力。

## 存储与迁移

已有用户可能在 `chrome.storage.local.vigilTier` 中保存过旧值。

推荐处理：

- 普通模式忽略该值，按推荐策略执行。
- 不需要弹迁移提示。
- 不需要清理 storage，避免做不必要的数据写入。

## 测试要求

需要覆盖以下行为：

- popup 源码不再出现 `strict`、`balanced`、`recall-first` 档位按钮。
- options 源码不再出现“守门档位”区域。
- popup 不再发送 `vigil_set_tier`。
- 普通模式仍然对可脱敏 secret 返回 `confirm_redact`。
- 高风险 PEM 私钥仍然 `block`。
- 旧 `vigilTier` 值不应改变普通模式推荐策略。

## 验收标准

- 普通用户打开 popup 时，看不到三档策略。
- Options 中看不到守门档位设置。
- 插件默认行为仍保持推荐保护：安全文本放行，可脱敏内容确认脱敏，高风险内容阻断。
- 没有引入 Native Host、临时豁免或 allow-once。
- 自动测试通过：`node --test extensions/chrome-mv3/tests/*.test.mjs`。
