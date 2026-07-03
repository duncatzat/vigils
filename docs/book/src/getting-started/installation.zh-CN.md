# 安装 Vigils

> English: [Install Vigils](./installation.md)

## 1. 我该下载哪个?

| 我想… | 下载 | 跳转 |
|---|---|---|
| **用这个 App** —— 看活动、批准操作(图形界面) | 对应系统的**桌面安装包** | [§2](#2-桌面-app) |
| **守护我的 AI 编码助手** —— Claude Code / Codex / Cursor / Zed | **CLI**(`vigils-cli-…`) | [§3](#3-cli--守护你的编码助手30-秒) |
| **守护往 AI 网站粘贴** —— ChatGPT / Claude / Gemini | **浏览器扩展** | [§4](#4-浏览器扩展chrome) |

大多数人要的是**桌面 App**;给 agent 接网关的开发者要的是 **CLI**。
所有文件都在 [**Releases 页**](https://github.com/duncatzat/vigils/releases/latest)
(把下文的 `<version>` 换成你下载的版本,例如 `0.3.0`)。

---

## 2. 桌面 App

选你的系统,下载,运行。首次启动会有一次性的"未知开发者"提示(我们暂未做 OS 代码签名)——放行步骤见下。

### Windows
1. 下载 **`Vigils_<version>_x64-setup.exe`** → 双击。
2. 若弹出蓝色 **"Windows 已保护你的电脑"** → **更多信息 → 仍要运行**。
3. 完成。*(随着安装量增加,该警告会自行消退。)*

### macOS(Apple 芯片)
1. 下载 **`Vigils_<version>_aarch64.dmg`** → 打开 → 把 **Vigils** 拖进 **应用程序**。
2. 首次启动会被拦("Apple 无法验证…")。**一次性**放行:
   **  系统设置 → 隐私与安全性 → 下拉到底 → 点"仍要打开" → 用 Touch ID / 密码确认。**
3. 完成 —— 之后不再询问。

> *终端替代方案(进阶用户):* `xattr -dr com.apple.quarantine /Applications/Vigils.app`
> 这是任何"尚未公证"App 的标准一次性步骤;签名已在计划中。

### Linux(Ubuntu 22.04+ / Debian 12+)
```bash
sudo dpkg -i Vigils_<version>_amd64.deb            # Debian / Ubuntu
sudo rpm  -i Vigils-<version>-1.x86_64.rpm          # Fedora / RHEL
chmod +x Vigils_<version>_amd64.AppImage && ./Vigils_<version>_amd64.AppImage   # 便携版,任意发行版
```
> **发行版较老**(桌面 GUI 需要 glibc ≥ 2.35)?改用 **[CLI](#3-cli--守护你的编码助手30-秒)** ——
> 它几乎能在任何 Linux 上跑(glibc ≥ 2.17)。

---

## 3. CLI —— 守护你的编码助手(30 秒)

一行装好:
```bash
curl -fsSL https://vigils.ai/install.sh | sh        # macOS / Linux
```
```powershell
irm https://vigils.ai/install.ps1 | iex             # Windows(PowerShell)
```
*(或从 Releases 下载 `vigils-cli-<os>` 解压 —— 里面有 `vigil-hub`。)*

然后开启防护:
```bash
vigil-hub setup       # 自动探测 Claude Code / Codex / Cursor 并接好守护
```
重启你的 agent —— 就这样。明文密钥从此被挡在它的工具调用之外,每次拦截都记进防篡改的本地账本。
想先试试就跑 **`vigil-hub demo`**(零设置)。各 agent 细节见 [Agent 集成](./agent-integration.zh-CN.md)。

> **ML 变体**(可选,语义 PII + 提示注入检测):改下载 `vigils-cli-ml-<os>`,跑 `vigil-hub serve --engine ml`。
> 底线:Linux glibc ≥ 2.28、macOS ≥ 14。见 [隐私过滤器](../concepts/privacy-filter.md)。

---

## 4. 浏览器扩展(Chrome)

在 AI 网站上粘贴/提交前先脱敏密钥与 PII。安装:`chrome://extensions` → 开 **开发者模式** →
**加载已解压的扩展程序** → 选 `extensions/chrome-mv3/`。*(它与桌面 App 的 native host 配合,后者由桌面安装包注册。)*

---

**担心来源真伪?** 每个下载都带 SHA-256 校验和 + 密码学构建证明 ——
见 [验证你的下载](./verifying-downloads.zh-CN.md)。
想把 Vigils 嵌进自己的 Rust 应用?见 [SDK 快速上手](./sdk-quickstart.md)。
