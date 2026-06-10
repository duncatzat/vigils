# chrome-mv3 — Vigils Browser Guard Extension

Chrome MV3 扩展,I09b-α1 提供 paste / input / submit 守门 + 与本机 Native Host(`com.vigil.host`)通信。

## 当前范围(I09b-α1)

- ✅ `manifest.json`:真实 MV3 配置(name / version 0.1.10 / host_permissions / content_scripts / CSP);permissions 最小化为 `nativeMessaging` + `activeTab`
- ✅ `background.js`:service worker,`chrome.runtime.connectNative` 长连接 + pending-request map + UUIDv4 `request_id` + 10s TTL;ErrorFrame 按 error 字段优先分流(含 Rust 侧 Option request_id 场景):有 request_id 精准路由 block,无 request_id 立即 **全 pending fail-closed block**(R1 MUST-FIX 2)
- ✅ `content-script.js`:paste + 防抖 input + submit + contenteditable Enter 路径 + 简易 `textContent` toast;submit allow 走 `form.requestSubmit(submitter)` + `WeakSet` allow-once(R1 MUST-FIX 1 保留 HTML validation + 其他 submit listener 参与)
  - **覆盖模型**:manifest 注入的**所有** host 都受**通用** paste/input/keydown 守门保护(与站点无关,主保护层)。content script 以 `all_frames: true` 注入匹配站点 iframe。**深选择器**(`siteAdapters.findPrimaryInput`,form-submit 主输入精确定位)目前覆盖 ChatGPT / Claude / Gemini / Perplexity 4 站;国内 AI 站点(DeepSeek / 豆包 / Kimi / 通义 / 千问 / 智谱 / 元宝 / 文心 / 星火)**仅靠通用守门**,深选择器待真站点 DOM 核验后补(无 adapter 时降级 form 聚合 / fail-safe block,绝不外发原文)
- ✅ 协议严格对齐 `crates/vigil-browser/src/protocol.rs`(`BrowserCheckRequest` / `BrowserCheckResponse` / `BrowserErrorFrame`)

## Native Host 注册

Native messaging host 必须注册到 Chrome 指定目录(OS 特定):

- **Windows**:注册表 `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vigil.host` 指向 host manifest json 的绝对路径
- **macOS**:`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vigil.host.json`
- **Linux**:`~/.config/google-chrome/NativeMessagingHosts/com.vigil.host.json`

Host manifest 需包含 `allowed_origins`(扩展 ID `chrome-extension://<id>/`)以授权此扩展连接。具体注册脚本延 β(需要知道打包后的扩展 ID)。

## 安全契约(ADR 0009 §I-9)

本目录遵守以下不变量:

- **§I-9.1 text in-memory only**:原文经 `chrome.runtime.sendMessage` → service worker → Native Host,中间**不写** `chrome.storage` / `console.log` / `window.*`
- **§I-9.3 特权 scheme fail-closed**:`file://` / `chrome://` / `chrome-extension://` / `devtools://` / `about://` 由 Native Host 拒;service worker 层对非 http(s) origin 做同等早退(`origin_denied_sw` reason code)
- **§I-9.5 1 MB 帧上限**:Native Host 层规范化拒绝;service worker 做 32 MB 字符早退兜底(`too_large_sw` reason code)
- **§D6 三态执行**:service worker 按 Response.action ∈ {allow, redact, block} 原样转发;非法 action / 协议错误帧 → fail-closed `block`
- **toast 不 HTML 注入**:`textContent` 赋值,拒绝 `innerHTML`(content-script.js)
- **纯 vanilla JS**:无外部 npm 依赖,零构建步骤,manifest 声明的文件可直接 "load unpacked" 加载

## 后续规划

- **α2**:按站点深度选择器(ChatGPT `#prompt-textarea` / Claude contenteditable / etc.)的精确 adapter,替代通用 textarea 降级
- **α3**:popup UI 展示最近 N 条 finding + 用户临时豁免(session-scoped allow)
- **β**:E2E(Playwright + headed Chrome + 构造含 hard-secret 的 paste),三平台打包,Host manifest 注册脚本
- **后续迭代**:options page / 用户自定义 host 白名单 / i18n

## 本地加载(开发)

1. Chrome `chrome://extensions/` → 打开 Developer mode
2. Load unpacked → 选 `extensions/chrome-mv3/`
3. 访问任一受支持站点(ChatGPT / Claude / Gemini / Perplexity / DeepSeek / 豆包 / Kimi / 通义 / 千问 / 智谱 / 元宝 / 文心 / 星火),touch paste / input / submit → 若 Native Host 未注册,应看到 "Vigil: 粘贴被阻断(host_disconnected)" 或输入/提交阻断提示(fail-closed)

Native Host 注册脚本未在 α1 范围,用户需按上文手工注册,或等 β 提供注册 CLI。
