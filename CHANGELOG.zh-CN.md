# 更新日志

Vigils 的所有重要变更记录于此。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/),版本遵循
[语义化版本](https://semver.org/lang/zh-CN/)(0.x 阶段允许接口演进)。

> English version: [CHANGELOG.md](./CHANGELOG.md)

---

## [v0.1.3] — 2026-06-01

桌面 GUI 渲染修复。桌面应用现在能真正渲染界面。v0.1.2 修好了"安装包装 GUI 而非 CLI",但 GUI
打开仍是空白/黑屏:vue-i18n 在运行时用 `new Function` 编译多语言消息,被应用的严格 CSP
(`script-src 'self'`,无 `'unsafe-eval'`)拦截,导致渲染中断。

### 修复

- 桌面 GUI 不再打开空白/黑屏窗口。给 vue-i18n 注入 CSP 安全的自定义 `messageCompiler`(纯
  `{named}` 插值,无 `eval` / `new Function`),使 UI 在不放宽严格 CSP 的前提下正常渲染。此问题
  只影响打包/安装的应用 —— `tauri dev` 用宽松 CSP,故在 v0.1.2 让 GUI 首次可安装前一直未暴露。

### 变更

- workspace 与桌面应用版本 `0.1.2` → `0.1.3`。

---

## [v0.1.2] — 2026-06-01

桌面安装包修复。Windows / macOS / Linux 三平台桌面安装包现在装的是真正的 GUI 应用。v0.1.0 与
v0.1.1 的桌面安装包误打入了无窗口的 CLI 二进制 —— 双击安装后的应用只闪一下控制台便退出,而不
打开窗口。CLI 二进制本身正常,仅桌面安装包受影响。

### 修复

- 桌面安装包现在装 GUI 而非 CLI。`apps/desktop` 原有第二个 `[[bin]]`(`vigil-desktop` 调试
  CLI);`cargo tauri build` 会构建全部二进制(`cargo build --bins`)并把错误的那个打成应用主
  程序。现 desktop crate 仅保留 `gui` 一个二进制,打包器只能打 GUI。

### 变更

- 移除 `vigil-desktop` 调试 CLI;其查账本能力整合进主 CLI 的 `vigil-hub inspect` 子命令
  (`activity` / `search` / `approvals` / `session` / `servers` / `sandbox` / `verify-chain`;
  单行 JSON 输出,便于脚本化)。
- workspace 与桌面应用版本 `0.1.1` → `0.1.2`。

---

## [v0.1.1] — 2026-06-01

打包补全版本。在既有 NSIS / DMG / DEB / AppImage 之外新增 Windows MSI 与 Linux RPM 安装包,并
将 workspace 与桌面应用版本号对齐公开发布线。无库或运行时行为变更。

### 新增

- Windows MSI 安装包与 Linux RPM 包纳入发布产物。

### 变更

- workspace 与桌面应用版本 `0.0.1` → `0.1.1`,对齐公开发布 tag。
- README 安装表补全各平台完整安装包清单。

---

## [v0.1.0] — 2026-06-01

Vigils 首个公开版本 —— 面向 AI Agent 的本地优先控制平面。

### 新增

- **审计账本** —— SQLite、SHA-256 哈希链、FTS5 全文检索、逐事件完整性。
- **防火墙与审批** —— 默认拒绝工具门禁、按 Agent 策略、人在回路的范围化审批队列。
- **脱敏引擎** —— 硬指纹规则 + 可选 ML 集成的密钥/PII 检测,配 fail-closed 合并层。
- **凭据租约 broker** —— 短时凭据租约;明文永不落盘。
- **沙箱 runner** —— Wasm(Wasmtime)与 native 执行、Linux Landlock LSM 文件系统隔离,默认
  fail-closed。
- **MCP 网关** —— stdio 与 HTTP 双传输、descriptor pinning + 漂移检测、OAuth scope 白名单。
- **桌面应用**(Tauri 2 + Vue 3)—— 审批队列、活动流、服务器注册、会话回放、隐私发现;键盘
  快捷键、主题切换、实时更新、中英双语 UI。
- **浏览器扩展**(Chrome MV3)—— 在 AI 站点粘贴/提交前脱敏密钥/PII。

采用 Apache-2.0 许可证。
