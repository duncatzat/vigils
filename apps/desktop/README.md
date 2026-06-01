# vigil-desktop

Vigil 本地控制面的 Desktop 层(ADR 0008)。

## 范围

- **I08a (已 Accepted)**:Rust CLI (`vigil-desktop` binary),完整 UiCommand dispatch → Ledger
- **I08b-α1 (本轮)**:Tauri 2 + Vue 3 GUI 脚手架(feature `gui`,默认关闭),smoke test

## CLI:命令行查账本(`vigil-hub inspect`)

I08a 的 `vigil-desktop` 调试 CLI 已于 v0.1.2 整合进产品主 CLI `vigil-hub`(本 crate 的
lib 层 dispatch/render 消费逻辑保留,由 `vigil-hub inspect` 复用):

```bash
vigil-hub inspect --db-path ./vigil.db session list
vigil-hub inspect --db-path ./vigil.db approvals list
# ... 详见 `vigil-hub inspect --help`
```

## GUI(I08b-α1,需 feature + 环境就绪)

### 环境依赖

| 依赖 | 要求 | 安装 |
|------|-----|------|
| Node.js | ≥ 18 | https://nodejs.org/ |
| npm | ≥ 9 | Node.js 自带 |
| `@tauri-apps/cli` | ^2.1.0 | `npm install` 时自动(devDep) |
| WebView2 runtime | Win 自带(Win11 默认装);Mac/Linux 自带 WebKit | — |

### 首次启动(dev)

```bash
# 1. 安装 UI 依赖(~300 MB node_modules,拉 ~600 packages;首次 ~2-3 min)
cd apps/desktop/ui
npm install
cd ..

# 2. 安装 tauri-cli(全局或 per-project cargo install)
cargo install tauri-cli --version '^2.0.0' --locked
# 或用 ui 侧 npm 脚本(`npm run tauri` 透传到 @tauri-apps/cli)

# 3. 启动 dev 模式(feature `gui` 会触发首次 tauri 依赖编译,~3-5 min;含 vite HMR)
cargo tauri dev --features gui
# 或:
# cd ui && npm run tauri -- dev
```

### 构建发行包(延 β,α1 未就绪)

⚠ **`cargo tauri build --features gui` 当前会失败**:`tauri.conf.json:bundle.icon`
引用的 `icons/*.png` / `.ico` 占位文件未生成。β 阶段补齐(`npx @tauri-apps/cli icon ...`)
后可用:

```bash
cargo tauri build --features gui  # 目标:target/release/bundle/{msi,deb,appimage}
```

**α1 范围**:仅验收 `tauri dev` smoke(使用 Tauri 默认 fallback 图标),**不跑 bundle**。

## 架构

```
apps/desktop/
├── Cargo.toml                       # 双 binary + feature gate
├── build.rs                         # cfg(feature="gui") 触发 tauri_build::build()
├── tauri.conf.json                  # Tauri 2 config(CSP + window + bundler)
├── capabilities/default.json        # 系统能力 capability 基线(window/core;非 app-command 级 gate)
├── icons/                           # 占位(β 正式化)
├── src/
│   ├── main.rs                      # I08a CLI binary(保留)
│   ├── lib.rs                       # dispatch 逻辑(CLI/GUI 共享)
│   ├── commands/                    # I08a CLI command 构造
│   ├── render.rs                    # UiResponse → JSON 渲染
│   └── bin/
│       └── gui.rs                   # I08b GUI binary(feature=gui)
├── tests/                           # Rust 集成测试(CLI 侧)
└── ui/                              # Vue 3 + Vite + TS 前端
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── .eslintrc.cjs                # 禁 v-html / security plugin
    ├── index.html
    ├── src/
    │   ├── main.ts
    │   ├── App.vue                  # α1 smoke UI
    │   ├── assets/tailwind.css
    │   └── api/ipc.ts               # Tauri invoke type-safe wrapper
    └── tests/                       # Vitest unit(α1-6 CSP test 延后)
```

## Feature matrix

| 场景 | 命令 | 编译的 binary | 触发 tauri deps? |
|------|-----|--------------|------------------|
| workspace CI | `cargo test --workspace` | 仅 lib | ❌ 零拉取 |
| 查账本 CLI | `vigil-hub inspect …` | `vigil-hub`(另一 crate) | ❌ 零拉取 |
| GUI 开发 | `cargo tauri dev --features gui` | 仅 `gui` | ✅ |
| GUI 发行 | `cargo tauri build --features gui` | 仅 `gui`(包内唯一 bin) | ✅ |

## 安全不变量(I08b α1-β1 累计守门)

1. **CSP 严格**:`script-src 'self'` + 禁 `unsafe-eval`(`tauri.conf.json:app.security.csp`);`style-src 'unsafe-inline'` 是 Vue/Naive UI dynamic style 的必要妥协(script 侧严格)
2. **Capability 真白名单(β1)**:`capabilities/default.json` 同时引用 `core:default`(系统能力)与 19 条 `allow-<slugified>` 应用层命令。构建期由 `tauri_build::Attributes::app_manifest(AppManifest::new().commands(INVOKE_COMMANDS))` 生成权限;未列入 SSOT(`apps/desktop/src/commands.rs::INVOKE_COMMANDS`)的 handler 即使注册了 `#[tauri::command]`,frontend invoke 会被 ACL 拒绝 —— hard gate。三处(SSOT + `generate_handler!` + `capabilities/default.json`)由单元测试精确集合比对守门
3. **Exact argv 展示**:前端一律 `{{ }}` / `<pre>` 渲染,**严禁 `v-html`**(ESLint `vue/no-v-html: error` 守)
4. **Secret 不可达 UI**:所有 payload 走 `vigil-ui-protocol` 已脱敏字段;新 IPC 类型必须经 redaction 断言
5. **unsafe 隔离**:Rust 侧 `forbid(unsafe_code)`(workspace 继承);GUI binary 不例外

## 已知延期项(β2+ / 发行前)

- **β2**:specta TS 类型自动生成(当前手写 `ui/src/api/ipc.ts`,α5 刚修过一个 `ListSessionsReq.limit` 漂移)
- **β3**:EffectKind TS enum + ReviewOverlay 审计员视角
- **β4**:Playwright + tauri-driver E2E
- **β5**:用户数据目录 SQLite(当前 GUI 启动用 in-memory ledger)
- **发行前**:`icons/` 正式图标(α1 占位)→ `tauri build` 可出发行包 / 三平台打包 CI / ESLint CSP 违反测试

## 相关文档

- 上游 roadmap:`.workflow/.planning/ROADMAP-i08b-desktop-ui-1776858799/roadmap.md`
- 栈选型 brainstorm:`.workflow/.brainstorm/BS-tauri-frontend-stack-1776857091/brainstorm.md`
- ADR 0008:`docs/adr/0008-desktop-ui.md`
