# Vigils Desktop (React)

基于 **Tauri 2 + React 18 + Vite 5 + Tailwind CSS 3** 的 Vigils 桌面控制面板。

## 定位

本项目是 `apps/desktop` 的 React 重构版本，面向非 CLI 用户的本地 AI 安全控制平面：

- 保护总览（Protection）
- 审批队列（Approvals）
- 审计活动流（Activity）
- 会话回放（Sessions）
- MCP Server 注册与漂移审批（Servers）
- 隐私发现（Privacy）
- 沙箱策略（Sandbox）
- 设置与 ONNX 模型管理（Settings）

后端复用 `apps/desktop` 的 `vigil_desktop` lib（`dispatch`、`embed`、`render`、`ledger_path` 等），前端通过 Tauri `invoke` 与本地 Ledger + Hub 交互。

## 目录结构

```
apps/desktop_react/
├── Cargo.toml              # Tauri binary crate: vigil-desktop-react
├── build.rs                # tauri-build，注入 30 条 invoke 命令白名单
├── tauri.conf.json         # Tauri 2 配置（devUrl / CSP / capability）
├── capabilities/default.json # 30 条 invoke command ACL 白名单
├── src/
│   ├── main.rs             # Tauri 入口：ledger + Hub + 30 个 #[tauri::command]
│   ├── commands.rs         # INVOKE_COMMANDS SSOT（构建期 + capability 引用）
│   └── tests/smoke.rs
└── ui/                     # React 前端
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    └── src/
        ├── App.tsx
        ├── main.tsx
        ├── routes.tsx
        ├── lib/tauri.ts      # 所有 invoke 命令与 DTO 的前端封装
        ├── stores/           # Zustand 主题/姿态 store
        ├── i18n/             # react-i18next 中英双语
        ├── components/layout/# Sidebar / TopBar / PageShell
        └── features/*/pages/ # 8 个功能页面
```

## 本地启动

需要 Node 18+ 与 Rust stable（当前 workspace `rust-toolchain.toml`）。

```bash
# 1. 构建前端
cd apps/desktop_react/ui
npm install
npm run build

# 2. 启动静态预览服务（tauri.conf.json 的 devUrl 指向 http://localhost:8080）
python3 -m http.server 8080 --directory dist

# 3. 在另一个终端编译并运行 Tauri binary
cd ../../..
export CARGO_HOME=/tmp/cargohome              # 规避 iCloud FileProvider 阻塞
export CARGO_TARGET_DIR=/tmp/vigils-target
cargo build -p vigil-desktop-react --no-default-features --features gui
cargo run -p vigil-desktop-react --no-default-features --features gui
```

> 注：`cargo tauri dev` 在当前环境下会频繁触发 `npm list` 插件版本检查并受 node_modules 云同步影响，因此推荐先用 `npm run build` 产出 dist，再用 `cargo run` 直接启动。

## 与旧版 `apps/desktop` 的关系

- `apps/desktop`：原桌面端，binary 名为 `vigils`，启动命令 `cargo run -p vigil-desktop --features gui --bin vigils`。
- `apps/desktop_react`：新的 React 桌面端，binary 名为 `vigil-desktop-react`，启动命令 `cargo run -p vigil-desktop-react --features gui`。

两者共享 `vigil_desktop` lib 的 dispatch / embed / ledger_path 逻辑；`desktop_react` 扩展了 30 条 invoke 命令与 React 前端。

## 关键设计

- **Capability 白名单**：`capabilities/default.json` 与 `src/commands.rs` 的 `INVOKE_COMMANDS` 严格同步，构建期由 `tauri-build` 生成 `allow-*` permission。
- **热更新 Hub 配置**：Settings 页直接调用 `update_hub_config`，修改 `Hub` 的运行时 `RwLock<HubConfig>`。
- **ONNX 模型管理**：Settings 页调用 `list_onnx_models` / `ensure_onnx_model`，后台线程下载模型并通过 `onnx-model-progress` 事件通知前端。
- **实时轮询**：后端 1s 轮询 `Ledger::latest_event_id()`，向前端 emit `ledger-events-changed`，前端 Activity / Approval / Server / Replay 页统一监听。
- **版本号**：沿用 workspace `0.2.0-beta.9`，未单独 bump。

## 当前限制

- 首次 `cargo build` 需要下载 Tauri 2.11 + ONNX 相关 crate，建议在非 iCloud 同步目录设置 `CARGO_HOME` / `CARGO_TARGET_DIR`。
- `devUrl` 当前指向本地静态服务器 `http://localhost:8080`，生产 bundle 使用 `frontendDist: ./ui/dist`。
- 实时更新目前走后端轮询 + 前端事件，SSE/WebSocket 后续迭代补充。
