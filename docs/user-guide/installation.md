# Installation — Vigil

> **从 [GitHub Releases](https://github.com/duncatzat/vigils/releases) 获取当前版本产物**(CLI 三平台 zip/tar、桌面安装包、ML 变体、Chrome 扩展,全部带 `.sha256` 与 minisign 签名)。下文示例中的 `dist/v0.2/` 目录布局是**旧版打包形态**,仅作路径示意;复制到 PATH、注册扩展 / native-host 等步骤在各版本通用。较新命令(`setup` / `posture` / `demo` 等)见 [getting-started](getting-started.md) 与 [`CHANGELOG.md`](../../CHANGELOG.md)。

## 1. 系统要求

| 平台 | 最低 | 备注 |
|---|---|---|
| Windows | 10 / 11 x86_64 | WebView2 预装(Win10+ 默认有) |
| Linux | Ubuntu 22.04+ / glibc 2.31+,x86_64 | **v0.2 支持 GUI**,运行时需 `libwebkit2gtk-4.1-0`、`libayatana-appindicator3-1`、`librsvg2-2` |
| macOS | 11+ arm64(Apple Silicon)| **v0.2 支持 GUI**,x86_64 需自行编译 |
| Chrome | 109+(MV3 稳定) | Firefox / Safari 未支持 |

## 2. 下载 artifact

**来源**:本仓库 `dist/v0.2/`(预打包)。

```
dist/v0.2/
├── windows/
│   ├── vigil-desktop-gui.exe    ← ★ 真 Tauri GUI(双击出窗口)
│   ├── vigil-desktop.exe        ← CLI(I08a 协议层,通常不直接用)
│   ├── vigil-hub.exe            ← CLI 管理 + `serve --stdio`(供 agent 连)
│   ├── vigil-native-host.exe    ← Chrome Native Host
│   └── SHA256SUMS
├── linux/
│   ├── vigil-desktop            ← Tauri GUI(ELF)
│   ├── vigil-hub
│   ├── vigil-native-host
│   └── SHA256SUMS
├── macos/
│   ├── vigil-desktop            ← Tauri GUI(Mach-O arm64)
│   ├── vigil-hub
│   ├── vigil-native-host
│   └── SHA256SUMS
└── extensions/
    ├── vigil-chrome-mv3-v0.1.zip
    └── vigil-chrome-mv3-v0.1.zip.sha256
```

## 3. Windows 安装(5 步)

### 3.1 放置 binary

```powershell
# 随处解压,推荐
mkdir C:\Vigil
Copy-Item dist\v0.2\windows\*.exe C:\Vigil\
```

### 3.2 加入 PATH(可选但推荐)

```powershell
# 系统变量 → Path → 新增 C:\Vigil
[Environment]::SetEnvironmentVariable(
  "Path", $env:Path + ";C:\Vigil", "User")
# 新开 PowerShell 生效
```

### 3.3 加载 Chrome 扩展(unpacked)

1. 解压 `dist\v0.2\extensions\vigil-chrome-mv3-v0.1.zip` 到任意目录,例如 `C:\Vigil\chrome-mv3`
2. Chrome → `chrome://extensions` → 右上"开发者模式"开
3. 点 "加载已解压的扩展程序" → 选 `C:\Vigil\chrome-mv3`
4. **复制扩展 ID**(UI 上显示的 32 字符串,形如 `ahvzoxrk…`)

### 3.4 注册 Native Messaging Host

```powershell
cd C:\Vigil
.\vigil-native-host.exe install --extension-id <上一步复制的 ID>
# 输出:Installed native messaging host 'com.vigil.host'
```

这会写 HKCU 注册表 `SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vigil.host`。

### 3.5 启动 Desktop GUI

```powershell
# 直接双击 C:\Vigil\vigil-desktop-gui.exe(注意是 -gui 后缀)
# 或 PowerShell:
.\vigil-desktop-gui.exe
# 说明:不带 `-gui` 后缀的 vigil-desktop.exe 是 CLI(I08a 协议层,输出 JSON),
# 双击不会出窗口。GUI 唯一入口 = vigil-desktop-gui.exe
```

首次启动会在 `%LOCALAPPDATA%\Vigil\ledger.sqlite3` 创建 SQLite ledger(**是 `%LOCALAPPDATA%`,不是 `%APPDATA%`/Roaming,文件名带 `3`**;Linux = `~/.local/share/Vigil/ledger.sqlite3`,macOS = `~/Library/Application Support/Vigil/ledger.sqlite3`)。

## 4. Linux 安装(v0.2 起支持 GUI)

### 4.1 运行 GUI 需系统包(一次性)

```bash
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libxdo-dev
# 仅运行 portable 二进制时需要运行时 SO 版本(通常 Ubuntu 22.04+ 默认有 libwebkit2gtk-4.1-0 等)
```

### 4.2 放 binary

```bash
# GUI + CLI
sudo install -m 755 dist/v0.2/linux/vigil-desktop       /usr/local/bin/
sudo install -m 755 dist/v0.2/linux/vigil-hub           /usr/local/bin/
sudo install -m 755 dist/v0.2/linux/vigil-native-host   /usr/local/bin/
# 或免 sudo:放 ~/.local/bin(确保在 PATH)

vigil-desktop   # 启动 GUI
```

## 5. macOS 安装(v0.2 起支持 GUI,arm64)

```bash
# 1. 放 binary(arm64 原生)
sudo install -m 755 dist/v0.2/macos/vigil-desktop       /usr/local/bin/
sudo install -m 755 dist/v0.2/macos/vigil-hub           /usr/local/bin/
sudo install -m 755 dist/v0.2/macos/vigil-native-host   /usr/local/bin/
# 或免 sudo:~/.local/bin

# 首次启动会触发 Gatekeeper 警告(v0.2 未 notarize),右键 → 打开 → 允许

# 2. Chrome 扩展(同 Windows 3.3)
unzip dist/v0.2/extensions/vigil-chrome-mv3-v0.1.zip -d ~/vigil-chrome-mv3

# 3. 注册 Native Host
vigil-native-host install --extension-id <EXTENSION_ID>
# Linux 写:~/.config/google-chrome/NativeMessagingHosts/com.vigil.host.json
# macOS 写:~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vigil.host.json
```

## 5. 验证安装

```powershell
# Windows
.\vigil-hub.exe --version      # 应打印所装 release 的版本号(与下载的 tag 一致)
.\vigil-native-host.exe status # 应打印 installed: true + manifest 路径
```

Chrome 打开 `chrome://extensions` → "Vigil" 项 → 展开 service worker → Console 没红色 error。

**下一步**:[Getting Started](getting-started.md) — 5 分钟跑通一个真实场景。

## 6. 卸载

```powershell
# Windows
.\vigil-native-host.exe uninstall
Remove-Item -Recurse C:\Vigil
# Chrome 扩展页手动移除
# %LOCALAPPDATA%\Vigil\ledger.sqlite3 的 ledger 数据(审计链)按需保留/删除
```

Linux/macOS 对应:`rm` binary + `vigil-native-host uninstall` + 清 `~/.config/Vigil/` 或 `~/Library/Application Support/Vigil/`。
