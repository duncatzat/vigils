# Multi-Platform Build

3 平台 7 件 installer/bundle。

## Linux
```bash
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev
cd apps/desktop
cargo tauri build --features gui --bundles deb,rpm,appimage
```

## macOS
```bash
export CI=true  # 触发 --skip-jenkins,跳过 AppleScript Finder 美化(SSH 非 GUI)
cd apps/desktop
cargo tauri build --features gui --bundles app,dmg
# app target = updater artifact (.app.tar.gz + .sig)
# dmg target = user-facing install
```

## Windows
```bash
cd apps/desktop
cargo tauri build --features gui --bundles msi,nsis
```

## Bin layout(per ADR 0018)

`apps/desktop/Cargo.toml`:`[[bin]] name = "vigils" path = "src/bin/vigils.rs"` —
对齐 Tauri v2 bundle 默认查 path basename(name == path basename == `mainBinaryName`)。
安装后可执行文件为 `vigils.exe`(v0.1.5 起;此前为 `gui`)。
