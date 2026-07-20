# Tauri Bundle Icons

由 `icon-source.png`(1024x1024 设计源)经两段流水线生成(#92 圆角柔化):

```bash
# 1) 派生两个圆角源(universal 全画布圆角 / mac 按 Apple HIG 缩放留白)
python scripts/gen-icons.py

# 2) tauri CLI 生成平台资产(用仓库自带 CLI,避免版本漂移)
cd apps/desktop/ui
./node_modules/.bin/tauri icon ../../../target/icon-gen/source-universal.png -o ../../../target/icon-gen/universal
./node_modules/.bin/tauri icon ../../../target/icon-gen/source-mac.png -o ../../../target/icon-gen/mac

# 3) 部署:universal 全量 → icons/;macOS 专属留白版只取 icns
cp -r target/icon-gen/universal/. apps/desktop/icons/
cp target/icon-gen/mac/icon.icns apps/desktop/icons/icon.icns
```

- `32x32.png` / `128x128.png` / `icon.ico`(`tauri.conf.json` bundle.icon 引用;Win/Linux)
- `icon.icns`(Mac app bundle)——**独立源**:图形缩放 824/1024 居中留白 + 圆角,
  贴合 Apple HIG 图标网格(macOS 不给 app 图标自动加遮罩,全出血方形在 Dock 里
  会比邻居"更大更方",#92)
- `Square*Logo.png` / `StoreLogo.png`(Windows store tiles)
- `android/` `ios/`(tauri icon 副产品;桌面 bundle targets 不消费)

更新图标:改 `icon-source.png` 后重跑上面三步。圆角参数在 `scripts/gen-icons.py`
(`RADIUS_RATIO = 0.2237`,Apple 圆角矩形比例)。
