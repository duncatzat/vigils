# Tauri Bundle Icons (占位)

I08b-α1 仅放占位说明。β 阶段正式化:
- `32x32.png`(Win 任务栏 / Linux 任务栏)
- `128x128.png`(Mac dock / Linux menu)
- `icon.ico`(Win installer)
- `icon.icns`(Mac app bundle)

生成方式(β 前执行):
```bash
# 从 SVG 或高分辨率 PNG 自动派生
npx @tauri-apps/cli icon path/to/source-icon.png
```

**现状**:`tauri.conf.json` 里 icon 数组已指向这些文件名,但文件不存在 → `tauri build` 会失败。开发期 `tauri dev` 不强制需要 icon(默认 fallback),smoke test 可跑。
