# 桌面图标生成流水线(#92:圆角柔化,贴合桌面平台惯例)。
#
# 输入:apps/desktop/icons/icon-source.png(1024x1024 设计源,全出血方形)
# 输出:两个派生源(temp)→ 交给 `npx @tauri-apps/cli icon` 生成平台资产:
#   1) universal:全画布加 Apple 比例圆角遮罩(r = 22.37% 边长)→ Windows/Linux/store 资产
#      (四角裁透明;Windows 11 / 现代 Linux shell 同样流行软圆角,统一无违和)
#   2) mac:图形圆角化后缩放到 824/1024 居中(四周留白 100px)→ 仅取 icon.icns
#      (Apple HIG 图标网格:macOS 不给 app 图标自动加遮罩,rounded-square + 留白须资产自备,
#       否则 Launchpad/Dock/Finder 里比邻居"更大更方")
#
# 用法(仓库根):
#   python scripts/gen-icons.py            # 生成派生源到 target/icon-gen/
#   npx @tauri-apps/cli icon target/icon-gen/source-universal.png -o target/icon-gen/universal
#   npx @tauri-apps/cli icon target/icon-gen/source-mac.png -o target/icon-gen/mac
#   然后:universal/* → apps/desktop/icons/(保留 mac/icon.icns 覆盖 icon.icns)
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "apps" / "desktop" / "icons" / "icon-source.png"
OUT = ROOT / "target" / "icon-gen"

# Apple 圆角矩形比例:1024 网格上图形 824x824、圆角半径 ~185.4 → r/边 ≈ 22.5%。
# 全画布版取同比例(1024 * 0.2237 ≈ 229),视觉与系统图标一致。
RADIUS_RATIO = 0.2237
MAC_CONTENT = 824  # Apple HIG:1024 画布上图标图形区 824x824(四周留白 100)
SUPERSAMPLE = 4  # mask 超采样抗锯齿


def rounded(im: Image.Image, radius_ratio: float) -> Image.Image:
    """给整幅图加圆角遮罩(四角透明),mask 超采样抗锯齿。"""
    im = im.convert("RGBA")
    w, h = im.size
    r = int(min(w, h) * radius_ratio)
    big = (w * SUPERSAMPLE, h * SUPERSAMPLE)
    mask = Image.new("L", big, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, big[0] - 1, big[1] - 1], radius=r * SUPERSAMPLE, fill=255
    )
    mask = mask.resize(im.size, Image.LANCZOS)
    out = Image.new("RGBA", im.size, (0, 0, 0, 0))
    out.paste(im, (0, 0), mask)
    return out


def main() -> int:
    if not SRC.is_file():
        print(f"source not found: {SRC}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    src = Image.open(SRC).convert("RGBA")
    if src.size != (1024, 1024):
        src = src.resize((1024, 1024), Image.LANCZOS)

    # 1) universal:全画布圆角。
    uni = rounded(src, RADIUS_RATIO)
    uni.save(OUT / "source-universal.png")

    # 2) mac:圆角化 → 缩到 824 → 1024 透明画布居中(Apple HIG 留白)。
    content = rounded(src, RADIUS_RATIO).resize((MAC_CONTENT, MAC_CONTENT), Image.LANCZOS)
    pad = (1024 - MAC_CONTENT) // 2
    mac = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    mac.paste(content, (pad, pad), content)
    mac.save(OUT / "source-mac.png")

    print(f"wrote {OUT / 'source-universal.png'}")
    print(f"wrote {OUT / 'source-mac.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
