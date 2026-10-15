"""从桌面端图标生成 Android 启动图标（legacy + adaptive）。

用法：在仓库根目录执行
    python android/tools/make_icons.py
依赖：PySide6（桌面端已依赖，无需额外安装）。

源图 resources/app_icon.png 是**透明背景 + 盾牌**，
因此：legacy 图标保持透明底；自适应图标用白色底 + 居中的盾牌前景。
"""

from __future__ import annotations

import os

from PySide6.QtCore import QRect, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPainterPath

HERE = os.path.dirname(os.path.abspath(__file__))
ANDROID = os.path.dirname(HERE)
REPO = os.path.dirname(ANDROID)
SOURCE = os.path.join(REPO, "resources", "app_icon.png")
RES = os.path.join(ANDROID, "app", "src", "main", "res")

DENSITIES = {"mdpi": 1.0, "hdpi": 1.5, "xhdpi": 2.0, "xxhdpi": 3.0, "xxxhdpi": 4.0}

LEGACY_DP = 48
ADAPTIVE_DP = 108
# 自适应前景：图案占画布比例。安全区是 72/108≈0.667，圆形遮罩下也不会被切。
FOREGROUND_RATIO = 0.66
# legacy 方形 / 圆形里图案的占比
SQUARE_RATIO = 0.92
ROUND_RATIO = 0.72
# 自适应图标背景色（源图是透明底，这里取干净的白色）
ADAPTIVE_BACKGROUND = "#FFFFFF"


def opaque_rect(image: QImage) -> QRect:
    """按 alpha 通道找出实际图案范围。"""
    left, top, right, bottom = image.width(), image.height(), -1, -1
    for y in range(image.height()):
        for x in range(image.width()):
            if (image.pixel(x, y) >> 24) & 0xFF > 8:
                left, top = min(left, x), min(top, y)
                right, bottom = max(right, x), max(bottom, y)
    if right < 0:
        return QRect(0, 0, image.width(), image.height())
    return QRect(left, top, right - left + 1, bottom - top + 1)


def render(source: QImage, rect: QRect, size: int, ratio: float, mask: str | None) -> QImage:
    """把 rect 区域按比例居中画到 size×size 的透明画布上；mask 为 round 时套圆形裁切。"""
    target = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    target.fill(Qt.GlobalColor.transparent)

    box = size * ratio
    scale = min(box / rect.width(), box / rect.height())
    width, height = rect.width() * scale, rect.height() * scale
    left, top = (size - width) / 2.0, (size - height) / 2.0

    painter = QPainter(target)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    if mask == "round":
        path = QPainterPath()
        path.addEllipse(QRectF(0, 0, size, size))
        painter.setClipPath(path)
    painter.drawImage(QRectF(left, top, width, height), source, QRectF(rect))
    painter.end()
    return target


def render_adaptive(source: QImage, rect: QRect, size: int, background: QColor) -> QImage:
    """自适应前景：白色不透明底 + 居中图案（背景层同色，视觉上无缝）。"""
    target = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    target.fill(background)

    box = size * FOREGROUND_RATIO
    scale = min(box / rect.width(), box / rect.height())
    width, height = rect.width() * scale, rect.height() * scale
    left, top = (size - width) / 2.0, (size - height) / 2.0

    painter = QPainter(target)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    painter.drawImage(QRectF(left, top, width, height), source, QRectF(rect))
    painter.end()
    return target


def write(path: str, image: QImage) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    image.save(path, "PNG")


def main() -> int:
    application = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841
    source = QImage(SOURCE)
    if source.isNull():
        print("无法读取源图标:", SOURCE)
        return 1

    rect = opaque_rect(source)
    background = QColor(ADAPTIVE_BACKGROUND)
    print(
        f"源图 {source.width()} x {source.height()}，图案区域 "
        f"{rect.x()},{rect.y()} {rect.width()} x {rect.height()}"
    )

    for name, scale in DENSITIES.items():
        folder = os.path.join(RES, "mipmap-" + name)
        legacy = round(LEGACY_DP * scale)
        adaptive = round(ADAPTIVE_DP * scale)

        write(os.path.join(folder, "ic_launcher.png"), render(source, rect, legacy, SQUARE_RATIO, None))
        write(
            os.path.join(folder, "ic_launcher_round.png"), render(source, rect, legacy, ROUND_RATIO, "round")
        )
        write(
            os.path.join(folder, "ic_launcher_foreground.png"),
            render_adaptive(source, rect, adaptive, background),
        )
        print(f"  mipmap-{name:<8} legacy={legacy}px foreground={adaptive}px")

    values = os.path.join(RES, "values")
    os.makedirs(values, exist_ok=True)
    with open(
        os.path.join(values, "ic_launcher_background.xml"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<resources>\n"
            '    <color name="ic_launcher_background">' + background.name() + "</color>\n"
            "</resources>\n"
        )

    anydpi = os.path.join(RES, "mipmap-anydpi-v26")
    os.makedirs(anydpi, exist_ok=True)
    for resource in ("ic_launcher", "ic_launcher_round"):
        with open(os.path.join(anydpi, resource + ".xml"), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@color/ic_launcher_background" />\n'
                '    <foreground android:drawable="@mipmap/ic_launcher_foreground" />\n'
                "</adaptive-icon>\n"
            )
    print("完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
