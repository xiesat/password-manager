"""主题系统：浅色 / 深色 / 跟随系统。

resources/style.qss 是带 @token 占位符的模板，这里把 token 替换为调色板颜色。
"""

from __future__ import annotations

import logging
import re

import storage

logger = logging.getLogger(__name__)

LIGHT: dict[str, str] = {
    "brand": "#2E5BE0",
    "brandDark": "#1E3FA8",
    "onBrand": "#FFFFFF",
    "navy": "#1B2A4A",
    "green": "#2BD98A",
    "danger": "#E5484D",
    "warn": "#F59E0B",
    "bg": "#F5F7FB",
    "surface": "#FFFFFF",
    "surfaceAlt": "#FAFBFD",
    "border": "#E2E8F0",
    "text": "#1E293B",
    "muted": "#64748B",
    "headerBg": "#F1F5F9",
    "selBg": "#EEF2FF",
    "selText": "#1E293B",
    "hoverBg": "#F1F5F9",
    "disabledText": "#94A3B8",
    "scrollHandle": "#CBD5E1",
    "tooltipBg": "#1B2A4A",
    "tooltipText": "#FFFFFF",
}

DARK: dict[str, str] = {
    "brand": "#4C7DF0",
    "brandDark": "#3A63C8",
    "onBrand": "#FFFFFF",
    "navy": "#E2E8F0",
    "green": "#34D399",
    "danger": "#F87171",
    "warn": "#FBBF24",
    "bg": "#0F172A",
    "surface": "#1E293B",
    "surfaceAlt": "#172033",
    "border": "#334155",
    "text": "#E2E8F0",
    "muted": "#94A3B8",
    "headerBg": "#172033",
    "selBg": "#1E3A8A",
    "selText": "#E2E8F0",
    "hoverBg": "#273449",
    "disabledText": "#64748B",
    "scrollHandle": "#475569",
    "tooltipBg": "#E2E8F0",
    "tooltipText": "#0F172A",
}

PALETTES = {"light": LIGHT, "dark": DARK}
THEME_SETTINGS = ("light", "dark", "system")
DEFAULT_SETTING = "system"
_TOKEN_RE = re.compile(r"@([A-Za-z][A-Za-z0-9]*)")


def detect_system_dark() -> bool:
    """Windows：读取注册表判断系统是否使用深色应用主题。"""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return value == 0
    except Exception:  # noqa: BLE001 - 非 Windows 或读取失败都退回浅色
        return False


def resolve_theme(setting: str) -> str:
    """把设置值解析为具体的 light/dark。"""
    if setting in PALETTES:
        return setting
    return "dark" if detect_system_dark() else "light"


def build_stylesheet(setting: str) -> str:
    """按设置生成最终 QSS。"""
    palette = PALETTES[resolve_theme(setting)]
    template = storage.read_text(storage.resource_path("resources", "style.qss"))

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in palette:
            return palette[key]
        logger.warning("样式表中存在未知主题变量：@%s", key)
        return match.group(0)

    return _TOKEN_RE.sub(replace, template)


def load_setting() -> str:
    value = str(storage.load_config().get("theme", DEFAULT_SETTING))
    return value if value in THEME_SETTINGS else DEFAULT_SETTING


def save_setting(value: str) -> None:
    if value not in THEME_SETTINGS:
        value = DEFAULT_SETTING
    config = storage.load_config()
    config["theme"] = value
    storage.save_config(config)
