"""本地存储与配置。

- 原子写入：先写同目录临时文件，fsync 后 os.replace，避免写坏密码库。
- 配置改为 %APPDATA%\\PasswordManager\\config.json，不再使用 CWD 下的
  Base64 \"伪加密\" last_file_config.ini。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

APP_NAME = "PasswordManager"
CONFIG_FILE = "config.json"


def resource_path(*parts: str) -> str:
    """返回资源绝对路径（兼容 PyInstaller 打包）。"""
    import sys

    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def app_config_dir() -> Path:
    """返回应用配置目录（不存在则创建）。"""
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = Path(base) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: str | os.PathLike[str], text: str, encoding: str = "utf-8") -> None:
    """原子地把文本写入 path。失败时不会留下半截目标文件。"""
    target = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(target)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp", prefix=".pm-")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def read_text(path: str | os.PathLike[str], encoding: str = "utf-8") -> str:
    """读取文本；解码失败时以忽略错误的方式读取（保持旧的容错行为）。"""
    with open(path, encoding=encoding, errors="ignore") as handle:
        return handle.read()


def get_device_id() -> str:
    """返回本机稳定的短设备标识（首次调用时生成并持久化）。"""
    import uuid

    config = load_config()
    device_id = str(config.get("device_id") or "")
    if not device_id:
        device_id = uuid.uuid4().hex[:8]
        config["device_id"] = device_id
        save_config(config)
    return device_id


def load_config() -> dict:
    """读取 config.json；不存在或损坏时返回空字典。"""
    path = app_config_dir() / CONFIG_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
        return {}


def save_config(config: dict) -> None:
    """原子写入 config.json。"""
    atomic_write_text(
        app_config_dir() / CONFIG_FILE,
        json.dumps(config, ensure_ascii=False, indent=2),
    )
