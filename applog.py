"""统一日志配置。

打包后 console=False，print 的内容会全部丢失；改为写入
%APPDATA%\\PasswordManager\\logs\\app.log（滚动，最多 3 个备份）。
"""

from __future__ import annotations

import logging
import logging.handlers

from storage import app_config_dir

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """初始化根日志器（幂等，可重复调用）。"""
    log_dir = app_config_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)

    already = any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers)
    if not already:
        handler = logging.handlers.RotatingFileHandler(
            log_dir / "app.log", maxBytes=512 * 1024, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root.addHandler(handler)

    return root
