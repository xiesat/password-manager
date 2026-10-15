"""密码管理器入口。"""

from __future__ import annotations

import os
import sys

from PySide6.QtWidgets import QApplication

from applog import setup_logging
from controller import PasswordManagerController


def resource_path(*parts: str) -> str:
    """返回资源绝对路径（兼容 PyInstaller 打包）。"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def main() -> int:
    setup_logging()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    qss_path = resource_path("resources", "style.qss")
    if os.path.exists(qss_path):
        with open(qss_path, encoding="utf-8") as handle:
            app.setStyleSheet(handle.read())

    controller = PasswordManagerController()
    app.aboutToQuit.connect(controller.on_app_close)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
