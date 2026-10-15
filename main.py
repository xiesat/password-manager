"""密码管理器入口。"""

from __future__ import annotations

import os
import sys

from PySide6.QtCore import QTranslator
from PySide6.QtWidgets import QApplication

import storage
from applog import setup_logging
from controller import PasswordManagerController


def install_translator(app: QApplication) -> QTranslator | None:
    """按配置安装英文翻译（缺省中文，即源语言）。"""
    language = str(storage.load_config().get("language", "zh"))
    if language != "en":
        return None
    qm_path = storage.resource_path("resources", "translations", "app_en.qm")
    if not os.path.exists(qm_path):
        return None
    translator = QTranslator(app)
    if translator.load(qm_path):
        app.installTranslator(translator)
        return translator
    return None


def main() -> int:
    setup_logging()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    translator = install_translator(app)  # noqa: F841 - 保持引用防止被回收

    controller = PasswordManagerController()
    app.aboutToQuit.connect(controller.on_app_close)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
