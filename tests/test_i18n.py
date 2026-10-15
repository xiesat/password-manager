"""i18n 测试：确认英文 .qm 可加载并生效。"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import storage


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def test_english_qm_translates(app):
    qm_path = storage.resource_path("resources", "translations", "app_en.qm")
    assert os.path.exists(qm_path), "app_en.qm 缺失，请先运行 lrelease"

    translator = QTranslator()
    assert translator.load(qm_path) is True
    app.installTranslator(translator)
    try:
        assert QCoreApplication.translate("PasswordManagerView", "新建文件") == "New Vault"
        assert QCoreApplication.translate("PasswordManagerView", "主题") == "Theme"
        assert QCoreApplication.translate("PasswordManagerController", "解锁成功") == "Unlocked"
        assert QCoreApplication.translate("UnlockDialog", "密钥不能为空！") == "Key cannot be empty."
    finally:
        app.removeTranslator(translator)


def test_zh_is_source_language(app):
    # 不安装翻译时应回退到中文源字符串
    assert QCoreApplication.translate("PasswordManagerView", "新建文件") == "新建文件"
