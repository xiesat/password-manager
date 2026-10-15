"""离屏 UI 冒烟测试（需要 PySide6）。"""

from __future__ import annotations

import os
from datetime import datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture()
def controller(app, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from controller import PasswordManagerController

    instance = PasswordManagerController()
    instance.view.switch_to_main_interface()  # 真实流程：先解锁/新建，再刷新表格
    return instance


def test_masking_and_row_values(controller):
    controller.model.add_or_update_subject("Google", length=16)
    controller._refresh_table_from_model()
    items = controller.view.get_all_row_items()
    assert len(items) == 1
    assert items[0].text(1) == "Google"
    assert items[0].text(2) == "\u2022" * 10  # 默认掩码
    assert controller.view.get_row_values(items[0])[2]  # 真实密码取得到

    controller.view.show_passwords_action.setChecked(True)
    assert items[0].text(2) != "\u2022" * 10  # 显示后为明文


def test_dirty_marker_in_title(controller):
    controller.view.update_window_title(r"C:\vault\MyVault.sk")
    assert "MyVault.sk" in controller.view.windowTitle()
    assert "C:\\vault" not in controller.view.windowTitle()  # 不再暴露完整路径
    controller.view.set_dirty(True)
    assert controller.view.windowTitle().endswith("*")
    assert "未保存" in controller.view.dirty_indicator.text()


def test_live_search_filters_rows(controller):
    controller.model.add_or_update_subject("Google")
    controller.model.add_or_update_subject("GitHub")
    controller._refresh_table_from_model()
    controller.view._on_search_changed("git")
    assert [i.isHidden() for i in controller.view.get_all_row_items()] == [True, False]
    controller.view._on_search_changed("")
    assert not any(i.isHidden() for i in controller.view.get_all_row_items())


def test_history_window_populates_and_masks(controller):
    controller.model.add_or_update_subject("A", length=12)
    controller.model.generate_new_password_for_subject(0)
    history = controller.model.get_history_for_subject("A")
    noop = lambda *_args: None  # noqa: E731
    controller.view.show_history_window(
        "A", history, {"copy": noop, "delete": noop, "undo": noop, "redo": noop}
    )
    window = controller.view.history_window
    assert window is not None
    assert window.subject_name == "A"
    assert window.tree.topLevelItemCount() == 1
    assert window.tree.topLevelItem(0).text(2)  # 生成时间
    assert window.tree.topLevelItem(0).text(1) == "\u2022" * 10


def test_write_current_sets_path_and_clears_dirty(controller, tmp_path):
    controller.model.add_or_update_subject("X")
    controller._session_key = "k"
    path = tmp_path / "vault.sk"
    assert controller._write_current(str(path), new_path=True) is True
    assert path.exists()
    assert controller.model.current_file_path == str(path)
    assert controller.model.is_dirty() is False
    assert str(path) not in controller.view.windowTitle()
    assert "vault.sk" in controller.view.windowTitle()


def test_backup_timestamp_handles_underscore_names():
    from controller import PasswordManagerController

    result = PasswordManagerController._extract_timestamp_from_backup(
        r"C:\x\.password_manager_backups\my_file_20240102_030405.tmp"
    )
    assert result == datetime(2024, 1, 2, 3, 4, 5)


def test_dialogs_construct(controller):
    from view import AddSubjectDialog, UnlockDialog

    add = AddSubjectDialog()
    assert add.get_data()[1] == 16
    assert "预览" in add.preview_label.text()

    unlock = UnlockDialog("t", "m", confirm=True)
    unlock.key_edit.setText("abc")
    unlock.confirm_edit.setText("abc")
    assert unlock.key() == "abc"


def test_reset_to_initial_clears_table(controller):
    controller.model.add_or_update_subject("A")
    controller._refresh_table_from_model()
    controller.view.reset_to_initial()
    assert controller.view.work_widget.isVisible() is False
    assert "密码管理器" == controller.view.windowTitle()
