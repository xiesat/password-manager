"""离屏 UI 冒烟测试（需要 PySide6）。"""

from __future__ import annotations

import os
from datetime import datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication  # noqa: E402

import theme
from table_model import MASK, PASSWORD_ROLE


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture()
def controller(app, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from controller import PasswordManagerController

    instance = PasswordManagerController()
    instance.view.switch_to_main_interface()
    return instance


def _display(view, row, column):
    return view.table_model.data(view.table_model.index(row, column), Qt.ItemDataRole.DisplayRole)


def test_table_masks_passwords_by_default(controller):
    controller.model.add_or_update_subject("Google", length=16)
    controller._reload()
    assert controller.view.table_model.rowCount() == 1
    assert _display(controller.view, 0, 0) == "Google"
    assert _display(controller.view, 0, 1) == MASK

    index = controller.view.table_model.index(0, 1)
    assert controller.view.table_model.data(index, PASSWORD_ROLE) == controller.model.main_data[0]["password"]

    controller.view.set_show_passwords(True)
    assert _display(controller.view, 0, 1) == controller.model.main_data[0]["password"]


def test_empty_state_and_stack(controller):
    controller._reload()
    assert controller.view.table_model.rowCount() == 0
    assert controller.view.stack.currentIndex() == 1
    controller.model.add_or_update_subject("A")
    controller._reload()
    assert controller.view.stack.currentIndex() == 0


def test_dirty_marker_in_title(controller):
    controller.view.update_window_title(r"C:\vault\MyVault.sk")
    assert "MyVault.sk" in controller.view.windowTitle()
    assert "C:\\vault" not in controller.view.windowTitle()
    controller.view.set_dirty(True)
    assert controller.view.windowTitle().endswith("*")
    assert controller.view.dirty_indicator.text()


def test_live_search_filters_rows(controller):
    controller.model.add_or_update_subject("Google")
    controller.model.add_or_update_subject("GitHub")
    controller._reload()
    assert controller.view.proxy.rowCount() == 2
    controller.view._on_search_changed("git")
    assert controller.view.proxy.rowCount() == 1
    controller.view._on_search_changed("")
    assert controller.view.proxy.rowCount() == 2


def test_sorting_by_count(controller):
    controller.model.add_or_update_subject("A")
    controller.model.add_or_update_subject("B")
    controller.model.main_data[0]["count"] = "9"
    controller.model.main_data[1]["count"] = "1"
    controller._reload()
    controller.view.table.sortByColumn(2, Qt.SortOrder.AscendingOrder)
    first = controller.view.proxy.data(controller.view.proxy.index(0, 0), Qt.ItemDataRole.DisplayRole)
    assert first == "B"


def test_history_window_populates_and_masks(controller):
    controller.model.add_or_update_subject("A", length=12)
    controller.model.generate_new_password_for_subject(0)
    history = controller.model.get_history_for_subject("A")
    noop = lambda *_args: None  # noqa: E731
    controller.view.show_history_window(
        "A", history, {"copy": noop, "delete": noop, "undo": noop, "redo": noop}
    )
    window = controller.view.history_window
    assert window is not None and window.subject_name == "A"
    # 新增时的首个密码 + 重新生成的一条
    assert window.tree.topLevelItemCount() == 2
    assert window.tree.topLevelItem(0).text(2)
    assert window.tree.topLevelItem(0).text(1) == MASK


def test_write_current_sets_path_and_clears_dirty(controller, tmp_path):
    controller.model.add_or_update_subject("X")
    controller._session_key = "k"
    path = tmp_path / "vault.sk"
    assert controller._write_current(str(path), new_path=True) is True
    assert path.exists()
    assert controller.model.current_file_path == str(path)
    assert controller.model.is_dirty() is False
    assert "vault.sk" in controller.view.windowTitle()


def test_clipboard_countdown(controller):
    controller._copy_to_clipboard_with_timer("secret")
    assert "30" in controller.view.clipboard_label.text()
    controller._on_clipboard_tick()
    assert "29" in controller.view.clipboard_label.text()
    controller.clipboard_seconds = 1
    controller._on_clipboard_tick()
    assert controller.view.clipboard_label.text() == ""


def test_theme_applies(controller):
    controller.view.apply_theme("dark")
    assert theme.DARK["bg"] in QApplication.instance().styleSheet()
    controller.view.apply_theme("light")
    assert theme.LIGHT["bg"] in QApplication.instance().styleSheet()


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

    unlock = UnlockDialog("t", "m", confirm=True)
    unlock.key_edit.setText("abc")
    unlock.confirm_edit.setText("abc")
    assert unlock.key() == "abc"


def test_generate_selected_via_controller(controller):
    controller.model.add_or_update_subject("A", length=12)
    controller._reload()
    controller.view.table.selectRow(0)
    previous = controller.model.main_data[0]["password"]
    controller.handle_generate_selected()
    assert controller.model.main_data[0]["password"] != previous
    assert controller.model.main_data[0]["count"] == "1"
