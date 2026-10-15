"""控制器层 (Controller)。

负责把视图事件转成模型操作，并管理文件、剪贴板、备份与自动加载。
"""

from __future__ import annotations

import copy
import glob
import logging
import os
import re
from datetime import datetime

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

import storage
from model import PasswordManagerModel
from view import PasswordManagerView

logger = logging.getLogger(__name__)

BACKUP_FOLDER = ".password_manager_backups"
BACKUP_PATTERN = re.compile(r"_(\d{8}_\d{6})\.tmp$")
KEEP_BACKUPS = 10
CLIPBOARD_CLEAR_MS = 30_000


class PasswordManagerController:
    """连接模型与视图，处理所有业务流程。"""

    def __init__(self) -> None:
        self.model = PasswordManagerModel()
        self.view = PasswordManagerView()
        self.view.set_controller(self)

        self._session_key = ""  # 本次会话的密钥（仅内存）
        self._last_copied_text = ""

        self.clipboard_timer = QTimer()
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self._clear_clipboard)

        self.history_undo_stack: list = []
        self.history_redo_stack: list = []
        self.current_history_subject: str | None = None

        self._connect_signals()
        self.view.show()
        QTimer.singleShot(0, self._auto_load_last_file)

    # ===================== 信号 =====================
    def _connect_signals(self) -> None:
        v = self.view
        v.new_file_requested.connect(self.handle_new_file)
        v.open_file_requested.connect(self.handle_open_file)
        v.save_file_requested.connect(self.handle_save_file)
        v.save_as_requested.connect(self.handle_save_as)
        v.add_subject_requested.connect(self.handle_add_subject)
        v.clear_all_requested.connect(self.handle_clear_all)
        v.copy_selected_requested.connect(self.handle_copy_selected)
        v.delete_selected_requested.connect(self.handle_delete_selected)
        v.undo_requested.connect(self.handle_undo)
        v.redo_requested.connect(self.handle_redo)
        v.lock_requested.connect(self.handle_lock)

    # ===================== 密钥 =====================
    def _require_key(self) -> str:
        if self._session_key:
            return self._session_key
        key = self.view.ask_key("输入密钥", "请输入密钥：")
        if key:
            self._session_key = key
        return key

    # ===================== 文件操作 =====================
    def handle_new_file(self) -> None:
        path = self.view.ask_save_file_path("创建密钥文件", ".sk", [("sk加密文件", "*.sk")], "new_file")
        if not path:
            return

        key = self.view.ask_key("设置密钥", "为新建的密钥文件设置密钥。", confirm=True)
        if not key:
            return

        try:
            from storage import atomic_write_text

            encrypted = self.model.encrypt_data(key, {"mainData": [], "historyData": {}})
            atomic_write_text(path, encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.exception("新建文件失败")
            self.view.show_error("错误", f"文件创建失败：{exc}")
            return

        self._session_key = key
        self.model.set_current_file_path(path)
        self.model.initialize_empty_state()
        self.view.switch_to_main_interface()
        self.view.update_window_title(path)
        self.view.set_dirty(False)
        self._refresh_table_from_model()
        self._ensure_backup_folder(path)
        self.view.show_status(f"新文件已创建：{os.path.basename(path)}", 3000)

    def handle_open_file(self) -> None:
        path = self.view.ask_open_file_path("选择sk加密文件", [("sk加密文件", "*.sk")])
        if not path:
            return
        if not path.endswith(".sk"):
            self.view.show_warning("警告", "请选择合法的 .sk 格式文件！")
            return
        self._open_path(path)

    def _open_path(self, path: str, *, save_path: str | None = None, recovered: str | None = None) -> bool:
        """读取并解锁文件。save_path 不为空时用于"从备份恢复"。"""
        try:
            content = storage.read_text(path)
        except OSError as exc:
            self.view.show_error("错误", f"文件读取失败：{exc}")
            return False

        ok, message, version = self.model.detect_and_store(content)
        if not ok:
            self.view.show_error("文件校验失败", message)
            return False

        hint = f"请输入密钥以解锁：\n{os.path.basename(path)}"
        if version < 3:
            hint += f"\n\n（检测到旧版 v{version} 格式，解锁后将按 v3 重新保存）"

        key = self.view.ask_key("解锁密钥库", hint)
        if not key:
            return False
        if not self.model.decrypt_with_user_key(key):
            self.view.show_error("解锁失败", "密钥不正确或文件已损坏！")
            return False

        try:
            upgraded = self.model.load_data_from_decrypted_json()
        except Exception as exc:  # noqa: BLE001
            logger.exception("解析解密数据失败")
            self.view.show_error("打开失败", f"数据解析错误：{exc}")
            return False

        target = save_path or path
        self._session_key = key
        self.model.set_current_file_path(target)
        self.view.switch_to_main_interface()
        self.view.update_window_title(target)
        self.view.set_dirty(bool(upgraded))
        self._refresh_table_from_model()
        self._ensure_backup_folder(target)

        if recovered and os.path.exists(recovered):
            try:
                os.remove(recovered)
            except OSError as exc:
                logger.warning("删除已恢复的备份失败：%s", exc)

        if upgraded:
            self.view.show_status(f"已升级 {upgraded} 条旧规则，请重新保存", 6000)
        else:
            self.view.show_status("解锁成功", 3000)
        return True

    def handle_save_file(self) -> None:
        if not self.model.current_file_path:
            self.handle_save_as()
            return
        self._write_current(self.model.current_file_path)

    def handle_save_as(self) -> None:
        key = self._require_key()
        if not key:
            self.view.show_warning("提示", "请输入密钥！")
            return
        if not self.model.main_data and not self.model.history_data:
            self.view.show_warning("提示", "无数据可导出")
            return

        path = self.view.ask_save_file_path("另存为", ".sk", [("sk加密文件", "*.sk")], "密钥数据")
        if not path:
            return
        self._write_current(path, new_path=True)

    def _write_current(self, path: str, *, new_path: bool = False) -> bool:
        key = self._require_key()
        if not key:
            self.view.show_warning("提示", "请输入密钥！")
            return False
        try:
            encrypted = self.model.encrypt_data(key, self.model.prepare_export_data())
            storage.atomic_write_text(path, encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.exception("保存失败")
            self.view.show_error("保存失败", str(exc))
            return False

        if new_path:
            self.model.set_current_file_path(path)
            self._ensure_backup_folder(path)
        self.model.mark_clean()
        self.view.update_window_title(path)
        self.view.set_dirty(False)
        self.view.show_status(f"数据已保存至：{os.path.basename(path)}", 4000)
        return True

    def handle_lock(self) -> None:
        if self.model.is_dirty() and not self.view.ask_yes_no(
            "未保存的修改", "当前有未保存的修改，锁定后将丢失。确定继续吗？"
        ):
            return
        self._session_key = ""
        self.model.main_data = []
        self.model.history_data = {}
        self.model.set_current_file_path(None)
        self.view.reset_to_initial()
        self.view.set_dirty(False)
        self.view.show_status("已锁定", 2000)

    # ===================== 主表格 =====================
    def handle_add_subject(self) -> None:
        def on_confirm(name, length, lower, upper, digit, symbol):
            self.model.add_or_update_subject(
                name, length=length, lower=lower, upper=upper, digit=digit, symbol=symbol
            )
            self._refresh_table_from_model()
            self.view.show_status(f"密码主体“{name}”已添加并生成密码", 3000)

        self.view.show_add_subject_dialog(on_confirm)

    def handle_clear_all(self) -> None:
        if self.view.ask_yes_no("确认", "确定要清空所有数据吗？此操作不可撤销（可用 Ctrl+Z 尝试恢复）。"):
            self.model.clear_all_data()
            self._refresh_table_from_model()
            self.view.show_status("所有数据已清空", 3000)

    def handle_generate_password(self, item) -> None:
        items = self.view.get_all_row_items()
        if item not in items:
            return
        index = items.index(item)
        result = self.model.generate_new_password_for_subject(index)
        if not result:
            return
        new_pwd, new_count = result
        values = self.view.get_row_values(item)
        self.view.update_table_row(
            item, values[0], values[1], new_pwd, new_count, self.model.main_data[index]["rule"]
        )
        self.view.show_status(f"已生成第 {new_count} 个密码", 3000)

    def handle_copy_password(self, item) -> None:
        values = self.view.get_row_values(item)
        if values[2]:
            self._copy_to_clipboard_with_timer(values[2])

    def handle_delete_row(self, item) -> None:
        items = self.view.get_all_row_items()
        if item not in items:
            return
        index = items.index(item)
        name = self.model.main_data[index]["name"]
        self.model.delete_subject(index)
        self._refresh_table_from_model()
        self.view.show_status(f"密码主体“{name}”已删除", 3000)

    def handle_copy_selected(self) -> None:
        item = self.view.get_selected_row_item()
        if item:
            self.handle_copy_password(item)

    def handle_delete_selected(self) -> None:
        item = self.view.get_selected_row_item()
        if item:
            self.handle_delete_row(item)

    def handle_row_reorder(self) -> None:
        names = []
        for item in self.view.get_all_row_items():
            name = self.view.get_row_values(item)[1]
            if name and name != "暂无密码主体":
                names.append(name)
        self.model.reorder_subjects(names)
        self.view.refresh_row_numbers()
        self.view.show_status("排序已更新", 2000)

    # ===================== 撤销/重做 =====================
    def handle_undo(self) -> None:
        if self.model.undo():
            self._refresh_table_from_model()
            self.view.show_status("已撤销", 2000)
        else:
            self.view.show_status("无操作可撤销", 2000)

    def handle_redo(self) -> None:
        if self.model.redo():
            self._refresh_table_from_model()
            self.view.show_status("已重做", 2000)
        else:
            self.view.show_status("无操作可重做", 2000)

    # ===================== 历史窗口 =====================
    def handle_show_history(self, item) -> None:
        subject_name = self.view.get_row_values(item)[1]
        if not subject_name or subject_name == "暂无密码主体":
            return
        self.current_history_subject = subject_name
        history = self.model.get_history_for_subject(subject_name)

        self.history_undo_stack = []
        self.history_redo_stack = []
        self._save_history_state()

        callbacks = {
            "copy": self.handle_history_copy,
            "delete": self.handle_history_delete,
            "undo": self.handle_history_undo,
            "redo": self.handle_history_redo,
        }
        self.view.show_history_window(subject_name, history, callbacks)

    def _save_history_state(self) -> None:
        current = copy.deepcopy(self.model.history_data.get(self.current_history_subject, []))
        self.history_undo_stack.append(current)
        self.history_redo_stack.clear()

    def _restore_history_state(self, state: list) -> None:
        self.model.history_data[self.current_history_subject] = copy.deepcopy(state)
        self.view.update_history_window(self.model.get_history_for_subject(self.current_history_subject))

    def handle_history_copy(self, tree) -> None:
        selection = self.view.get_history_selection(tree)
        if selection and selection["password"]:
            self._copy_to_clipboard_with_timer(selection["password"])

    def handle_history_delete(self, tree) -> None:
        selection = self.view.get_history_selection(tree)
        if not selection:
            return
        if not self.view.ask_yes_no("确认", "确定删除该历史密码？"):
            return
        self._save_history_state()
        self.model.delete_history_entry(self.current_history_subject, selection["index"])
        self.view.update_history_window(self.model.get_history_for_subject(self.current_history_subject))
        self.view.show_status("历史密码已删除", 3000)

    def handle_history_undo(self, tree) -> None:
        if len(self.history_undo_stack) <= 1:
            self.view.show_status("无历史操作可撤销", 2000)
            return
        self.history_redo_stack.append(self.history_undo_stack.pop())
        self._restore_history_state(self.history_undo_stack[-1])
        self.view.show_status("已撤销", 2000)

    def handle_history_redo(self, tree) -> None:
        if not self.history_redo_stack:
            self.view.show_status("无历史操作可重做", 2000)
            return
        state = self.history_redo_stack.pop()
        self.history_undo_stack.append(state)
        self._restore_history_state(state)
        self.view.show_status("已重做", 2000)

    # ===================== 辅助 =====================
    def _refresh_table_from_model(self) -> None:
        self.view.clear_table()
        if not self.model.main_data:
            self.view.insert_placeholder_row()
        else:
            for index, item in enumerate(self.model.main_data, 1):
                self.view.insert_table_row(index, item["name"], item["password"], item["count"], item["rule"])

    def _copy_to_clipboard_with_timer(self, text: str) -> None:
        self.view.copy_to_clipboard(text)
        self._last_copied_text = text
        self.clipboard_timer.start(CLIPBOARD_CLEAR_MS)
        self.view.show_status("密码已复制到剪贴板（30 秒后自动清空）", 3000)

    def _clear_clipboard(self) -> None:
        if QApplication.clipboard().text() == self._last_copied_text:
            QApplication.clipboard().clear()
        self._last_copied_text = ""

    # ===================== 备份与自动加载 =====================
    def _ensure_backup_folder(self, file_path: str) -> None:
        folder = os.path.join(os.path.dirname(file_path), BACKUP_FOLDER)
        os.makedirs(folder, exist_ok=True)

    def _find_backup_files(self, original_path: str) -> list[str]:
        folder = os.path.join(os.path.dirname(original_path), BACKUP_FOLDER)
        if not os.path.isdir(folder):
            return []
        base_name = os.path.splitext(os.path.basename(original_path))[0]
        files = glob.glob(os.path.join(folder, f"{base_name}_*.tmp"))
        files.sort(key=self._extract_timestamp_from_backup)
        return files

    @staticmethod
    def _extract_timestamp_from_backup(backup_path: str) -> datetime:
        """从 名称_YYYYMMDD_HHMMSS.tmp 中提取时间戳（用正则，避免文件名含下划线出错）。"""
        match = BACKUP_PATTERN.search(os.path.basename(backup_path))
        if match:
            try:
                return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
            except ValueError:
                pass
        return datetime.min

    def _create_managed_backup(self, user_key: str) -> str | None:
        if not self.model.current_file_path:
            return None
        folder = os.path.join(os.path.dirname(self.model.current_file_path), BACKUP_FOLDER)
        os.makedirs(folder, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(self.model.current_file_path))[0]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.model.create_backup(user_key, os.path.join(folder, f"{base_name}_{stamp}.tmp"))

    def _cleanup_old_backups(self, original_path: str, keep_count: int = KEEP_BACKUPS) -> None:
        files = self._find_backup_files(original_path)
        files.sort(key=self._extract_timestamp_from_backup, reverse=True)
        for old_file in files[keep_count:]:
            try:
                os.remove(old_file)
            except OSError as exc:
                logger.warning("清理旧备份失败 %s：%s", old_file, exc)

    def _last_file_path(self) -> str:
        return str(storage.load_config().get("last_file", "") or "")

    def _save_last_file_path(self) -> None:
        config = storage.load_config()
        config["last_file"] = self.model.current_file_path or ""
        storage.save_config(config)

    def _auto_load_last_file(self) -> None:
        path = self._last_file_path()
        if not (path and os.path.exists(path) and path.endswith(".sk")):
            return

        path_to_read, recovered = path, None
        backups = self._find_backup_files(path)
        if backups:
            latest = backups[-1]
            when = self._extract_timestamp_from_backup(latest).strftime("%Y-%m-%d %H:%M:%S")
            if self.view.ask_yes_no(
                "恢复备份",
                f"检测到未保存的备份文件：\n{os.path.basename(latest)}\n备份时间：{when}\n\n是否恢复？",
            ):
                path_to_read, recovered = latest, latest

        self._open_path(path_to_read, save_path=path, recovered=recovered)

    # ===================== 关闭 =====================
    def on_app_close(self) -> bool:
        self._save_last_file_path()
        if self.model.is_dirty() and self.model.current_file_path:
            if self._session_key:
                backup = self._create_managed_backup(self._session_key)
                logger.info("关闭时自动备份：%s", backup)
            else:
                logger.warning("有未保存修改但无会话密钥，无法自动备份")
        if self.model.current_file_path:
            self._cleanup_old_backups(self.model.current_file_path)
        return True
