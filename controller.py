"""控制器层 (Controller)。

把视图事件转成模型操作，并管理文件、剪贴板、备份、主题与语言。
"""

from __future__ import annotations

import copy
import glob
import json
import logging
import os
import re
import socket
from datetime import datetime

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication

import io_exchange
import storage
import sync_service
import theme
from model import PasswordManagerModel
from view import PasswordManagerView

logger = logging.getLogger(__name__)

BACKUP_FOLDER = ".password_manager_backups"
BACKUP_PATTERN = re.compile(r"_(\d{8}_\d{6})\.tmp$")
KEEP_BACKUPS = 10
CLIPBOARD_SECONDS = 30


class PasswordManagerController(QObject):
    """连接模型与视图，处理所有业务流程。"""

    # 主机侧完成一次同步后，从 HTTP 工作线程通知主线程刷新界面
    sync_applied = Signal(list)
    sync_started = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.model = PasswordManagerModel()
        self.view = PasswordManagerView()
        self.view.set_controller(self)

        self._session_key = ""
        self._last_copied_text = ""
        self.clipboard_seconds = 0

        self.clipboard_tick = QTimer(self)
        self.clipboard_tick.setInterval(1000)
        self.clipboard_tick.timeout.connect(self._on_clipboard_tick)

        self.history_undo_stack: list = []
        self.history_redo_stack: list = []
        self.current_history_subject: str | None = None

        self._sync_server: sync_service.SyncServer | None = None
        self.sync_applied.connect(self._on_sync_applied)
        self.sync_started.connect(self._on_sync_started)

        self._connect_signals()
        self.view.apply_theme(theme.load_setting())
        self.view.set_language_checked(self._language())
        self.view.show()
        QTimer.singleShot(0, self._auto_load_last_file)

    # ===================== 信号 =====================
    def _connect_signals(self) -> None:
        view = self.view
        view.new_file_requested.connect(self.handle_new_file)
        view.open_file_requested.connect(self.handle_open_file)
        view.save_file_requested.connect(self.handle_save_file)
        view.save_as_requested.connect(self.handle_save_as)
        view.import_csv_requested.connect(self.handle_import_csv)
        view.export_csv_requested.connect(self.handle_export_csv)
        view.add_subject_requested.connect(self.handle_add_subject)
        view.clear_all_requested.connect(self.handle_clear_all)
        view.generate_selected_requested.connect(self.handle_generate_selected)
        view.copy_selected_requested.connect(self.handle_copy_selected)
        view.delete_selected_requested.connect(self.handle_delete_selected)
        view.history_selected_requested.connect(self.handle_history_selected)
        view.undo_requested.connect(self.handle_undo)
        view.redo_requested.connect(self.handle_redo)
        view.lock_requested.connect(self.handle_lock)
        view.lan_sync_requested.connect(self.handle_lan_sync)
        view.order_changed.connect(self.handle_order_changed)
        view.theme_changed.connect(self.handle_theme_changed)
        view.language_changed.connect(self.handle_language_changed)

    # ===================== 设置 =====================
    def _language(self) -> str:
        value = str(storage.load_config().get("language", "zh"))
        return value if value in ("zh", "en") else "zh"

    def handle_theme_changed(self, setting: str) -> None:
        theme.save_setting(setting)
        self.view.apply_theme(setting)
        self.view.show_status(self.tr("主题已切换"), 2000)

    # ===================== 局域网同步 =====================
    def handle_lan_sync(self) -> None:
        """打开同步窗口：本机作为主机等待配对，同时也能作为客户端连接别人。"""
        key = self._require_key()
        if not key:
            self.view.show_warning(self.tr("提示"), self.tr("请输入密钥！"))
            return
        if not self.model.current_file_path:
            self.view.show_warning(self.tr("提示"), self.tr("请先打开或新建密钥文件"))
            return

        server = sync_service.SyncServer(
            apply_remote=self._apply_remote_blob,
            get_blob=self._export_blob,
            vault_id=self.model.vault_id,
            device_id=self.model.device_id,
            device_name=socket.gethostname(),
        )
        try:
            server.start()
        except OSError as exc:
            self.view.show_error(self.tr("同步失败"), self.tr("无法启动同步服务：%1").replace("%1", str(exc)))
            return

        self._sync_server = server
        try:
            self.view.show_sync_dialog(server, self._client_sync)
        finally:
            server.stop()
            self._sync_server = None

    @staticmethod
    def _conflict_dict(conflict) -> dict:
        return {
            "kind": conflict.kind,
            "name": conflict.name,
            "copy_id": conflict.copy_id,
            "origin": conflict.origin,
        }

    def _export_blob(self) -> str:
        """导出本机整库密文（供新设备"首次加入"下载）。"""
        if not self._session_key:
            raise ValueError("本机未解锁")
        return self.model.encrypt_data(self._session_key, self.model.prepare_export_data())

    def _apply_remote_blob(self, remote_blob: str) -> tuple[str, list[dict]]:
        """主机侧：解密对端密文 → 合并 → 返回合并后的整库密文（在 HTTP 线程执行）。"""
        if not self._session_key:
            raise ValueError("本机未解锁")

        self.sync_started.emit(self.tr("正在处理来自其他设备的同步请求…"))

        remote = PasswordManagerModel()
        ok, message, _version = remote.detect_and_store(remote_blob)
        if not ok:
            raise ValueError(message)
        if not remote.decrypt_with_user_key(self._session_key):
            raise ValueError("对端使用了不同的密钥")
        try:
            payload = json.loads(remote.raw_decrypted_data)
        except json.JSONDecodeError as exc:
            raise ValueError("对端数据无法解析") from exc

        conflicts = self.model.merge_remote(payload)
        merged_blob = self.model.encrypt_data(self._session_key, self.model.prepare_export_data())
        if self.model.current_file_path:
            storage.atomic_write_text(self.model.current_file_path, merged_blob)
            self.model.mark_clean()

        summary = [self._conflict_dict(c) for c in conflicts]
        self.sync_applied.emit(summary)
        return merged_blob, summary

    def _on_sync_started(self, message: str) -> None:
        self.view.notify_sync_started(message)

    def _on_sync_applied(self, summary: list) -> None:
        self._reload()
        self.view.update_window_title(self.model.current_file_path)
        self.view.set_dirty(self.model.is_dirty())
        message = self.tr("已与一台设备完成同步")
        if summary:
            message += self.tr("，其中 %1 条存在冲突（两个版本都已保留）").replace("%1", str(len(summary)))
        self.view.notify_sync_applied(message)

    def _client_sync(self, pairing_text: str) -> tuple[bool, str, list]:
        """客户端侧：把本机密文发给主机，并采用主机返回的合并结果。"""
        key = self._require_key()
        if not key:
            return False, self.tr("请先输入密钥"), []
        if not self.model.current_file_path:
            return False, self.tr("请先打开或新建密钥文件"), []

        try:
            client = sync_service.SyncClient.from_pairing_text(pairing_text)
        except sync_service.SyncError as exc:
            return False, str(exc), []
        if client.vault_id != self.model.vault_id:
            return False, self.tr("对方的库与本机不是同一个（vault_id 不一致）"), []

        local_blob = self.model.encrypt_data(key, self.model.prepare_export_data())
        try:
            result = client.sync(local_blob)
        except sync_service.SyncError as exc:
            return False, str(exc), []

        merged_blob = str(result.get("vault") or "")
        if not merged_blob:
            return False, self.tr("主机返回内容为空"), []

        check = PasswordManagerModel()
        ok, _message, _version = check.detect_and_store(merged_blob)
        if not ok or not check.decrypt_with_user_key(key):
            return False, self.tr("主机返回的库无法解密"), []

        storage.atomic_write_text(self.model.current_file_path, merged_blob)
        self.model.detect_and_store(merged_blob)
        self.model.decrypt_with_user_key(key)
        self.model.load_data_from_decrypted_json()
        self.model.mark_clean()
        self._reload()
        self.view.update_window_title(self.model.current_file_path)
        self.view.set_dirty(False)

        conflicts = list(result.get("conflicts") or [])
        message = self.tr("同步完成")
        if conflicts:
            message += self.tr("，%1 条冲突已保留两个版本").replace("%1", str(len(conflicts)))
        return True, message, conflicts

    def handle_language_changed(self, language: str) -> None:
        config = storage.load_config()
        config["language"] = language
        storage.save_config(config)
        self.view.set_language_checked(language)
        self.view.show_status(self.tr("语言已保存，重启后生效"), 4000)

    # ===================== 密钥 =====================
    def _require_key(self) -> str:
        if self._session_key:
            return self._session_key
        key = self.view.ask_key(self.tr("输入密钥"), self.tr("请输入密钥："))
        if key:
            self._session_key = key
        return key

    # ===================== 文件操作 =====================
    def handle_new_file(self) -> None:
        path = self.view.ask_save_file_path(
            self.tr("创建密钥文件"), ".sk", [(self.tr("sk加密文件"), "*.sk")], "new_file"
        )
        if not path:
            return

        key = self.view.ask_key(
            self.tr("设置密钥"),
            self.tr("为新建的密钥文件设置密钥。"),
            confirm=True,
        )
        if not key:
            return

        try:
            self.model.main_data = []
            self.model.history_data = {}
            self.model.tombstones = []
            self.model.sync_base = {}
            encrypted = self.model.encrypt_data(key, self.model.prepare_export_data())
            storage.atomic_write_text(path, encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.exception("新建文件失败")
            self.view.show_error(self.tr("错误"), self.tr("文件创建失败：%1").replace("%1", str(exc)))
            return

        self._session_key = key
        self.model.set_current_file_path(path)
        self.model.initialize_empty_state()
        self.view.switch_to_main_interface()
        self.view.update_window_title(path)
        self.view.set_dirty(False)
        self._reload()
        self._ensure_backup_folder(path)
        self.view.show_status(self.tr("新文件已创建：%1").replace("%1", os.path.basename(path)), 3000)

    def handle_open_file(self) -> None:
        path = self.view.ask_open_file_path(self.tr("选择sk加密文件"), [(self.tr("sk加密文件"), "*.sk")])
        if not path:
            return
        if not path.endswith(".sk"):
            self.view.show_warning(self.tr("警告"), self.tr("请选择合法的 .sk 格式文件！"))
            return
        self._open_path(path)

    def _open_path(self, path: str, *, save_path: str | None = None, recovered: str | None = None) -> bool:
        try:
            content = storage.read_text(path)
        except OSError as exc:
            self.view.show_error(self.tr("错误"), self.tr("文件读取失败：%1").replace("%1", str(exc)))
            return False

        ok, message, version = self.model.detect_and_store(content)
        if not ok:
            self.view.show_error(self.tr("文件校验失败"), message)
            return False

        hint = self.tr("请输入密钥以解锁：\n%1").replace("%1", os.path.basename(path))
        if version < 3:
            hint += "\n\n" + self.tr("（检测到旧版 v%1 格式，解锁后将按 v3 重新保存）").replace(
                "%1", str(version)
            )

        key = self.view.ask_key(self.tr("解锁密钥库"), hint)
        if not key:
            return False
        if not self.model.decrypt_with_user_key(key):
            self.view.show_error(self.tr("解锁失败"), self.tr("密钥不正确或文件已损坏！"))
            return False

        try:
            upgraded = self.model.load_data_from_decrypted_json()
        except Exception as exc:  # noqa: BLE001
            logger.exception("解析解密数据失败")
            self.view.show_error(self.tr("打开失败"), self.tr("数据解析错误：%1").replace("%1", str(exc)))
            return False

        target = save_path or path
        self._session_key = key
        self.model.set_current_file_path(target)
        self.view.switch_to_main_interface()
        self.view.update_window_title(target)
        self.view.set_dirty(bool(upgraded))
        self._reload()
        self._ensure_backup_folder(target)

        if recovered and os.path.exists(recovered):
            try:
                os.remove(recovered)
            except OSError as exc:
                logger.warning("删除已恢复的备份失败：%s", exc)

        if upgraded:
            self.view.show_status(
                self.tr("已修正 %1 条旧记录，请重新保存").replace("%1", str(upgraded)), 6000
            )
        else:
            self.view.show_status(self.tr("解锁成功"), 3000)
        return True

    def handle_save_file(self) -> None:
        if not self.model.current_file_path:
            self.handle_save_as()
            return
        self._write_current(self.model.current_file_path)

    def handle_save_as(self) -> None:
        key = self._require_key()
        if not key:
            self.view.show_warning(self.tr("提示"), self.tr("请输入密钥！"))
            return
        if not self.model.main_data and not self.model.history_data:
            self.view.show_warning(self.tr("提示"), self.tr("无数据可导出"))
            return

        path = self.view.ask_save_file_path(
            self.tr("另存为"), ".sk", [(self.tr("sk加密文件"), "*.sk")], "密钥数据"
        )
        if not path:
            return
        self._write_current(path, new_path=True)

    def _write_current(self, path: str, *, new_path: bool = False) -> bool:
        key = self._require_key()
        if not key:
            self.view.show_warning(self.tr("提示"), self.tr("请输入密钥！"))
            return False
        try:
            encrypted = self.model.encrypt_data(key, self.model.prepare_export_data())
            storage.atomic_write_text(path, encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.exception("保存失败")
            self.view.show_error(self.tr("保存失败"), str(exc))
            return False

        if new_path:
            self.model.set_current_file_path(path)
            self._ensure_backup_folder(path)
        self.model.mark_clean()
        self.view.update_window_title(path)
        self.view.set_dirty(False)
        self.view.show_status(self.tr("数据已保存至：%1").replace("%1", os.path.basename(path)), 4000)
        return True

    def handle_lock(self) -> None:
        if self.model.is_dirty() and not self.view.ask_yes_no(
            self.tr("未保存的修改"), self.tr("当前有未保存的修改，锁定后将丢失。确定继续吗？")
        ):
            return
        self._session_key = ""
        self.model.main_data = []
        self.model.history_data = {}
        self.model.set_current_file_path(None)
        self.view.reset_to_initial()
        self.view.set_dirty(False)
        self.view.show_status(self.tr("已锁定"), 2000)

    # ===================== CSV =====================
    def handle_export_csv(self) -> None:
        if not self.model.main_data:
            self.view.show_warning(self.tr("提示"), self.tr("无数据可导出"))
            return
        if not self.view.ask_yes_no(
            self.tr("导出 CSV"),
            self.tr("CSV 是明文文件，其中的密码不加密。\n确定要导出吗？"),
        ):
            return
        path = self.view.ask_save_file_path(
            self.tr("导出 CSV"), ".csv", [(self.tr("CSV 文件"), "*.csv")], "passwords"
        )
        if not path:
            return
        try:
            io_exchange.export_csv(path, self.model.export_rows())
        except OSError as exc:
            self.view.show_error(self.tr("导出失败"), str(exc))
            return
        self.view.show_status(
            self.tr("已导出 %1 条到 CSV").replace("%1", str(len(self.model.main_data))), 4000
        )

    def handle_import_csv(self) -> None:
        path = self.view.ask_open_file_path(self.tr("导入 CSV"), [(self.tr("CSV 文件"), "*.csv")])
        if not path:
            return
        try:
            rows = io_exchange.import_csv(path)
        except (OSError, ValueError) as exc:
            self.view.show_error(self.tr("导入失败"), str(exc))
            return
        if not rows:
            self.view.show_warning(self.tr("提示"), self.tr("CSV 中没有可导入的数据"))
            return

        imported = 0
        for row in rows:
            self.model.add_or_update_subject(
                row["name"],
                password=row.get("password") or None,
                rule=row.get("rule") or None,
                count=row.get("count") or "0",
                updated_at=row.get("updated_at") or None,
            )
            imported += 1
        self._reload()
        self.view.show_status(self.tr("已导入 %1 条记录").replace("%1", str(imported)), 4000)

    # ===================== 主表格 =====================
    def handle_add_subject(self) -> None:
        def on_confirm(name, length, lower, upper, digit, symbol):
            self.model.add_or_update_subject(
                name, length=length, lower=lower, upper=upper, digit=digit, symbol=symbol
            )
            self._reload()
            self.view.show_status(self.tr("密码主体“%1”已添加并生成密码").replace("%1", name), 3000)

        self.view.show_add_subject_dialog(on_confirm)

    def handle_clear_all(self) -> None:
        if self.view.ask_yes_no(
            self.tr("确认"), self.tr("确定要清空所有数据吗？此操作可用 Ctrl+Z 尝试恢复。")
        ):
            self.model.clear_all_data()
            self._reload()
            self.view.show_status(self.tr("所有数据已清空"), 3000)

    def handle_generate_selected(self) -> None:
        indexes = self.view.selected_row_indexes()
        if not indexes:
            self.view.show_warning(self.tr("提示"), self.tr("请先选择一行"))
            return
        for index in indexes:
            self.model.generate_new_password_for_subject(index)
        self._reload()
        self.view.show_status(self.tr("已为 %1 个主体生成新密码").replace("%1", str(len(indexes))), 3000)

    def handle_copy_selected(self) -> None:
        rows = self.view.selected_row_indexes()
        if not rows:
            self.view.show_warning(self.tr("提示"), self.tr("请先选择一行"))
            return
        passwords = [self.model.main_data[i]["password"] for i in rows]
        self._copy_to_clipboard_with_timer("\n".join(passwords))

    def handle_delete_selected(self) -> None:
        rows = self.view.selected_row_indexes()
        if not rows:
            self.view.show_warning(self.tr("提示"), self.tr("请先选择一行"))
            return
        if len(rows) > 1 and not self.view.ask_yes_no(
            self.tr("确认"), self.tr("确定删除选中的 %1 个主体？").replace("%1", str(len(rows)))
        ):
            return
        removed = self.model.delete_subjects(rows)
        self._reload()
        self.view.show_status(self.tr("已删除 %1 个主体").replace("%1", str(len(removed))), 3000)

    def handle_order_changed(self, names: list) -> None:
        self.model.reorder_subjects([str(n) for n in names])
        self.view.show_status(self.tr("排序已更新"), 2000)

    # ===================== 撤销/重做 =====================
    def handle_undo(self) -> None:
        if self.model.undo():
            self._reload()
            self.view.show_status(self.tr("已撤销"), 2000)
        else:
            self.view.show_status(self.tr("无操作可撤销"), 2000)

    def handle_redo(self) -> None:
        if self.model.redo():
            self._reload()
            self.view.show_status(self.tr("已重做"), 2000)
        else:
            self.view.show_status(self.tr("无操作可重做"), 2000)

    # ===================== 历史窗口 =====================
    def handle_history_selected(self) -> None:
        index = self.view.selected_row()
        if index is None or not (0 <= index < len(self.model.main_data)):
            return
        subject_name = self.model.main_data[index]["name"]
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
        if not self.view.ask_yes_no(self.tr("确认"), self.tr("确定删除该历史密码？")):
            return
        self._save_history_state()
        self.model.delete_history_entry(self.current_history_subject, selection["index"])
        self.view.update_history_window(self.model.get_history_for_subject(self.current_history_subject))
        self.view.show_status(self.tr("历史密码已删除"), 3000)

    def handle_history_undo(self, tree) -> None:
        if len(self.history_undo_stack) <= 1:
            self.view.show_status(self.tr("无历史操作可撤销"), 2000)
            return
        self.history_redo_stack.append(self.history_undo_stack.pop())
        self._restore_history_state(self.history_undo_stack[-1])
        self.view.show_status(self.tr("已撤销"), 2000)

    def handle_history_redo(self, tree) -> None:
        if not self.history_redo_stack:
            self.view.show_status(self.tr("无历史操作可重做"), 2000)
            return
        state = self.history_redo_stack.pop()
        self.history_undo_stack.append(state)
        self._restore_history_state(state)
        self.view.show_status(self.tr("已重做"), 2000)

    # ===================== 辅助 =====================
    def _reload(self) -> None:
        self.view.load_rows(self.model.export_rows())

    def _copy_to_clipboard_with_timer(self, text: str) -> None:
        self.view.copy_to_clipboard(text)
        self._last_copied_text = text
        self.clipboard_seconds = CLIPBOARD_SECONDS
        self.view.set_clipboard_countdown(self.clipboard_seconds)
        self.clipboard_tick.start()
        self.view.show_status(
            self.tr("已复制到剪贴板（%1 秒后自动清空）").replace("%1", str(CLIPBOARD_SECONDS)), 3000
        )

    def _on_clipboard_tick(self) -> None:
        self.clipboard_seconds -= 1
        if self.clipboard_seconds > 0:
            self.view.set_clipboard_countdown(self.clipboard_seconds)
            return
        self.clipboard_tick.stop()
        clipboard = QApplication.clipboard()
        if clipboard.text() == self._last_copied_text:
            clipboard.clear()
        self._last_copied_text = ""
        self.view.set_clipboard_countdown(0)

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
                self.tr("恢复备份"),
                self.tr("检测到未保存的备份文件：\n%1\n备份时间：%2\n\n是否恢复？")
                .replace("%1", os.path.basename(latest))
                .replace("%2", when),
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
