"""局域网同步对话框。

本机作为主机时展示配对二维码与配对文本；也可粘贴对方配对信息作为客户端发起同步。
"""

from __future__ import annotations

import os
import secrets
import tempfile

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

import sync_service


def _temp_qr_path() -> str:
    return os.path.join(tempfile.gettempdir(), "pmqrpair_" + secrets.token_hex(8) + ".png")


class _ClientSyncWorker(QThread):
    """在后台线程执行客户端同步，避免阻塞界面（同步是阻塞式网络调用）。"""

    done = Signal(bool, str, list)

    def __init__(self, call, pairing_text: str, parent=None) -> None:
        super().__init__(parent)
        self._call = call
        self._pairing_text = pairing_text

    def run(self) -> None:
        try:
            ok, message, conflicts = self._call(self._pairing_text)
        except Exception as exc:  # noqa: BLE001 - 任何异常都要展示给用户
            ok, message, conflicts = False, str(exc), []
        self.done.emit(bool(ok), str(message), list(conflicts or []))


class SyncDialog(QDialog):
    """局域网同步界面。on_client_sync(text) -> (ok, message, conflicts)。"""

    def __init__(self, server, on_client_sync, parent=None) -> None:
        super().__init__(parent)
        self.server = server
        self._on_client_sync = on_client_sync
        self._qr_path = _temp_qr_path()
        self._worker: _ClientSyncWorker | None = None

        self.setWindowTitle(self.tr("局域网同步"))
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)

        # ---------------- 主机 ----------------
        host_group = QGroupBox(self.tr("本机作为主机（等待其他设备连接）"))
        host_layout = QVBoxLayout(host_group)
        address = QLabel(self.tr("地址：%1").replace("%1", server.url()))
        address.setObjectName("emptyStateHint")
        host_layout.addWidget(address)

        qr_row = QHBoxLayout()
        self.qr_label = QLabel()
        self.qr_label.setFixedSize(214, 214)
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setStyleSheet("background:#FFFFFF; border:1px solid #E2E8F0; border-radius:8px;")
        if sync_service.make_qr_png(server.pairing_text(), self._qr_path):
            pixmap = QPixmap(self._qr_path)
            if not pixmap.isNull():
                self.qr_label.setPixmap(
                    pixmap.scaled(
                        200,
                        200,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        qr_row.addWidget(self.qr_label)

        right = QVBoxLayout()
        hint = QLabel(self.tr("用另一台设备扫描二维码，或复制下方配对信息粘贴过去。"))
        hint.setWordWrap(True)
        hint.setObjectName("emptyStateHint")
        right.addWidget(hint)
        self.pairing_view = QPlainTextEdit(server.pairing_text())
        self.pairing_view.setReadOnly(True)
        self.pairing_view.setMaximumHeight(96)
        right.addWidget(self.pairing_view)
        copy_btn = QPushButton(self.tr("复制配对信息"))
        copy_btn.clicked.connect(self._copy_pairing)
        right.addWidget(copy_btn)
        right.addStretch()
        qr_row.addLayout(right, 1)
        host_layout.addLayout(qr_row)
        layout.addWidget(host_group)

        # ---------------- 客户端 ----------------
        client_group = QGroupBox(self.tr("连接到其他设备"))
        client_layout = QVBoxLayout(client_group)
        self.paste_input = QPlainTextEdit()
        self.paste_input.setPlaceholderText(self.tr("粘贴对方设备显示的配对信息…"))
        self.paste_input.setMaximumHeight(72)
        client_layout.addWidget(self.paste_input)
        self.connect_btn = QPushButton(self.tr("连接并同步"))
        self.connect_btn.setProperty("role", "primary")
        self.connect_btn.clicked.connect(self._client_sync)
        client_layout.addWidget(self.connect_btn)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # 不确定进度：网络往返耗时不可预估
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        client_layout.addWidget(self.progress)

        self.status_label = QLabel("")
        self.status_label.setObjectName("emptyStateHint")
        self.status_label.setWordWrap(True)
        self.status_label.setVisible(False)
        client_layout.addWidget(self.status_label)
        layout.addWidget(client_group)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(110)
        layout.addWidget(self.log_view)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText(self.tr("关闭"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------
    def append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)

    def _copy_pairing(self) -> None:
        QApplication.clipboard().setText(self.server.pairing_text())
        self.append_log(self.tr("已复制配对信息"))

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.progress.setVisible(busy)
        self.connect_btn.setEnabled(not busy)
        self.status_label.setText(message)
        self.status_label.setVisible(bool(message))

    def _client_sync(self) -> None:
        text = self.paste_input.toPlainText().strip()
        if not text:
            self.append_log(self.tr("请先粘贴配对信息"))
            return
        if self._worker is not None and self._worker.isRunning():
            return

        self._set_busy(True, self.tr("正在与对端同步…"))
        self.append_log(self.tr("开始同步…"))
        worker = _ClientSyncWorker(self._on_client_sync, text, self)
        worker.done.connect(self._on_client_sync_finished)
        self._worker = worker
        worker.start()

    def _on_client_sync_finished(self, ok: bool, message: str, conflicts: list) -> None:
        self._set_busy(False)
        self._worker = None
        self.append_log(message)
        for conflict in conflicts:
            self.append_log(
                self.tr("冲突：%1（两个版本都已保留）").replace("%1", str(conflict.get("name", "")))
            )
        if ok:
            self.append_log(self.tr("同步完成，可关闭本窗口。"))
            QMessageBox.information(self, self.tr("同步完成"), message)
        else:
            QMessageBox.warning(self, self.tr("同步失败"), message)

    def notify_remote_sync_started(self, message: str) -> None:
        """主机侧：有其他设备正在同步。"""
        self.append_log(message)
        self.progress.setVisible(True)
        self.status_label.setText(message)
        self.status_label.setVisible(True)

    def notify_remote_sync_finished(self) -> None:
        """主机侧：同步处理结束（若本机自己也在同步则不打扰）。"""
        if self._worker is None or not self._worker.isRunning():
            self.progress.setVisible(False)
            self.status_label.setVisible(False)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 约定
        if self._worker is not None and self._worker.isRunning():
            self.append_log(self.tr("同步进行中，请等待完成后再关闭。"))
            event.ignore()
            return
        try:
            os.remove(self._qr_path)
        except OSError:
            pass
        super().closeEvent(event)
