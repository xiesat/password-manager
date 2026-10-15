"""视图层 (View) - PySide6 实现。

只负责界面与用户交互，不含业务逻辑。样式集中在 resources/style.qss。
"""

from __future__ import annotations

import os
import secrets
import string
import sys

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

MASK = "\u2022" * 10
PLACEHOLDER_NAME = "暂无密码主体"


def resource_path(*parts: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def estimate_strength(password: str) -> tuple[int, str]:
    """粗略强度评估，返回 (1-5, 文案)。"""
    length = len(password)
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if length == 0:
        return 0, ""
    if length < 8:
        score = 1
    elif length < 12:
        score = min(3, classes)
    else:
        score = min(5, 1 + classes + (1 if length >= 16 else 0))
    score = max(1, min(5, score))
    return score, {1: "很弱", 2: "弱", 3: "中", 4: "强", 5: "极强"}[score]


class UnlockDialog(QDialog):
    """密钥输入 / 设置对话框。"""

    def __init__(self, title: str, message: str, confirm: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(430)
        self.confirm_edit: QLineEdit | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        heading = QLabel(message)
        heading.setWordWrap(True)
        layout.addWidget(heading)

        key_row = QHBoxLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_edit.setPlaceholderText("请输入密钥…")
        key_row.addWidget(self.key_edit)
        self.show_btn = QPushButton("显示")
        self.show_btn.setCheckable(True)
        self.show_btn.setProperty("role", "icon")
        key_row.addWidget(self.show_btn)
        layout.addLayout(key_row)

        if confirm:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_edit.setPlaceholderText("再次输入密钥…")
            layout.addWidget(self.confirm_edit)

        self.strength_label = QLabel("")
        self.strength_label.setStyleSheet("color:#64748B;")
        layout.addWidget(self.strength_label)

        if confirm:
            warn = QLabel("注意：密钥丢失将无法恢复数据，请务必妥善保管。")
            warn.setWordWrap(True)
            warn.setStyleSheet("color:#B45309;")
            layout.addWidget(warn)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("确定")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("role", "primary")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setDefault(True)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.show_btn.toggled.connect(self._toggle_echo)
        self.key_edit.textChanged.connect(self._update_strength)
        self.key_edit.setFocus()

    def _toggle_echo(self, shown: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
        self.key_edit.setEchoMode(mode)
        if self.confirm_edit is not None:
            self.confirm_edit.setEchoMode(mode)

    def _update_strength(self, text: str) -> None:
        score, label = estimate_strength(text)
        bars = "\u2588" * score + "\u2591" * (5 - score) if score else ""
        self.strength_label.setText(f"强度 {bars} {label}" if score else "")

    def _on_accept(self) -> None:
        if not self.key_edit.text():
            QMessageBox.warning(self, "提示", "密钥不能为空！")
            return
        if self.confirm_edit is not None and self.confirm_edit.text() != self.key_edit.text():
            QMessageBox.warning(self, "提示", "两次输入的密钥不一致！")
            return
        self.accept()

    def key(self) -> str:
        return self.key_edit.text()


class AddSubjectDialog(QDialog):
    """添加密码主体对话框。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("添加密码主体")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如：Google 账号")
        form.addRow("名称", self.name_edit)

        self.length_spin = QSpinBox()
        self.length_spin.setRange(6, 64)
        self.length_spin.setValue(16)
        form.addRow("密码长度", self.length_spin)
        layout.addLayout(form)

        group = QGroupBox("字符类型")
        group_layout = QVBoxLayout(group)
        self.lower_check = QCheckBox("小写字母 (a-z)")
        self.upper_check = QCheckBox("大写字母 (A-Z)")
        self.digit_check = QCheckBox("数字 (0-9)")
        self.symbol_check = QCheckBox("特殊字符 (!@#$…)")
        for box in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            box.setChecked(True)
            group_layout.addWidget(box)
        layout.addWidget(group)

        self.preview_label = QLabel("")
        self.preview_label.setStyleSheet("color:#334155;")
        layout.addWidget(self.preview_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("确定")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("role", "primary")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setDefault(True)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.length_spin.valueChanged.connect(self._update_preview)
        for box in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            box.toggled.connect(self._update_preview)
        self._update_preview()

    def _update_preview(self) -> None:
        pool = ""
        classes = []
        if self.lower_check.isChecked():
            pool += string.ascii_lowercase
            classes.append(string.ascii_lowercase)
        if self.upper_check.isChecked():
            pool += string.ascii_uppercase
            classes.append(string.ascii_uppercase)
        if self.digit_check.isChecked():
            pool += string.digits
            classes.append(string.digits)
        if self.symbol_check.isChecked():
            pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            classes.append("!@#$%^&*()_+-=[]{}|;:,.<>?")
        if not pool:
            pool = string.ascii_lowercase + string.digits
            classes = [string.ascii_lowercase, string.digits]

        length = self.length_spin.value()
        sample = [secrets.choice(c) for c in classes]
        sample += [secrets.choice(pool) for _ in range(max(0, length - len(sample)))]
        secrets.SystemRandom().shuffle(sample)
        preview = "".join(sample)[:16]
        score, label = estimate_strength("".join(sample))
        self.preview_label.setText(f"预览：{preview}…   强度：{label}")

    def get_data(self) -> tuple:
        return (
            self.name_edit.text().strip(),
            self.length_spin.value(),
            self.lower_check.isChecked(),
            self.upper_check.isChecked(),
            self.digit_check.isChecked(),
            self.symbol_check.isChecked(),
        )


class HistoryWindow(QDialog):
    """历史密码窗口。"""

    def __init__(self, subject_name: str, parent=None) -> None:
        super().__init__(parent)
        self.subject_name = subject_name
        self.setWindowTitle(f"历史密码 - {subject_name}")
        self.resize(680, 420)

        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.show_btn = QPushButton("显示密码")
        self.show_btn.setCheckable(True)
        self.copy_btn = QPushButton("复制")
        self.delete_btn = QPushButton("删除")
        self.delete_btn.setProperty("role", "danger")
        self.undo_btn = QPushButton("撤销")
        self.redo_btn = QPushButton("重做")
        toolbar.addWidget(self.show_btn)
        toolbar.addStretch()
        toolbar.addWidget(self.undo_btn)
        toolbar.addWidget(self.redo_btn)
        toolbar.addWidget(self.copy_btn)
        toolbar.addWidget(self.delete_btn)
        layout.addLayout(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["序号", "历史密码", "生成时间"])
        self.tree.setColumnWidth(0, 70)
        self.tree.setColumnWidth(1, 320)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self.tree)


class PasswordManagerView(QMainWindow):
    """主窗口视图。"""

    new_file_requested = Signal()
    open_file_requested = Signal()
    save_file_requested = Signal()
    save_as_requested = Signal()
    add_subject_requested = Signal()
    clear_all_requested = Signal()
    copy_selected_requested = Signal()
    delete_selected_requested = Signal()
    undo_requested = Signal()
    redo_requested = Signal()
    lock_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("密码管理器")
        self.resize(980, 660)

        self.controller = None
        self.history_window: HistoryWindow | None = None
        self._current_path: str | None = None
        self._dirty = False
        self._show_passwords = False

        icon_path = resource_path("resources", "app_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._create_status_bar()
        self._create_central_widget()
        self._create_menu_bar()
        self._create_shortcuts()
        self._show_initial_view()

    # ===================== 基础布局 =====================
    def set_controller(self, controller) -> None:
        self.controller = controller

    def _create_status_bar(self) -> None:
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.dirty_indicator = QLabel("")
        self.dirty_indicator.setStyleSheet("color:#F59E0B;")
        self.status_bar.addPermanentWidget(self.dirty_indicator)
        self.status_bar.showMessage("就绪", 2000)

    def _create_central_widget(self) -> None:
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.initial_widget = QWidget()
        self.main_layout.addWidget(self.initial_widget)

        self.work_widget = QWidget()
        self.work_widget.setVisible(False)
        self.main_layout.addWidget(self.work_widget)

    def _show_initial_view(self) -> None:
        layout = QVBoxLayout(self.initial_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("密码管理器")
        font = QFont()
        font.setPointSize(24)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("本地加密 · AES-256-GCM · 密码不落盘")
        subtitle.setStyleSheet("color:#64748B;")
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(36)

        buttons = QHBoxLayout()
        buttons.setAlignment(Qt.AlignmentFlag.AlignCenter)

        new_btn = QPushButton("新建文件")
        new_btn.setProperty("role", "primary")
        new_btn.setMinimumSize(130, 40)
        new_btn.clicked.connect(self.new_file_requested.emit)
        buttons.addWidget(new_btn)

        open_btn = QPushButton("打开文件")
        open_btn.setMinimumSize(130, 40)
        open_btn.clicked.connect(self.open_file_requested.emit)
        buttons.addWidget(open_btn)

        layout.addLayout(buttons)

    def _create_menu_bar(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件(&F)")
        self._add_action(file_menu, "新建(&N)", "Ctrl+N", self.new_file_requested)
        self._add_action(file_menu, "打开(&O)", "Ctrl+O", self.open_file_requested)
        file_menu.addSeparator()
        self._add_action(file_menu, "保存(&S)", "Ctrl+S", self.save_file_requested)
        self._add_action(file_menu, "另存为(&A)", "Ctrl+Shift+S", self.save_as_requested)
        file_menu.addSeparator()
        self._add_action(file_menu, "锁定(&L)", "Ctrl+L", self.lock_requested)
        quit_action = QAction("退出(&Q)", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        edit_menu = menubar.addMenu("编辑(&E)")
        self._add_action(edit_menu, "撤销(&U)", "Ctrl+Z", self.undo_requested)
        self._add_action(edit_menu, "重做(&R)", "Ctrl+Y", self.redo_requested)
        edit_menu.addSeparator()
        self._add_action(edit_menu, "复制密码(&C)", "Ctrl+C", self.copy_selected_requested)
        self._add_action(edit_menu, "删除选中", "Delete", self.delete_selected_requested)
        edit_menu.addSeparator()
        self._add_action(edit_menu, "清空所有数据", None, self.clear_all_requested)

        view_menu = menubar.addMenu("视图(&V)")
        self.show_passwords_action = QAction("显示密码", self)
        self.show_passwords_action.setCheckable(True)
        self.show_passwords_action.toggled.connect(self._toggle_show_passwords)
        view_menu.addAction(self.show_passwords_action)

        help_menu = menubar.addMenu("帮助(&H)")
        shortcuts = QAction("键盘快捷键", self)
        shortcuts.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts)
        about = QAction("关于", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _add_action(self, menu, text, shortcut, signal) -> QAction:
        action = QAction(text, self)
        if shortcut:
            action.setShortcut(shortcut)
        action.triggered.connect(signal.emit)
        menu.addAction(action)
        return action

    def _create_shortcuts(self) -> None:
        focus_search = QAction(self)
        focus_search.setShortcut(QKeySequence.StandardKey.Find)
        focus_search.triggered.connect(self._focus_search)
        self.addAction(focus_search)

    # ===================== 主界面 =====================
    def switch_to_main_interface(self) -> None:
        self.initial_widget.setVisible(False)
        self.work_widget.setVisible(True)
        if not hasattr(self, "tree"):
            self._create_main_interface()

    def reset_to_initial(self) -> None:
        if hasattr(self, "tree"):
            self.tree.clear()
        self.work_widget.setVisible(False)
        self.initial_widget.setVisible(True)
        self.update_window_title(None)

    def _create_main_interface(self) -> None:
        layout = QVBoxLayout(self.work_widget)

        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索主体…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMaximumWidth(320)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)
        toolbar.addStretch()

        add_btn = QPushButton("新增主体")
        add_btn.setProperty("role", "primary")
        add_btn.clicked.connect(self.add_subject_requested.emit)
        toolbar.addWidget(add_btn)

        for label, signal in (
            ("生成新密码", self._generate_selected),
            ("复制", self.copy_selected_requested.emit),
            ("历史", self._history_selected),
            ("删除", self.delete_selected_requested.emit),
            ("锁定", self.lock_requested.emit),
        ):
            button = QPushButton(label)
            if label == "删除":
                button.setProperty("role", "danger")
            button.clicked.connect(signal)
            toolbar.addWidget(button)

        layout.addLayout(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["序号", "密码生成主体", "密码", "第n次生成", "规则"])
        self.tree.setColumnWidth(0, 60)
        self.tree.setColumnWidth(1, 220)
        self.tree.setColumnWidth(2, 240)
        self.tree.setColumnWidth(3, 100)
        self.tree.setColumnHidden(4, True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.tree.setDragEnabled(True)
        self.tree.setAcceptDrops(True)
        self.tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.tree.model().rowsMoved.connect(lambda *_: self.controller.handle_row_reorder())
        layout.addWidget(self.tree)

    def _focus_search(self) -> None:
        if hasattr(self, "search_input") and self.work_widget.isVisible():
            self.search_input.setFocus()
            self.search_input.selectAll()

    def _on_search_changed(self, text: str) -> None:
        if not hasattr(self, "tree"):
            return
        keyword = text.strip().lower()
        for item in self.get_all_row_items():
            hidden = bool(keyword) and keyword not in item.text(1).lower()
            item.setHidden(hidden)

    def _toggle_show_passwords(self, shown: bool) -> None:
        self._show_passwords = shown
        if hasattr(self, "tree"):
            for item in self.get_all_row_items():
                self._render_password(item)
        if self.history_window:
            self._populate_history(self.history_window, self._history_cache)

    def _render_password(self, item: QTreeWidgetItem) -> None:
        real = item.data(2, Qt.ItemDataRole.UserRole) or ""
        item.setText(2, real if self._show_passwords else MASK)

    def _selected_item(self):
        if not hasattr(self, "tree"):
            return None
        items = self.tree.selectedItems()
        return items[0] if items else None

    def _generate_selected(self) -> None:
        item = self._selected_item()
        if item:
            self.controller.handle_generate_password(item)

    def _history_selected(self) -> None:
        item = self._selected_item()
        if item:
            self.controller.handle_show_history(item)

    def _show_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if not item or item.text(1) == PLACEHOLDER_NAME:
            return
        menu = QMenu(self)
        gen_action = menu.addAction("生成新密码")
        copy_action = menu.addAction("复制密码")
        menu.addSeparator()
        history_action = menu.addAction("历史密码")
        menu.addSeparator()
        delete_action = menu.addAction("删除")
        action = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if action == gen_action:
            self.controller.handle_generate_password(item)
        elif action == copy_action:
            self.controller.handle_copy_password(item)
        elif action == history_action:
            self.controller.handle_show_history(item)
        elif action == delete_action:
            self.controller.handle_delete_row(item)

    def _on_item_double_clicked(self, item) -> None:
        if item and item.text(1) != PLACEHOLDER_NAME:
            self.controller.handle_show_history(item)

    # ===================== 表格数据接口 =====================
    def clear_table(self) -> None:
        self.tree.clear()

    def insert_table_row(self, index, name, password, count, rule) -> None:
        item = QTreeWidgetItem()
        item.setText(0, str(index))
        item.setText(1, name)
        item.setData(2, Qt.ItemDataRole.UserRole, password)
        item.setText(3, str(count))
        item.setText(4, rule)
        self._render_password(item)
        self.tree.addTopLevelItem(item)

    def update_table_row(self, item, index, name, password, count, rule) -> None:
        item.setText(0, str(index))
        item.setText(1, name)
        item.setData(2, Qt.ItemDataRole.UserRole, password)
        item.setText(3, str(count))
        item.setText(4, rule)
        self._render_password(item)

    def insert_placeholder_row(self) -> None:
        item = QTreeWidgetItem()
        item.setText(0, "—")
        item.setText(1, PLACEHOLDER_NAME)
        item.setData(2, Qt.ItemDataRole.UserRole, "")
        item.setText(2, "等待生成")
        item.setText(3, "0")
        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self.tree.addTopLevelItem(item)

    def get_all_row_items(self) -> list:
        return [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]

    def get_selected_row_item(self):
        return self._selected_item()

    def get_row_values(self, item) -> list:
        return [
            item.text(0),
            item.text(1),
            item.data(2, Qt.ItemDataRole.UserRole) or "",
            item.text(3),
            item.text(4),
        ]

    def refresh_row_numbers(self) -> None:
        number = 0
        for item in self.get_all_row_items():
            if item.text(1) == PLACEHOLDER_NAME:
                continue
            number += 1
            item.setText(0, str(number))

    # ===================== 对话框 =====================
    def show_add_subject_dialog(self, callback) -> None:
        dialog = AddSubjectDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, length, lower, upper, digit, symbol = dialog.get_data()
            if not name:
                QMessageBox.warning(self, "警告", "密码主体名称不能为空！")
                return
            callback(name, length, lower, upper, digit, symbol)

    def ask_key(self, title: str, message: str, confirm: bool = False) -> str:
        dialog = UnlockDialog(title, message, confirm=confirm, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            return dialog.key()
        return ""

    def ask_yes_no(self, title: str, message: str) -> bool:
        reply = QMessageBox.question(
            self,
            title,
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def ask_save_file_path(self, title, default_extension, filetypes, initialfile="") -> str:
        filters = ";;".join(f"{name} (*{ext})" for name, ext in filetypes)
        path, _ = QFileDialog.getSaveFileName(self, title, initialfile, filters)
        if path and not path.endswith(default_extension):
            path += default_extension
        return path

    def ask_open_file_path(self, title, filetypes) -> str:
        filters = ";;".join(f"{name} (*{ext})" for name, ext in filetypes)
        path, _ = QFileDialog.getOpenFileName(self, title, "", filters)
        return path

    def ask_string(self, title: str, prompt: str) -> str:
        text, ok = QInputDialog.getText(self, title, prompt)
        return text if ok else ""

    # ===================== 历史窗口 =====================
    def show_history_window(self, subject_name, history_data, callbacks) -> None:
        if (
            self.history_window
            and self.history_window.isVisible()
            and self.history_window.subject_name == subject_name
        ):
            self.history_window.raise_()
            self.history_window.activateWindow()
            return

        if self.history_window:
            self.history_window.close()

        window = HistoryWindow(subject_name, self)
        window.copy_btn.clicked.connect(lambda: callbacks["copy"](window.tree))
        window.delete_btn.clicked.connect(lambda: callbacks["delete"](window.tree))
        window.undo_btn.clicked.connect(lambda: callbacks["undo"](window.tree))
        window.redo_btn.clicked.connect(lambda: callbacks["redo"](window.tree))
        window.show_btn.toggled.connect(lambda *_: self._populate_history(window, self._history_cache))

        self.history_window = window
        self._populate_history(window, history_data)
        window.show()

    def _populate_history(self, window: HistoryWindow, history_data) -> None:
        self._history_cache = history_data
        window.tree.clear()
        reveal = getattr(window, "show_btn", None)
        show = bool(reveal and reveal.isChecked())
        for index, entry in enumerate(history_data, 1):
            password, count, timestamp = entry
            item = QTreeWidgetItem()
            item.setText(0, str(index))
            item.setData(1, Qt.ItemDataRole.UserRole, password)
            item.setText(1, password if show else MASK)
            item.setText(2, timestamp or f"第 {count} 次")
            window.tree.addTopLevelItem(item)

    def update_history_window(self, history_data) -> None:
        if self.history_window:
            self._populate_history(self.history_window, history_data)

    def get_history_selection(self, tree):
        item = tree.currentItem()
        if not item:
            return None
        try:
            index = int(item.text(0)) - 1
        except ValueError:
            return None
        return {"password": item.data(1, Qt.ItemDataRole.UserRole) or "", "index": index}

    # ===================== 状态与提示 =====================
    def show_status(self, message: str, timeout: int = 3000, is_error: bool = False) -> None:
        self.status_bar.showMessage(message, timeout)

    def show_info(self, title: str, message: str) -> None:
        self.show_status(message, 4000)

    def show_warning(self, title: str, message: str) -> None:
        self.show_status(f"⚠ {message}", 5000)

    def show_error(self, title: str, message: str) -> None:
        self.show_status(message, 8000, is_error=True)
        QMessageBox.critical(self, title, message)

    def _show_shortcuts(self) -> None:
        QMessageBox.information(
            self,
            "键盘快捷键",
            "Ctrl+N 新建    Ctrl+O 打开    Ctrl+S 保存    Ctrl+Shift+S 另存为\n"
            "Ctrl+Z 撤销    Ctrl+Y 重做    Ctrl+C 复制密码    Delete 删除\n"
            "Ctrl+F 搜索    Ctrl+L 锁定    Ctrl+Q 退出",
        )

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "关于",
            "密码管理器\n\n"
            "本地加密密码管理器：AES-256-GCM + PBKDF2-HMAC-SHA256。\n"
            "密码不以明文落盘，由「主体名 + 盐」确定性生成。",
        )

    # ===================== 窗口标题与脏标记 =====================
    def set_dirty(self, dirty: bool) -> None:
        self._dirty = dirty
        self.dirty_indicator.setText("● 有未保存的修改" if dirty else "")
        self.update_window_title(self._current_path)

    def update_window_title(self, file_path: str | None) -> None:
        self._current_path = file_path
        if file_path:
            name = os.path.basename(file_path)
            star = " *" if self._dirty else ""
            self.setWindowTitle(f"密码管理器 — {name}{star}")
        else:
            self.setWindowTitle("密码管理器")

    def copy_to_clipboard(self, text: str) -> None:
        QApplication.clipboard().setText(text)
