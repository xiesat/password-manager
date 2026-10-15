"""视图层 (View) - PySide6 实现。

只负责界面与用户交互，不含业务逻辑。样式由 theme.py 生成并应用。
"""

from __future__ import annotations

import os
import secrets
import string

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QAction, QActionGroup, QIcon, QKeySequence
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
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

import storage
import theme
from password_generator import estimate_strength
from table_model import MASK, PasswordFilterProxy, PasswordTableModel


def _strength_labels() -> list[str]:
    return ["", "很弱", "弱", "中", "强", "极强"]


class PasswordTableView(QTableView):
    """支持内部拖拽排序的表格视图。"""

    rows_reordered = Signal(list, int)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        selection = self.selectionModel()
        if selection is None:
            event.ignore()
            return
        rows = sorted({index.row() for index in selection.selectedRows()})
        if not rows:
            event.ignore()
            return

        position = event.position().toPoint() if hasattr(event, "position") else event.pos()
        index = self.indexAt(position)
        target = index.row() if index.isValid() else self.model().rowCount()
        rect = self.visualRect(index) if index.isValid() else None
        if rect is not None and position.y() > rect.center().y():
            target += 1

        event.setDropAction(Qt.DropAction.MoveAction)
        event.accept()
        self.rows_reordered.emit(rows, target)


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
        self.key_edit.setPlaceholderText(self.tr("请输入密钥…"))
        key_row.addWidget(self.key_edit)
        self.show_btn = QPushButton(self.tr("显示"))
        self.show_btn.setCheckable(True)
        self.show_btn.setProperty("role", "icon")
        key_row.addWidget(self.show_btn)
        layout.addLayout(key_row)

        if confirm:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_edit.setPlaceholderText(self.tr("再次输入密钥…"))
            layout.addWidget(self.confirm_edit)

        self.strength_label = QLabel("")
        self.strength_label.setObjectName("emptyStateHint")
        layout.addWidget(self.strength_label)

        if confirm:
            warn = QLabel(self.tr("注意：密钥丢失将无法恢复数据，请务必妥善保管。"))
            warn.setWordWrap(True)
            warn.setStyleSheet("color:#B45309;")
            layout.addWidget(warn)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText(self.tr("确定"))
        ok.setProperty("role", "primary")
        ok.setDefault(True)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(self.tr("取消"))
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
        score = estimate_strength(text)
        if not score:
            self.strength_label.setText("")
            return
        labels = _strength_labels()
        bars = "\u2588" * score + "\u2591" * (5 - score)
        self.strength_label.setText(self.tr("强度 %1 %2").replace("%1", bars).replace("%2", labels[score]))

    def _on_accept(self) -> None:
        if not self.key_edit.text():
            QMessageBox.warning(self, self.tr("提示"), self.tr("密钥不能为空！"))
            return
        if self.confirm_edit is not None and self.confirm_edit.text() != self.key_edit.text():
            QMessageBox.warning(self, self.tr("提示"), self.tr("两次输入的密钥不一致！"))
            return
        self.accept()

    def key(self) -> str:
        return self.key_edit.text()


class AddSubjectDialog(QDialog):
    """添加密码主体对话框。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("添加密码主体"))
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(self.tr("例如：Google 账号"))
        form.addRow(self.tr("名称"), self.name_edit)

        self.length_spin = QSpinBox()
        self.length_spin.setRange(6, 64)
        self.length_spin.setValue(16)
        form.addRow(self.tr("密码长度"), self.length_spin)
        layout.addLayout(form)

        group = QGroupBox(self.tr("字符类型"))
        group_layout = QVBoxLayout(group)
        self.lower_check = QCheckBox(self.tr("小写字母 (a-z)"))
        self.upper_check = QCheckBox(self.tr("大写字母 (A-Z)"))
        self.digit_check = QCheckBox(self.tr("数字 (0-9)"))
        self.symbol_check = QCheckBox(self.tr("特殊字符 (!@#$…)"))
        for box in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            box.setChecked(True)
            group_layout.addWidget(box)
        layout.addWidget(group)

        self.preview_label = QLabel("")
        self.preview_label.setObjectName("emptyStateHint")
        layout.addWidget(self.preview_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText(self.tr("确定"))
        ok.setProperty("role", "primary")
        ok.setDefault(True)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(self.tr("取消"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.length_spin.valueChanged.connect(self._update_preview)
        for box in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            box.toggled.connect(self._update_preview)
        self._update_preview()

    def _update_preview(self) -> None:
        pool = ""
        classes: list[str] = []
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
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            pool += symbols
            classes.append(symbols)
        if not pool:
            pool = string.ascii_lowercase + string.digits
            classes = [string.ascii_lowercase, string.digits]

        length = self.length_spin.value()
        sample = [secrets.choice(c) for c in classes]
        sample += [secrets.choice(pool) for _ in range(max(0, length - len(sample)))]
        secrets.SystemRandom().shuffle(sample)
        preview = "".join(sample)[:16]
        labels = _strength_labels()
        score = estimate_strength("".join(sample))
        self.preview_label.setText(
            self.tr("预览：%1…   强度：%2").replace("%1", preview).replace("%2", labels[score])
        )

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
        self.setWindowTitle(self.tr("历史密码 - %1").replace("%1", subject_name))
        self.resize(680, 420)

        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.show_btn = QPushButton(self.tr("显示密码"))
        self.show_btn.setCheckable(True)
        self.copy_btn = QPushButton(self.tr("复制"))
        self.delete_btn = QPushButton(self.tr("删除"))
        self.delete_btn.setProperty("role", "danger")
        self.undo_btn = QPushButton(self.tr("撤销"))
        self.redo_btn = QPushButton(self.tr("重做"))
        toolbar.addWidget(self.show_btn)
        toolbar.addStretch()
        toolbar.addWidget(self.undo_btn)
        toolbar.addWidget(self.redo_btn)
        toolbar.addWidget(self.copy_btn)
        toolbar.addWidget(self.delete_btn)
        layout.addLayout(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels([self.tr("序号"), self.tr("历史密码"), self.tr("生成时间")])
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
    import_csv_requested = Signal()
    export_csv_requested = Signal()
    add_subject_requested = Signal()
    clear_all_requested = Signal()
    generate_selected_requested = Signal()
    copy_selected_requested = Signal()
    delete_selected_requested = Signal()
    history_selected_requested = Signal()
    undo_requested = Signal()
    redo_requested = Signal()
    lock_requested = Signal()
    order_changed = Signal(list)
    theme_changed = Signal(str)
    language_changed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(self.tr("密码管理器"))
        self.resize(1020, 680)

        self.controller = None
        self.history_window: HistoryWindow | None = None
        self._current_path: str | None = None
        self._dirty = False
        self._show_passwords = False
        self._history_cache: list = []
        self._theme_actions: dict[str, QAction] = {}
        self._language_actions: dict[str, QAction] = {}

        icon_path = storage.resource_path("resources", "app_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._create_status_bar()
        self._create_central_widget()
        self._create_menu_bar()
        self._create_shortcuts()
        self._show_initial_view()

    # ===================================================== 基础布局
    def set_controller(self, controller) -> None:
        self.controller = controller

    def _create_status_bar(self) -> None:
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.clipboard_label = QLabel("")
        self.clipboard_label.setObjectName("emptyStateHint")
        self.status_bar.addPermanentWidget(self.clipboard_label)
        self.dirty_indicator = QLabel("")
        self.dirty_indicator.setStyleSheet("color:#F59E0B;")
        self.status_bar.addPermanentWidget(self.dirty_indicator)
        self.status_bar.showMessage(self.tr("就绪"), 2000)

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

        title = QLabel(self.tr("密码管理器"))
        title.setObjectName("brandTitle")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel(self.tr("本地加密 · AES-256-GCM · 密码不落盘"))
        subtitle.setObjectName("emptyStateHint")
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(36)
        buttons = QHBoxLayout()
        buttons.setAlignment(Qt.AlignmentFlag.AlignCenter)

        new_btn = QPushButton(self.tr("新建文件"))
        new_btn.setProperty("role", "primary")
        new_btn.setMinimumSize(130, 40)
        new_btn.clicked.connect(self.new_file_requested.emit)
        buttons.addWidget(new_btn)

        open_btn = QPushButton(self.tr("打开文件"))
        open_btn.setMinimumSize(130, 40)
        open_btn.clicked.connect(self.open_file_requested.emit)
        buttons.addWidget(open_btn)

        layout.addLayout(buttons)

    def _create_menu_bar(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu(self.tr("文件(&F)"))
        self._add_action(file_menu, self.tr("新建(&N)"), "Ctrl+N", self.new_file_requested)
        self._add_action(file_menu, self.tr("打开(&O)"), "Ctrl+O", self.open_file_requested)
        file_menu.addSeparator()
        self._add_action(file_menu, self.tr("保存(&S)"), "Ctrl+S", self.save_file_requested)
        self._add_action(file_menu, self.tr("另存为(&A)"), "Ctrl+Shift+S", self.save_as_requested)
        file_menu.addSeparator()
        self._add_action(file_menu, self.tr("导入 CSV(&I)"), None, self.import_csv_requested)
        self._add_action(file_menu, self.tr("导出 CSV(&E)"), None, self.export_csv_requested)
        file_menu.addSeparator()
        self._add_action(file_menu, self.tr("锁定(&L)"), "Ctrl+L", self.lock_requested)
        quit_action = QAction(self.tr("退出(&Q)"), self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        edit_menu = menubar.addMenu(self.tr("编辑(&E)"))
        self._add_action(edit_menu, self.tr("撤销(&U)"), "Ctrl+Z", self.undo_requested)
        self._add_action(edit_menu, self.tr("重做(&R)"), "Ctrl+Y", self.redo_requested)
        edit_menu.addSeparator()
        self._add_action(edit_menu, self.tr("生成新密码(&G)"), "Ctrl+G", self.generate_selected_requested)
        self._add_action(edit_menu, self.tr("复制密码(&C)"), "Ctrl+C", self.copy_selected_requested)
        self._add_action(edit_menu, self.tr("删除选中(&D)"), "Delete", self.delete_selected_requested)
        edit_menu.addSeparator()
        self._add_action(edit_menu, self.tr("清空所有数据"), None, self.clear_all_requested)

        view_menu = menubar.addMenu(self.tr("视图(&V)"))
        self.show_passwords_action = QAction(self.tr("显示密码"), self)
        self.show_passwords_action.setCheckable(True)
        self.show_passwords_action.toggled.connect(self._toggle_show_passwords)
        view_menu.addAction(self.show_passwords_action)

        theme_menu = view_menu.addMenu(self.tr("主题"))
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)
        for key, label in (
            ("system", self.tr("跟随系统")),
            ("light", self.tr("浅色")),
            ("dark", self.tr("深色")),
        ):
            action = QAction(label, self)
            action.setCheckable(True)
            action.setChecked(key == "system")
            action.triggered.connect(lambda _checked=False, k=key: self.theme_changed.emit(k))
            theme_group.addAction(action)
            theme_menu.addAction(action)
            self._theme_actions[key] = action

        language_menu = view_menu.addMenu(self.tr("语言 / Language"))
        language_group = QActionGroup(self)
        language_group.setExclusive(True)
        for key, label in (("zh", "简体中文"), ("en", "English")):
            action = QAction(label, self)
            action.setCheckable(True)
            action.setChecked(key == "zh")
            action.triggered.connect(lambda _checked=False, k=key: self.language_changed.emit(k))
            language_group.addAction(action)
            language_menu.addAction(action)
            self._language_actions[key] = action

        help_menu = menubar.addMenu(self.tr("帮助(&H)"))
        shortcuts = QAction(self.tr("键盘快捷键"), self)
        shortcuts.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts)
        about = QAction(self.tr("关于"), self)
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

    # ===================================================== 主界面
    def switch_to_main_interface(self) -> None:
        self.initial_widget.setVisible(False)
        self.work_widget.setVisible(True)
        if not hasattr(self, "table"):
            self._create_main_interface()

    def reset_to_initial(self) -> None:
        if hasattr(self, "table_model"):
            self.table_model.set_rows([])
        self.work_widget.setVisible(False)
        self.initial_widget.setVisible(True)
        self.update_window_title(None)

    def _create_main_interface(self) -> None:
        layout = QVBoxLayout(self.work_widget)

        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(self.tr("搜索主体、更新时间…"))
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMaximumWidth(320)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)
        toolbar.addStretch()

        add_btn = QPushButton(self.tr("新增主体"))
        add_btn.setProperty("role", "primary")
        add_btn.clicked.connect(self.add_subject_requested.emit)
        toolbar.addWidget(add_btn)
        for label, signal, role in (
            (self.tr("生成新密码"), self.generate_selected_requested.emit, None),
            (self.tr("复制"), self.copy_selected_requested.emit, None),
            (self.tr("历史"), self.history_selected_requested.emit, None),
            (self.tr("删除"), self.delete_selected_requested.emit, "danger"),
            (self.tr("锁定"), self.lock_requested.emit, None),
        ):
            button = QPushButton(label)
            if role:
                button.setProperty("role", role)
            button.clicked.connect(signal)
            toolbar.addWidget(button)
        layout.addLayout(toolbar)

        self.stack = QStackedWidget()
        self.table_model = PasswordTableModel(
            [
                self.tr("名称"),
                self.tr("密码"),
                self.tr("次数"),
                self.tr("更新时间"),
                self.tr("强度"),
            ],
            _strength_labels(),
            self,
        )
        self.proxy = PasswordFilterProxy(self)
        self.proxy.setSourceModel(self.table_model)

        self.table = PasswordTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(lambda *_: self.history_selected_requested.emit())
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDropIndicatorShown(True)
        self.table.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.table.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.rows_reordered.connect(self._on_rows_reordered)

        self.stack.addWidget(self.table)
        self.stack.addWidget(self._create_empty_state())
        layout.addWidget(self.stack)

    def _create_empty_state(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel(self.tr("还没有密码主体"))
        title.setObjectName("emptyStateTitle")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(self.tr("点击下方按钮添加第一个，或从 CSV 导入。"))
        hint.setObjectName("emptyStateHint")
        layout.addWidget(hint, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(16)
        add_btn = QPushButton(self.tr("新增主体"))
        add_btn.setProperty("role", "primary")
        add_btn.setMinimumWidth(140)
        add_btn.clicked.connect(self.add_subject_requested.emit)
        layout.addWidget(add_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        return page

    # ===================================================== 数据接口
    def load_rows(self, rows: list[dict]) -> None:
        self.table_model.set_rows(rows)
        self.table_model.set_show_passwords(self._show_passwords)
        self._update_empty_state()

    def _update_empty_state(self) -> None:
        if hasattr(self, "stack"):
            self.stack.setCurrentIndex(0 if self.table_model.rowCount() else 1)

    def selected_row_indexes(self) -> list[int]:
        if not hasattr(self, "table"):
            return []
        source_rows = set()
        for index in self.table.selectionModel().selectedRows():
            mapped = self.proxy.mapToSource(index)
            if mapped.isValid():
                source_rows.add(mapped.row())
        return sorted(source_rows)

    def selected_row(self) -> int | None:
        rows = self.selected_row_indexes()
        return rows[0] if rows else None

    def row_at(self, index: int) -> dict:
        return self.table_model.row_at(index)

    def set_show_passwords(self, show: bool) -> None:
        self._show_passwords = show
        if hasattr(self, "table_model"):
            self.table_model.set_show_passwords(show)

    # ===================================================== 交互
    def _focus_search(self) -> None:
        if hasattr(self, "search_input") and self.work_widget.isVisible():
            self.search_input.setFocus()
            self.search_input.selectAll()

    def _on_search_changed(self, text: str) -> None:
        if hasattr(self, "proxy"):
            self.proxy.set_search(text)
            self._update_empty_state()

    def _toggle_show_passwords(self, shown: bool) -> None:
        self.set_show_passwords(shown)
        if self.history_window:
            self._populate_history(self.history_window, self._history_cache)

    def _on_rows_reordered(self, proxy_rows: list, target_proxy_row: int) -> None:
        if not hasattr(self, "proxy"):
            return
        source_rows = []
        for row in proxy_rows:
            mapped = self.proxy.mapToSource(self.proxy.index(row, 0))
            if mapped.isValid():
                source_rows.append(mapped.row())
        if not source_rows:
            return
        if target_proxy_row >= self.proxy.rowCount():
            target = self.table_model.rowCount()
        else:
            mapped_target = self.proxy.mapToSource(self.proxy.index(target_proxy_row, 0))
            target = mapped_target.row() if mapped_target.isValid() else self.table_model.rowCount()
        if self.table_model.move_rows(source_rows, target):
            self.order_changed.emit(self.table_model.names())

    def _show_context_menu(self, pos: QPoint) -> None:
        if not hasattr(self, "table"):
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        menu = QMenu(self)
        generate_action = menu.addAction(self.tr("生成新密码"))
        copy_action = menu.addAction(self.tr("复制密码"))
        menu.addSeparator()
        history_action = menu.addAction(self.tr("历史密码"))
        menu.addSeparator()
        delete_action = menu.addAction(self.tr("删除"))
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == generate_action:
            self.generate_selected_requested.emit()
        elif chosen == copy_action:
            self.copy_selected_requested.emit()
        elif chosen == history_action:
            self.history_selected_requested.emit()
        elif chosen == delete_action:
            self.delete_selected_requested.emit()

    # ===================================================== 对话框
    def show_add_subject_dialog(self, callback) -> None:
        dialog = AddSubjectDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, length, lower, upper, digit, symbol = dialog.get_data()
            if not name:
                QMessageBox.warning(self, self.tr("警告"), self.tr("密码主体名称不能为空！"))
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

    # ===================================================== 历史窗口
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
        show = window.show_btn.isChecked()
        for index, entry in enumerate(history_data, 1):
            password, count, timestamp = entry
            item = QTreeWidgetItem()
            item.setText(0, str(index))
            item.setData(1, Qt.ItemDataRole.UserRole, password)
            item.setText(1, password if show else MASK)
            item.setText(2, timestamp or self.tr("第 %1 次").replace("%1", str(count)))
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

    # ===================================================== 主题与状态
    def apply_theme(self, setting: str) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.build_stylesheet(setting))
        for key, action in self._theme_actions.items():
            action.blockSignals(True)
            action.setChecked(key == setting)
            action.blockSignals(False)

    def set_language_checked(self, language: str) -> None:
        for key, action in self._language_actions.items():
            action.blockSignals(True)
            action.setChecked(key == language)
            action.blockSignals(False)

    def show_status(self, message: str, timeout: int = 3000, is_error: bool = False) -> None:
        self.status_bar.showMessage(message, timeout)

    def show_info(self, title: str, message: str) -> None:
        self.status_bar.showMessage(message, 4000)

    def show_warning(self, title: str, message: str) -> None:
        self.status_bar.showMessage(f"\u26a0 {message}", 5000)

    def show_error(self, title: str, message: str) -> None:
        self.status_bar.showMessage(message, 8000)
        QMessageBox.critical(self, title, message)

    def set_clipboard_countdown(self, seconds: int) -> None:
        if seconds > 0:
            self.clipboard_label.setText(self.tr("剪贴板 %1 秒后清空").replace("%1", str(seconds)))
        else:
            self.clipboard_label.setText("")

    def _show_shortcuts(self) -> None:
        QMessageBox.information(
            self,
            self.tr("键盘快捷键"),
            self.tr(
                "Ctrl+N 新建    Ctrl+O 打开    Ctrl+S 保存    Ctrl+Shift+S 另存为\n"
                "Ctrl+Z 撤销    Ctrl+Y 重做    Ctrl+G 生成新密码    Ctrl+C 复制\n"
                "Delete 删除    Ctrl+F 搜索    Ctrl+L 锁定    Ctrl+Q 退出"
            ),
        )

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            self.tr("关于"),
            self.tr(
                "密码管理器\n\n"
                "本地加密密码管理器：AES-256-GCM + PBKDF2-HMAC-SHA256。\n"
                "数据整体加密存储在单个 .sk 文件中。"
            ),
        )

    # ===================================================== 标题与脏标记
    def set_dirty(self, dirty: bool) -> None:
        self._dirty = dirty
        self.dirty_indicator.setText(self.tr("● 有未保存的修改") if dirty else "")
        self.update_window_title(self._current_path)

    def update_window_title(self, file_path: str | None) -> None:
        self._current_path = file_path
        if file_path:
            name = os.path.basename(file_path)
            star = " *" if self._dirty else ""
            self.setWindowTitle(self.tr("密码管理器 — %1%2").replace("%1", name).replace("%2", star))
        else:
            self.setWindowTitle(self.tr("密码管理器"))

    def copy_to_clipboard(self, text: str) -> None:
        QApplication.clipboard().setText(text)
