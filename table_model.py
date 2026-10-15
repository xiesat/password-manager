"""密码表格的 Qt 模型与过滤代理。"""

from __future__ import annotations

import json

from PySide6.QtCore import (
    QAbstractTableModel,
    QMimeData,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from password_generator import estimate_strength

MASK = "\u2022" * 10
PASSWORD_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
MIME_TYPE = "application/x-password-manager-rows"

COLUMN_KEYS = ("name", "password", "count", "updated_at", "strength")


class PasswordTableModel(QAbstractTableModel):
    """只读表格模型；行数据是 dict 副本，不直接修改领域模型。"""

    def __init__(self, headers: list[str], strength_labels: list[str], parent=None) -> None:
        super().__init__(parent)
        self._rows: list[dict] = []
        self._headers = headers
        self._strength_labels = strength_labels
        self._show_passwords = False

    # ------------------------------------------------------------ Qt 接口
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: B008 - Qt 约定
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: B008 - Qt 约定
        return 0 if parent.isValid() else len(COLUMN_KEYS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(self._headers)
        ):
            return self._headers[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        if role == PASSWORD_ROLE:
            return row.get("password", "")
        if role == SORT_ROLE:
            return self._sort_key(row, column)
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == 1:
                return row.get("password", "") if self._show_passwords else ""
            if column == 0:
                return row.get("name", "")
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return (
                int(Qt.AlignmentFlag.AlignCenter)
                if column in (2, 4)
                else int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            )
        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)
        return None

    def flags(self, index: QModelIndex):
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.isValid():
            return base | Qt.ItemFlag.ItemIsDragEnabled
        return base | Qt.ItemFlag.ItemIsDropEnabled

    # ------------------------------------------------------- 拖拽（自定义）
    def supportedDropActions(self):
        return Qt.DropAction.MoveAction

    def mimeTypes(self) -> list[str]:
        return [MIME_TYPE]

    def mimeData(self, indexes) -> QMimeData:
        rows = sorted({index.row() for index in indexes if index.isValid()})
        payload = QMimeData()
        payload.setData(MIME_TYPE, json.dumps(rows).encode("utf-8"))
        return payload

    def move_rows(self, source_rows: list[int], target: int) -> bool:
        """把 source_rows 移动到 target 之前。"""
        moving_set = {r for r in source_rows if 0 <= r < len(self._rows)}
        if not moving_set:
            return False
        moving = [self._rows[r] for r in sorted(moving_set)]
        remaining = [row for i, row in enumerate(self._rows) if i not in moving_set]
        offset = sum(1 for r in moving_set if r < target)
        insert_at = max(0, min(len(remaining), target - offset))
        self.beginResetModel()
        self._rows = remaining[:insert_at] + moving + remaining[insert_at:]
        self.endResetModel()
        return True

    # ------------------------------------------------------------- 便捷方法
    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self._rows = [dict(row) for row in rows]
        self.endResetModel()

    def set_show_passwords(self, show: bool) -> None:
        self._show_passwords = bool(show)
        if self._rows:
            top = self.index(0, 1)
            bottom = self.index(len(self._rows) - 1, 1)
            self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole])

    def set_strength_labels(self, labels: list[str]) -> None:
        self._strength_labels = labels
        if self._rows:
            top = self.index(0, 4)
            bottom = self.index(len(self._rows) - 1, 4)
            self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.DisplayRole])

    def names(self) -> list[str]:
        return [row.get("name", "") for row in self._rows]

    def row_at(self, row: int) -> dict:
        return self._rows[row]

    # --------------------------------------------------------------- 内部
    def _display(self, row: dict, column: int):
        if column == 0:
            return row.get("name", "")
        if column == 1:
            return row.get("password", "") if self._show_passwords else MASK
        if column == 2:
            return row.get("count", "")
        if column == 3:
            return row.get("updated_at", "")
        if column == 4:
            score = estimate_strength(row.get("password", ""))
            return self._strength_labels[score] if 0 <= score < len(self._strength_labels) else ""
        return ""

    def _sort_key(self, row: dict, column: int):
        if column == 0:
            return row.get("name", "").casefold()
        if column == 1:
            return row.get("password", "")
        if column == 2:
            try:
                return int(row.get("count", "0"))
            except (TypeError, ValueError):
                return 0
        if column == 3:
            return row.get("updated_at", "")
        if column == 4:
            return estimate_strength(row.get("password", ""))
        return ""


class PasswordFilterProxy(QSortFilterProxyModel):
    """按主体名与更新时间过滤；排序使用模型的 SORT_ROLE。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._needle = ""
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(True)

    def set_search(self, text: str) -> None:
        self._needle = text.strip().casefold()
        self.invalidateFilter()

    def search_text(self) -> str:
        return self._needle

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        model = self.sourceModel()
        for column in (0, 3):
            index = model.index(source_row, column, source_parent)
            text = str(model.data(index, Qt.ItemDataRole.DisplayRole) or "").casefold()
            if self._needle in text:
                return True
        return False
