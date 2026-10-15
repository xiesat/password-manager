"""CSV 导入 / 导出。

导出会包含明文密码，调用方必须先向用户明确风险。
"""

from __future__ import annotations

import csv
import io

import storage

COLUMNS = ["name", "password", "count", "updated_at", "rule"]

_ALIASES: dict[str, str] = {
    "name": "name",
    "名称": "name",
    "密码生成主体": "name",
    "主体": "name",
    "password": "password",
    "密码": "password",
    "count": "count",
    "次数": "count",
    "第n次生成的密码": "count",
    "updated_at": "updated_at",
    "更新时间": "updated_at",
    "更新时间/日期": "updated_at",
    "updated": "updated_at",
    "time": "updated_at",
    "rule": "rule",
    "规则": "rule",
}


def _normalize(header: str) -> str:
    return header.strip().lstrip("\ufeff").lower()


def rows_to_csv(rows: list[dict], *, include_rule: bool = False) -> str:
    """把行结构序列化为 CSV 文本（CRLF，便于 Excel）。"""
    headers = COLUMNS if include_rule else COLUMNS[:4]
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(headers)
    for row in rows:
        line = [
            str(row.get("name", "")),
            str(row.get("password", "")),
            str(row.get("count", "")),
            str(row.get("updated_at", "")),
        ]
        if include_rule:
            line.append(str(row.get("rule", "")))
        writer.writerow(line)
    return buffer.getvalue()


def parse_csv(text: str) -> list[dict]:
    """解析 CSV 文本，返回行结构；支持中英文表头与 BOM。"""
    text = text.lstrip("\ufeff")
    records = list(csv.reader(io.StringIO(text)))
    if not records:
        return []

    header = [_normalize(header_cell) for header_cell in records[0]]
    mapping: dict[str, int] = {}
    for index, header_cell in enumerate(header):
        key = _ALIASES.get(header_cell) or _ALIASES.get(header_cell.lower())
        if key and key not in mapping:
            mapping[key] = index

    if "name" not in mapping:
        raise ValueError("CSV 缺少『名称 / name』列")

    def cell(row: list[str], key: str) -> str:
        index = mapping.get(key)
        if index is None or index >= len(row):
            return ""
        return row[index].strip()

    result: list[dict] = []
    for row in records[1:]:
        if not any(part.strip() for part in row):
            continue
        name = cell(row, "name")
        if not name:
            continue
        result.append(
            {
                "name": name,
                "password": cell(row, "password"),
                "count": cell(row, "count") or "0",
                "updated_at": cell(row, "updated_at"),
                "rule": cell(row, "rule"),
            }
        )
    return result


def export_csv(path: str, rows: list[dict], *, include_rule: bool = False) -> None:
    """原子写入 CSV（UTF-8 BOM，Excel 友好）。"""
    storage.atomic_write_text(path, rows_to_csv(rows, include_rule=include_rule), encoding="utf-8-sig")


def import_csv(path: str) -> list[dict]:
    return parse_csv(storage.read_text(path, encoding="utf-8-sig"))
