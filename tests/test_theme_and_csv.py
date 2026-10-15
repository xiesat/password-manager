"""主题与 CSV 测试。"""

from __future__ import annotations

import pytest

import io_exchange
import theme


# ------------------------------------------------------------------ 主题
def test_build_stylesheet_resolves_all_tokens():
    for setting in ("light", "dark"):
        qss = theme.build_stylesheet(setting)
        assert "@" not in qss.replace("@@", "")
        assert "{" in qss and "QPushButton" in qss


def test_light_and_dark_differ():
    assert theme.build_stylesheet("light") != theme.build_stylesheet("dark")
    assert theme.LIGHT["bg"] in theme.build_stylesheet("light")
    assert theme.DARK["bg"] in theme.build_stylesheet("dark")


def test_resolve_theme_explicit_and_system(monkeypatch):
    assert theme.resolve_theme("light") == "light"
    assert theme.resolve_theme("dark") == "dark"
    monkeypatch.setattr(theme, "detect_system_dark", lambda: True)
    assert theme.resolve_theme("system") == "dark"
    monkeypatch.setattr(theme, "detect_system_dark", lambda: False)
    assert theme.resolve_theme("system") == "light"


def test_theme_setting_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    theme.save_setting("dark")
    assert theme.load_setting() == "dark"
    theme.save_setting("nonsense")
    assert theme.load_setting() == theme.DEFAULT_SETTING


# ------------------------------------------------------------------ CSV
ROWS = [
    {
        "name": "Google",
        "password": "Ab3$kQ9m",
        "count": "2",
        "updated_at": "2026-01-02 03:04:05",
        "rule": "12|True|True|True|True|salt|v2",
    },
    {"name": '含,逗号"引号"', "password": 'p,w"d', "count": "0", "updated_at": "", "rule": ""},
]


def test_csv_roundtrip_including_quoting():
    text = io_exchange.rows_to_csv(ROWS, include_rule=True)
    parsed = io_exchange.parse_csv(text)
    assert [r["name"] for r in parsed] == ["Google", '含,逗号"引号"']
    assert parsed[1]["password"] == 'p,w"d'
    assert parsed[0]["rule"].endswith("|v2")


def test_csv_headers_aliases_and_bom():
    text = "\ufeff密码生成主体,密码,次数\nA,secret,3\n"
    parsed = io_exchange.parse_csv(text)
    assert parsed == [{"name": "A", "password": "secret", "count": "3", "updated_at": "", "rule": ""}]


def test_csv_skips_blank_rows_and_missing_name():
    parsed = io_exchange.parse_csv("name,password\n\n,onlypw\nB,ok\n")
    assert [r["name"] for r in parsed] == ["B"]


def test_csv_without_name_column_raises():
    with pytest.raises(ValueError):
        io_exchange.parse_csv("foo,bar\n1,2\n")


def test_csv_export_import_file(tmp_path):
    path = tmp_path / "out.csv"
    io_exchange.export_csv(str(path), ROWS)
    parsed = io_exchange.import_csv(str(path))
    assert parsed[0]["name"] == "Google"
    assert parsed[0]["password"] == "Ab3$kQ9m"
    assert parsed[0]["rule"] == ""  # 未导出规则
