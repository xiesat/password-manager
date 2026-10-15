"""模型层测试：规则解析、生成、加解密往返、撤销、排序、旧格式兼容。"""

from __future__ import annotations

import json

import pytest

from encryption import AESCipher, VaultCipher
from model import PasswordManagerModel, build_rule, parse_rule


# --------------------------------------------------------------- 规则解析
def test_parse_rule_all_shapes():
    assert parse_rule("12|True|True|True|True")["algorithm"] == "v1"
    assert parse_rule("12|True|True|True|True")["salt"] == ""
    assert parse_rule("12|True|True|True|True|abc").get("salt") == "abc"
    v2 = parse_rule("12|True|False|True|False|abc|v2")
    assert v2["algorithm"] == "v2" and v2["upper"] is False and v2["salt"] == "abc"


@pytest.mark.parametrize(
    "bad", ["", "a|b", "12|True|True|True|True|s|vX", "999|True|True|True|True", "x|True|True|True|True"]
)
def test_parse_rule_rejects_bad(bad):
    assert parse_rule(bad) is None


def test_build_rule_roundtrip():
    rule = build_rule(16, True, False, True, True, "salt1", "v2")
    spec = parse_rule(rule)
    assert spec["length"] == 16 and spec["lower"] is True and spec["upper"] is False
    assert spec["salt"] == "salt1" and spec["algorithm"] == "v2"


# --------------------------------------------------------------- 基本操作
def test_add_subject_generates_v2_password():
    m = PasswordManagerModel()
    item = m.add_or_update_subject("Google", length=16)
    assert item["password"] != "等待生成"
    assert len(item["password"]) == 16
    spec = parse_rule(item["rule"])
    assert spec["algorithm"] == "v2" and spec["salt"]
    assert m.is_dirty()


def test_generate_new_password_increments_count_and_history():
    m = PasswordManagerModel()
    m.add_or_update_subject("A", length=12)
    old = m.main_data[0]["password"]
    result = m.generate_new_password_for_subject(0)
    assert result is not None
    assert m.main_data[0]["count"] == "1"
    assert m.main_data[0]["password"] != old
    history = m.get_history_for_subject("A")
    assert len(history) == 1
    assert len(history[0]) == 3  # (密码, 次数, 时间)
    assert history[0][2]


def test_add_same_name_updates_in_place():
    m = PasswordManagerModel()
    m.add_or_update_subject("A", length=12)
    m.add_or_update_subject("A", length=20)
    assert len(m.main_data) == 1
    assert parse_rule(m.main_data[0]["rule"])["length"] == 20


def test_reorder_subjects():
    m = PasswordManagerModel()
    for name in ("A", "B", "C"):
        m.add_or_update_subject(name)
    m.reorder_subjects(["C", "A", "B"])
    assert [i["name"] for i in m.main_data] == ["C", "A", "B"]


def test_undo_redo():
    m = PasswordManagerModel()
    m.initialize_empty_state()
    m.add_or_update_subject("A")
    m.add_or_update_subject("B")
    assert len(m.main_data) == 2
    assert m.undo() is True
    assert len(m.main_data) == 1
    assert m.redo() is True
    assert len(m.main_data) == 2


def test_undo_stack_is_bounded():
    m = PasswordManagerModel()
    m.initialize_empty_state()
    for i in range(150):
        m.add_or_update_subject(f"S{i}")
    assert len(m.undo_stack) <= 100


def test_delete_subject_and_history_entry():
    m = PasswordManagerModel()
    m.add_or_update_subject("A")
    m.generate_new_password_for_subject(0)
    assert m.delete_history_entry("A", 0) is True
    assert m.get_history_for_subject("A") == []
    assert m.delete_subject(0) is True
    assert m.main_data == []
    assert m.delete_subject(5) is False


# --------------------------------------------------------------- 往返
def test_v3_roundtrip_reproduces_passwords():
    m = PasswordManagerModel()
    m.add_or_update_subject("Google", length=18)
    m.add_or_update_subject("GitHub", length=12)
    token = m.encrypt_data("master", m.prepare_export_data())

    m2 = PasswordManagerModel()
    ok, _msg, version = m2.detect_and_store(token)
    assert ok and version == 3
    assert m2.decrypt_with_user_key("master") is True
    m2.load_data_from_decrypted_json()
    assert [i["name"] for i in m2.main_data] == ["Google", "GitHub"]
    # 规则可复现：重新加载得到的密码必须与保存前一致
    assert [i["password"] for i in m2.main_data] == [i["password"] for i in m.main_data]


def test_v3_wrong_key_fails():
    m = PasswordManagerModel()
    m.add_or_update_subject("A")
    token = m.encrypt_data("right", m.prepare_export_data())
    m2 = PasswordManagerModel()
    assert m2.detect_and_store(token)[0] is True
    assert m2.decrypt_with_user_key("wrong") is False


def test_encrypt_requires_key():
    m = PasswordManagerModel()
    with pytest.raises(ValueError):
        m.encrypt_data("", {"mainData": [], "historyData": {}})


# --------------------------------------------------------------- 旧格式兼容
def test_v2_file_still_readable():
    """构造旧的 v2 双层加密文件，确认仍能打开。"""
    payload = json.dumps(
        {
            "mainData": [
                {"密码生成主体": "Legacy", "第n次生成的密码": "1", "规则": "12|True|True|True|True|saltABC"}
            ],
            "historyData": {},
        },
        ensure_ascii=False,
    )
    ic, ii, isalt = AESCipher("user-key").encrypt(payload)
    oc, oi, osalt = AESCipher("F_Y").encrypt(f"{ic}|{ii}|{isalt}")
    content = f"v2:{oc}|{oi}|{osalt}"

    m = PasswordManagerModel()
    ok, _msg, version = m.detect_and_store(content)
    assert ok and version == 2
    assert m.decrypt_with_user_key("user-key") is True
    m.load_data_from_decrypted_json()
    assert m.main_data[0]["name"] == "Legacy"
    assert parse_rule(m.main_data[0]["rule"])["algorithm"] == "v1"


def test_v1_saltless_rule_is_upgraded_and_reproducible():
    """5 段无盐旧规则不可复现 → 加载时升级为 v2，并且此后可复现。"""
    payload = json.dumps(
        {
            "mainData": [{"密码生成主体": "Old", "第n次生成的密码": "2", "规则": "12|True|True|True|True"}],
            "historyData": {},
        },
        ensure_ascii=False,
    )
    token = VaultCipher("k").encrypt(payload)

    m = PasswordManagerModel()
    assert m.detect_and_store(token)[0] is True
    assert m.decrypt_with_user_key("k") is True
    upgraded = m.load_data_from_decrypted_json()
    assert upgraded == 1
    assert parse_rule(m.main_data[0]["rule"])["algorithm"] == "v2"
    assert m.is_dirty() is True  # 升级需要落盘

    # 再走一遍往返，密码应稳定
    token2 = m.encrypt_data("k", m.prepare_export_data())
    m2 = PasswordManagerModel()
    m2.detect_and_store(token2)
    m2.decrypt_with_user_key("k")
    m2.load_data_from_decrypted_json()
    assert m2.main_data[0]["password"] == m.main_data[0]["password"]


def test_corrupt_file_detected():
    m = PasswordManagerModel()
    assert m.detect_and_store("v3:not-base64!!!")[0] is False
    assert m.detect_and_store("short")[0] is False


# --------------------------------------------------------------- 备份
def test_create_backup_is_readable(tmp_path):
    m = PasswordManagerModel()
    m.add_or_update_subject("A")
    backup = tmp_path / "b.tmp"
    assert m.create_backup("k", str(backup)) == str(backup)
    m2 = PasswordManagerModel()
    assert m2.detect_and_store(backup.read_text(encoding="utf-8"))[0] is True
    assert m2.decrypt_with_user_key("k") is True
