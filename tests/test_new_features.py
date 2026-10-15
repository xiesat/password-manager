"""新增能力测试：显式密码存储、批量删除、强度评估、导出行。"""

from __future__ import annotations

import json

from encryption import VaultCipher
from model import PasswordManagerModel, parse_rule
from password_generator import estimate_strength


def _roundtrip(model: PasswordManagerModel, key: str = "k") -> PasswordManagerModel:
    token = model.encrypt_data(key, model.prepare_export_data())
    other = PasswordManagerModel()
    assert other.detect_and_store(token)[0] is True
    assert other.decrypt_with_user_key(key) is True
    other.load_data_from_decrypted_json()
    return other


def test_export_contains_plaintext_inside_encrypted_vault():
    m = PasswordManagerModel()
    m.add_or_update_subject("Google", length=16)
    data = m.prepare_export_data()
    assert data["mainData"][0]["password"] == m.main_data[0]["password"]
    token = m.encrypt_data("k", data)
    assert m.main_data[0]["password"] not in token  # 密文里不应出现明文


def test_stored_password_survives_roundtrip_and_algorithm_change():
    """密码改为显式存储后，不再依赖生成算法可复现。"""
    m = PasswordManagerModel()
    m.add_or_update_subject("Site", length=20)
    original = m.main_data[0]["password"]

    other = _roundtrip(m)
    assert other.main_data[0]["password"] == original
    assert other.is_dirty() is False


def test_import_explicit_password():
    m = PasswordManagerModel()
    item = m.add_or_update_subject("Imported", password="Manual$ecret123")
    assert item["password"] == "Manual$ecret123"
    assert parse_rule(item["rule"])["algorithm"] == "v2"

    other = _roundtrip(m)
    assert other.main_data[0]["password"] == "Manual$ecret123"


def test_updated_at_is_set_and_persisted():
    m = PasswordManagerModel()
    item = m.add_or_update_subject("A")
    assert item["updated_at"]

    before = item["updated_at"]
    m.generate_new_password_for_subject(0)
    assert m.main_data[0]["updated_at"] >= before

    other = _roundtrip(m)
    assert other.main_data[0]["updated_at"] == m.main_data[0]["updated_at"]


def test_delete_subjects_batch():
    m = PasswordManagerModel()
    for name in ("A", "B", "C", "D"):
        m.add_or_update_subject(name)
    removed = m.delete_subjects([0, 2, 99])
    assert removed == ["A", "C"]
    assert [i["name"] for i in m.main_data] == ["B", "D"]


def test_export_rows_shape():
    m = PasswordManagerModel()
    m.add_or_update_subject("A", length=12)
    rows = m.export_rows()
    assert set(rows[0]) == {"name", "password", "count", "updated_at", "rule"}


def test_rule_missing_is_repaired_on_load():
    payload = json.dumps(
        {"mainData": [{"密码生成主体": "Legacy", "第n次生成的密码": "0", "规则": ""}], "historyData": {}},
        ensure_ascii=False,
    )
    m = PasswordManagerModel()
    m.detect_and_store(VaultCipher("k").encrypt(payload))
    assert m.decrypt_with_user_key("k") is True
    upgraded = m.load_data_from_decrypted_json()
    assert upgraded == 1
    assert parse_rule(m.main_data[0]["rule"]) is not None
    assert m.main_data[0]["password"]  # 已补出一个可用密码
    assert m.is_dirty() is True


def test_estimate_strength():
    assert estimate_strength("") == 0
    assert estimate_strength("abc") == 1
    assert estimate_strength("Ab3$kQ9m") == 3
    assert estimate_strength("Ab3$kQ9mPz!2Xy7Q") == 5
