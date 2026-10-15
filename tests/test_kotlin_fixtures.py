"""Kotlin/Android 端生成的夹具：确认桌面端能打开手机保存的库。

重点验证「会话内复用盐保存」这条新路径 ——
盐复用是安全的，但每次保存必须换新 nonce（GCM 下 nonce 复用会致命）。
"""

from __future__ import annotations

import base64
import json
import pathlib

from model import PasswordManagerModel

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "spec" / "fixtures"

KEY = (FIXTURES / "reused_key.key").read_text(encoding="utf-8").strip()
BLOB = (FIXTURES / "reused_key.sk").read_text(encoding="utf-8").strip()
FIRST = (FIXTURES / "reused_key.first.sk").read_text(encoding="utf-8").strip()
EXPECTED = (FIXTURES / "reused_key.expected.json").read_text(encoding="utf-8")


def header(token: str) -> dict:
    blob = base64.b64decode(token[3:])
    assert blob[:4] == b"PMGR"
    assert blob[4] == 3
    return {
        "iterations": int.from_bytes(blob[5:9], "big"),
        "salt": blob[9:25],
        "nonce": blob[25:37],
        "tag": blob[37:53],
        "ciphertext": blob[53:],
    }


def test_kotlin_saved_vault_opens_on_desktop():
    model = PasswordManagerModel()
    ok, message, _version = model.detect_and_store(BLOB)
    assert ok, message
    assert model.decrypt_with_user_key(KEY) is True
    model.load_data_from_decrypted_json()

    assert [record["name"] for record in model.main_data] == ["手机保存🔐"]
    assert model.main_data[0]["password"] == "P@ss-手机-!@#"


def test_kotlin_payload_matches_expected():
    model = PasswordManagerModel()
    model.detect_and_store(BLOB)
    assert model.decrypt_with_user_key(KEY) is True
    assert json.loads(model.raw_decrypted_data) == json.loads(EXPECTED)


def test_reused_salt_keeps_nonce_unique():
    first, second = header(FIRST), header(BLOB)
    assert first["salt"] == second["salt"], "同一会话内保存应复用同一个盐"
    assert first["nonce"] != second["nonce"], "GCM 下每次保存必须换新 nonce"
    assert first["iterations"] == 200_000
    assert len(first["salt"]) == 16 and len(first["nonce"]) == 12


def test_both_kotlin_saves_decrypt_to_same_payload():
    plains = []
    for token in (FIRST, BLOB):
        model = PasswordManagerModel()
        assert model.detect_and_store(token)[0] is True
        assert model.decrypt_with_user_key(KEY) is True
        model.load_data_from_decrypted_json()
        plains.append([record["name"] for record in model.main_data])
    assert plains[0] == plains[1] == ["手机保存🔐"]
