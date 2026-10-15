"""加解密测试：v3 往返、篡改检测、格式识别、v2/v1 兼容。"""

from __future__ import annotations

import base64
import json

import pytest

from encryption import (
    DEFAULT_ITERATIONS,
    FORMAT_VERSION,
    AESCipher,
    LegacyAESCipher,
    VaultCipher,
    detect_format,
)

PAYLOAD = json.dumps({"mainData": [{"密码生成主体": "Google"}], "historyData": {}}, ensure_ascii=False)


def test_v3_roundtrip_unicode():
    token = VaultCipher("my-master-key").encrypt(PAYLOAD)
    assert token.startswith("v3:")
    assert VaultCipher.decrypt("my-master-key", token) == PAYLOAD


def test_v3_wrong_password_rejected():
    token = VaultCipher("right").encrypt(PAYLOAD)
    with pytest.raises(ValueError):
        VaultCipher.decrypt("wrong", token)


def test_v3_tamper_is_detected():
    token = VaultCipher("k").encrypt(PAYLOAD)
    blob = bytearray(base64.b64decode(token[3:]))
    blob[-1] ^= 0x01  # 翻转密文最后一位
    tampered = "v3:" + base64.b64encode(bytes(blob)).decode("ascii")
    with pytest.raises(ValueError):
        VaultCipher.decrypt("k", tampered)


def test_v3_nonce_tamper_is_detected():
    """v2 的缺陷：IV 不在 MAC 覆盖内。v3 必须覆盖 nonce。"""
    token = VaultCipher("k").encrypt(PAYLOAD)
    blob = bytearray(base64.b64decode(token[3:]))
    nonce_offset = 9 + 16
    blob[nonce_offset] ^= 0x01
    tampered = "v3:" + base64.b64encode(bytes(blob)).decode("ascii")
    with pytest.raises(ValueError):
        VaultCipher.decrypt("k", tampered)


def test_v3_header_carries_iterations():
    token = VaultCipher("k", iterations=1234).encrypt(PAYLOAD)
    blob = base64.b64decode(token[3:])
    assert blob[4] == FORMAT_VERSION
    assert int.from_bytes(blob[5:9], "big") == 1234
    assert VaultCipher.decrypt("k", token) == PAYLOAD


def test_v3_default_iterations_meets_owasp_baseline():
    assert DEFAULT_ITERATIONS >= 600_000


@pytest.mark.parametrize("prefix,expected", [("v3:abc", 3), ("v2:a|b|c", 2), ("anything", 1)])
def test_detect_format(prefix, expected):
    assert detect_format(prefix) == expected


def test_v2_legacy_roundtrip():
    """模拟旧的双层加密，确认仍可读。"""
    outer_key = "F_Y"
    inner = AESCipher("user-key")
    inner_b64, inner_iv, inner_salt = inner.encrypt(PAYLOAD)
    inner_result = f"{inner_b64}|{inner_iv}|{inner_salt}"
    outer = AESCipher(outer_key)
    outer_b64, outer_iv, outer_salt = outer.encrypt(inner_result)
    content = f"v2:{outer_b64}|{outer_iv}|{outer_salt}"

    assert detect_format(content) == 2
    payload = content[3:]
    o_ct, o_iv, o_salt = payload.split("|")
    mid = AESCipher.decrypt_with_params(outer_key, o_ct, o_iv, o_salt)
    i_ct, i_iv, i_salt = mid.split("|")
    assert AESCipher.decrypt_with_params("user-key", i_ct, i_iv, i_salt) == PAYLOAD


def test_v1_legacy_roundtrip():
    cipher = LegacyAESCipher("secret")
    data = PAYLOAD + "DATA_CHECK"
    ct, iv = cipher.encrypt(data)
    content = ct + iv
    assert detect_format(content) == 1
    decrypted = LegacyAESCipher("secret").decrypt(content[:-24], content[-24:])
    assert decrypted == data
