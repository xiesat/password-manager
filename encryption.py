"""加密模块。

当前格式 v3：单层 AES-256-GCM（AEAD）+ PBKDF2-HMAC-SHA256，迭代次数写入文件头。
兼容读取：
  v2 —— 内层用户密钥 + 外层硬编码密钥的双层 AES-CBC + HMAC（旧实现）。
  v1 —— sha256(key) 直接作为密钥的 AES-CBC（更早实现）。

相对旧实现的修复：
  * GCM tag 覆盖 magic/version/iterations/salt/nonce/密文，IV 被认证（v2 的 IV 不在 HMAC 覆盖范围内）。
  * KDF 迭代次数随密文保存，将来可平滑升级。
  * 不再使用硬编码外层密钥。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import warnings

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

MAGIC = b"PMGR"
FORMAT_VERSION = 3
DEFAULT_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
_HEADER_SIZE = len(MAGIC) + 1 + 4  # magic + version + iterations


class VaultCipher:
    """v3 密码库加密器（AES-256-GCM）。"""

    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS) -> None:
        if not password:
            raise ValueError("密钥不能为空")
        self._password = password.encode("utf-8")
        self.iterations = iterations

    def _derive(self, salt: bytes, iterations: int) -> bytes:
        return PBKDF2(self._password, salt, dkLen=KEY_SIZE, count=iterations, hmac_hash_module=SHA256)

    def encrypt(self, plaintext: str) -> str:
        """加密并返回 `v3:<base64>` 文本。"""
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        header = MAGIC + bytes([FORMAT_VERSION]) + self.iterations.to_bytes(4, "big")
        cipher = AES.new(self._derive(salt, self.iterations), AES.MODE_GCM, nonce=nonce)
        cipher.update(header + salt)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        blob = header + salt + nonce + tag + ciphertext
        return "v3:" + base64.b64encode(blob).decode("ascii")

    @staticmethod
    def decrypt(password: str, token: str) -> str:
        """解密 v3 文本；密钥错误/内容被篡改都会抛出 ValueError。"""
        raw = token[3:] if token.startswith("v3:") else token
        try:
            blob = base64.b64decode(raw, validate=True)
        except Exception as exc:  # noqa: BLE001 - 统一转换为领域异常
            raise ValueError("文件内容不是合法的 Base64") from exc

        if len(blob) < _HEADER_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise ValueError("文件长度异常")
        if blob[: len(MAGIC)] != MAGIC:
            raise ValueError("文件标识不匹配，可能不是本程序生成")
        if blob[len(MAGIC)] != FORMAT_VERSION:
            raise ValueError(f"不支持的格式版本：{blob[len(MAGIC)]}")

        iterations = int.from_bytes(blob[len(MAGIC) + 1 : _HEADER_SIZE], "big")
        offset = _HEADER_SIZE
        salt = blob[offset : offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        tag = blob[offset : offset + TAG_SIZE]
        offset += TAG_SIZE
        ciphertext = blob[offset:]

        key = PBKDF2(
            password.encode("utf-8"), salt, dkLen=KEY_SIZE, count=iterations, hmac_hash_module=SHA256
        )
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(blob[:_HEADER_SIZE] + salt)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        except ValueError as exc:
            raise ValueError("密钥不正确或文件已损坏") from exc


def detect_format(content: str) -> int:
    """按文件内容判断格式版本：3（最新）/ 2 / 1（旧版）。"""
    if content.startswith("v3:"):
        return 3
    if content.startswith("v2:"):
        return 2
    return 1


def validate_v2_outer(content: str) -> bool:
    """v2 外层结构校验：v2:ct|iv|salt。"""
    return len(content[3:].split("|")) == 3


# ---------------------------------------------------------------------------
# 以下为旧格式兼容实现，仅用于读取历史文件，不再用于写入新文件。
# ---------------------------------------------------------------------------


class AESCipher:
    """[仅兼容读取] v2 的 AES-CBC + HMAC(密文) 实现。"""

    PBKDF2_ITERATIONS = 100_000
    HMAC_KEY_SIZE = 32
    SALT_SIZE = 16

    def __init__(self, password: str) -> None:
        warnings.warn("AESCipher 仅用于读取 v2 旧文件", DeprecationWarning, stacklevel=2)
        self.password = password.encode("utf-8")
        self.salt = os.urandom(self.SALT_SIZE)
        derived = PBKDF2(
            self.password,
            self.salt,
            dkLen=64,
            count=self.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256,
        )
        self.aes_key = derived[:32]
        self.hmac_key = derived[32:64]

    def encrypt(self, plaintext: str) -> tuple[str, str, str]:
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        iv = cipher.iv
        padded = pad(plaintext.encode("utf-8"), AES.block_size)
        ciphertext = cipher.encrypt(padded)
        mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()
        combined = ciphertext + mac
        return (
            base64.b64encode(combined).decode("utf-8"),
            base64.b64encode(iv).decode("utf-8"),
            base64.b64encode(self.salt).decode("utf-8"),
        )

    @classmethod
    def decrypt_with_params(cls, password: str, ciphertext_b64: str, iv_b64: str, salt_b64: str) -> str:
        salt = base64.b64decode(salt_b64)
        derived = PBKDF2(
            password.encode("utf-8"),
            salt,
            dkLen=64,
            count=cls.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256,
        )
        aes_key = derived[:32]
        hmac_key = derived[32:64]
        combined = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        if len(combined) < 32:
            raise ValueError("Invalid ciphertext length")
        ciphertext = combined[:-32]
        received_mac = combined[-32:]
        expected_mac = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_mac, expected_mac):
            raise ValueError("HMAC verification failed")
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES.block_size)
        return plaintext.decode("utf-8")


class LegacyAESCipher:
    """[仅兼容读取] v1：sha256(key) 直接作为 AES-CBC 密钥（无盐、无迭代）。"""

    def __init__(self, key: str) -> None:
        warnings.warn("LegacyAESCipher 仅用于读取 v1 旧文件", DeprecationWarning, stacklevel=2)
        self.key = hashlib.sha256(key.encode("utf-8")).digest()

    def encrypt(self, plain_text: str) -> tuple[str, str]:
        iv = AES.new(self.key, AES.MODE_CBC).iv
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plain_text.encode("utf-8"), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode("utf-8"), base64.b64encode(iv).decode("utf-8")

    def decrypt(self, encrypted_base64: str, iv_base64: str) -> str:
        encrypted = base64.b64decode(encrypted_base64)
        iv = base64.b64decode(iv_base64)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted)
        return unpad(decrypted_padded, AES.block_size).decode("utf-8")
