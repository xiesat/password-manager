"""密码生成模块。

- v2（当前，algorithm="v2"）：PBKDF2-HMAC-SHA256 派生密钥流 + 拒绝采样，
  使用 256bit 种子（不再 `% 10**18` 截断）；盐由 secrets 生成。
- v1（仅兼容复现）：以 `sha256(主体 + 盐) % 10**18` 作为 Mersenne Twister 种子。
  旧规则必须继续用它复现，否则用户已有密码会变化。

规则字符串格式：
  v1 无盐：`<len>|<lower>|<upper>|<digit>|<symbol>`
  v1 有盐：`<len>|<lower>|<upper>|<digit>|<symbol>|<salt>`
  v2     ：`<len>|<lower>|<upper>|<digit>|<symbol>|<salt>|v2`
"""

from __future__ import annotations

import hashlib
import random
import secrets
import string

ALGORITHM_V1 = "v1"
ALGORITHM_V2 = "v2"
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
LEGACY_SEED_MODULUS = 10**18
STREAM_ITERATIONS = 200_000
DEFAULT_SALT_LENGTH = 16


class _KeyStream:
    """由 (主体, 盐) 派生的确定性字节流，用于 v2 生成。"""

    def __init__(self, secret: str, salt: str) -> None:
        self._secret = secret.encode("utf-8")
        self._salt = salt.encode("utf-8")
        self._block = 0
        self._buffer = bytearray()

    def _fill(self) -> None:
        block = hashlib.pbkdf2_hmac(
            "sha256",
            self._secret,
            self._salt + b"|" + str(self._block).encode("ascii"),
            STREAM_ITERATIONS,
            32,
        )
        self._buffer += block
        self._block += 1

    def take(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._fill()
        out = bytes(self._buffer[:count])
        del self._buffer[:count]
        return out

    def pick(self, pool: str) -> str:
        """从字符池中均匀取一个字符（拒绝采样，消除模偏差）。"""
        size = len(pool)
        limit = 256 - (256 % size)
        while True:
            byte = self.take(1)[0]
            if byte < limit:
                return pool[byte % size]

    def rand_below(self, n: int) -> int:
        if n <= 1:
            return 0
        nbytes = (n.bit_length() + 7) // 8
        space = 256**nbytes
        limit = space - (space % n)
        while True:
            value = int.from_bytes(self.take(nbytes), "big")
            if value < limit:
                return value % n

    def shuffle(self, items: list) -> None:
        for i in range(len(items) - 1, 0, -1):
            j = self.rand_below(i + 1)
            items[i], items[j] = items[j], items[i]


def estimate_strength(password: str) -> int:
    """粗略强度评估，返回 0（空）或 1-5。"""
    length = len(password)
    if length == 0:
        return 0
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if length < 8:
        score = 1
    elif length < 12:
        score = min(3, classes)
    else:
        score = min(5, 1 + classes + (1 if length >= 16 else 0))
    return max(1, min(5, score))


class PasswordGenerator:
    """确定性密码生成器。"""

    lower_letters = string.ascii_lowercase
    upper_letters = string.ascii_uppercase
    digits = string.digits
    symbols = SYMBOLS

    @classmethod
    def build_pool(cls, lower: bool, upper: bool, digit: bool, symbol: bool) -> tuple[str, list[str]]:
        """构建字符池与类别列表；全不选时回退为小写 + 数字。"""
        pool = ""
        classes: list[str] = []
        if lower:
            pool += cls.lower_letters
            classes.append(cls.lower_letters)
        if upper:
            pool += cls.upper_letters
            classes.append(cls.upper_letters)
        if digit:
            pool += cls.digits
            classes.append(cls.digits)
        if symbol:
            pool += cls.symbols
            classes.append(cls.symbols)
        if not pool:
            pool = cls.lower_letters + cls.digits
            classes = [cls.lower_letters, cls.digits]
        return pool, classes

    @staticmethod
    def random_salt(length: int = DEFAULT_SALT_LENGTH) -> str:
        """使用 secrets 生成随机盐。"""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    # ------------------------------------------------------------------ v2
    def generate_v2(
        self,
        input_text: str,
        *,
        length: int,
        lower: bool,
        upper: bool,
        digit: bool,
        symbol: bool,
        salt: str | None = None,
    ) -> dict:
        """生成 v2 密码；salt 为空时新建随机盐（可复现需带盐）。"""
        salt = salt or self.random_salt()
        pool, classes = self.build_pool(lower, upper, digit, symbol)
        stream = _KeyStream(input_text, salt)
        parts = [stream.pick(charset) for charset in classes]
        while len(parts) < length:
            parts.append(stream.pick(pool))
        stream.shuffle(parts)
        return {"password": "".join(parts), "salt": salt, "algorithm": ALGORITHM_V2}

    # ------------------------------------------------------------------ v1
    def generate_v1(
        self,
        input_text: str,
        *,
        length: int,
        lower: bool,
        upper: bool,
        digit: bool,
        symbol: bool,
        salt: str = "",
    ) -> str:
        """复现旧算法生成的密码（使用局部 Random 实例，避免污染全局 PRNG）。"""
        seed = int(hashlib.sha256((input_text + salt).encode()).hexdigest(), 16) % LEGACY_SEED_MODULUS
        rng = random.Random(seed)
        pool, classes = self.build_pool(lower, upper, digit, symbol)
        parts = [rng.choice(charset) for charset in classes]
        remaining = length - len(parts)
        if remaining > 0:
            parts += [rng.choice(pool) for _ in range(remaining)]
        rng.shuffle(parts)
        return "".join(parts)

    # --------------------------------------------------------------- 统一入口
    def generate(
        self,
        input_text: str,
        *,
        length: int,
        lower: bool,
        upper: bool,
        digit: bool,
        symbol: bool,
        salt: str | None = None,
        algorithm: str = ALGORITHM_V2,
    ) -> dict:
        if algorithm == ALGORITHM_V1:
            password = self.generate_v1(
                input_text,
                length=length,
                lower=lower,
                upper=upper,
                digit=digit,
                symbol=symbol,
                salt=salt or "",
            )
            return {"password": password, "salt": salt or "", "algorithm": ALGORITHM_V1}
        return self.generate_v2(
            input_text,
            length=length,
            lower=lower,
            upper=upper,
            digit=digit,
            symbol=symbol,
            salt=salt,
        )
