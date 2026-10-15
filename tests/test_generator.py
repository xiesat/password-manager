"""密码生成器测试（含 v1 兼容性回归）。"""

from __future__ import annotations

import hashlib
import random

import pytest

from password_generator import (
    ALGORITHM_V1,
    ALGORITHM_V2,
    LEGACY_SEED_MODULUS,
    PasswordGenerator,
)

SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def legacy_reference(
    input_text: str, salt: str, length: int, lower=True, upper=True, digit=True, symbol=True
) -> str:
    """旧实现的逐字复刻（使用全局 random.seed），用于验证兼容性。"""
    seed_str = input_text + salt
    hash_seed = int(hashlib.sha256(seed_str.encode()).hexdigest(), 16) % LEGACY_SEED_MODULUS
    random.seed(hash_seed)
    char_types = []
    char_pool = ""
    if lower:
        char_pool += "abcdefghijklmnopqrstuvwxyz"
        char_types.append("abcdefghijklmnopqrstuvwxyz")
    if upper:
        char_pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        char_types.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if digit:
        char_pool += "0123456789"
        char_types.append("0123456789")
    if symbol:
        char_pool += SYMBOLS
        char_types.append(SYMBOLS)
    parts = [random.choice(c) for c in char_types]
    remaining = length - len(parts)
    parts += [random.choice(char_pool) for _ in range(remaining)]
    random.shuffle(parts)
    return "".join(parts)


@pytest.mark.parametrize(
    "name,salt,length",
    [
        ("Google", "AbC123xyz", 12),
        ("GitHub", "Zz9Qq7Ww", 16),
        ("招商银行", "salt值不支持", 8),
        ("AWS 控制台", "", 20),
    ],
)
def test_v1_matches_legacy_reference(name, salt, length):
    gen = PasswordGenerator()
    got = gen.generate_v1(name, length=length, lower=True, upper=True, digit=True, symbol=True, salt=salt)
    assert got == legacy_reference(name, salt, length)


def test_v1_does_not_pollute_global_random():
    random.seed(1234)
    before = [random.random() for _ in range(3)]
    random.seed(1234)
    PasswordGenerator().generate_v1("X", length=12, lower=True, upper=True, digit=True, symbol=True, salt="s")
    after = [random.random() for _ in range(3)]
    assert before == after


def test_v2_is_deterministic_with_salt():
    gen = PasswordGenerator()
    a = gen.generate_v2(
        "Google", length=16, lower=True, upper=True, digit=True, symbol=True, salt="fixed-salt"
    )
    b = gen.generate_v2(
        "Google", length=16, lower=True, upper=True, digit=True, symbol=True, salt="fixed-salt"
    )
    assert a["password"] == b["password"]
    assert a["salt"] == "fixed-salt"


def test_v2_differs_across_salt_and_subject():
    gen = PasswordGenerator()
    a = gen.generate_v2("Google", length=16, lower=True, upper=True, digit=True, symbol=True, salt="s1")[
        "password"
    ]
    b = gen.generate_v2("Google", length=16, lower=True, upper=True, digit=True, symbol=True, salt="s2")[
        "password"
    ]
    c = gen.generate_v2("GitHub", length=16, lower=True, upper=True, digit=True, symbol=True, salt="s1")[
        "password"
    ]
    assert a != b and a != c


def test_v2_length_and_character_classes():
    gen = PasswordGenerator()
    result = gen.generate_v2("Site", length=24, lower=True, upper=True, digit=True, symbol=True)
    pwd = result["password"]
    assert len(pwd) == 24
    assert any(ch.islower() for ch in pwd)
    assert any(ch.isupper() for ch in pwd)
    assert any(ch.isdigit() for ch in pwd)
    assert any(ch in SYMBOLS for ch in pwd)


def test_v2_only_selected_classes():
    gen = PasswordGenerator()
    pwd = gen.generate_v2("Site", length=20, lower=False, upper=False, digit=True, symbol=False)["password"]
    assert pwd.isdigit()


def test_v2_random_salt_is_generated_when_absent():
    gen = PasswordGenerator()
    a = gen.generate_v2("Site", length=12, lower=True, upper=True, digit=True, symbol=True)
    b = gen.generate_v2("Site", length=12, lower=True, upper=True, digit=True, symbol=True)
    assert a["salt"] and len(a["salt"]) == 16
    assert a["salt"] != b["salt"]
    assert a["password"] != b["password"]


def test_build_pool_fallback_and_uuid_like_uniqueness():
    pool, classes = PasswordGenerator.build_pool(False, False, False, False)
    assert pool == "abcdefghijklmnopqrstuvwxyz0123456789"
    assert len(classes) == 2


def test_generate_dispatch():
    gen = PasswordGenerator()
    v1 = gen.generate(
        "S", length=10, lower=True, upper=True, digit=True, symbol=True, salt="k", algorithm=ALGORITHM_V1
    )
    v2 = gen.generate(
        "S", length=10, lower=True, upper=True, digit=True, symbol=True, salt="k", algorithm=ALGORITHM_V2
    )
    assert v1["algorithm"] == ALGORITHM_V1
    assert v2["algorithm"] == ALGORITHM_V2
