"""黄金测试向量：锁定哈希算法与合并行为，供 Android 端对齐。"""

from __future__ import annotations

import json
import pathlib

import pytest

import merge

VECTORS_PATH = pathlib.Path(__file__).resolve().parents[1] / "spec" / "merge_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
CASE_IDS = [case["name"] for case in VECTORS["cases"]]


def test_vectors_file_is_wellformed():
    assert VECTORS["spec"] == "password-manager/merge"
    assert VECTORS["hash_vectors"] and VECTORS["cases"]


def test_conflict_namespace_is_locked():
    assert str(merge.CONFLICT_NAMESPACE) == VECTORS["hash_namespace"]


def test_hash_vectors_lock_canonicalization_and_hash():
    for vector in VECTORS["hash_vectors"]:
        record = vector["record"]
        assert merge.semantic_payload(record) == vector["payload"]
        assert merge.canonical_json(vector["payload"]) == vector["canonical"]
        assert merge.semantic_hash(record) == vector["semantic_hash"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=CASE_IDS)
def test_merge_case_matches_expected(case):
    result = merge.merge_records(case["base"], case["local"], case["remote"], case["vault_id"])
    expected = case["expected"]

    assert sorted(r["id"] for r in result.records) == expected["record_ids"]
    assert (
        sorted(r["password"] for r in result.records if not r.get("deleted")) == expected["alive_passwords"]
    )
    assert sorted(r["id"] for r in result.records if r.get("deleted")) == expected["deleted_ids"]
    assert [c.kind for c in result.conflicts] == expected["conflict_kinds"]
    assert [c.copy_id for c in result.conflicts] == expected["conflict_copy_ids"]
    assert result.base == expected["base"]
    assert result.content_hash == expected["content_hash"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=CASE_IDS)
def test_merge_case_is_commutative(case):
    ab = merge.merge_records(case["base"], case["local"], case["remote"], case["vault_id"])
    ba = merge.merge_records(case["base"], case["remote"], case["local"], case["vault_id"])
    assert ab.content_hash == ba.content_hash
