"""三方合并引擎测试 —— 覆盖"两端离线同时修改"的全部判定分支。"""

from __future__ import annotations

from merge import (
    content_hash,
    merge_history,
    merge_records,
    semantic_hash,
)

VAULT = "vault-0001"


def rec(rid, name, password, *, rule="r", hlc="0000000000001-0000-dev00001", deleted=False):
    return {
        "id": rid,
        "name": name,
        "password": password,
        "rule": rule,
        "count": "0",
        "updated_at": "",
        "hlc": hlc,
        "deleted": deleted,
    }


def hm(rid, name, password="") -> dict:
    return {rid: semantic_hash(rec(rid, name, password))}


# ------------------------------------------------------------- 语义哈希
def test_semantic_hash_ignores_volatile_fields():
    a = rec("1", "Google", "pw", hlc="0000000000001-0000-dev00001")
    b = {**a, "count": "9", "updated_at": "2026-01-01", "hlc": "0000000009999-0003-zzz99999"}
    assert semantic_hash(a) == semantic_hash(b)


def test_tombstone_hash_ignores_name():
    a = rec("1", "Google", "", deleted=True)
    b = rec("1", "GitHub", "", deleted=True)
    assert semantic_hash(a) == semantic_hash(b)


# ------------------------------------------------------------- 非冲突
def test_disjoint_edits_are_both_kept():
    base = {**hm("1", "A", "p1"), **hm("2", "B", "p2")}
    local = [rec("1", "A", "p1-new")]
    remote = [rec("2", "B", "p2-new")]
    result = merge_records(base, local, remote, VAULT)
    got = {r["id"]: r["password"] for r in result.records}
    assert got == {"1": "p1-new", "2": "p2-new"}
    assert result.conflicts == []


def test_only_one_side_changed_takes_changed_side():
    base = hm("1", "A", "old")
    local = [rec("1", "A", "local-new")]
    remote = [rec("1", "A", "old")]
    assert merge_records(base, local, remote, VAULT).records[0]["password"] == "local-new"
    assert merge_records(base, remote, local, VAULT).records[0]["password"] == "local-new"


def test_identical_change_on_both_sides_collapses():
    base = hm("1", "A", "old")
    local = [rec("1", "A", "same-new")]
    remote = [rec("1", "A", "same-new")]
    result = merge_records(base, local, remote, VAULT)
    assert len(result.records) == 1 and result.conflicts == []


# ------------------------------------------------------------- 冲突
def test_both_modified_keeps_both_versions():
    base = hm("1", "Google", "old")
    local = [rec("1", "Google", "desktop-pw", hlc="0000000000010-0000-desk0001")]
    remote = [rec("1", "Google", "android-pw", hlc="0000000000020-0000-andr0002")]
    result = merge_records(base, local, remote, VAULT)

    assert len(result.records) == 2
    passwords = sorted(r["password"] for r in result.records)
    assert passwords == ["android-pw", "desktop-pw"]  # 两端修改都没丢
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.kind == "both_modified" and conflict.copy_id

    # HLC 较大者（android, ...020）保留原 id；落败版本成为确定性副本
    winner = next(r for r in result.records if r["id"] == "1")
    copy = next(r for r in result.records if r["id"] == conflict.copy_id)
    assert winner["password"] == "android-pw"
    assert copy["password"] == "desktop-pw"
    assert "冲突副本" in copy["name"] and copy["hlc"].endswith("desk0001")
    assert copy["conflict_of"] == "1"


def test_conflict_copy_id_is_deterministic_across_both_devices():
    base = hm("1", "Google", "old")
    local = [rec("1", "Google", "desktop-pw", hlc="0000000000010-0000-desk0001")]
    remote = [rec("1", "Google", "android-pw", hlc="0000000000020-0000-andr0002")]

    ab = merge_records(base, local, remote, VAULT)
    ba = merge_records(base, remote, local, VAULT)
    assert ab.content_hash == ba.content_hash  # 收敛
    assert ab.conflicts[0].copy_id == ba.conflicts[0].copy_id


def test_merge_is_commutative_on_content_hash():
    base = {**hm("1", "A", "a0"), **hm("2", "B", "b0")}
    local = [rec("1", "A", "a1", hlc="0000000000010-0000-desk0001"), rec("2", "B", "b1")]
    remote = [rec("1", "A", "a2", hlc="0000000000011-0000-andr0002"), rec("3", "C", "c1")]
    ab = merge_records(base, local, remote, VAULT)
    ba = merge_records(base, remote, local, VAULT)
    assert ab.content_hash == ba.content_hash


# ------------------------------------------------------------- 删除
def test_delete_one_side_propagates_tombstone():
    base = hm("1", "A", "pw")
    local = [rec("1", "A", "", deleted=True, hlc="0000000000010-0000-desk0001")]
    remote = [rec("1", "A", "pw", hlc="0000000000001-0000-dev00001")]
    result = merge_records(base, local, remote, VAULT)
    assert len(result.records) == 1 and result.records[0]["deleted"] is True


def test_delete_vs_edit_resurrects_the_edited_version():
    base = hm("1", "A", "pw")
    local = [rec("1", "A", "", deleted=True, hlc="0000000000099-0000-desk0001")]
    remote = [rec("1", "A", "edited-pw", hlc="0000000000010-0000-andr0002")]
    result = merge_records(base, local, remote, VAULT)
    alive = [r for r in result.records if not r.get("deleted")]
    assert len(alive) == 1 and alive[0]["password"] == "edited-pw"  # 不丢密码
    assert result.conflicts[0].kind == "delete_vs_edit"
    # 反向也应得到同样的结果（活着的版本获胜，与参数顺序无关）


def test_delete_vs_edit_is_symmetric():
    base = hm("1", "A", "pw")
    dead = [rec("1", "A", "", deleted=True, hlc="0000000000099-0000-desk0001")]
    alive = [rec("1", "A", "edited-pw", hlc="0000000000010-0000-andr0002")]
    assert (
        merge_records(base, dead, alive, VAULT).content_hash
        == merge_records(base, alive, dead, VAULT).content_hash
    )


def test_both_deleted_keeps_single_tombstone():
    base = hm("1", "A", "pw")
    dead_l = [rec("1", "A", "", deleted=True, hlc="0000000000010-0000-desk0001")]
    dead_r = [rec("1", "A", "", deleted=True, hlc="0000000000020-0000-andr0002")]
    result = merge_records(base, dead_l, dead_r, VAULT)
    assert len(result.records) == 1 and result.records[0]["deleted"] is True


# ------------------------------------------------------------- 新增 / base 缺失
def test_new_records_created_independently_are_both_kept():
    result = merge_records({}, [rec("1", "A", "pa")], [rec("2", "B", "pb")], VAULT)
    assert {r["id"] for r in result.records} == {"1", "2"}
    assert result.conflicts == []


def test_missing_base_never_loses_data():
    """换机/从旧备份恢复导致 base 丢失时，退化为并集 + 冲突，绝不丢数据。"""
    local = [rec("1", "A", "pa", hlc="0000000000010-0000-desk0001")]
    remote = [rec("1", "A", "pb", hlc="0000000000020-0000-andr0002")]
    result = merge_records(None, local, remote, VAULT)
    assert sorted(r["password"] for r in result.records) == ["pa", "pb"]
    assert len(result.conflicts) == 1


def test_base_is_updated_for_all_result_records():
    base = hm("1", "A", "old")
    local = [rec("1", "A", "new", hlc="0000000000010-0000-desk0001")]
    remote = [rec("1", "A", "other", hlc="0000000000020-0000-andr0002")]
    result = merge_records(base, local, remote, VAULT)
    assert set(result.base) == {r["id"] for r in result.records}
    # 用新 base 再合并一次应无变化
    again = merge_records(result.base, result.records, result.records, VAULT)
    assert again.content_hash == result.content_hash
    assert again.conflicts == []


# ------------------------------------------------------------- 历史
def test_merge_history_is_union_without_loss():
    local = {"A": [["1", "r1", "2026-01-01 00:00:00"]]}
    remote = {"A": [["2", "r2", "2026-02-01 00:00:00"]], "B": [["1", "r3", "2026-03-01 00:00:00"]]}
    merged = merge_history(local, remote)
    assert [e[0] for e in merged["A"]] == ["2", "1"]  # 按时间倒序
    assert merged["B"] == [["1", "r3", "2026-03-01 00:00:00"]]


def test_content_hash_is_order_independent():
    a = [rec("1", "A", "p"), rec("2", "B", "q")]
    assert content_hash(a) == content_hash(list(reversed(a)))
