"""双端离线修改 → 重连合并 的模拟测试（桌面端即可完整验证）。"""

from __future__ import annotations

import merge
from hlc import HLC
from model import PasswordManagerModel


def make_pair() -> tuple[PasswordManagerModel, PasswordManagerModel]:
    """构造两台"已同步过一次"的设备：同一份库、相同的 base。"""
    a = PasswordManagerModel()
    a.add_or_update_subject("Base", length=12)

    payload = a.prepare_export_data()
    b = PasswordManagerModel()
    assert b.detect_and_store(a.encrypt_data("k", payload))[0] is True
    assert b.decrypt_with_user_key("k") is True
    b.load_data_from_decrypted_json()

    snapshot = {r["id"]: merge.semantic_hash(r) for r in a.all_records()}
    a.sync_base = dict(snapshot)
    b.sync_base = dict(snapshot)

    # 真实世界里两台设备有不同的 device_id
    a.device_id, a.hlc = "aaaa0001", HLC("aaaa0001")
    b.device_id, b.hlc = "bbbb0002", HLC("bbbb0002")
    return a, b


def sync(a: PasswordManagerModel, b: PasswordManagerModel):
    """模拟一次局域网同步：先交换"合并前"的载荷，再各自合并。"""
    payload_a = a.prepare_export_data()
    payload_b = b.prepare_export_data()
    conflicts_a = a.merge_remote(payload_b)
    conflicts_b = b.merge_remote(payload_a)
    return conflicts_a, conflicts_b


def edit(a: PasswordManagerModel, index: int, password: str) -> None:
    a.main_data[index]["password"] = password
    a.main_data[index]["hlc"] = a.hlc.next()
    a._mark_dirty()


def names(model: PasswordManagerModel) -> set[str]:
    return {r["name"] for r in model.main_data}


# =====================================================================
def test_offline_disjoint_edits_both_survive():
    a, b = make_pair()
    a.add_or_update_subject("Desktop-Only")
    b.add_or_update_subject("Android-Only")

    conflicts_a, conflicts_b = sync(a, b)

    assert conflicts_a == [] and conflicts_b == []
    assert names(a) == names(b) == {"Base", "Desktop-Only", "Android-Only"}
    assert a.content_hash() == b.content_hash()


def test_offline_conflicting_edit_keeps_both_and_converges():
    a, b = make_pair()
    edit(a, 0, "desktop-pw")
    edit(b, 0, "android-pw")

    conflicts_a, conflicts_b = sync(a, b)

    # 两端各自的修改都没丢
    passwords = sorted(r["password"] for r in a.main_data)
    assert passwords == ["android-pw", "desktop-pw"]
    assert sorted(r["password"] for r in b.main_data) == passwords
    # 收敛：两端内容完全一致
    assert a.content_hash() == b.content_hash()
    # 冲突被记录，且两端指向同一个冲突副本
    assert len(conflicts_a) == 1 and len(conflicts_b) == 1
    assert conflicts_a[0].kind == "both_modified"
    assert conflicts_a[0].copy_id == conflicts_b[0].copy_id
    assert any("冲突副本" in r["name"] for r in a.main_data)


def test_sync_again_is_noop_after_convergence():
    a, b = make_pair()
    edit(a, 0, "desktop-pw")
    edit(b, 0, "android-pw")
    sync(a, b)
    before = a.content_hash()

    conflicts_a, conflicts_b = sync(a, b)

    assert conflicts_a == [] and conflicts_b == []
    assert a.content_hash() == b.content_hash() == before


def test_offline_delete_propagates():
    a, b = make_pair()
    a.delete_subject(0)

    sync(a, b)

    assert a.main_data == [] and b.main_data == []
    assert len(a.tombstones) == 1 and len(b.tombstones) == 1
    assert a.content_hash() == b.content_hash()


def test_offline_delete_vs_edit_resurrects_and_reports():
    a, b = make_pair()
    a.delete_subject(0)
    edit(b, 0, "edited-pw")

    conflicts_a, conflicts_b = sync(a, b)

    # 不丢密码：编辑版本存活
    assert [r["password"] for r in a.main_data] == ["edited-pw"]
    assert [r["password"] for r in b.main_data] == ["edited-pw"]
    assert a.content_hash() == b.content_hash()
    assert len(conflicts_a) == 1 and conflicts_a[0].kind == "delete_vs_edit"


def test_offline_rename_conflict_keeps_both():
    a, b = make_pair()
    a.main_data[0]["name"] = "Desktop-Name"
    a.main_data[0]["hlc"] = a.hlc.next()
    b.main_data[0]["name"] = "Android-Name"
    b.main_data[0]["hlc"] = b.hlc.next()

    sync(a, b)

    assert len(a.main_data) == 2 and len(b.main_data) == 2
    assert a.content_hash() == b.content_hash()


def test_history_is_merged_without_loss():
    a, b = make_pair()
    a.generate_new_password_for_subject(0)  # A 产生一条历史
    b.generate_new_password_for_subject(0)  # B 也产生一条

    sync(a, b)

    history_a = a.history_data.get("Base", [])
    history_b = b.history_data.get("Base", [])
    assert len(history_a) >= 2 and len(history_b) >= 2
    assert merge.merge_history(a.history_data, b.history_data) == a.history_data


def test_three_rounds_stay_converged():
    a, b = make_pair()
    for round_index in range(3):
        a.add_or_update_subject(f"A-{round_index}")
        b.add_or_update_subject(f"B-{round_index}")
        edit(a, 0, f"a-pw-{round_index}")
        edit(b, 0, f"b-pw-{round_index}")
        sync(a, b)
        assert a.content_hash() == b.content_hash()

    # 每轮：双方各自新增一条 + 对 Base 的冲突产生一个副本 → 1 + 3 + 3 + 3
    assert names(a) == names(b)
    assert len(a.main_data) == 10


def test_merge_stays_commutative_even_if_device_ids_collide():
    """极端情况：两台设备 device_id 相同 → HLC 可能完全相同，仍须收敛。"""
    a, b = make_pair()
    a.device_id = b.device_id = "same0001"
    a.hlc, b.hlc = HLC("same0001"), HLC("same0001")
    edit(a, 0, "desktop-pw")
    edit(b, 0, "android-pw")

    conflicts_a, conflicts_b = sync(a, b)

    assert a.content_hash() == b.content_hash()
    assert conflicts_a[0].copy_id == conflicts_b[0].copy_id
    assert sorted(r["password"] for r in a.main_data) == ["android-pw", "desktop-pw"]


def test_merge_remote_observes_remote_clock():
    a, b = make_pair()
    edit(b, 0, "android-pw")
    a.merge_remote(b.prepare_export_data())
    # 观察远端时钟后，本机新产生的时间戳必须大于远端记录的时间戳
    newest_local = a.hlc.next()
    assert newest_local > b.main_data[0]["hlc"]
