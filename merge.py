"""三方合并（3-way merge）—— 两端离线各自修改后的合并引擎。

设计目标：**任何一端的编辑都不会被静默丢弃**。

- 记录以稳定 UUID 为身份（不是名字）；
- 删除保留"墓碑"记录，而不是直接移除；
- base 只保存上一次同步时的"语义哈希"，体积很小；
- 冲突时两个版本都保留，副本 UUID 由 uuid5 确定性派生，
  因此两端各自计算会得到完全相同的合并结果（收敛）。

合并判定（b=base 哈希，l/r=两端语义哈希）：
    l == r          两边一致            → 取其一
    l == b          只有远端改过        → 取远端
    r == b          只有本地改过        → 取本地
    其他            双方都改且不同      → 冲突
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field

CONFLICT_SUFFIX = "（冲突副本 {origin}）"
_HASH_LEN = 32
# 固定的 uuid5 命名空间，保证任意两端派生出相同的冲突副本 ID
CONFLICT_NAMESPACE = uuid.UUID("6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4051")


def canonical_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def semantic_payload(record: dict) -> dict:
    """提取参与"内容是否算变过"判断的字段（忽略 count / updated_at / hlc）。"""
    if record.get("deleted"):
        return {"deleted": True}
    return {
        "name": record.get("name", ""),
        "password": record.get("password", ""),
        "rule": record.get("rule", ""),
    }


def semantic_hash(record: dict) -> str:
    """记录内容的语义哈希（32 位 hex）。"""
    return hashlib.sha256(canonical_json(semantic_payload(record)).encode("utf-8")).hexdigest()[:_HASH_LEN]


def content_hash(records: list[dict]) -> str:
    """与列表顺序无关的内容指纹，用于验证两端是否收敛。"""
    digests = sorted(f"{r.get('id', '')}:{semantic_hash(r)}" for r in records)
    return hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()


@dataclass
class Conflict:
    record_id: str
    kind: str  # both_modified | delete_vs_edit | both_deleted
    winner_id: str
    copy_id: str | None = None
    name: str = ""
    origin: str = ""  # 冲突来源设备（取自 loser 的 HLC）


@dataclass
class MergeResult:
    records: list[dict] = field(default_factory=list)
    base: dict[str, str] = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)

    @property
    def content_hash(self) -> str:
        return content_hash(self.records)


def _by_id(records: list[dict]) -> dict[str, dict]:
    return {str(r["id"]): r for r in records if r.get("id")}


def _hlc(record: dict) -> str:
    return str(record.get("hlc") or "")


def _key(record: dict) -> tuple[str, str, str]:
    """合并用的严格全序键。

    加入 semantic_hash 是为了在极端情况下（两台设备恰好有相同的 device_id，
    导致 HLC 与 id 都相同）仍然保持"交换律"，即两端独立计算得到同一结果。
    """
    return _hlc(record), str(record.get("id", "")), semantic_hash(record)


def _origin(record: dict) -> str:
    try:
        return _hlc(record).split("-", 2)[2]
    except IndexError:
        return "?"


def conflict_copy(record: dict, vault_id: str) -> dict:
    """为落败版本生成确定性副本（两端结果一致）。"""
    origin = _origin(record)
    copy = dict(record)
    copy["id"] = str(
        uuid.uuid5(
            CONFLICT_NAMESPACE,
            f"{vault_id}:{record.get('id')}:{_hlc(record)}:{semantic_hash(record)}",
        )
    )
    copy["name"] = str(record.get("name", "")) + CONFLICT_SUFFIX.format(origin=origin)
    copy["deleted"] = False
    copy["conflict_of"] = str(record.get("id", ""))
    return copy


def _resolve(
    left: dict | None, right: dict | None, vault_id: str
) -> tuple[dict, dict | None, Conflict | None]:
    """处理"双方都改且不同"的分支。返回 (winner, loser_copy, conflict)。"""
    if left is None:
        return right, None, None  # type: ignore[return-value]
    if right is None:
        return left, None, None

    left_dead = bool(left.get("deleted"))
    right_dead = bool(right.get("deleted"))

    if left_dead != right_dead:
        # 删除 vs 编辑：宁可多一条记录，也不丢密码 —— 保留活着的版本
        alive, dead = (right, left) if left_dead else (left, right)
        return (
            alive,
            None,
            Conflict(
                str(alive["id"]),
                "delete_vs_edit",
                str(alive["id"]),
                None,
                str(alive.get("name", "")),
                _origin(dead),
            ),
        )

    if left_dead and right_dead:
        winner = left if _key(left) >= _key(right) else right
        loser = right if winner is left else left
        return (
            winner,
            None,
            Conflict(
                str(winner["id"]),
                "both_deleted",
                str(winner["id"]),
                None,
                str(winner.get("name", "")),
                _origin(loser),
            ),
        )

    winner, loser = (left, right) if _key(left) >= _key(right) else (right, left)
    copy = conflict_copy(loser, vault_id)
    return (
        winner,
        copy,
        Conflict(
            str(winner["id"]),
            "both_modified",
            str(winner["id"]),
            str(copy["id"]),
            str(loser.get("name", "")),
            _origin(loser),
        ),
    )


def merge_records(
    base: dict[str, str] | None,
    local: list[dict],
    remote: list[dict],
    vault_id: str,
) -> MergeResult:
    """三方合并。结果中同时包含可见记录与墓碑。"""
    base = dict(base or {})
    local_by_id = _by_id(local)
    remote_by_id = _by_id(remote)

    result = MergeResult()
    ids: list[str] = list(dict.fromkeys([*local_by_id, *remote_by_id, *base]))

    for rid in ids:
        left = local_by_id.get(rid)
        right = remote_by_id.get(rid)
        left_hash = semantic_hash(left) if left else None
        right_hash = semantic_hash(right) if right else None
        base_hash = base.get(rid)

        copy: dict | None = None
        if left_hash == right_hash:
            chosen = left or right
        elif left_hash == base_hash:
            chosen = right
        elif right_hash == base_hash:
            chosen = left
        else:
            chosen, copy, conflict = _resolve(left, right, vault_id)
            if conflict is not None:
                result.conflicts.append(conflict)

        if chosen is not None:
            result.records.append(chosen)
            result.base[str(chosen["id"])] = semantic_hash(chosen)
        if copy is not None:
            result.records.append(copy)
            result.base[str(copy["id"])] = semantic_hash(copy)

    return result


def merge_history(local: dict | None, remote: dict | None) -> dict:
    """历史记录按"条目并集"合并（只增不删，保证不丢）。"""
    local = local or {}
    remote = remote or {}
    merged: dict[str, list] = {}
    for name in set(local) | set(remote):
        seen: set[str] = set()
        entries: list = []
        for entry in list(local.get(name, [])) + list(remote.get(name, [])):
            key = canonical_json(entry) if isinstance(entry, (list, dict)) else str(entry)
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
        entries.sort(key=lambda e: e[2] if isinstance(e, list) and len(e) > 2 else "", reverse=True)
        merged[name] = entries
    return merged
