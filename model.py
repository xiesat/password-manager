"""数据模型层 (Model)。

负责密码主体、历史记录、加解密文件、撤销/重做、备份与变更追踪。
不依赖任何 GUI 组件，可独立单元测试。

数据 schema v4（载荷内部版本，加密容器仍是 AES-256-GCM 的 v3）：
    {
      "schema": 4,
      "vault_id": "...", "device_id": "...", "rev": 42,
      "mainData":   [ 记录 ... ],       # 可见记录
      "tombstones": [ 墓碑记录 ... ],    # 已删除但仍需参与同步
      "historyData": { 主体名: [[次数, 规则, 时间], ...] },
      "sync_base":  { 记录ID: 语义哈希 }  # 上次同步时的基准，用于三方合并
    }

记录结构：
    { id, name, password, rule, count, updated_at, hlc, deleted }
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import uuid
from datetime import datetime

import merge
from encryption import (
    AESCipher,
    LegacyAESCipher,
    VaultCipher,
    detect_format,
    validate_v2_outer,
)
from hlc import HLC
from password_generator import ALGORITHM_V1, ALGORITHM_V2, PasswordGenerator
from storage import atomic_write_text, get_device_id

logger = logging.getLogger(__name__)

UNDO_LIMIT = 100
MIN_LENGTH = 4
MAX_LENGTH = 128
RULE_ALGORITHMS = (ALGORITHM_V1, ALGORITHM_V2)
DEFAULT_RULE_LENGTH = 16
PLACEHOLDER_PASSWORD = "等待生成"
PAYLOAD_SCHEMA = 4


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_rule(rule_str: str) -> dict | None:
    """解析规则字符串；无法识别时返回 None。"""
    parts = rule_str.split("|")
    if len(parts) == 5:
        length, lower, upper, digit, symbol = parts
        salt, algorithm = "", ALGORITHM_V1
    elif len(parts) == 6:
        length, lower, upper, digit, symbol, salt = parts
        algorithm = ALGORITHM_V1
    elif len(parts) == 7 and parts[6] in RULE_ALGORITHMS:
        length, lower, upper, digit, symbol, salt, algorithm = parts
    else:
        return None

    try:
        length_int = int(length)
    except (TypeError, ValueError):
        return None
    if not MIN_LENGTH <= length_int <= MAX_LENGTH:
        return None

    return {
        "length": length_int,
        # 大小写都接受：旧版 Android 曾把布尔写成 true/false
        "lower": lower.lower() == "true",
        "upper": upper.lower() == "true",
        "digit": digit.lower() == "true",
        "symbol": symbol.lower() == "true",
        "salt": salt,
        "algorithm": algorithm,
    }


def build_rule(
    length: int,
    lower: bool,
    upper: bool,
    digit: bool,
    symbol: bool,
    salt: str,
    algorithm: str,
) -> str:
    """由参数构造规则字符串。"""
    return f"{length}|{lower}|{upper}|{digit}|{symbol}|{salt}|{algorithm}"


class PasswordManagerModel:
    """密码管理器核心数据模型。"""

    def __init__(self) -> None:
        self.file_verify_key = "F_Y"  # 仅用于读取 v1/v2 旧文件
        self.file_format_version = 3

        self._raw_content = ""
        self._outer_legacy = ""
        self.raw_decrypted_data = ""

        self.main_data: list[dict] = []
        self.tombstones: list[dict] = []
        self.history_data: dict[str, list] = {}

        self.undo_stack: list[dict] = []
        self.redo_stack: list[dict] = []

        self.current_file_path: str | None = None

        self.pwd_generator = PasswordGenerator()

        self.device_id = get_device_id()
        self.hlc = HLC(self.device_id)
        self.vault_id = self._new_id()
        self.rev = 0
        self.sync_base: dict[str, str] = {}

        self._dirty = False
        self._last_saved_state: dict | None = None

    # ===================== 记录工具 =====================
    @staticmethod
    def _new_id() -> str:
        return uuid.uuid4().hex

    def all_records(self) -> list[dict]:
        """可见记录 + 墓碑，用于同步/合并。"""
        return [*self.main_data, *self.tombstones]

    def content_hash(self) -> str:
        """与顺序无关的内容指纹，用于验证两端是否收敛。"""
        return merge.content_hash(self.all_records())

    def _make_record(
        self,
        *,
        name: str,
        password: str,
        rule: str,
        count: str = "0",
        record_id: str | None = None,
        updated_at: str | None = None,
        hlc: str | None = None,
        deleted: bool = False,
    ) -> dict:
        return {
            "id": record_id or self._new_id(),
            "name": name,
            "password": password,
            "rule": rule,
            "count": str(count),
            "updated_at": updated_at or _now(),
            "hlc": hlc or self.hlc.next(),
            "deleted": bool(deleted),
        }

    def _default_rule(self) -> str:
        return build_rule(
            DEFAULT_RULE_LENGTH,
            True,
            True,
            True,
            True,
            self.pwd_generator.random_salt(),
            ALGORITHM_V2,
        )

    def _build_record(self, raw: dict) -> tuple[dict | None, bool]:
        """把载荷中的一条记录转成内部结构。返回 (记录, 是否需要重新保存)。"""
        if raw.get("id"):
            record = {
                "id": str(raw["id"]),
                "name": str(raw.get("name", "")),
                "password": str(raw.get("password", "")),
                "rule": str(raw.get("rule", "")),
                "count": str(raw.get("count", "0")),
                "updated_at": str(raw.get("updated_at", "")),
                "hlc": str(raw.get("hlc") or self.hlc.next()),
                "deleted": bool(raw.get("deleted", False)),
            }
            return record, not raw.get("hlc")

        # ---- 旧格式（schema < 4）：中文键名 ----
        name = str(raw.get("密码生成主体", ""))
        if not name:
            return None, False
        rule = str(raw.get("规则", ""))
        count = str(raw.get("第n次生成的密码", "0"))
        updated_at = str(raw.get("更新时间", ""))
        password = str(raw.get("密码", ""))

        spec = parse_rule(rule) if rule else None
        if spec is None:
            rule = self._default_rule()
        elif spec["algorithm"] == ALGORITHM_V1 and not spec["salt"]:
            result = self.pwd_generator.generate(
                name,
                length=spec["length"],
                lower=spec["lower"],
                upper=spec["upper"],
                digit=spec["digit"],
                symbol=spec["symbol"],
                salt=None,
                algorithm=ALGORITHM_V2,
            )
            rule = build_rule(
                spec["length"],
                spec["lower"],
                spec["upper"],
                spec["digit"],
                spec["symbol"],
                result["salt"],
                ALGORITHM_V2,
            )

        if not password or password == PLACEHOLDER_PASSWORD:
            spec = parse_rule(rule)
            if spec is not None:
                password = self.pwd_generator.generate(
                    name,
                    length=spec["length"],
                    lower=spec["lower"],
                    upper=spec["upper"],
                    digit=spec["digit"],
                    symbol=spec["symbol"],
                    salt=spec["salt"] or None,
                    algorithm=spec["algorithm"],
                )["password"]

        return (
            self._make_record(name=name, password=password, rule=rule, count=count, updated_at=updated_at),
            True,
        )

    # ===================== 变更追踪 =====================
    def _mark_dirty(self) -> None:
        self._dirty = True
        self.rev += 1

    def mark_clean(self) -> None:
        self._dirty = False
        self._save_current_state_snapshot()

    def is_dirty(self) -> bool:
        if self._dirty:
            return True
        if self._last_saved_state is None:
            return bool(self.main_data or self.history_data)
        return self._get_state_snapshot() != self._last_saved_state

    def _get_state_snapshot(self) -> dict:
        return {
            "main": copy.deepcopy(self.main_data),
            "history": copy.deepcopy(self.history_data),
            "tombstones": copy.deepcopy(self.tombstones),
            "sync_base": copy.deepcopy(self.sync_base),
        }

    def _save_current_state_snapshot(self) -> None:
        self._last_saved_state = self._get_state_snapshot()

    # ===================== 文件加解密 =====================
    def detect_and_store(self, content: str) -> tuple[bool, str, int]:
        """校验文件格式并保存原始内容。返回 (是否有效, 消息, 版本)。"""
        version = detect_format(content)
        self.file_format_version = version

        if version == 3:
            try:
                base64.b64decode(content[3:], validate=True)
            except Exception:
                return False, "v3 文件内容损坏", 3
            self._raw_content = content
            return True, "v3 文件校验通过", 3

        if version == 2:
            if not validate_v2_outer(content):
                return False, "v2 文件格式错误", 2
            self._raw_content = content
            return True, "v2 文件格式", 2

        if len(content) < 24:
            return False, "文件长度异常，不是合法 sk 文件", 1
        try:
            decrypted = LegacyAESCipher(self.file_verify_key).decrypt(content[:-24], content[-24:])
        except Exception:
            return False, "文件已损坏或非本程序生成", 1
        if not decrypted.endswith("KEY_CHECKSUM"):
            return False, "文件校验失败，可能已损坏", 1
        self._outer_legacy = decrypted[: -len("KEY_CHECKSUM")]
        self._raw_content = content
        return True, "旧版文件校验通过", 1

    def decrypt_with_user_key(self, user_key: str) -> bool:
        """用用户密钥解密，成功则把 JSON 存入 self.raw_decrypted_data。"""
        try:
            if self.file_format_version == 3:
                self.raw_decrypted_data = VaultCipher.decrypt(user_key, self._raw_content)
            elif self.file_format_version == 2:
                parts = self._raw_content[3:].split("|")
                if len(parts) != 3:
                    return False
                inner_payload = AESCipher.decrypt_with_params(self.file_verify_key, *parts)
                inner_parts = inner_payload.split("|")
                if len(inner_parts) != 3:
                    return False
                self.raw_decrypted_data = AESCipher.decrypt_with_params(user_key, *inner_parts)
            else:
                if len(self._outer_legacy) < 24:
                    return False
                decrypted = LegacyAESCipher(user_key).decrypt(
                    self._outer_legacy[:-24], self._outer_legacy[-24:]
                )
                if not decrypted.endswith("DATA_CHECK"):
                    return False
                self.raw_decrypted_data = decrypted[: -len("DATA_CHECK")]
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("解密失败（格式 v%s）：%s", self.file_format_version, exc)
            return False

    def encrypt_data(self, user_key: str, data_dict: dict) -> str:
        """把数据字典加密为文件内容。"""
        if not user_key:
            raise ValueError("密钥不能为空")
        plaintext = json.dumps(data_dict, ensure_ascii=False)
        return VaultCipher(user_key).encrypt(plaintext)

    # ===================== 数据加载与导出 =====================
    def load_data_from_decrypted_json(self) -> int:
        """解析解密后的 JSON，填充数据。返回需要重新保存的条目数。"""
        data = json.loads(self.raw_decrypted_data)

        self.vault_id = str(data.get("vault_id") or self.vault_id or self._new_id())
        self.rev = int(data.get("rev", 0) or 0)
        self.sync_base = dict(data.get("sync_base", {}) or {})
        self.history_data = data.get("historyData", {}) or {}
        self.main_data = []
        self.tombstones = []

        schema = data.get("schema")
        needs_resave = schema != PAYLOAD_SCHEMA

        upgraded = 0
        for raw in data.get("mainData", []):
            record, changed = self._build_record(raw)
            if record is None:
                continue
            upgraded += 1 if changed else 0
            if record["deleted"]:
                self.tombstones.append(record)
            else:
                self.main_data.append(record)

        for raw in data.get("tombstones", []):
            record, _changed = self._build_record(raw)
            if record is not None:
                record["deleted"] = True
                self.tombstones.append(record)

        self.mark_clean()
        if needs_resave or upgraded:
            logger.info("数据已迁移/修复（需要重新保存）：schema=%s upgraded=%d", schema, upgraded)
            self._dirty = True
        return max(upgraded, 1 if needs_resave else 0)

    def prepare_export_data(self) -> dict:
        """构造 schema 4 载荷（密码随整个库一起被 AES-256-GCM 加密）。"""
        return {
            "schema": PAYLOAD_SCHEMA,
            "vault_id": self.vault_id,
            "device_id": self.device_id,
            "rev": self.rev,
            "mainData": [dict(r) for r in self.main_data],
            "tombstones": [dict(r) for r in self.tombstones],
            "historyData": self.history_data,
            "sync_base": dict(self.sync_base),
        }

    def export_rows(self) -> list[dict]:
        """导出为通用行结构（供 UI / CSV 使用，仅可见记录）。"""
        return [
            {
                "name": item["name"],
                "password": item["password"],
                "count": item["count"],
                "updated_at": item.get("updated_at", ""),
                "rule": item["rule"],
            }
            for item in self.main_data
        ]

    # ===================== 主数据操作 =====================
    def add_or_update_subject(
        self,
        name: str,
        *,
        length: int = DEFAULT_RULE_LENGTH,
        lower: bool = True,
        upper: bool = True,
        digit: bool = True,
        symbol: bool = True,
        password: str | None = None,
        rule: str | None = None,
        count: str = "0",
        updated_at: str | None = None,
    ) -> dict:
        """新增（或同名覆盖）主体。password 为空时按规则生成。"""
        if password:
            used_password = password
            used_rule = rule or build_rule(
                length,
                lower,
                upper,
                digit,
                symbol,
                self.pwd_generator.random_salt(),
                ALGORITHM_V2,
            )
        else:
            result = self.pwd_generator.generate(
                name,
                length=length,
                lower=lower,
                upper=upper,
                digit=digit,
                symbol=symbol,
                salt=None,
                algorithm=ALGORITHM_V2,
            )
            used_password = result["password"]
            used_rule = rule or build_rule(length, lower, upper, digit, symbol, result["salt"], ALGORITHM_V2)

        existing_id = next((item["id"] for item in self.main_data if item["name"] == name), None)
        new_item = self._make_record(
            name=name,
            password=used_password,
            rule=used_rule,
            count=count,
            record_id=existing_id,
            updated_at=updated_at,
        )

        for index, item in enumerate(self.main_data):
            if item["name"] == name:
                self.main_data[index] = new_item
                break
        else:
            self.main_data.append(new_item)

        # 自动生成的首个密码同样要进历史，否则"第一次生成的那条"永远查不到。
        # 注意：显式传入密码（如 CSV 导入）时，规则是随机造出来的、与密码并不对应，
        # 记进历史会显示一条与真实密码不符的记录，所以那种情况不能记。
        if not password:
            self._add_to_history(name, new_item["count"], new_item["rule"])

        self._mark_dirty()
        self._save_state()
        return new_item

    def delete_subjects(self, indexes: list[int]) -> list[str]:
        """按索引批量删除（生成墓碑），返回被删除的主体名列表。"""
        valid = sorted({i for i in indexes if 0 <= i < len(self.main_data)})
        removed: list[str] = []
        for index in reversed(valid):
            item = self.main_data.pop(index)
            removed.append(item["name"])
            self.tombstones.append(
                self._make_record(
                    name=item["name"],
                    password="",
                    rule="",
                    count=item.get("count", "0"),
                    record_id=item["id"],
                    deleted=True,
                )
            )
        removed.reverse()
        if removed:
            self._mark_dirty()
            self._save_state()
        return removed

    def delete_subject(self, index: int) -> bool:
        return bool(self.delete_subjects([index]))

    def generate_new_password_for_subject(self, index: int) -> tuple[str, str] | None:
        """为指定主体生成新密码（始终 v2）。返回 (密码, 次数)。"""
        if not (0 <= index < len(self.main_data)):
            return None

        item = self.main_data[index]
        spec = parse_rule(item["rule"]) or parse_rule(self._default_rule())
        assert spec is not None

        result = self.pwd_generator.generate(
            item["name"],
            length=spec["length"],
            lower=spec["lower"],
            upper=spec["upper"],
            digit=spec["digit"],
            symbol=spec["symbol"],
            salt=None,
            algorithm=ALGORITHM_V2,
        )
        item["password"] = result["password"]
        item["rule"] = build_rule(
            spec["length"],
            spec["lower"],
            spec["upper"],
            spec["digit"],
            spec["symbol"],
            result["salt"],
            ALGORITHM_V2,
        )
        item["count"] = str(int(item["count"]) + 1)
        item["updated_at"] = _now()
        item["hlc"] = self.hlc.next()

        self._add_to_history(item["name"], item["count"], item["rule"])
        self._mark_dirty()
        self._save_state()
        return item["password"], item["count"]

    def reorder_subjects(self, names_in_order: list[str]) -> None:
        """按给定名称顺序重排主体（仅影响本机显示顺序，不参与同步）。"""
        by_name = {item["name"]: item for item in self.main_data}
        ordered = [by_name[name] for name in names_in_order if name in by_name]
        if len(ordered) != len(self.main_data):
            seen = {id(item) for item in ordered}
            ordered += [item for item in self.main_data if id(item) not in seen]
        self.main_data = ordered
        self._mark_dirty()
        self._save_state()

    def clear_all_data(self) -> None:
        """清空：可见记录转为墓碑，历史清空。"""
        for item in self.main_data:
            self.tombstones.append(
                self._make_record(
                    name=item["name"],
                    password="",
                    rule="",
                    count=item.get("count", "0"),
                    record_id=item["id"],
                    deleted=True,
                )
            )
        self.main_data = []
        self.history_data = {}
        self._mark_dirty()
        self._save_state()

    # ===================== 同步/合并 =====================
    def _records_from_payload(self, payload: dict) -> list[dict]:
        records: list[dict] = []
        for raw in payload.get("mainData", []) or []:
            record, _ = self._build_record(raw)
            if record is not None:
                records.append(record)
        for raw in payload.get("tombstones", []) or []:
            record, _ = self._build_record(raw)
            if record is not None:
                record["deleted"] = True
                records.append(record)
        return records

    def merge_remote(self, remote_payload: dict) -> list[merge.Conflict]:
        """把对端载荷合并进本机（三方合并）。返回冲突列表。"""
        remote_records = self._records_from_payload(remote_payload)
        for record in remote_records:
            self.hlc.observe(record.get("hlc"))

        result = merge.merge_records(self.sync_base, self.all_records(), remote_records, self.vault_id or "")
        merged_history = merge.merge_history(self.history_data, remote_payload.get("historyData", {}) or {})

        self.main_data = [r for r in result.records if not r.get("deleted")]
        self.tombstones = [r for r in result.records if r.get("deleted")]
        self.history_data = merged_history
        self.sync_base = result.base
        self._mark_dirty()
        self._save_state()
        return result.conflicts

    # ===================== 历史记录 =====================
    def _add_to_history(self, name: str, count: str, rule_str: str) -> None:
        self.history_data.setdefault(name, []).insert(0, [count, rule_str, _now()])

    def get_history_for_subject(self, name: str) -> list[tuple[str, str, str]]:
        """返回 [(密码, 次数, 时间), ...]，兼容两元素旧条目。"""
        result = []
        for entry in self.history_data.get(name, []):
            count, rule_str = entry[0], entry[1]
            timestamp = entry[2] if len(entry) > 2 else ""
            spec = parse_rule(rule_str)
            if spec is None:
                continue
            generated = self.pwd_generator.generate(
                name,
                length=spec["length"],
                lower=spec["lower"],
                upper=spec["upper"],
                digit=spec["digit"],
                symbol=spec["symbol"],
                salt=spec["salt"] or None,
                algorithm=spec["algorithm"],
            )
            result.append((generated["password"], count, timestamp))
        return result

    def delete_history_entry(self, name: str, history_index: int) -> bool:
        entries = self.history_data.get(name)
        if entries and 0 <= history_index < len(entries):
            del entries[history_index]
            self._mark_dirty()
            return True
        return False

    # ===================== 撤销/重做 =====================
    def _save_state(self) -> None:
        self.undo_stack.append(self._get_state_snapshot())
        if len(self.undo_stack) > UNDO_LIMIT:
            del self.undo_stack[0]
        self.redo_stack.clear()

    def _restore(self, state: dict) -> None:
        self.main_data = copy.deepcopy(state["main"])
        self.history_data = copy.deepcopy(state["history"])
        self.tombstones = copy.deepcopy(state.get("tombstones", []))
        self.sync_base = copy.deepcopy(state.get("sync_base", {}))

    def undo(self) -> bool:
        if len(self.undo_stack) <= 1:
            return False
        self.redo_stack.append(self.undo_stack.pop())
        self._restore(self.undo_stack[-1])
        self._mark_dirty()
        return True

    def redo(self) -> bool:
        if not self.redo_stack:
            return False
        nxt = self.redo_stack.pop()
        self.undo_stack.append(nxt)
        self._restore(nxt)
        self._mark_dirty()
        return True

    def initialize_empty_state(self) -> None:
        self._save_state()
        self.mark_clean()

    # ===================== 文件路径 =====================
    def set_current_file_path(self, path: str | None) -> None:
        self.current_file_path = path

    def get_current_file_path(self) -> str | None:
        return self.current_file_path

    # ===================== 备份 =====================
    def create_backup(self, user_key: str, backup_path: str) -> str | None:
        """把当前数据加密写入 backup_path（原子写入）。"""
        try:
            encrypted = self.encrypt_data(user_key, self.prepare_export_data())
            atomic_write_text(backup_path, encrypted)
            return backup_path
        except Exception as exc:  # noqa: BLE001
            logger.error("创建备份失败：%s", exc)
            return None
