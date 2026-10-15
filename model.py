"""数据模型层 (Model)。

负责密码主体、历史记录、加解密文件、撤销/重做、备份与变更追踪。
不依赖任何 GUI 组件，可独立单元测试。
"""

from __future__ import annotations

import base64
import copy
import json
import logging
from datetime import datetime

from encryption import (
    AESCipher,
    LegacyAESCipher,
    VaultCipher,
    detect_format,
    validate_v2_outer,
)
from password_generator import ALGORITHM_V1, ALGORITHM_V2, PasswordGenerator
from storage import atomic_write_text

logger = logging.getLogger(__name__)

UNDO_LIMIT = 100
MIN_LENGTH = 4
MAX_LENGTH = 128
RULE_ALGORITHMS = (ALGORITHM_V1, ALGORITHM_V2)


def parse_rule(rule_str: str) -> dict | None:
    """解析规则字符串；无法识别时返回 None。

    兼容三种形态（见 password_generator 模块文档）。
    """
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
        "lower": lower == "True",
        "upper": upper == "True",
        "digit": digit == "True",
        "symbol": symbol == "True",
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
    """由参数构造规则字符串（v2 形态）。"""
    return f"{length}|{lower}|{upper}|{digit}|{symbol}|{salt}|{algorithm}"


class PasswordManagerModel:
    """密码管理器核心数据模型。"""

    def __init__(self) -> None:
        # ---------- 旧格式兼容所需 ----------
        self.file_verify_key = "F_Y"  # 仅用于读取 v1/v2 旧文件，不再用于写入
        self.file_format_version = 3

        self._raw_content = ""  # 原始文件内容（v3/v2）
        self._outer_legacy = ""  # v1 外层解密后的内容
        self.raw_decrypted_data = ""  # 最终解密出的 JSON 字符串

        # ---------- 业务数据 ----------
        self.main_data: list[dict] = []
        self.history_data: dict[str, list] = {}

        # ---------- 撤销/重做 ----------
        self.undo_stack: list[dict] = []
        self.redo_stack: list[dict] = []

        # ---------- 文件 ----------
        self.current_file_path: str | None = None

        # ---------- 生成器 ----------
        self.pwd_generator = PasswordGenerator()

        # ---------- 变更追踪 ----------
        self._dirty = False
        self._last_saved_state = None

    # ===================== 变更追踪 =====================
    def _mark_dirty(self) -> None:
        self._dirty = True

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

        # v1
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
        except Exception as exc:  # noqa: BLE001 - 统一转为布尔结果
            logger.warning("解密失败（格式 v%s）：%s", self.file_format_version, exc)
            return False

    def encrypt_data(self, user_key: str, data_dict: dict) -> str:
        """把数据字典加密为 v3 文件内容。"""
        if not user_key:
            raise ValueError("密钥不能为空")
        plaintext = json.dumps(data_dict, ensure_ascii=False)
        return VaultCipher(user_key).encrypt(plaintext)

    # ===================== 数据加载与导出 =====================
    def load_data_from_decrypted_json(self) -> int:
        """解析解密后的 JSON，填充数据。返回被升级为 v2 的旧规则数量。"""
        data_dict = json.loads(self.raw_decrypted_data)
        self.main_data = []
        self.history_data = data_dict.get("historyData", {}) or {}

        upgraded = 0
        for item in data_dict.get("mainData", []):
            name = item.get("密码生成主体", "")
            count = str(item.get("第n次生成的密码", "0"))
            rule_str = item.get("规则", "")
            if not name or not rule_str:
                continue

            spec = parse_rule(rule_str)
            if spec is None:
                logger.warning("跳过无法解析的规则：%s", rule_str)
                continue

            if spec["algorithm"] == ALGORITHM_V1 and not spec["salt"]:
                # 旧的无盐规则本身不可复现（每次加载都会变），升级为 v2 并标记待保存
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
                rule_str = build_rule(
                    spec["length"],
                    spec["lower"],
                    spec["upper"],
                    spec["digit"],
                    spec["symbol"],
                    result["salt"],
                    ALGORITHM_V2,
                )
                password = result["password"]
                upgraded += 1
            else:
                result = self.pwd_generator.generate(
                    name,
                    length=spec["length"],
                    lower=spec["lower"],
                    upper=spec["upper"],
                    digit=spec["digit"],
                    symbol=spec["symbol"],
                    salt=spec["salt"] or None,
                    algorithm=spec["algorithm"],
                )
                password = result["password"]

            self.main_data.append({"name": name, "password": password, "count": count, "rule": rule_str})

        self.mark_clean()
        if upgraded:
            # 升级后的规则需要落盘，因此仍标记为"有未保存修改"
            logger.info("已将 %d 条无盐旧规则升级为 v2，需要重新保存", upgraded)
            self._dirty = True
        return upgraded

    def prepare_export_data(self) -> dict:
        """准备导出数据：只保存规则与历史，不落盘明文密码。"""
        export_main = [
            {
                "密码生成主体": item["name"],
                "第n次生成的密码": item["count"],
                "规则": item["rule"],
            }
            for item in self.main_data
        ]
        return {"mainData": export_main, "historyData": self.history_data}

    # ===================== 主数据操作 =====================
    def add_or_update_subject(
        self,
        name: str,
        *,
        length: int = 12,
        lower: bool = True,
        upper: bool = True,
        digit: bool = True,
        symbol: bool = True,
    ) -> dict:
        """新增（或同名覆盖）密码主体，并立即生成 v2 密码。"""
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
        rule_str = build_rule(length, lower, upper, digit, symbol, result["salt"], ALGORITHM_V2)
        new_item = {
            "name": name,
            "password": result["password"],
            "count": "0",
            "rule": rule_str,
        }

        for index, item in enumerate(self.main_data):
            if item["name"] == name:
                self.main_data[index] = new_item
                break
        else:
            self.main_data.append(new_item)

        self._mark_dirty()
        self._save_state()
        return new_item

    def delete_subject(self, index: int) -> bool:
        if 0 <= index < len(self.main_data):
            del self.main_data[index]
            self._mark_dirty()
            self._save_state()
            return True
        return False

    def generate_new_password_for_subject(self, index: int) -> tuple[str, str] | None:
        """为指定主体生成新密码（始终使用 v2）。返回 (密码, 次数)。"""
        if not (0 <= index < len(self.main_data)):
            return None

        item = self.main_data[index]
        spec = parse_rule(item["rule"])
        if spec is None:
            return None

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

        self._add_to_history(item["name"], item["count"], item["rule"])
        self._mark_dirty()
        self._save_state()
        return item["password"], item["count"]

    def reorder_subjects(self, names_in_order: list[str]) -> None:
        """按给定名称顺序重排主体（供 UI 拖拽排序调用）。"""
        by_name = {item["name"]: item for item in self.main_data}
        ordered = [by_name[name] for name in names_in_order if name in by_name]
        if len(ordered) != len(self.main_data):
            seen = {id(item) for item in ordered}
            ordered += [item for item in self.main_data if id(item) not in seen]
        self.main_data = ordered
        self._mark_dirty()
        self._save_state()

    def clear_all_data(self) -> None:
        self.main_data = []
        self.history_data = {}
        self._mark_dirty()
        self._save_state()

    # ===================== 历史记录 =====================
    def _add_to_history(self, name: str, count: str, rule_str: str) -> None:
        self.history_data.setdefault(name, []).insert(
            0, [count, rule_str, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        )

    def get_history_for_subject(self, name: str) -> list[tuple[str, str, str]]:
        """返回 [(密码, 次数, 时间), ...]，兼容两元素的旧历史条目。"""
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

    def undo(self) -> bool:
        if len(self.undo_stack) <= 1:
            return False
        self.redo_stack.append(self.undo_stack.pop())
        prev = self.undo_stack[-1]
        self.main_data = copy.deepcopy(prev["main"])
        self.history_data = copy.deepcopy(prev["history"])
        self._mark_dirty()
        return True

    def redo(self) -> bool:
        if not self.redo_stack:
            return False
        nxt = self.redo_stack.pop()
        self.undo_stack.append(nxt)
        self.main_data = copy.deepcopy(nxt["main"])
        self.history_data = copy.deepcopy(nxt["history"])
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

    # ===================== 临时备份 =====================
    def create_backup(self, user_key: str, backup_path: str) -> str | None:
        """把当前数据加密写入 backup_path（原子写入）。"""
        try:
            encrypted = self.encrypt_data(user_key, self.prepare_export_data())
            atomic_write_text(backup_path, encrypted)
            return backup_path
        except Exception as exc:  # noqa: BLE001
            logger.error("创建备份失败：%s", exc)
            return None
