"""混合逻辑时钟 (Hybrid Logical Clock)。

给记录提供一个"因果一致、贴近墙钟、且可确定性全序比较"的时间戳。
编码为定长字符串：<wall_ms:13>-<counter:04>-<device>，字典序即时间序。

为什么不用墙上时钟：手机/电脑的系统时间可能不准或被人为调整，
用墙钟排序会导致合并结果错乱；HLC 在保持接近真实时间的同时保证单调与全序。
"""

from __future__ import annotations

import threading
import time

WALL_DIGITS = 13
COUNTER_DIGITS = 4
MAX_COUNTER = 10**COUNTER_DIGITS - 1


def format_hlc(wall_ms: int, counter: int, device: str) -> str:
    """拼装定长 HLC 字符串。device 不能包含 '-'。"""
    return f"{wall_ms:0{WALL_DIGITS}d}-{counter:0{COUNTER_DIGITS}d}-{device}"


def parse_hlc(value: str) -> tuple[int, int, str]:
    """拆分 HLC；格式非法时抛出 ValueError。"""
    parts = str(value).split("-")
    if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit() or not parts[2]:
        raise ValueError(f"非法的 HLC：{value!r}")
    return int(parts[0]), int(parts[1]), parts[2]


class HLC:
    """单设备逻辑时钟。线程安全。"""

    def __init__(self, device: str, *, wall_ms: int = 0) -> None:
        if not device or "-" in device:
            raise ValueError("device 不能为空且不能包含 '-'")
        self.device = device
        self._wall = int(wall_ms)
        self._counter = 0
        self._lock = threading.Lock()

    def next(self) -> str:
        """产生一个严格大于此前所有本机时间戳的值。"""
        with self._lock:
            now_ms = int(time.time() * 1000)
            if now_ms > self._wall:
                self._wall, self._counter = now_ms, 0
            else:
                self._counter += 1
                if self._counter > MAX_COUNTER:
                    self._wall += 1
                    self._counter = 0
            return format_hlc(self._wall, self._counter, self.device)

    def observe(self, value: str | None) -> None:
        """吸收对端时间戳，保证本机之后产生的时间戳更大。"""
        if not value:
            return
        try:
            wall, counter, _device = parse_hlc(str(value))
        except (ValueError, TypeError):
            return
        with self._lock:
            if wall > self._wall or (wall == self._wall and counter > self._counter):
                self._wall, self._counter = wall, counter
