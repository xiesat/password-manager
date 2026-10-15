"""HLC 混合逻辑时钟测试。"""

from __future__ import annotations

import pytest

import hlc as hlc_module
from hlc import HLC, format_hlc, parse_hlc


def test_format_is_fixed_width_and_lexicographically_ordered():
    a = format_hlc(1000, 0, "aaaa1111")
    b = format_hlc(1000, 1, "aaaa1111")
    c = format_hlc(1001, 0, "aaaa1111")
    assert len(a) == len(c)
    assert a < b < c  # 字典序 == 时间序
    assert parse_hlc(c) == (1001, 0, "aaaa1111")


@pytest.mark.parametrize("bad", ["", "1-2", "x-0-d", "1-2-3-4"])
def test_parse_rejects_bad(bad):
    with pytest.raises(ValueError):
        parse_hlc(bad)


def test_device_must_not_contain_dash():
    with pytest.raises(ValueError):
        HLC("bad-device")


def test_next_is_strictly_increasing_at_frozen_time(monkeypatch):
    monkeypatch.setattr(hlc_module.time, "time", lambda: 1_000.0)
    clock = HLC("dev00001")
    values = [clock.next() for _ in range(5)]
    assert values == sorted(values)
    assert len(set(values)) == 5
    # 同一毫秒内靠 counter 递增
    assert parse_hlc(values[0])[1] == 0
    assert parse_hlc(values[4])[1] == 4


def test_counter_overflow_bumps_wall(monkeypatch):
    monkeypatch.setattr(hlc_module.time, "time", lambda: 1_000.0)
    clock = HLC("dev00001")
    clock.next()  # 先让 wall 对齐当前（冻结的）时间
    clock._counter = hlc_module.MAX_COUNTER
    value = clock.next()
    wall, counter, _ = parse_hlc(value)
    assert wall == 1_000_001 and counter == 0  # 同一毫秒内计数溢出 → wall 进位


def test_observe_makes_local_clock_advance(monkeypatch):
    monkeypatch.setattr(hlc_module.time, "time", lambda: 1_000.0)
    clock = HLC("dev00001")
    remote = format_hlc(5_000_000_000_000, 7, "dev00002")
    clock.observe(remote)
    value = clock.next()
    assert value > remote  # 观察到远端后，本机时间戳必须更大


def test_observe_ignores_garbage():
    clock = HLC("dev00001")
    before = clock.next()
    clock.observe(None)
    clock.observe("not-an-hlc")
    assert clock.next() > before
