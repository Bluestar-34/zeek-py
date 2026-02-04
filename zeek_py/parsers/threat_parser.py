from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..models import ThreatEvent


def _parse_ts(value: str) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _normalize_str(value: str | None) -> Optional[str]:
    if value is None:
        return None
    if value in ("", "-", "(empty)", "N/A"):
        return None
    return value


# 分别维护 notice.log / intel.log / weird.log 的字段顺序
_NOTICE_FIELDS: list[str] | None = None
_INTEL_FIELDS: list[str] | None = None
_WEIRD_FIELDS: list[str] | None = None


def _parse_ascii_line(
    line: str, *, is_intel: bool
) -> Optional[ThreatEvent]:
    """
    通用解析 Zeek ASCII notice / intel 日志单行。
    """
    global _NOTICE_FIELDS, _INTEL_FIELDS

    line = line.rstrip("\n")
    if not line:
        return None

    # 头部行
    if line.startswith("#"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "#fields":
            if is_intel:
                _INTEL_FIELDS = parts[1:]
            else:
                _NOTICE_FIELDS = parts[1:]
        return None

    fields = _INTEL_FIELDS if is_intel else _NOTICE_FIELDS
    if not fields:
        return None

    values = line.split("\t")
    if len(values) != len(fields):
        return None

    data = dict(zip(fields, values))

    try:
        ts_raw = data.get("ts")
        if not ts_raw or ts_raw in ("-", ""):
            return None
        ts = _parse_ts(ts_raw)

        if is_intel:
            note = _normalize_str(data.get("indicator")) or "THREAT"
            msg = _normalize_str(data.get("note")) or _normalize_str(data.get("msg"))
            source = "intel"
        else:
            note = _normalize_str(data.get("note")) or "THREAT"
            msg = _normalize_str(data.get("msg"))
            source = "notice"

        src = _normalize_str(data.get("id.orig_h") or data.get("src"))
        dst = _normalize_str(data.get("id.resp_h") or data.get("dst"))
        uid = _normalize_str(data.get("uid"))
        proto = _normalize_str(data.get("proto"))
        level = _normalize_str(
            data.get("severity") or data.get("fuid") or data.get("seen.indicator")
        )

        return ThreatEvent(
            ts=ts,
            note=note,
            msg=msg,
            src=src,
            dst=dst,
            uid=uid,
            proto=proto,
            level=level,
            source=source,
        )
    except Exception:
        return None


def parse_notice_line(line: str) -> Optional[ThreatEvent]:
    """解析 notice.log（ASCII 格式）的一行。"""
    return _parse_ascii_line(line, is_intel=False)


def parse_intel_line(line: str) -> Optional[ThreatEvent]:
    """解析 intel.log（ASCII 格式）的一行。"""
    return _parse_ascii_line(line, is_intel=True)


def parse_weird_line(line: str) -> Optional[ThreatEvent]:
    """
    解析 weird.log（ASCII 格式）的一行，并映射为 ThreatEvent。

    典型字段（根据 #fields 行）：
    ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, name, addl, notice, peer, source
    """
    global _WEIRD_FIELDS

    line = line.rstrip("\n")
    if not line:
        return None

    # 头部行：记录字段顺序
    if line.startswith("#"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "#fields":
            _WEIRD_FIELDS = parts[1:]
        return None

    if not _WEIRD_FIELDS:
        return None

    values = line.split("\t")
    if len(values) != len(_WEIRD_FIELDS):
        return None

    data = dict(zip(_WEIRD_FIELDS, values))

    try:
        ts_raw = data.get("ts")
        if not ts_raw or ts_raw in ("-", ""):
            return None
        ts = _parse_ts(ts_raw)

        note = _normalize_str(data.get("name")) or "WEIRD"
        msg = _normalize_str(data.get("addl"))

        src = _normalize_str(data.get("id.orig_h"))
        dst = _normalize_str(data.get("id.resp_h"))
        uid = _normalize_str(data.get("uid"))
        # weird.log 通常不含 proto 字段，这里可以用 source/name 之类占位
        proto = None

        # 级别可以简单映射为 notice 标志或 source 字段
        level = _normalize_str(data.get("source") or data.get("notice"))

        return ThreatEvent(
            ts=ts,
            note=note,
            msg=msg,
            src=src,
            dst=dst,
            uid=uid,
            proto=proto,
            level=level,
            source="weird",
        )
    except Exception:
        return None
