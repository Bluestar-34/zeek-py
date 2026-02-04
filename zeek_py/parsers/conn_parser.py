from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..models import Flow


def _parse_ts(value: str) -> datetime:
    """
    解析 Zeek ASCII 日志中的 ts 字段（通常为 epoch 秒，可能带小数）。
    """
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _to_int(value: str) -> Optional[int]:
    if value in ("", "-", "(empty)", "N/A", "nan"):
        return None
    try:
        return int(value)
    except Exception:
        return None


def _to_float(value: str) -> Optional[float]:
    if value in ("", "-", "(empty)", "N/A", "nan"):
        return None
    try:
        return float(value)
    except Exception:
        return None


# 当前 conn.log 的字段名顺序（在 #fields 行中定义）。
_CONN_FIELDS: list[str] | None = None


def parse_conn_line(line: str) -> Optional[Flow]:
    """
    解析 Zeek 默认 ASCII 格式的 conn.log 单行。

    支持带有如下头部的标准 Zeek 日志格式：
    - `#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state ...`
    """
    global _CONN_FIELDS

    line = line.rstrip("\n")
    if not line:
        return None

    # 处理头部行（以 # 开头）
    if line.startswith("#"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "#fields":
            # 记录字段名顺序，后续数据行按此映射
            _CONN_FIELDS = parts[1:]
        return None

    # 没有字段定义，无法解析
    if not _CONN_FIELDS:
        return None

    # 数据行按制表符分割
    values = line.split("\t")
    if len(values) != len(_CONN_FIELDS):
        # 字段数不匹配，跳过
        return None

    data = dict(zip(_CONN_FIELDS, values))

    try:
        ts_raw = data.get("ts")
        if not ts_raw or ts_raw in ("-", ""):
            return None
        ts = _parse_ts(ts_raw)

        return Flow(
            ts=ts,
            uid=data.get("uid", ""),
            orig_h=data.get("id.orig_h", ""),
            orig_p=_to_int(data.get("id.orig_p", "-")) or 0,
            resp_h=data.get("id.resp_h", ""),
            resp_p=_to_int(data.get("id.resp_p", "-")) or 0,
            proto=data.get("proto", ""),
            service=(data.get("service") or None) if data.get("service") not in ("-", "") else None,
            duration=_to_float(data.get("duration", "-")),
            orig_bytes=_to_int(data.get("orig_bytes", "-")),
            resp_bytes=_to_int(data.get("resp_bytes", "-")),
            conn_state=(data.get("conn_state") or None) if data.get("conn_state") not in ("-", "") else None,
        )
    except Exception:
        # 解析异常时返回 None，避免影响其他行
        return None
