from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Flow(BaseModel):
    """普通网络流量（基于 Zeek conn.log）"""

    ts: datetime = Field(..., description="时间戳")
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None


class ThreatEvent(BaseModel):
    """威胁/告警事件（基于 Zeek notice.log / intel.log / weird.log 等）"""

    ts: datetime = Field(..., description="时间戳")
    note: str
    msg: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    uid: Optional[str] = None
    proto: Optional[str] = None
    level: Optional[str] = Field(
        default=None,
        description="告警级别（如果可用）",
    )
    source: Optional[str] = Field(
        default=None,
        description="告警来源日志类型，例如 notice/intel/weird 等",
    )


class FlowAggregateBucket(BaseModel):
    """普通流量聚合桶"""

    bucket_start: datetime = Field(..., description="时间桶起始时间（含）")
    bucket_end: datetime = Field(..., description="时间桶结束时间（不含）")
    flow_count: int = Field(..., description="该时间桶内的流量条数")
    orig_bytes_sum: int = Field(..., description="orig_bytes 总和（缺失按 0 处理）")
    resp_bytes_sum: int = Field(..., description="resp_bytes 总和（缺失按 0 处理）")


class ThreatAggregateBucket(BaseModel):
    """威胁/告警聚合桶"""

    bucket_start: datetime = Field(..., description="时间桶起始时间（含）")
    bucket_end: datetime = Field(..., description="时间桶结束时间（不含）")
    threat_count: int = Field(..., description="该时间桶内的告警数量")
    by_level: dict[str, int] = Field(
        default_factory=dict, description="按 level 维度的计数"
    )
    by_note: dict[str, int] = Field(
        default_factory=dict, description="按 note 维度的计数"
    )


class ZeekStatus(BaseModel):
    running: bool
    pid: Optional[int] = None
    zeek_bin: str
    logs_dir: str
    iface: str


