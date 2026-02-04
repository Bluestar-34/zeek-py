from __future__ import annotations

import threading
from collections import deque
from datetime import datetime
from typing import Deque, List, Optional

from .models import Flow, ThreatEvent


class InMemoryStorage:
    """
    简单的内存存储，适合初版与开发调试。

    - 使用 deque 限制最大条目数，防止内存无限增长。
    """

    def __init__(self, max_flows: int = 10_000, max_threats: int = 10_000) -> None:
        self._flows: Deque[Flow] = deque(maxlen=max_flows)
        self._threats: Deque[ThreatEvent] = deque(maxlen=max_threats)
        self._lock = threading.Lock()

    def add_flow(self, flow: Flow) -> None:
        with self._lock:
            self._flows.append(flow)

    def add_threat(self, threat: ThreatEvent) -> None:
        with self._lock:
            self._threats.append(threat)

    def list_flows(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[Flow]:
        with self._lock:
            items = list(self._flows)
        if since:
            items = [f for f in items if f.ts >= since]
        return items[-limit:]

    def list_threats(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        source: Optional[str] = None,
    ) -> List[ThreatEvent]:
        with self._lock:
            items = list(self._threats)
        if since:
            items = [t for t in items if t.ts >= since]
        if source:
            items = [t for t in items if t.source == source]
        return items[-limit:]


storage = InMemoryStorage()


