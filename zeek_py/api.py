from __future__ import annotations

import os
from datetime import datetime, timezone
import time
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import settings
from .models import (
    Flow,
    # 新增 HTTP 流量模型目前仍沿用 Flow 结构，如后续需要可单独扩展
    ThreatEvent,
    ZeekStatus,
    FlowAggregateBucket,
    ThreatAggregateBucket,
)
from .storage import storage
from .zeek_runner import zeek_runner

import json
from pathlib import Path
import subprocess

app = FastAPI(title="Zeek-Py 网络流量分析 API")

# 简单模板环境（用于前端单页）
templates_env = Environment(
    loader=FileSystemLoader(str(settings.project_root / "frontend")),
    autoescape=select_autoescape(["html", "xml"]),
)


@app.get("/", response_class=HTMLResponse)
def index_page() -> str:
    template = templates_env.get_template("index.html")
    return template.render()


@app.get("/api/status", response_model=ZeekStatus)
def api_status() -> ZeekStatus:
    return ZeekStatus(
        running=zeek_runner.running,
        pid=zeek_runner.pid,
        zeek_bin=str(settings.zeek_bin),
        logs_dir=str(settings.logs_dir),
        iface=settings.capture_iface,
    )


@app.post("/api/control/start")
def api_start_zeek() -> dict:
    if zeek_runner.running:
        return {"ok": True, "message": "Zeek 已在运行"}
    try:
        zeek_runner.start()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # 启动后短暂等待一下，确认进程没有立刻退出，否则前端会感觉“点了启动但马上又变未运行”
    time.sleep(1.0)
    if not zeek_runner.running:
        raise HTTPException(
            status_code=500,
            detail=(
                "Zeek 进程启动后立即退出，请检查 Zeek 配置/网卡权限，"
                "并查看日志目录中的 zeek_stderr.log 获取详细错误信息。"
            ),
        )

    return {"ok": True, "message": "Zeek 已启动"}


@app.post("/api/control/stop")
def api_stop_zeek() -> dict:
    if not zeek_runner.running:
        return {"ok": True, "message": "Zeek 未运行"}
    zeek_runner.stop()
    return {"ok": True, "message": "Zeek 已停止"}


@app.get("/api/flows", response_model=List[Flow])
def api_list_flows(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[Flow]:
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_flows(limit=limit, since=since_dt)


@app.get("/api/flows/http", response_model=List[Flow])
def api_list_http_flows(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[Flow]:
    """
    HTTP 流量明细接口：基于 /api/flows 结果进行筛选，只返回 service 为 http 的流。

    如后续需要更丰富的 HTTP 维度（method/host/uri 等），可以在 models/storage 中
    扩展专门的 HttpFlow 结构，并从 Zeek http.log 解析注入。
    """
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    all_flows = storage.list_flows(limit=10_000, since=since_dt)
    http_flows = [f for f in all_flows if (f.service or "").lower() == "http"]
    # 按时间排序后截取最新 limit 条，避免返回过多
    http_flows_sorted = sorted(http_flows, key=lambda f: f.ts)[-limit:]
    return http_flows_sorted


@app.get("/api/threats", response_model=List[ThreatEvent])
def api_list_threats(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[ThreatEvent]:
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_threats(limit=limit, since=since_dt)


@app.get("/api/logs/notice", response_model=List[ThreatEvent])
def api_list_notice_logs(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[ThreatEvent]:
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_threats(limit=limit, since=since_dt, source="notice")


@app.get("/api/logs/intel", response_model=List[ThreatEvent])
def api_list_intel_logs(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[ThreatEvent]:
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_threats(limit=limit, since=since_dt, source="intel")


@app.get("/api/logs/weird", response_model=List[ThreatEvent])
def api_list_weird_logs(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[ThreatEvent]:
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_threats(limit=limit, since=since_dt, source="weird")


@app.get("/api/logs/conn", response_model=List[Flow])
def api_list_conn_logs(
    limit: int = Query(100, ge=1, le=1000),
    since_ts: Optional[float] = Query(None, description="从此 UNIX 时间戳（秒）之后的记录"),
) -> List[Flow]:
    """
    conn.log 明细接口，语义上等价于 /api/flows，便于前端按“日志类型”访问。
    """
    since_dt = (
        datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts is not None else None
    )
    return storage.list_flows(limit=limit, since=since_dt)


@app.get("/api/flows/aggregate", response_model=List[FlowAggregateBucket])
def api_aggregate_flows(
    bucket_seconds: int = Query(60, ge=1, le=3600, description="聚合时间桶大小（秒）"),
    since_ts: Optional[float] = Query(
        None, description="从此 UNIX 时间戳（秒）之后的记录参与聚合"
    ),
) -> List[FlowAggregateBucket]:
    """
    普通流量聚合接口：按时间桶统计流量数量和字节数。
    """
    from datetime import timezone

    since_dt = datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts else None
    flows = storage.list_flows(limit=10_000, since=since_dt)

    buckets: dict[int, FlowAggregateBucket] = {}
    for f in flows:
        ts_sec = int(f.ts.timestamp())
        bucket_start_sec = ts_sec - (ts_sec % bucket_seconds)
        bucket_end_sec = bucket_start_sec + bucket_seconds

        key = bucket_start_sec
        if key not in buckets:
            buckets[key] = FlowAggregateBucket(
                bucket_start=datetime.fromtimestamp(bucket_start_sec, tz=f.ts.tzinfo),
                bucket_end=datetime.fromtimestamp(bucket_end_sec, tz=f.ts.tzinfo),
                flow_count=0,
                orig_bytes_sum=0,
                resp_bytes_sum=0,
            )

        b = buckets[key]
        b.flow_count += 1
        b.orig_bytes_sum += f.orig_bytes or 0
        b.resp_bytes_sum += f.resp_bytes or 0

    return [buckets[k] for k in sorted(buckets.keys())]


@app.get("/api/threats/aggregate", response_model=List[ThreatAggregateBucket])
def api_aggregate_threats(
    bucket_seconds: int = Query(60, ge=1, le=3600, description="聚合时间桶大小（秒）"),
    since_ts: Optional[float] = Query(
        None, description="从此 UNIX 时间戳（秒）之后的记录参与聚合"
    ),
) -> List[ThreatAggregateBucket]:
    """
    威胁/告警聚合接口：按时间桶统计威胁数量，并按 level/note 细分。
    """
    from datetime import timezone

    since_dt = datetime.fromtimestamp(since_ts, tz=timezone.utc) if since_ts else None
    threats = storage.list_threats(limit=10_000, since=since_dt)

    buckets: dict[int, ThreatAggregateBucket] = {}
    for t in threats:
        ts_sec = int(t.ts.timestamp())
        bucket_start_sec = ts_sec - (ts_sec % bucket_seconds)
        bucket_end_sec = bucket_start_sec + bucket_seconds

        key = bucket_start_sec
        if key not in buckets:
            buckets[key] = ThreatAggregateBucket(
                bucket_start=datetime.fromtimestamp(bucket_start_sec, tz=t.ts.tzinfo),
                bucket_end=datetime.fromtimestamp(bucket_end_sec, tz=t.ts.tzinfo),
                threat_count=0,
            )

        b = buckets[key]
        b.threat_count += 1
        if t.level:
            b.by_level[t.level] = b.by_level.get(t.level, 0) + 1
        if t.note:
            b.by_note[t.note] = b.by_note.get(t.note, 0) + 1

    return [buckets[k] for k in sorted(buckets.keys())]


@app.get("/api/rules")
def api_get_rules() -> dict:
    """
    获取当前规则配置：
    {
        "enabled_rules": [...],
        "custom_rule": "...",
        "data_retention_days": 7,
        "data_display_days": 7
    }
    """
    config_path = settings.zeek_scripts_dir / "rules_config.json"
    if not config_path.is_file():
        # 默认 7 天
        return {
            "enabled_rules": [],
            "custom_rule": "",
            "data_retention_days": 7,
            "data_display_days": 7,
        }

    try:
        with config_path.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    # 兼容旧版本：字段缺失时给默认值 7
    return {
        "enabled_rules": cfg.get("enabled_rules") or [],
        "custom_rule": cfg.get("custom_rule") or "",
        "data_retention_days": cfg.get("data_retention_days") or 7,
        "data_display_days": cfg.get("data_display_days") or 7,
    }


@app.post("/api/rules")
def api_set_rules(payload: dict = Body(...)) -> dict:
    """
    保存规则配置。

    请求体示例：
    {
        "enabled_rules": ["policy/protocols/conn/scan", "custom/portscan"],
        "custom_rule": "event zeek_init() { ... }",
        "data_retention_days": 7,
        "data_display_days": 7
    }
    """
    enabled_rules = payload.get("enabled_rules") or []
    custom_rule = payload.get("custom_rule") or ""
    data_retention_days_raw = payload.get("data_retention_days", 7)
    data_display_days_raw = payload.get("data_display_days", 7)

    if not isinstance(enabled_rules, list):
        raise HTTPException(status_code=400, detail="enabled_rules 必须为数组")
    if not isinstance(custom_rule, str):
        raise HTTPException(status_code=400, detail="custom_rule 必须为字符串")

    # 数据保存时间 / 显示时间（天），允许前端传字符串，后端做一次 int 转换
    try:
        data_retention_days = int(data_retention_days_raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="data_retention_days 必须为整数")
    try:
        data_display_days = int(data_display_days_raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="data_display_days 必须为整数")

    if data_retention_days <= 0:
        raise HTTPException(status_code=400, detail="data_retention_days 必须大于 0")
    if data_display_days <= 0:
        raise HTTPException(status_code=400, detail="data_display_days 必须大于 0")

    # 只保存简单 JSON，由 zeek_runner 在启动前生成 local.zeek
    config_path: Path = settings.zeek_scripts_dir / "rules_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "enabled_rules": enabled_rules,
        "custom_rule": custom_rule,
        "data_retention_days": data_retention_days,
        "data_display_days": data_display_days,
    }
    try:
        with config_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"无法写入规则配置文件: {config_path}. "
                "请检查该文件和目录的权限（例如使用 chown/chmod 让运行 FastAPI 的用户可写），"
                "然后重试。"
            ),
        )
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"保存规则配置失败（{e.__class__.__name__}: {e}）",
        )

    return {"ok": True}


@app.post("/api/rules/validate")
def api_validate_rules(payload: dict = Body(...)) -> dict:
    """
    校验给定规则路径在当前 Zeek 环境中是否可加载。

    请求体示例：
    {
        "rules": ["policy/protocols/conn/scan", "policy/frameworks/notice/weird-manager"]
    }

    返回：
    {
        "ok": true,
        "invalid": [],
        "detail": ""
    }
    """
    rules = payload.get("rules") or []
    if not isinstance(rules, list):
        raise HTTPException(status_code=400, detail="rules 必须为数组")

    invalid: list[str] = []

    for rule in rules:
        if not isinstance(rule, str):
            invalid.append(str(rule))
            continue
        # 只对 Zeek 内置脚本路径做检查，custom/* 之类前端自己管理
        if not (rule.startswith("policy/") or rule.startswith("base/")):
            continue

        # 调用 Zeek 检查脚本是否存在：
        # zeek -N <script-path>
        try:
            proc = subprocess.run(
                [str(settings.zeek_bin), "-N", rule],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5.0,
            )
        except Exception:
            # Zeek 不可用时，直接认为此规则无效，防止运行期崩溃
            invalid.append(rule)
            continue

        if proc.returncode != 0:
            invalid.append(rule)

    return {
        "ok": len(invalid) == 0,
        "invalid": invalid,
        "detail": "" if not invalid else "部分规则在当前 Zeek 环境中不可加载",
    }


def create_app() -> FastAPI:
    """
    提供给 uvicorn 调用的入口：
    uvicorn zeek_py.api:create_app --factory
    """
    return app


@app.on_event("startup")
def _startup_autostart_zeek() -> None:
    """
    开发/演示模式下可自动启动 Zeek，避免“API 已启动但没有流量”的困惑。

    通过环境变量控制：AUTO_START_ZEEK=1/true/yes/on
    """
    flag = os.environ.get("AUTO_START_ZEEK", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        try:
            zeek_runner.start()
        except Exception:
            # API 应能起来，即使 Zeek 启动失败（例如网卡权限问题）
            pass


