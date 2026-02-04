## Zeek-Py API 文档

本项目基于 FastAPI，所有后端接口前缀为 `/api/...`，返回 JSON。  
核心模型定义在 `zeek_py/models.py`，接口定义在 `zeek_py/api.py`。

---

## 公共数据模型

### Flow

普通网络流量（基于 Zeek `conn.log`）：

```json
{
  "ts": "2025-02-04T12:34:56.789Z",
  "uid": "C8t9a81fW2B1gK7D3",
  "orig_h": "192.168.1.10",
  "orig_p": 54321,
  "resp_h": "93.184.216.34",
  "resp_p": 80,
  "proto": "tcp",
  "service": "http",
  "duration": 1.234,
  "orig_bytes": 512,
  "resp_bytes": 2048,
  "conn_state": "SF"
}
```

字段说明：

- **ts**: 时间戳 `datetime`
- **uid**: Zeek 连接唯一 ID
- **orig_h / orig_p**: 源 IP / 源端口
- **resp_h / resp_p**: 目的 IP / 目的端口
- **proto**: 协议（如 `tcp` / `udp`）
- **service**: 应用层服务名（如 `http`，可为空）
- **duration**: 连接持续时间（秒，可为空）
- **orig_bytes / resp_bytes**: 双向字节数（可为空）
- **conn_state**: 连接状态代码（如 `SF`）

---

### ThreatEvent

威胁 / 告警事件（基于 `notice.log` / `intel.log` / `weird.log` 等）：

```json
{
  "ts": "2025-02-04T12:35:00.123Z",
  "note": "Scan::Port_Scan",
  "msg": "Possible port scan detected",
  "src": "192.168.1.10",
  "dst": "93.184.216.34",
  "uid": "C8t9a81fW2B1gK7D3",
  "proto": "tcp",
  "level": "Notice",
  "source": "notice"
}
```

字段说明：

- **ts**: 时间戳 `datetime`
- **note**: 告警类型标识
- **msg**: 告警描述信息（可为空）
- **src / dst**: 源 / 目的地址（可以是 IP 或其他标识，可为空）
- **uid**: 关联连接的 UID（如果存在，可为空）
- **proto**: 协议（可为空）
- **level**: 告警级别（如 Notice/Warning，可为空）
- **source**: 告警来源日志类型（如 `notice` / `intel` / `weird`）

---

### FlowAggregateBucket

普通流量聚合桶：

```json
{
  "bucket_start": "2025-02-04T12:30:00Z",
  "bucket_end": "2025-02-04T12:31:00Z",
  "flow_count": 120,
  "orig_bytes_sum": 123456,
  "resp_bytes_sum": 234567
}
```

字段说明：

- **bucket_start / bucket_end**: 时间桶起止时间（起始含，结束不含）
- **flow_count**: 桶内流量条数
- **orig_bytes_sum / resp_bytes_sum**: 字节数总和（缺失按 0 处理）

---

### ThreatAggregateBucket

威胁 / 告警聚合桶：

```json
{
  "bucket_start": "2025-02-04T12:30:00Z",
  "bucket_end": "2025-02-04T12:31:00Z",
  "threat_count": 10,
  "by_level": {
    "Notice": 8,
    "Warning": 2
  },
  "by_note": {
    "Scan::Port_Scan": 5,
    "Intel::Seen": 5
  }
}
```

字段说明：

- **bucket_start / bucket_end**: 时间桶起止时间
- **threat_count**: 桶内告警总数
- **by_level**: 按 `level` 维度的计数
- **by_note**: 按 `note` 维度的计数

---

### ZeekStatus

Zeek 运行状态：

```json
{
  "running": true,
  "pid": 12345,
  "zeek_bin": "/usr/bin/zeek",
  "logs_dir": "/opt/zeek/logs",
  "iface": "eth0"
}
```

字段说明：

- **running**: Zeek 是否正在运行
- **pid**: Zeek 进程 PID（未运行时为空）
- **zeek_bin**: Zeek 可执行文件路径
- **logs_dir**: Zeek 日志目录
- **iface**: 当前抓取的网络接口

---

## 页面与基础路由

### GET `/`

- **描述**: 返回前端单页 HTML（仪表盘 UI）。
- **请求参数**: 无
- **响应内容**: HTML 页面。

---

## Zeek 状态与控制

### GET `/api/status`

- **描述**: 获取当前 Zeek 运行状态与配置信息。
- **查询参数**: 无
- **响应模型**: `ZeekStatus`

示例：

```http
GET /api/status HTTP/1.1
Host: 127.0.0.1:8000
```

---

### POST `/api/control/start`

- **描述**: 启动 Zeek 采集进程。
- **请求体**: 无
- **响应示例**:

```json
{ "ok": true, "message": "Zeek 已启动" }
```

可能错误：

- Zeek 已在运行时仍返回 200，但 `message` 为 `"Zeek 已在运行"`。
- Zeek 启动失败（如权限/配置问题）时返回 500，并在 `detail` 中说明原因。

---

### POST `/api/control/stop`

- **描述**: 停止 Zeek 采集进程。
- **请求体**: 无
- **响应示例**:

```json
{ "ok": true, "message": "Zeek 已停止" }
```

Zeek 未运行时同样返回 200，`message` 为 `"Zeek 未运行"`。

---

## 流量明细接口

### GET `/api/flows`

- **描述**: 普通网络流量明细接口，基于 Zeek `conn.log`。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`，返回最大条数。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒），只返回该时间之后的记录。
- **响应模型**: `Flow[]`

示例：

```http
GET /api/flows?limit=100&since_ts=1738660000 HTTP/1.1
Host: 127.0.0.1:8000
```

---

### GET `/api/flows/http`

- **描述**: HTTP 流量明细接口。基于 `/api/flows` 结果筛选，只返回 `service == "http"` 的流。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `Flow[]`

实现说明：

- 内部会调用 `storage.list_flows(limit=10000, since=since_dt)` 读取至多 10000 条记录；
- 按 `service` 字段过滤出 HTTP 流量；
- 按时间排序，仅保留最新的 `limit` 条。

示例：

```http
GET /api/flows/http?limit=50&since_ts=1738660000 HTTP/1.1
Host: 127.0.0.1:8000
```

---

### GET `/api/logs/conn`

- **描述**: `conn.log` 明细接口，语义上等价于 `/api/flows`，主要方便前端以“日志类型”视角访问。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `Flow[]`

---

## 流量聚合接口

### GET `/api/flows/aggregate`

- **描述**: 按时间桶聚合普通流量，统计条数和字节数。
- **查询参数**:
  - **bucket_seconds**: `int`，默认 `60`，范围 `[1, 3600]`，时间桶大小（秒）。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒），只聚合该时间之后的流量。
- **响应模型**: `FlowAggregateBucket[]`

行为说明：

- 内部最多读取 `10000` 条 `Flow`；
- 将每条记录的时间戳按 `bucket_seconds` 整除划分时间桶；
- 对每个桶统计 `flow_count`、`orig_bytes_sum`、`resp_bytes_sum`。

示例：

```http
GET /api/flows/aggregate?bucket_seconds=60&since_ts=1738660000 HTTP/1.1
Host: 127.0.0.1:8000
```

---

## 威胁 / 告警明细接口

### GET `/api/threats`

- **描述**: 综合威胁 / 告警事件列表，包含 `notice` / `intel` / `weird` 等来源。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `ThreatEvent[]`

---

### GET `/api/logs/notice`

- **描述**: 仅返回 `notice.log` 来源的威胁事件。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `ThreatEvent[]`

内部实现调用 `storage.list_threats(..., source="notice")`。

---

### GET `/api/logs/intel`

- **描述**: 仅返回 `intel.log` 来源的威胁事件。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `ThreatEvent[]`

---

### GET `/api/logs/weird`

- **描述**: 仅返回 `weird.log` 来源的“异常”事件。
- **查询参数**:
  - **limit**: `int`，默认 `100`，范围 `[1, 1000]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `ThreatEvent[]`

---

## 威胁聚合接口

### GET `/api/threats/aggregate`

- **描述**: 按时间桶聚合威胁 / 告警事件，统计数量，并细分 `level` / `note`。
- **查询参数**:
  - **bucket_seconds**: `int`，默认 `60`，范围 `[1, 3600]`。
  - **since_ts**: `float`，可选，UNIX 时间戳（秒）。
- **响应模型**: `ThreatAggregateBucket[]`

行为说明：

- 内部最多读取 `10000` 条 `ThreatEvent`；
- 将每条记录时间戳按 `bucket_seconds` 整除划分时间桶；
- 对每条告警：
  - `threat_count += 1`
  - 若有 `level`，对应的 `by_level[level] += 1`
  - 若有 `note`，对应的 `by_note[note] += 1`

---

## 规则配置接口

### GET `/api/rules`

- **描述**: 获取当前规则配置：`rules_config.json`。若文件不存在，则返回默认配置。
- **请求体**: 无
- **响应示例**:

```json
{
  "enabled_rules": [
    "policy/protocols/conn/scan",
    "custom/portscan"
  ],
  "custom_rule": "event zeek_init() { ... }",
  "data_retention_days": 7,
  "data_display_days": 7
}
```

字段说明：

- **enabled_rules**: 启用的 Zeek 规则脚本路径数组。
- **custom_rule**: 自定义规则脚本内容。
- **data_retention_days**: 数据保存时间（天）。
- **data_display_days**: 默认展示时间范围（天）。

---

### POST `/api/rules`

- **描述**: 保存（覆盖）规则配置到 `rules_config.json`，由 `zeek_runner` 在启动前生成 `local.zeek`。
- **请求体示例**:

```json
{
  "enabled_rules": ["policy/protocols/conn/scan", "custom/portscan"],
  "custom_rule": "event zeek_init() { ... }",
  "data_retention_days": 7,
  "data_display_days": 7
}
```

校验规则：

- `enabled_rules` 必须为数组；
- `custom_rule` 必须为字符串；
- `data_retention_days` / `data_display_days` 允许传字符串，后端会转换为 `int`；
- 两个天数字段必须大于 0。

响应：

```json
{ "ok": true }
```

错误情况：

- 400：字段类型错误或天数非正整数；
- 500：无法写入配置文件（包含详细错误信息）。

---

### POST `/api/rules/validate`

- **描述**: 校验给定规则路径在当前 Zeek 环境中是否可加载（调用 `zeek -N <script-path>`）。
- **请求体示例**:

```json
{
  "rules": [
    "policy/protocols/conn/scan",
    "policy/frameworks/notice/weird-manager"
  ]
}
```

- **响应示例（全部有效）**:

```json
{
  "ok": true,
  "invalid": [],
  "detail": ""
}
```

- **响应示例（部分无效）**:

```json
{
  "ok": false,
  "invalid": ["policy/protocols/conn/scan"],
  "detail": "部分规则在当前 Zeek 环境中不可加载"
}
```

行为说明：

- 仅对以 `policy/` 或 `base/` 开头的规则做实际检查；
- 若 Zeek 不可用或脚本不存在，则规则被视为无效；
- 其他路径（如 `custom/*`）前端自行管理。

---

## 应用启动行为

### 工厂函数

- **函数**: `create_app() -> FastAPI`
- **用途**: 允许通过工厂模式启动应用，例如：

```bash
uvicorn zeek_py.api:create_app --factory
```

---

### 启动事件：AUTO_START_ZEEK

- **事件**: `@app.on_event("startup")`
- **行为**:
  - 读取环境变量 `AUTO_START_ZEEK`；
  - 若值为 `1` / `true` / `yes` / `on`（不区分大小写），则在应用启动时自动调用 `zeek_runner.start()` 启动 Zeek；
  - 即使 Zeek 启动失败，API 也会照常启动（异常会被忽略）。

这样在开发 / 演示环境下，可以做到“启动 API 即自动开始抓取流量”。


