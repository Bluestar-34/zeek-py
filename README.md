## Zeek-Py 网络流量采集与分析框架

本项目目标：

- **Python 为框架**：提供 HTTP API 与基础前端，用于管理与查询流量数据。
- **Zeek 为引擎**：利用 Zeek 抓取网络流量，输出普通流量与威胁流量日志。
- **自动化与通用部署**：默认基于 `sudo apt install zeek-7.0` 安装的 Zeek，兼容多数 Linux 发行版，提供一键启动脚本。
- **基础可视化前端**：提供精简的 Web 页面，控制 Zeek 运行与查看关键流量/告警指标。

### 目录结构（规划）

- `zeek_py/`
  - `__init__.py`
  - `config.py`：全局配置（Zeek 路径、日志路径、接口端口等）。
  - `zeek_runner.py`：负责启动/停止 Zeek、加载脚本、管理日志输出。
  - `parsers/`
    - `__init__.py`
    - `conn_parser.py`：普通流量（连接日志）解析。
    - `threat_parser.py`：威胁/告警日志解析（如 `notice.log` / `intel.log`）。
  - `models.py`：数据模型与类型定义。
  - `api.py`：FastAPI / Flask HTTP 接口。
  - `storage.py`：内存或简单数据库存储层（可后续替换为 Redis / PostgreSQL）。
- `zeek_scripts/`
  - `local.zeek`：额外启用的 Zeek 脚本配置，用于输出需要的日志。
- `frontend/`
  - `index.html`：精简控制台与可视化页面。
- `scripts/`
  - `run_dev.sh`：开发环境一键启动脚本（Linux）。

### 基本思路

1. **Zeek 日志输出（JSON）**  
   - 使用 Zeek 的 `conn.log`（JSON 行）代表普通网络流量。  
   - 使用 `notice.log` / `intel.log`（JSON 行）（或自定义脚本）代表威胁/异常流量。  
   - 通过 `zeek_scripts/local.zeek` 启用 `Log::WRITER_JSON`，所有日志以 JSON 行形式输出，Python 直接解析原生 JSON。  

2. **Python 后端**  
   - 监控 Zeek 日志目录（轮询或简单的 tail）。  
   - 实时解析新增日志，写入内存缓存或轻量数据库。  
   - 提供 HTTP API：  
     - `/api/flows`：查询普通流量。  
     - `/api/threats`：查询威胁流量。  
     - `/api/status`：Zeek 运行状态。  
     - `/api/control/start` / `/api/control/stop`：控制 Zeek。  

3. **前端页面**  
   - 调用上述 API 展示：当前 Zeek 状态、最近连接列表、最近威胁告警、简单图表（按时间统计等）。  

### 部署与运行（一键脚本）

```bash
# 1. 安装 Zeek（已由系统提供）
sudo apt install -y zeek-7.0

# 2. 授权并一键启动
chmod +x scripts/start.sh
./scripts/start.sh
```

脚本会自动：

- 检测 `zeek` 可执行文件（默认 `/usr/bin/zeek` 等路径）。  
- 创建虚拟环境并安装依赖。  
- 自动选择抓包网卡（默认路由网卡优先，可用 `ZEEK_IFACE` 覆盖）。  
- 设置 `ZEEK_LOGS_DIR`、`ZEEK_IFACE` 等环境变量（可自行覆盖）。  
- 启动 FastAPI 服务 `uvicorn zeek_py.api:create_app`，并默认 `AUTO_START_ZEEK=1` 自动启动 Zeek。  
- 前端页面为 `http://<HOST>:<PORT>/`。  

Windows（WSL）也可一键：

```powershell
.\scripts\start.ps1
```

后续的代码实现会与上述设计保持一致，尽量做到配置自动化与跨 Linux 通用。


