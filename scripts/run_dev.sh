#!/usr/bin/env bash
set -euo pipefail

# 切到项目根目录
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[zeek-py] 项目根目录: $ROOT_DIR"

# 检测 / 选择 Zeek 可执行文件
if [[ -z "${ZEEK_BIN:-}" ]]; then
  if command -v zeek >/dev/null 2>&1; then
    ZEEK_BIN="$(command -v zeek)"
  elif [[ -x "/usr/bin/zeek" ]]; then
    ZEEK_BIN="/usr/bin/zeek"
  elif [[ -x "/usr/local/bin/zeek" ]]; then
    ZEEK_BIN="/usr/local/bin/zeek"
  else
    echo "未找到 Zeek 可执行文件，请先执行: sudo apt install -y zeek-7.0"
    exit 1
  fi
fi
export ZEEK_BIN
echo "[zeek-py] 使用 Zeek: $ZEEK_BIN"

# 日志目录
export ZEEK_LOGS_DIR="${ZEEK_LOGS_DIR:-$ROOT_DIR/logs}"
mkdir -p "$ZEEK_LOGS_DIR"
echo "[zeek-py] 日志目录: $ZEEK_LOGS_DIR"

# 抓包网卡
export ZEEK_IFACE="${ZEEK_IFACE:-eth0}"
echo "[zeek-py] 抓包网卡: $ZEEK_IFACE"

# API 监听地址与端口
export API_HOST="${API_HOST:-0.0.0.0}"
export API_PORT="${API_PORT:-8000}"
echo "[zeek-py] API 监听: http://${API_HOST}:${API_PORT}"

# 是否自动启动 Zeek（开发默认开启）
export AUTO_START_ZEEK="${AUTO_START_ZEEK:-1}"
echo "[zeek-py] AUTO_START_ZEEK: $AUTO_START_ZEEK"

# Python 虚拟环境
if [[ ! -d "venv" ]]; then
  echo "[zeek-py] 创建 Python 虚拟环境..."
  python3 -m venv venv
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install -r requirements.txt
fi

echo "[zeek-py] 启动 FastAPI (uvicorn)..."
exec ./venv/bin/uvicorn zeek_py.api:create_app --factory --host "${API_HOST}" --port "${API_PORT}"


