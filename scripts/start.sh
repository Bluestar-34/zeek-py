#!/usr/bin/env bash
set -euo pipefail

# One-click start script:
# - auto-detect zeek binary
# - auto-detect capture interface
# - bootstrap Python venv
# - start FastAPI and auto-start Zeek

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[zeek-py] 项目根目录: $ROOT_DIR"

fix_rules_config_perms() {
  local cfg_dir="$ROOT_DIR/zeek_scripts"
  local cfg_file="$cfg_dir/rules_config.json"
  local current_uid="${EUID:-$(id -u)}"
  local target_user

  # 希望最终由谁来写这个文件：
  # - 如果是通过 sudo 调用的脚本，则用 SUDO_USER
  # - 否则就用当前用户
  target_user="${SUDO_USER:-$USER}"
  : "${target_user:=$USER}"

  echo "[zeek-py] 调整规则配置目录/文件权限（使用 sudo 如有需要）: user=$target_user"

  # 目录：确保存在并可由 target_user 写
  if [[ "$current_uid" -eq 0 ]]; then
    mkdir -p "$cfg_dir"
    chown "$target_user:$target_user" "$cfg_dir" 2>/dev/null || true
    chmod 755 "$cfg_dir" 2>/dev/null || true
  else
    mkdir -p "$cfg_dir"
    if command -v sudo >/dev/null 2>&1; then
      sudo chown "$target_user:$target_user" "$cfg_dir" 2>/dev/null || true
      sudo chmod 755 "$cfg_dir" 2>/dev/null || true
    else
      chmod 755 "$cfg_dir" 2>/dev/null || true
      echo "[zeek-py] ⚠️ 没有 sudo，仅能本地调整目录权限，如仍有问题请手动 chown: $cfg_dir"
    fi
  fi

  if [[ -f "$cfg_file" ]]; then
    # 如果文件存在，不管当前是否可写，都强制修复属主和权限
    echo "[zeek-py] 规则配置文件存在，强制修复属主和权限: $cfg_file"
    if [[ "$current_uid" -eq 0 ]]; then
      chown "$target_user:$target_user" "$cfg_file" 2>/dev/null || true
      chmod 664 "$cfg_file" 2>/dev/null || true
    else
      if command -v sudo >/dev/null 2>&1; then
        sudo chown "$target_user:$target_user" "$cfg_file" 2>/dev/null || true
        sudo chmod 664 "$cfg_file" 2>/dev/null || true
      else
        chmod 664 "$cfg_file" 2>/dev/null || true
        echo "[zeek-py] ⚠️ 无法使用 sudo 修复 rules_config.json，请手动执行："
        echo "       chown $target_user:$target_user \"$cfg_file\" && chmod 664 \"$cfg_file\""
      fi
    fi
  else
    # 创建一个最小的默认配置文件（如果不存在）
    echo "[zeek-py] 初始化规则配置文件: $cfg_file"
    mkdir -p "$cfg_dir"
    cat >"$cfg_file" <<'EOF'
{
  "enabled_rules": [],
  "custom_rule": "",
  "data_retention_days": 7,
  "data_display_days": 7
}
EOF
    chmod 644 "$cfg_file" 2>/dev/null || true
  fi
}

detect_zeek_bin() {
  if [[ -n "${ZEEK_BIN:-}" ]]; then
    echo "$ZEEK_BIN"
    return 0
  fi
  if command -v zeek >/dev/null 2>&1; then
    command -v zeek
    return 0
  fi
  for p in /usr/bin/zeek /usr/local/bin/zeek /opt/zeek/bin/zeek; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

detect_iface() {
  if [[ -n "${ZEEK_IFACE:-}" ]]; then
    echo "$ZEEK_IFACE"
    return 0
  fi
  # Prefer default-route interface
  local dev
  dev="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
  if [[ -n "${dev:-}" ]]; then
    echo "$dev"
    return 0
  fi
  # Fallback: first non-loopback interface
  dev="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -vE '^(lo|docker.*|br-.*|veth.*|tun.*|tap.*)$' | head -n1 || true)"
  if [[ -n "${dev:-}" ]]; then
    echo "$dev"
    return 0
  fi
  echo "eth0"
}

if ! ZEEK_BIN_DETECTED="$(detect_zeek_bin)"; then
  echo "[zeek-py] 未找到 Zeek，可先安装: sudo apt install -y zeek-7.0"
  exit 1
fi
export ZEEK_BIN="$ZEEK_BIN_DETECTED"
echo "[zeek-py] 使用 Zeek: $ZEEK_BIN"

export ZEEK_LOGS_DIR="${ZEEK_LOGS_DIR:-$ROOT_DIR/logs}"
mkdir -p "$ZEEK_LOGS_DIR"
echo "[zeek-py] 日志目录: $ZEEK_LOGS_DIR"

export ZEEK_IFACE="$(detect_iface)"
echo "[zeek-py] 抓包网卡: $ZEEK_IFACE"

print_checks() {
  echo "----------------------------------------"
  echo "[zeek-py] 运行前自检 / 问题排查提示"
  echo "1) 确认网卡是否存在："
  echo "   ip link show \"$ZEEK_IFACE\""
  if ip link show "$ZEEK_IFACE" >/dev/null 2>&1; then
    echo "   ✅ 网卡 \"$ZEEK_IFACE\" 存在"
  else
    echo "   ⚠️ 网卡 \"$ZEEK_IFACE\" 不存在，请检查 ZEEK_IFACE 或使用："
    echo "      ZEEK_IFACE=实际网卡 ./scripts/start.sh"
  fi
  echo
  echo "2) Zeek 日志输出目录检查："
  echo "   当前目录: $ZEEK_LOGS_DIR"
  if ls "$ZEEK_LOGS_DIR"/*.log >/dev/null 2>&1; then
    echo "   ✅ 发现已有 Zeek 日志文件："
    ls -l "$ZEEK_LOGS_DIR"/*.log || true
  else
    echo "   ℹ️ 暂未发现 *.log 文件，属于以下情况之一："
    echo "      - FastAPI/Zeek 还未启动或刚启动"
    echo "      - 还没有实际网络流量被捕获"
    echo "      - Zeek 启动失败（可查看 API 日志 stderr）"
  fi
  echo
  echo "3) 启动后如果界面没有流量："
  echo "   - 用 ps 检查 Zeek 是否在运行（API 会负责拉起 Zeek）："
  echo "       ps aux | grep zeek"
  echo "   - 再次查看日志目录是否有 conn.log/notice.log："
  echo "       ls -l \"$ZEEK_LOGS_DIR\""
  echo "   - 确认当前网卡上确实有流量（如 tcpdump -i \"$ZEEK_IFACE\"）"
  echo "----------------------------------------"
}

export API_HOST="${API_HOST:-0.0.0.0}"
export API_PORT="${API_PORT:-8000}"
echo "[zeek-py] API 监听: http://${API_HOST}:${API_PORT}"

# dev default: auto start zeek
export AUTO_START_ZEEK="${AUTO_START_ZEEK:-1}"
echo "[zeek-py] AUTO_START_ZEEK: $AUTO_START_ZEEK"

bootstrap_venv() {
  if [[ ! -d "venv" ]]; then
    echo "[zeek-py] 创建 Python 虚拟环境..."
    python3 -m venv venv
  fi
  echo "[zeek-py] 安装/更新依赖..."
  ./venv/bin/pip install --upgrade pip >/dev/null
  ./venv/bin/pip install -r requirements.txt >/dev/null
}

start_api_as_root_if_needed() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[zeek-py] 抓包需要权限，使用 sudo 启动服务..."
    exec sudo -E ./venv/bin/uvicorn zeek_py.api:create_app --factory --host "${API_HOST}" --port "${API_PORT}"
  fi
  echo "[zeek-py] 启动 FastAPI (uvicorn)..."
  exec ./venv/bin/uvicorn zeek_py.api:create_app --factory --host "${API_HOST}" --port "${API_PORT}"
}

bootstrap_venv
fix_rules_config_perms
print_checks
start_api_as_root_if_needed


