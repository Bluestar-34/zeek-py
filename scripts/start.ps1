Param(
  [string]$Distro = "Ubuntu"
)

# One-click launcher for Windows + WSL.
# Run this from PowerShell in the repo root.

$ErrorActionPreference = "Stop"

if (!(Test-Path -Path ".\scripts\start.sh")) {
  throw "请在项目根目录运行本脚本（需要存在 scripts/start.sh）"
}

Write-Host "[zeek-py] WSL distro: $Distro"
Write-Host "[zeek-py] 启动中..."

# Use bash -lc so we can cd + chmod + run in one go
wsl -d $Distro -e bash -lc "cd '$PWD' && chmod +x scripts/start.sh && ./scripts/start.sh"


