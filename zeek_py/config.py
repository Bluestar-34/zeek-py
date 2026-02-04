from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class Settings:
    """
    全局配置。

    默认假设 Zeek 通过 `apt install zeek-7.0` 安装：
    - 可执行文件：`/usr/bin/zeek` 或 `/usr/local/bin/zeek`
    - 系统 Zeek 脚本目录：`/usr/share/zeek`（如有需要再用）
    """

    def __init__(self) -> None:
        self.project_root: Path = Path(__file__).resolve().parent.parent

        # Zeek 可执行路径，允许通过环境变量覆盖
        self.zeek_bin: Path = Path(
            os.environ.get("ZEEK_BIN", "/usr/bin/zeek")
        )

        # 日志输出目录（Zeek 将写入此处，Python 解析）
        self.logs_dir: Path = Path(
            os.environ.get("ZEEK_LOGS_DIR", self.project_root / "logs")
        )

        # Zeek 自定义脚本目录
        self.zeek_scripts_dir: Path = self.project_root / "zeek_scripts"

        # 网络接口（抓实时流量），可通过环境变量修改
        self.capture_iface: str = os.environ.get("ZEEK_IFACE", "eth0")

        # Python API 监听地址与端口
        self.api_host: str = os.environ.get("API_HOST", "0.0.0.0")
        self.api_port: int = int(os.environ.get("API_PORT", "8000"))

    @property
    def zeek_exists(self) -> bool:
        return self.zeek_bin.is_file() and os.access(self.zeek_bin, os.X_OK)


settings = Settings()


