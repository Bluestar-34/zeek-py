from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .config import settings
from .storage import storage


class ZeekRunner:
    """
    负责启动/停止 Zeek，并持续解析日志写入 storage。

    初版策略：
    - 使用接口抓取实时流量：zeek -i <iface> local.zeek（在 local.zeek 中启用 JSON writer）
    - Zeek 进程与日志目录在同一进程内管理。
    - 解析线程定期扫描 conn.log / notice.log / intel.log 增量更新。
    """

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._parser_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_conn_size: int = 0
        self._last_notice_size: int = 0
        self._last_intel_size: int = 0
        self._last_weird_size: int = 0

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self.running and self._proc else None

    def start(self) -> None:
        if self.running:
            return
        if not settings.zeek_exists:
            raise RuntimeError(f"Zeek 不存在或不可执行: {settings.zeek_bin}")

        # 在启动 Zeek 前，根据规则配置生成 local.zeek
        try:
            self._prepare_local_zeek()
        except Exception as e:
            # 不因为规则配置失败而阻止启动，但打印提示
            print(f"[zeek-runner] 生成 local.zeek 失败: {e}")

        logs_dir: Path = settings.logs_dir
        logs_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(settings.zeek_bin),
            "-i",
            settings.capture_iface,
            "-b",  # 不做 stdout buffer
            f"Log::default_logdir={logs_dir}",
            str(settings.zeek_scripts_dir / "local.zeek"),
        ]

        self._stop_event.clear()
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # 独立线程持续读取 Zeek stderr，写入日志文件，方便排查启动/运行问题
        def _stderr_pump(proc: subprocess.Popen, log_path: Path) -> None:
            try:
                with log_path.open("a", encoding="utf-8", errors="ignore") as log_f:
                    if proc.stderr is None:
                        return
                    for line in proc.stderr:
                        # 同时写入文件与标准输出（方便在终端直接看到）
                        log_f.write(line)
                        log_f.flush()
                        print(f"[zeek stderr] {line.rstrip()}")
            except Exception:
                # 不因日志线程异常影响主流程
                pass

        self._stderr_thread = threading.Thread(
            target=_stderr_pump,
            args=(self._proc, logs_dir / "zeek_stderr.log"),
            name="zeek-stderr-logger",
            daemon=True,
        )
        self._stderr_thread.start()

        # 启动解析线程
        self._parser_thread = threading.Thread(
            target=self._parser_loop, name="zeek-log-parser", daemon=True
        )
        self._parser_thread.start()

    def _prepare_local_zeek(self) -> None:
        """
        根据 /api/rules 保存的配置文件生成 Zeek 启动使用的 local.zeek。

        规则配置文件格式（JSON）示例：
        {
            "enabled_rules": ["policy/protocols/conn/scan", "custom/portscan"],
            "custom_rule": "event zeek_init() { ... }"
        }
        """
        import json
        import subprocess

        config_path = settings.zeek_scripts_dir / "rules_config.json"
        local_zeek_path = settings.zeek_scripts_dir / "local.zeek"

        enabled_rules = []
        custom_rule = ""

        if config_path.is_file():
            with config_path.open("r", encoding="utf-8") as f:
                try:
                    cfg = json.load(f)
                except json.JSONDecodeError:
                    cfg = {}
            enabled_rules = cfg.get("enabled_rules") or []
            custom_rule = cfg.get("custom_rule") or ""

        lines = []
        # 基础必要模块
        lines.append("@load base/protocols/conn")
        lines.append("@load base/frameworks/notice")
        lines.append("@load base/frameworks/intel")
        lines.append("")

        # 已启用规则（Zeek 官方脚本通常直接 @load 路径）
        for rule in enabled_rules:
            # 自定义规则占位（例如 custom/portscan），具体逻辑可在 custom_rule 中实现
            if rule.startswith("custom/"):
                lines.append(f"# custom rule: {rule}")
                continue

            # 只对 Zeek 内置脚本路径做一次本地校验，避免因为版本差异导致 Zeek 无法启动
            if rule.startswith("policy/") or rule.startswith("base/"):
                try:
                    proc = subprocess.run(
                        [str(settings.zeek_bin), "-N", rule],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=5.0,
                    )
                except Exception:
                    # Zeek 无法执行时，为了不影响启动，直接忽略此规则
                    lines.append(f"# skipped rule (zeek -N 失败): {rule}")
                    continue

                if proc.returncode != 0:
                    # 记录一行注释，方便在生成的 local.zeek 中排查
                    lines.append(f"# skipped rule (not available in this Zeek): {rule}")
                    continue

                # 校验通过，真正加载
                lines.append(f"@load {rule}")
            else:
                # 未知类型的 key，写成注释避免把 Zeek 弄挂
                lines.append(f"# unknown rule key: {rule}")

        lines.append("")
        if custom_rule.strip():
            lines.append("# ---- custom rule snippet begin ----")
            lines.append(custom_rule)
            lines.append("# ---- custom rule snippet end ----")

        with local_zeek_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def stop(self) -> None:
        self._stop_event.set()
        if self._proc and self.running:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _parser_loop(self) -> None:
        """
        简单轮询日志文件大小变化，重新解析整个文件。
        为了实现简单可靠，使用“按字节偏移”的增量读取策略：
        - 记录上次读取到的文件大小（字节数）；
        - 如果文件变大，只解析新增的部分；
        - 如果文件变小（如轮转），从头重新解析。
        """
        conn_log = settings.logs_dir / "conn.log"
        notice_log = settings.logs_dir / "notice.log"
        intel_log = settings.logs_dir / "intel.log"
        weird_log = settings.logs_dir / "weird.log"

        while not self._stop_event.is_set():
            try:
                # conn.log
                if conn_log.is_file():
                    size = conn_log.stat().st_size
                    # 文件被截断/轮转：从头开始
                    if size < self._last_conn_size:
                        self._last_conn_size = 0

                    if size > self._last_conn_size:
                        # 仅解析新增部分
                        with conn_log.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._last_conn_size)
                            for line in f:
                                from .parsers.conn_parser import parse_conn_line

                                flow = parse_conn_line(line)
                                if flow:
                                    storage.add_flow(flow)
                        self._last_conn_size = size

                # notice.log
                if notice_log.is_file():
                    size = notice_log.stat().st_size
                    if size < self._last_notice_size:
                        self._last_notice_size = 0

                    if size > self._last_notice_size:
                        with notice_log.open(
                            "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            f.seek(self._last_notice_size)
                            for line in f:
                                from .parsers.threat_parser import parse_notice_line

                                ev = parse_notice_line(line)
                                if ev:
                                    storage.add_threat(ev)
                        self._last_notice_size = size

                # intel.log
                if intel_log.is_file():
                    size = intel_log.stat().st_size
                    if size < self._last_intel_size:
                        self._last_intel_size = 0

                    if size > self._last_intel_size:
                        with intel_log.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._last_intel_size)
                            for line in f:
                                from .parsers.threat_parser import parse_intel_line

                                ev = parse_intel_line(line)
                                if ev:
                                    storage.add_threat(ev)
                        self._last_intel_size = size

                # weird.log 也视作“告警”来源之一
                if weird_log.is_file():
                    size = weird_log.stat().st_size
                    if size < self._last_weird_size:
                        self._last_weird_size = 0

                    if size > self._last_weird_size:
                        with weird_log.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._last_weird_size)
                            for line in f:
                                from .parsers.threat_parser import parse_weird_line

                                ev = parse_weird_line(line)
                                if ev:
                                    storage.add_threat(ev)
                        self._last_weird_size = size
            except Exception:
                # 解析线程不应因异常退出，简单忽略错误
                pass

            time.sleep(2.0)


zeek_runner = ZeekRunner()


