"""
X-Safe — 实时文件监控 + 进程行为监控模块
Real-time File System Monitor (watchdog) + Process Behavior Monitor (psutil)
"""

import os
import time
import threading
from pathlib import Path
from typing import Callable, Optional

# watchdog may not be installed — graceful fallback
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object

# 进程监控
try:
    from process_monitor import ProcessMonitor, ProcessAlert, BehaviorLevel
    PROCESS_MONITOR_AVAILABLE = True
except ImportError:
    PROCESS_MONITOR_AVAILABLE = False
    ProcessMonitor = None
    ProcessAlert = None
    BehaviorLevel = None


class FileMonitorHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """文件系统事件处理器"""

    def __init__(self, callback: Callable[[str, str], None],
                 extensions: Optional[set[str]] = None):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self._callback = callback
        self._extensions = extensions
        self._debounce: dict[str, float] = {}
        self._debounce_interval = 1.0  # 去重间隔（秒）

    def _should_process(self, filepath: str, event_type: str) -> bool:
        """判断是否应该处理该事件"""
        # 防抖：1秒内同一文件同一事件只处理一次
        key = f"{filepath}:{event_type}"
        now = time.time()
        if key in self._debounce and now - self._debounce[key] < self._debounce_interval:
            return False
        self._debounce[key] = now

        # 扩展名过滤
        if self._extensions:
            ext = Path(filepath).suffix.lower()
            if ext and ext not in self._extensions:
                return False

        # 跳过临时文件
        name = Path(filepath).name.lower()
        skip_patterns = [
            ".tmp", ".temp", "~$", ".crdownload", ".part",
            ".download", ".bak", ".swp", ".swo",
        ]
        for pat in skip_patterns:
            if pat in name or name.endswith(pat):
                return False

        return True

    def on_created(self, event):
        if event.is_directory:
            return
        if self._should_process(event.src_path, "created"):
            self._callback(event.src_path, "created")

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._should_process(event.src_path, "modified"):
            self._callback(event.src_path, "modified")

    def on_moved(self, event):
        if event.is_directory:
            return
        if self._should_process(event.dest_path, "moved"):
            self._callback(event.dest_path, "moved")


class RealTimeMonitor:
    """实时监控服务 — 文件系统监控 + 进程行为监控"""

    def __init__(self, scanner, quarantine_manager):
        """
        Args:
            scanner: AntivirusScanner 实例
            quarantine_manager: QuarantineManager 实例
        """
        self._scanner = scanner
        self._quarantine = quarantine_manager
        self._observer: Optional[Observer] = None if not WATCHDOG_AVAILABLE else None
        self._proc_monitor = ProcessMonitor() if PROCESS_MONITOR_AVAILABLE else None
        self._running = False
        self._monitored_paths: list[str] = []
        self._alert_callback: Optional[Callable] = None
        self._proc_alert_callback: Optional[Callable] = None  # 进程告警专用回调
        self._stats = {"files_scanned": 0, "threats_detected": 0,
                       "proc_alerts": 0}
        self._lock = threading.Lock()
        self._last_proc_alert_pid: int = 0  # 最近进程告警 PID，用于关联文件隔离

    @property
    def available(self) -> bool:
        return WATCHDOG_AVAILABLE

    @property
    def proc_monitor_available(self) -> bool:
        return PROCESS_MONITOR_AVAILABLE

    @property
    def running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    @property
    def last_proc_alert_pid(self) -> int:
        """获取最近一次进程告警的 PID"""
        return self._last_proc_alert_pid

    def set_alert_callback(self, callback: Callable):
        """设置威胁告警回调 (文件检测)"""
        self._alert_callback = callback

    def set_proc_alert_callback(self, callback: Callable):
        """设置进程行为告警回调"""
        self._proc_alert_callback = callback

    def start(self, paths: list[str], enable_proc_monitor: bool = True):
        """启动实时监控

        Args:
            paths: 文件系统监控目录
            enable_proc_monitor: 是否启用进程行为监控
        """
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("watchdog 库未安装，无法启动实时监控")

        if self._running:
            return

        self._monitored_paths = [p for p in paths if os.path.exists(p)]
        if not self._monitored_paths:
            raise ValueError("没有有效的监控路径")

        self._observer = Observer()

        # 危险扩展名集合（高危文件类型重点监控）
        dangerous_exts = {
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".hta", ".scr", ".pif", ".msi", ".com", ".py",
            ".php", ".pl", ".rb", ".sh",
        }

        handler = FileMonitorHandler(
            callback=self._on_file_event,
            extensions=dangerous_exts,
        )

        for path in self._monitored_paths:
            self._observer.schedule(handler, path, recursive=True)

        self._observer.start()

        # 启动进程行为监控
        if enable_proc_monitor and self._proc_monitor:
            try:
                self._proc_monitor.set_alert_callback(self._on_process_alert)
                self._proc_monitor.start()
            except Exception:
                pass  # 进程监控启动失败不影响文件监控

        self._running = True

    def stop(self):
        """停止实时监控"""
        if not self._running:
            return

        # 停止进程监控
        if self._proc_monitor and self._proc_monitor.running:
            try:
                self._proc_monitor.stop()
            except Exception:
                pass

        # 停止文件监控
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

        self._running = False

    def _on_file_event(self, filepath: str, event_type: str):
        """文件事件回调 — 自动扫描新文件"""
        # 等待文件写入完成（简单策略）
        time.sleep(0.3)

        if not os.path.exists(filepath):
            return

        # 检查文件大小
        try:
            size = os.path.getsize(filepath)
            if size > 100 * 1024 * 1024:  # 跳过大于100MB的文件
                return
        except OSError:
            return

        # 扫描文件
        result = self._scanner.scan_file(filepath)

        with self._lock:
            self._stats["files_scanned"] += 1

        if result.is_threat:
            with self._lock:
                self._stats["threats_detected"] += 1

            # 自动隔离高危威胁
            if result.threat_level.value in ("malicious", "high_risk"):
                try:
                    self._quarantine.quarantine_file(result)
                except Exception:
                    pass

            # 触发告警
            if self._alert_callback:
                self._alert_callback(result)

    def _on_process_alert(self, alert: ProcessAlert):
        """进程行为告警回调"""
        with self._lock:
            self._stats["proc_alerts"] += 1

        self._last_proc_alert_pid = alert.pid

        # 触发进程专用告警回调
        if self._proc_alert_callback:
            self._proc_alert_callback(alert)

    def block_process(self, pid: int) -> bool:
        """阻止指定进程 — 终止进程树"""
        if not self._proc_monitor:
            return False
        return self._proc_monitor.terminate_process(pid)

    def block_process_tree(self, pid: int) -> tuple[int, int]:
        """阻止进程树 — 终止进程及其所有子进程"""
        if not self._proc_monitor:
            return (0, 1)
        return self._proc_monitor.terminate_process_tree(pid)

    def quarantine_process_file(self, pid: int) -> bool:
        """隔离进程对应的可执行文件"""
        if not self._proc_monitor:
            return False

        # 获取进程的可执行文件路径
        exe_path = ""
        try:
            import psutil
            proc = psutil.Process(pid)
            exe_path = proc.exe()
        except Exception:
            pass

        if not exe_path or not os.path.exists(exe_path):
            return False

        # 先终止进程再隔离文件
        self._proc_monitor.terminate_process(pid)

        # 使用扫描器扫描并隔离
        result = self._scanner.scan_file(exe_path)
        if result.is_threat or True:  # 进程可疑即隔离
            try:
                return self._quarantine.quarantine_file(result)
            except Exception:
                return False
        return False

    def get_monitored_paths(self) -> list[str]:
        return list(self._monitored_paths)
