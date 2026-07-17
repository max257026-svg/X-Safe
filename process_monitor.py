"""
X-Safe — 进程行为监控模块
Process Behavior Monitor: 检测从可疑目录启动的程序、可疑命令行参数、高危行为
"""

import os
import re
import time
import threading
from pathlib import Path
from typing import Callable, Optional
from dataclasses import dataclass, field
from enum import Enum


# psutil 是可选的 — 优雅降级
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ============================================================
# 可疑行为等级
# ============================================================
class BehaviorLevel(Enum):
    """行为威胁等级"""
    SUSPICIOUS = "suspicious"     # 可疑
    HIGH_RISK = "high_risk"      # 高危
    MALICIOUS = "malicious"      # 恶意


# ============================================================
# 检测结果
# ============================================================
@dataclass
class ProcessAlert:
    """可疑进程告警"""
    pid: int
    name: str
    exe_path: str
    cmdline: str
    cwd: str
    username: str
    create_time: float = 0.0
    level: BehaviorLevel = BehaviorLevel.SUSPICIOUS
    reason: str = ""
    details: str = ""
    parent_name: str = ""
    parent_pid: int = 0
    parent_path: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "level": self.level.value,
            "reason": self.reason,
            "details": self.details,
            "parent_name": self.parent_name,
            "parent_pid": self.parent_pid,
            "timestamp": self.timestamp,
        }


# ============================================================
# 进程行为监控器
# ============================================================
class ProcessMonitor:
    """进程行为监控 — 轮询检测可疑进程启动和命令行行为"""

    # 可疑目录列表 (程序从这些目录启动时告警)
    SUSPICIOUS_DIRS = [
        "\\temp\\", "\\tmp\\",
        "\\downloads\\", "\\download\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\programdata\\temp\\",
        "\\users\\public\\",
        "\\recycler\\", "\\$recycle.bin\\",
    ]

    # 可疑命令行模式 (正则)
    SUSPICIOUS_CMDLINE_PATTERNS: list[tuple[str, str, BehaviorLevel]] = [
        # 格式: (正则模式, 描述, 威胁等级)
        # — PowerShell 高危操作 —
        (r"-WindowStyle\s+Hidden.*-EncodedCommand", "PowerShell 隐藏窗口 + 编码命令", BehaviorLevel.MALICIOUS),
        (r"-WindowStyle\s+Hidden.*-Command", "PowerShell 隐藏窗口执行命令", BehaviorLevel.HIGH_RISK),
        (r"-EncodedCommand\s+\S{20,}", "PowerShell Base64 编码命令", BehaviorLevel.MALICIOUS),
        (r"IEX\s*\(\s*New-Object\s+Net\.WebClient\s*\)", "PowerShell 远程下载执行 (IEX)", BehaviorLevel.MALICIOUS),
        (r"Invoke-Expression.*Net\.WebClient", "PowerShell IEX WebClient", BehaviorLevel.MALICIOUS),
        (r"Invoke-Expression.*WebRequest", "PowerShell IEX WebRequest", BehaviorLevel.MALICIOUS),
        (r"Invoke-Expression.*DownloadString", "PowerShell IEX 下载执行", BehaviorLevel.MALICIOUS),
        (r"-NoProfile\s+-NonInteractive\s+-WindowStyle\s+Hidden", "PowerShell 无交互隐藏执行", BehaviorLevel.HIGH_RISK),
        (r"DownloadString\s*\(.*http", "PowerShell 远程下载字符串", BehaviorLevel.HIGH_RISK),
        (r"DownloadFile\s*\(.*http", "PowerShell 远程下载文件", BehaviorLevel.HIGH_RISK),
        (r"WebClient\s*\)\s*\.\s*Download", "PowerShell WebClient 下载", BehaviorLevel.HIGH_RISK),
        (r"Invoke-WmiMethod", "PowerShell WMI 执行", BehaviorLevel.SUSPICIOUS),
        (r"Invoke-CimMethod", "PowerShell CIM 执行", BehaviorLevel.SUSPICIOUS),
        (r"Start-Process.*-WindowStyle\s+Hidden", "PowerShell 隐藏启动进程", BehaviorLevel.HIGH_RISK),

        # — CMD/BAT 高危操作 —
        (r"regsvr32\s+/s\s+/u\s+/i:", "regsvr32 远程加载", BehaviorLevel.MALICIOUS),
        (r"rundll32\.exe.*javascript:", "rundll32 执行 JavaScript", BehaviorLevel.MALICIOUS),
        (r"mshta\s+http", "mshta 远程执行 HTML", BehaviorLevel.MALICIOUS),
        (r"certutil\s+-urlcache\s+-split\s+-f", "certutil 下载文件", BehaviorLevel.HIGH_RISK),
        (r"bitsadmin\s+/transfer", "bitsadmin 下载文件", BehaviorLevel.HIGH_RISK),
        (r"wmic\s+process\s+call\s+create", "WMIC 远程创建进程", BehaviorLevel.HIGH_RISK),
        (r"schtasks\s+/create.*/sc\s+onlogon", "计划任务持久化 (登录触发)", BehaviorLevel.HIGH_RISK),
        (r"schtasks\s+/create.*/sc\s+daily", "计划任务持久化 (每日)", BehaviorLevel.SUSPICIOUS),
        (r"reg\s+add.*\\Run", "注册表 Run 键持久化", BehaviorLevel.HIGH_RISK),
        (r"sc\s+create.*start=\s*auto", "创建自启动服务", BehaviorLevel.HIGH_RISK),

        # — VBS/JS —
        (r"wscript\.exe.*\.vbs", "VBScript 执行", BehaviorLevel.SUSPICIOUS),
        (r"cscript\.exe.*\.vbs", "VBScript 命令行执行", BehaviorLevel.SUSPICIOUS),

        # — 网络与远控 —
        (r"net\s+user\s+\S+\s+\S+\s+/add", "添加本地用户", BehaviorLevel.HIGH_RISK),
        (r"net\s+localgroup\s+administrators\s+\S+\s+/add", "添加管理员用户", BehaviorLevel.MALICIOUS),
        (r"netsh\s+advfirewall\s+firewall\s+add\s+rule", "添加防火墙规则", BehaviorLevel.SUSPICIOUS),

        # — 防御规避 —
        (r"reg\s+add.*DisableAntiSpyware", "禁用 Defender 反间谍", BehaviorLevel.MALICIOUS),
        (r"reg\s+add.*DisableRealtimeMonitoring", "禁用 Defender 实时防护", BehaviorLevel.MALICIOUS),
        (r"Set-MpPreference\s+-DisableRealtimeMonitoring", "禁用 Defender (PS)", BehaviorLevel.MALICIOUS),
        (r"Set-MpPreference\s+-DisableIOAVProtection", "禁用 Defender IOAV", BehaviorLevel.MALICIOUS),
    ]

    # 高危父子关系 — 某些父进程启动子进程高度可疑
    SUSPICIOUS_PARENT_CHILDREN: list[tuple[str, str, str, BehaviorLevel]] = [
        # (父进程名模式, 子进程名模式, 描述, 等级)
        ("winword.exe", "powershell.exe", "Word 启动 PowerShell (宏攻击)", BehaviorLevel.MALICIOUS),
        ("winword.exe", "cmd.exe", "Word 启动 CMD (宏攻击)", BehaviorLevel.MALICIOUS),
        ("excel.exe", "powershell.exe", "Excel 启动 PowerShell (宏攻击)", BehaviorLevel.MALICIOUS),
        ("excel.exe", "cmd.exe", "Excel 启动 CMD (宏攻击)", BehaviorLevel.MALICIOUS),
        ("outlook.exe", "powershell.exe", "Outlook 启动 PowerShell", BehaviorLevel.HIGH_RISK),
        ("outlook.exe", "cmd.exe", "Outlook 启动 CMD", BehaviorLevel.HIGH_RISK),
        ("wscript.exe", "powershell.exe", "WScript 启动 PowerShell", BehaviorLevel.HIGH_RISK),
        ("cscript.exe", "powershell.exe", "CScript 启动 PowerShell", BehaviorLevel.HIGH_RISK),
        ("mshta.exe", "powershell.exe", "MSHTA 启动 PowerShell", BehaviorLevel.MALICIOUS),
        ("javaw.exe", "powershell.exe", "Java 启动 PowerShell (Log4j类)", BehaviorLevel.HIGH_RISK),
        ("java.exe", "powershell.exe", "Java 启动 PowerShell", BehaviorLevel.HIGH_RISK),
        ("python.exe", "cmd.exe", "Python 启动 CMD", BehaviorLevel.SUSPICIOUS),
    ]

    # 可信进程 — 不告警的系统/已知安全进程
    TRUSTED_PROCESSES = {
        "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "smss.exe", "spoolsv.exe",
        "taskhostw.exe", "dwm.exe", "explorer.exe", "sihost.exe",
        "runtimebroker.exe", "searchindexer.exe", "ctfmon.exe",
        "applicationframehost.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "systemsettings.exe",
        "textinputhost.exe", "fontdrvhost.exe", "audiodg.exe",
        "conhost.exe", "msedge.exe", "chrome.exe", "firefox.exe",
        "code.exe", "workbuddy.exe",
    }

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._alert_callback: Optional[Callable[[ProcessAlert], None]] = None
        self._known_pids: set[int] = set()  # 已知的 PID 集合 (启动时忽略)
        self._alerted_pids: set[int] = set()  # 已告警的 PID (避免重复)
        self._stats = {
            "processes_scanned": 0,
            "alerts_triggered": 0,
        }
        self._lock = threading.Lock()
        self._poll_interval = 0.8  # 轮询间隔 (秒) — 缩短以提升可疑程序检测灵敏度
        self._enable_cmdline_check = True
        self._enable_parent_check = True
        self._enable_path_check = True

    @property
    def available(self) -> bool:
        return PSUTIL_AVAILABLE

    @property
    def running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def set_alert_callback(self, callback: Callable[[ProcessAlert], None]):
        """设置告警回调 — 当检测到可疑进程时调用"""
        self._alert_callback = callback

    def start(self):
        """启动进程监控"""
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil 库未安装，无法启动进程监控")

        if self._running:
            return

        # 记录当前运行的所有进程 PID，避免启动时误报
        self._known_pids = set(p.info["pid"] for p in psutil.process_iter(["pid"]))
        self._alerted_pids.clear()

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """停止进程监控"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _monitor_loop(self):
        """主监控循环"""
        while self._running:
            try:
                self._scan_processes()
            except Exception as e:
                # 静默处理 — 不给用户造成困扰
                if self._running:
                    pass
            time.sleep(self._poll_interval)

    def _scan_processes(self):
        """扫描所有运行中的进程"""
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cwd",
                                              "username", "create_time", "ppid"]):
                try:
                    pid = proc.info["pid"]
                    # 跳过已知进程
                    if pid in self._known_pids:
                        continue
                    if pid in self._alerted_pids:
                        continue

                    # 检查进程是否仍在运行
                    name = proc.info["name"] or ""
                    exe_path = proc.info["exe"] or ""
                    cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

                    # 跳过系统/可信进程
                    name_lower = name.lower()
                    if name_lower in self.TRUSTED_PROCESSES:
                        self._known_pids.add(pid)
                        continue

                    with self._lock:
                        self._stats["processes_scanned"] += 1

                    # 分级检测
                    alert = None

                    # 第一级: 检查从可疑目录启动
                    if self._enable_path_check and exe_path:
                        alert = self._check_suspicious_path(pid, proc)

                    # 第二级: 检查可疑命令行
                    if not alert and self._enable_cmdline_check and cmdline:
                        alert = self._check_suspicious_cmdline(pid, proc)

                    # 第三级: 检查可疑父子关系
                    if not alert and self._enable_parent_check and proc.info["ppid"]:
                        alert = self._check_suspicious_parent(pid, proc)

                    # 标记为已知 (无论是否告警，避免重复扫描)
                    self._known_pids.add(pid)

                    if alert:
                        self._alerted_pids.add(pid)
                        with self._lock:
                            self._stats["alerts_triggered"] += 1
                        if self._alert_callback:
                            try:
                                self._alert_callback(alert)
                            except Exception:
                                pass

                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess, OSError):
                    # 进程可能已退出 — 跳过
                    pass
                    if proc.info.get("pid"):
                        self._known_pids.add(proc.info["pid"])

        except Exception:
            # 整体迭代失败 — 静默处理
            pass

    def _check_suspicious_path(self, pid: int, proc) -> Optional[ProcessAlert]:
        """检查进程是否从可疑目录启动"""
        exe_path = (proc.info.get("exe") or "").lower()
        if not exe_path:
            return None

        # 检查是否从可疑目录启动
        for suspicious_dir in self.SUSPICIOUS_DIRS:
            if suspicious_dir in exe_path:
                # 创建告警
                return self._create_alert(pid, proc,
                    level=BehaviorLevel.SUSPICIOUS,
                    reason=f"程序从可疑目录启动: {suspicious_dir.strip(chr(92))}",
                    details=f"程序路径: {proc.info.get('exe')}\n"
                            f"可疑目录: {suspicious_dir}\n"
                            f"从下载/临时目录启动的可执行文件可能是恶意软件投放",
                )

        return None

    def _check_suspicious_cmdline(self, pid: int, proc) -> Optional[ProcessAlert]:
        """检查可疑命令行参数"""
        cmdline = " ".join(proc.info.get("cmdline") or [])
        if not cmdline:
            return None

        for pattern, description, level in self.SUSPICIOUS_CMDLINE_PATTERNS:
            try:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    return self._create_alert(pid, proc,
                        level=level,
                        reason=description,
                        details=f"命令行: {cmdline[:500]}\n"
                                f"检测模式: {description}",
                    )
            except re.error:
                pass

        return None

    def _check_suspicious_parent(self, pid: int, proc) -> Optional[ProcessAlert]:
        """检查可疑父子进程关系"""
        name = (proc.info.get("name") or "").lower()
        parent_pid = proc.info.get("ppid", 0)
        if not parent_pid or not name:
            return None

        parent_name = ""
        parent_path = ""
        try:
            parent = psutil.Process(parent_pid)
            parent_name = (parent.name() or "").lower()
            parent_path = parent.exe() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if not parent_name:
            return None

        for pname_pattern, cname_pattern, description, level in self.SUSPICIOUS_PARENT_CHILDREN:
            if pname_pattern in parent_name and cname_pattern in name:
                alert = self._create_alert(pid, proc,
                    level=level,
                    reason=description,
                    details=f"父进程: {parent_name} (PID: {parent_pid})\n"
                            f"子进程: {name} (PID: {pid})\n"
                            f"父进程路径: {parent_path}",
                )
                alert.parent_name = parent_name
                alert.parent_pid = parent_pid
                alert.parent_path = parent_path
                return alert

        return None

    def _create_alert(self, pid: int, proc, level: BehaviorLevel,
                      reason: str, details: str) -> ProcessAlert:
        """创建进程告警对象"""
        import datetime
        return ProcessAlert(
            pid=pid,
            name=proc.info.get("name") or "unknown",
            exe_path=proc.info.get("exe") or "unknown",
            cmdline=" ".join(proc.info.get("cmdline") or [])[:500],
            cwd=proc.info.get("cwd") or "",
            username=proc.info.get("username") or "",
            create_time=proc.info.get("create_time", 0.0),
            level=level,
            reason=reason,
            details=details,
            timestamp=datetime.datetime.now().isoformat(),
        )

    def terminate_process(self, pid: int) -> bool:
        """强制终止指定进程"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            # 等待进程退出
            proc.wait(timeout=5)
            return True
        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
            # 如果 terminate 失败，强杀
            try:
                proc = psutil.Process(pid)
                proc.kill()
                return True
            except psutil.NoSuchProcess:
                return True  # 进程已不存在
        except (psutil.AccessDenied, OSError):
            return False

    def terminate_process_tree(self, pid: int) -> tuple[int, int]:
        """终止进程及其所有子进程，返回 (成功, 失败)"""
        success = 0
        failed = 0
        try:
            proc = psutil.Process(pid)
            # 先终止子进程
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                    success += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    failed += 1
            # 再终止目标进程
            proc.kill()
            success += 1
        except psutil.NoSuchProcess:
            return (1, 0)  # 已退出也算成功
        except (psutil.AccessDenied, OSError):
            return (0, 1)
        return (success, failed)
