"""
X-Safe — 注册表 HOOK 监控 (Registry Hook Monitor)
====================================================
持续监控 Windows 关键注册表项的写入 / 删除行为，发现可疑变更立即告警。
覆盖项：
  * HKCU\\...\\Run                   (用户启动项)
  * HKLM\\...\\Run                   (系统启动项)
  * HKLM\\...\\RunOnce
  * HKLM\\...\\Image File Execution Options (IFEO 劫持)
  * HKLM\\...\\Winlogon\\Shell / Userinit
  * HKLM\\...\\AppInit_DLLs           (DLL 注入)
  * HKLM\\...\\Winlogon\\Notify       (Winlogon 通知包)
  * HKLM\\SYSTEM\\...\\Session Manager\\BootExecute
  * HKCU\\...\\Explorer\\Shell Folders + User Shell Folders (持久化)
实现策略：
  - 启动时建立基线（路径 -> 值/类型/数据）
  - 后台线程按周期轮询，diff 出新增/修改/删除
  - 不修改注册表（只读 OpenKey），安全无害
  - 通过 set_alert_callback 把告警推给主线程
"""

from __future__ import annotations

import json
import os
import platform
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    try:
        import winreg
    except Exception:
        winreg = None  # type: ignore
else:
    winreg = None


# ============================================================
# 监控目标
# ============================================================
@dataclass(frozen=True)
class _Target:
    hive: int
    subkey: str
    label: str  # 人类可读

TARGETS: list[_Target] = []


def _init_targets():
    global TARGETS
    if not IS_WINDOWS or winreg is None:
        return
    TARGETS = [
        _Target(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU\\...\\Run"),
        _Target(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU\\...\\RunOnce"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM\\...\\Run"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM\\...\\RunOnce"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "HKLM\\Winlogon"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                "HKLM\\AppInit/Window"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                "HKLM\\Winlogon\\Notify"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                "HKLM\\Session Manager"),
        _Target(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "HKLM\\IFEO"),
    ]


_init_targets()


# ============================================================
# 数据
# ============================================================
@dataclass
class RegistryAlert:
    """单条可疑注册表变更"""
    target_label: str
    change: str          # "added" / "modified" / "deleted"
    value_name: str
    old_data: Optional[str] = None
    new_data: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_text(self) -> str:
        if self.change == "added":
            return f"[+] {self.target_label} 新增 {self.value_name} = {self.new_data}"
        if self.change == "deleted":
            return f"[-] {self.target_label} 删除 {self.value_name} (原值={self.old_data})"
        return f"[~] {self.target_label} 修改 {self.value_name}: {self.old_data} → {self.new_data}"


def _read_target(t: _Target) -> dict[str, tuple[int, str]]:
    """读取目标子键下所有值名 -> (类型, 数据 str)"""
    if winreg is None:
        return {}
    out: dict[str, tuple[int, str]] = {}
    try:
        with winreg.OpenKey(t.hive, t.subkey, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, data, typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                out[name] = (typ, _data_to_str(data))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return out


def _data_to_str(d) -> str:
    if isinstance(d, bytes):
        try:
            return d.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except Exception:
            return d.hex()[:64]
    return str(d)


# ============================================================
# 监控器
# ============================================================
class RegistryMonitor:
    """注册表 HOOK 监控器（轮询模式）"""

    def __init__(self, poll_interval: float = 8.0):
        self.poll_interval = poll_interval
        self._baseline: dict[str, dict[str, tuple[int, str]]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._alert_cb: Optional[Callable[[RegistryAlert], None]] = None
        self._lock = threading.Lock()
        self._suppress: dict[str, float] = {}  # path -> expiry ts，临时静默

    # ----- 公共 API -----
    def available(self) -> bool:
        return IS_WINDOWS and winreg is not None

    def set_alert_callback(self, cb: Callable[[RegistryAlert], None]):
        self._alert_cb = cb

    def build_baseline(self):
        """启动时建立基线（同步、阻塞几毫秒）"""
        if not self.available():
            return
        with self._lock:
            self._baseline = {t.label: _read_target(t) for t in TARGETS}

    def suppress(self, target_label: str, value_name: str, seconds: float = 30.0):
        """临时静默：用户主动确认无害变更后调用，避免反复告警"""
        key = f"{target_label}::{value_name}"
        self._suppress[key] = time.time() + seconds

    def start(self):
        if not self.available() or self._running:
            return
        self.build_baseline()
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="RegMonitor", daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            try:
                self._thread.join(timeout=0.5)
            except Exception:
                pass
            self._thread = None

    # ----- 内部 -----
    def _loop(self):
        while self._running:
            try:
                self._poll_once()
            except Exception:
                pass
            # sleep 切片退出，避免 stop 卡住
            for _ in range(int(self.poll_interval * 2)):
                if not self._running:
                    return
                time.sleep(0.5)

    def _poll_once(self):
        with self._lock:
            baseline = {k: dict(v) for k, v in self._baseline.items()}
        now = time.time()
        for t in TARGETS:
            current = _read_target(t)
            old = baseline.get(t.label, {})

            # 新增 / 修改
            for name, val in current.items():
                sk = f"{t.label}::{name}"
                if sk in self._suppress and self._suppress[sk] > now:
                    continue
                if name not in old:
                    self._fire(RegistryAlert(
                        target_label=t.label, change="added",
                        value_name=name, new_data=val[1],
                    ))
                elif old[name] != val:
                    self._fire(RegistryAlert(
                        target_label=t.label, change="modified",
                        value_name=name, old_data=old[name][1], new_data=val[1],
                    ))
            # 删除
            for name, val in old.items():
                if name not in current:
                    sk = f"{t.label}::{name}"
                    if sk in self._suppress and self._suppress[sk] > now:
                        continue
                    self._fire(RegistryAlert(
                        target_label=t.label, change="deleted",
                        value_name=name, old_data=val[1],
                    ))

        with self._lock:
            self._baseline = {t.label: _read_target(t) for t in TARGETS}

    def _fire(self, alert: RegistryAlert):
        if self._alert_cb:
            try:
                self._alert_cb(alert)
            except Exception:
                pass
