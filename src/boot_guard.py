r"""
X-Safe — 引导分区保护 (Boot Guard)
===================================
读取 MBR / VBR 的内容，计算哈希形成基线，发现变化即告警。
设计要点：
  - 不写引导区，只读
  - 用管理员权限打开 \\.\PhysicalDrive0 读第 0 扇区
  - 基线落盘到 appdata/xsafe_boot_baseline.json
  - 跨平台抽象：非 Windows 全部走 SKIP 路径
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

IS_WINDOWS = platform.system().lower() == "windows"

try:
    if IS_WINDOWS:
        import ctypes
        from ctypes import wintypes
    else:
        ctypes = None  # type: ignore
except Exception:
    ctypes = None


@dataclass
class BootEntry:
    """单条引导区快照"""
    label: str          # "MBR" / "VBR_C:" / ...
    sha256: str
    size: int
    captured_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


@dataclass
class BootSnapshot:
    entries: list[BootEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"entries": [asdict(e) for e in self.entries]}

    @classmethod
    def from_dict(cls, d: dict) -> "BootSnapshot":
        return cls(entries=[BootEntry(**e) for e in d.get("entries", [])])


# ============================================================
# 路径
# ============================================================
def _baseline_path() -> Path:
    """基线 JSON 落盘位置：%APPDATA%/xsafe/boot_baseline.json"""
    if IS_WINDOWS:
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path.home() / ".config"
    d = base / "xsafe"
    d.mkdir(parents=True, exist_ok=True)
    return d / "boot_baseline.json"


# ============================================================
# Windows：直接读 PhysicalDrive 头 512 字节（MBR）
# ============================================================
def _read_mbr_windows() -> Optional[bytes]:
    if not IS_WINDOWS or ctypes is None:
        return None
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1  # ctypes signed pointer

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE
    ReadFile = ctypes.windll.kernel32.ReadFile
    ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    ReadFile.restype = wintypes.BOOL
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    handle = CreateFileW(
        r"\\.\PhysicalDrive0", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
    )
    if handle in (None, INVALID_HANDLE_VALUE, wintypes.HANDLE(-1).value):
        return None
    try:
        buf = (ctypes.c_ubyte * 512)()
        got = wintypes.DWORD(0)
        ok = ReadFile(handle, ctypes.byref(buf), 512, ctypes.byref(got), None)
        if not ok or got.value == 0:
            return None
        return bytes(buf[: got.value])
    finally:
        CloseHandle(handle)


# ============================================================
# 公共入口
# ============================================================
class BootGuard:
    """MBR/VBR 哈希基线守护器"""

    def __init__(self, baseline_file: Optional[Path] = None):
        self.baseline_file = baseline_file or _baseline_path()
        self._baseline: Optional[BootSnapshot] = self._load_baseline()

    # ----- 基线管理 -----
    def _load_baseline(self) -> Optional[BootSnapshot]:
        if not self.baseline_file.exists():
            return None
        try:
            with open(self.baseline_file, "r", encoding="utf-8") as f:
                return BootSnapshot.from_dict(json.load(f))
        except Exception:
            return None

    def save_baseline(self, snap: BootSnapshot) -> None:
        try:
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(snap.to_dict(), f, ensure_ascii=False, indent=2)
            self._baseline = snap
        except Exception:
            pass

    # ----- 快照 -----
    def snapshot(self) -> BootSnapshot:
        snap = BootSnapshot()
        if IS_WINDOWS:
            mbr = _read_mbr_windows()
            if mbr:
                snap.entries.append(BootEntry(
                    label="MBR_PhysicalDrive0",
                    sha256=hashlib.sha256(mbr).hexdigest(),
                    size=len(mbr),
                ))
        return snap

    # ----- 比对 -----
    def diff_baseline(self, current: BootSnapshot) -> Optional[list[str]]:
        """返回变化列表；baseline 不存在时返回 None（视为"首次建基线"）。"""
        if self._baseline is None:
            return None
        b = {e.label: e for e in self._baseline.entries}
        c = {e.label: e for e in current.entries}
        changes: list[str] = []
        # 缺 / 新增
        for label in set(b) | set(c):
            if label not in b:
                changes.append(f"新增引导区项 {label}")
            elif label not in c:
                changes.append(f"引导区项消失 {label}")
            elif b[label].sha256 != c[label].sha256:
                changes.append(f"引导区哈希变化 {label}")
        return changes
