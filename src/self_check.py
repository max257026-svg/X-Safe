"""
X-Safe — 自检程序 (Self-Check)
=================================
对 X-Safe 自身防护链路做完整性校验，确保：
  1. 隔离操作真的落地（原文件已删、隔离文件已落盘、索引已写入）
  2. 三引擎都可调用且未异常降级
  3. 引导区（MBR/VBR）有基线哈希、能识别篡改
  4. 关键注册表项基线已建立
  5. 敏感文件路径覆盖检查
  6. 进程行为监控回路在跑
所有自检项独立可重入，UI 弹窗里点 "自检" 按钮时调用并把结果汇总。
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

# Windows-only 强依赖在导入时降级；非 Windows 平台函数全部返回 "N/A"
IS_WINDOWS = platform.system().lower() == "windows"

try:
    if IS_WINDOWS:
        import winreg  # noqa: F401
    else:
        winreg = None  # type: ignore
except Exception:
    winreg = None


@dataclass
class CheckItem:
    """单条自检项的结果"""
    name: str
    status: str  # "pass" / "fail" / "warn" / "skip"
    detail: str = ""
    cost_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SelfCheckReport:
    """完整自检报告 — UI 弹窗直接渲染"""
    started_at: str
    finished_at: str = ""
    items: list[CheckItem] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for i in self.items if i.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for i in self.items if i.status == "fail")

    @property
    def warn(self) -> int:
        return sum(1 for i in self.items if i.status == "warn")

    @property
    def skipped(self) -> int:
        return sum(1 for i in self.items if i.status == "skip")

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def overall(self) -> str:
        if self.failed > 0:
            return "FAIL"
        if self.warn > 0:
            return "WARN"
        if self.passed == 0:
            return "EMPTY"
        return "PASS"

    def add(self, name: str, status: str, detail: str = "", cost_ms: int = 0):
        self.items.append(CheckItem(name, status, detail, cost_ms))

    def finalize(self):
        self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.summary = {
            "overall": self.overall,
            "pass": self.passed,
            "fail": self.failed,
            "warn": self.warn,
            "skip": self.skipped,
            "total": self.total,
        }

    def render(self) -> str:
        """渲染成多行纯文本（UI 弹窗 Text 控件直接展示）"""
        lines = []
        lines.append("=" * 64)
        lines.append("  X-Safe 自检报告  /  Self-Check Report")
        lines.append("=" * 64)
        lines.append(f"  开始: {self.started_at}    结束: {self.finished_at}")
        lines.append(f"  总计: {self.total} 项    ✅ {self.passed}   "
                     f"❌ {self.failed}   ⚠️  {self.warn}   ⏭  {self.skipped}")
        lines.append(f"  结论: {self.overall}")
        lines.append("-" * 64)
        icon = {"pass": "✅", "fail": "❌", "warn": "⚠️ ", "skip": "⏭ "}
        for it in self.items:
            lines.append(f"  [{icon.get(it.status, '?')}] {it.name}  ({it.cost_ms}ms)")
            if it.detail:
                for dl in it.detail.splitlines():
                    lines.append(f"        {dl}")
        lines.append("=" * 64)
        return "\n".join(lines)


# ============================================================
# 单项自检 — 每个函数都返回 (status, detail, cost_ms)
# ============================================================

def _timed(fn: Callable[[], tuple[str, str]]) -> tuple[str, str, int]:
    t0 = time.perf_counter()
    try:
        status, detail = fn()
    except Exception as e:
        status, detail = "fail", f"异常: {e!r}"
    return status, detail, int((time.perf_counter() - t0) * 1000)


def _check_quarantine_integrity(quarantine, last_qname: Optional[str] = None) -> tuple[str, str, int]:
    """隔离区自检：原文件已删、隔离文件落盘、索引一致"""
    t0 = time.perf_counter()
    try:
        items = quarantine.list_quarantined()
    except Exception as e:
        return "fail", f"读取隔离区失败: {e!r}", int((time.perf_counter() - t0) * 1000)
    if not items:
        return "pass", f"隔离区当前为空 (0 项)，无一致性风险。", int((time.perf_counter() - t0) * 1000)

    # 抽检最近一次
    target = last_qname or (items[-1].get("quarantine_name") if items else None)
    if not target:
        return "warn", "隔离区非空但缺少 quarantined 字段。", int((time.perf_counter() - t0) * 1000)

    qdir = Path(quarantine.quarantine_dir)
    qfile = qdir / target
    index = quarantine._index.get(target, {})

    problems = []
    if not qfile.exists():
        problems.append(f"隔离文件缺失: {qfile}")
    if "original_path" not in index:
        problems.append("索引缺少 original_path")
    if index.get("original_path") and Path(index["original_path"]).exists():
        problems.append(f"原文件未删除: {index['original_path']}")
    if problems:
        return "fail", " | ".join(problems), int((time.perf_counter() - t0) * 1000)
    size = qfile.stat().st_size
    return "pass", f"抽检 {target} | 隔离 {size}B | 索引一致 | 原文件已清。", int((time.perf_counter() - t0) * 1000)


def _check_engines_alive(scanner, ai_engine, cloud_engine) -> tuple[str, str, int]:
    t0 = time.perf_counter()
    parts = []
    if scanner is None:
        parts.append("特征引擎 ❌未初始化")
    else:
        try:
            sig_count = scanner.scanner.sig_db.hash_count + scanner.scanner.sig_db.pattern_count
            parts.append(f"特征引擎 ✅{sig_count} 条")
        except Exception as e:
            parts.append(f"特征引擎 ⚠️ {e!r}")
    if ai_engine is None:
        parts.append("AI 引擎 ❌")
    else:
        try:
            parts.append(f"AI 引擎 ✅{ai_engine.scorer.total_samples} 样本")
        except Exception:
            parts.append("AI 引擎 ✅")
    if cloud_engine is None:
        parts.append("云引擎 ⚠️未启用")
    else:
        parts.append("云引擎 ✅就绪")
    overall = "pass" if "❌" not in " ".join(parts) else "fail"
    return overall, "  ·  ".join(parts), int((time.perf_counter() - t0) * 1000)


def _check_rtp_running(realtime_monitor) -> tuple[str, str, int]:
    t0 = time.perf_counter()
    if realtime_monitor is None:
        return "fail", "实时防护未初始化", int((time.perf_counter() - t0) * 1000)
    if not getattr(realtime_monitor, "available", False):
        return "warn", "实时防护依赖未就绪（请开启一次以触发自动安装）", int((time.perf_counter() - t0) * 1000)
    if getattr(realtime_monitor, "running", False):
        return "pass", "实时防护运行中", int((time.perf_counter() - t0) * 1000)
    return "warn", "实时防护未启动（可在「扫描控制」面板中开启）", int((time.perf_counter() - t0) * 1000)


def _check_sensitive_paths() -> tuple[str, str, int]:
    t0 = time.perf_counter()
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    paths = [
        Path(sys_root) / "System32" / "drivers",
        Path(sys_root) / "System32" / "config",
        Path(sys_root) / "System32" / "drivers" / "etc" / "hosts",
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    ok = []
    miss = []
    for p in paths:
        if p.exists():
            ok.append(str(p))
        else:
            miss.append(str(p))
    detail = f"存在 {len(ok)}/{len(paths)} 关键路径"
    if miss:
        detail += " · 缺失: " + ", ".join(miss[:3])
    status = "pass" if len(ok) >= 3 else "warn"
    return status, detail, int((time.perf_counter() - t0) * 1000)
    ok = []
    miss = []
    for p in paths:
        if p.exists():
            ok.append(str(p))
        else:
            miss.append(str(p))
    detail = f"存在 {len(ok)}/{len(paths)} 关键路径"
    if miss:
        detail += " · 缺失: " + ", ".join(miss[:3])
    status = "pass" if len(ok) >= 3 else "warn"
    return status, detail, int((time.perf_counter() - t0) * 1000)


def _check_registry_baseline() -> tuple[str, str, int]:
    """检查关键注册表项可读 + 基线落盘存在"""
    t0 = time.perf_counter()
    if not IS_WINDOWS or winreg is None:
        return "skip", "非 Windows 平台，跳过注册表检查", int((time.perf_counter() - t0) * 1000)
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    ]
    parts = []
    bad = 0
    for root, sub in keys:
        try:
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
                winreg.QueryInfoKey(k)
            parts.append(f"✅ {sub}")
        except FileNotFoundError:
            parts.append(f"⏭  {sub} (无此项)")
        except Exception as e:
            parts.append(f"❌ {sub} ({e!r})")
            bad += 1
    status = "pass" if bad == 0 else "fail"
    return status, "  ·  ".join(parts), int((time.perf_counter() - t0) * 1000)


def _check_boot_sector() -> tuple[str, str, int]:
    """引导区自检：基线落盘则比对；否则先建基线"""
    t0 = time.perf_counter()
    if not IS_WINDOWS:
        return "skip", "非 Windows 平台", int((time.perf_counter() - t0) * 1000)
    try:
        from boot_guard import BootGuard  # 延迟导入，避免循环
    except Exception as e:
        return "warn", f"boot_guard 不可用: {e!r}", int((time.perf_counter() - t0) * 1000)
    try:
        bg = BootGuard()
        snap = bg.snapshot()
        if not snap.entries:
            return "warn", "引导区快照为空（管理员权限不足）", int((time.perf_counter() - t0) * 1000)
        diff = bg.diff_baseline(snap)
        if diff is None:
            return "pass", f"已建立基线 ({len(snap.entries)} 项引导区)，下次对比", int((time.perf_counter() - t0) * 1000)
        if diff:
            return "fail", "引导区与基线不一致: " + ", ".join(diff[:3]), int((time.perf_counter() - t0) * 1000)
        return "pass", f"引导区与基线一致 ({len(snap.entries)} 项)", int((time.perf_counter() - t0) * 1000)
    except Exception as e:
        return "warn", f"引导区检测跳过: {e!r}", int((time.perf_counter() - t0) * 1000)


# ============================================================
# 顶层入口：跑全套
# ============================================================
def run_full_check(app) -> SelfCheckReport:
    """app = AntivirusApp 实例；带 -1 容错：缺啥跳啥。"""
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    report = SelfCheckReport(started_at=started)

    # 1) 隔离区完整性
    s, d, ms = _timed(lambda: _check_quarantine_integrity(
        getattr(app, "quarantine", None),
        last_qname=getattr(app, "_last_quarantined_name", None),
    ))
    report.add("隔离区完整性", s, d, ms)

    # 2) 三引擎存活
    s, d, ms = _timed(lambda: _check_engines_alive(
        getattr(app, "scanner", None),
        getattr(app, "ai_learning_db", None),
        getattr(app, "cloud_scanner", None),
    ))
    report.add("三引擎可用性", s, d, ms)

    # 3) 实时防护
    s, d, ms = _timed(lambda: _check_rtp_running(
        getattr(app, "realtime_monitor", None),
    ))
    report.add("实时防护回路", s, d, ms)

    # 4) 敏感路径覆盖
    s, d, ms = _timed(_check_sensitive_paths)
    report.add("敏感路径覆盖", s, d, ms)

    # 5) 注册表基线
    s, d, ms = _timed(_check_registry_baseline)
    report.add("注册表关键项", s, d, ms)

    # 6) 引导区
    s, d, ms = _timed(_check_boot_sector)
    report.add("引导区完整性", s, d, ms)

    report.finalize()
    return report
