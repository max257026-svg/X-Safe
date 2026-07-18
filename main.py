"""
X-Safe — 杀毒软件主程序
防御恶意软件，保护系统安全
"""

import sys
import os
import json
import queue
import time
import shutil
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# 全局常量
# ============================================================
APP_NAME = "X-Safe安全中心"
APP_FULL_NAME = "X-Safe安全中心 · 主动防御平台"
APP_VERSION = "1.0"
APP_BUILD = "100"
APP_RELEASE_DATE = "2026-07-18"
APP_COPYRIGHT = "© 2026 X-Safe安全中心"
# 制作 / 出品 / 鸣谢
APP_PRODUCER = "竹影清风（ZYWind · 竹影靑風）"
APP_STUDIO = "新启年工作室（NewEra Studio）"
APP_STUDIO_SHORT = "NewEra Studio"
APP_THANKS = [
    ("WinDF", "室长"),
    ("老干白", ""),
    ("小青墨", ""),
    ("不言而喻", ""),
]

from engine import (
    AntivirusScanner, SignatureDB, QuarantineManager,
    ScanResult, ScanStats, ThreatLevel, ScanCancelled,
)
from monitor import RealTimeMonitor, SensitiveFileMonitor, WATCHDOG_AVAILABLE
from ai_engine import AIScanner, AIScorer, LearningDatabase, FeedbackType, ConfidenceScore
from cloud_engine import CloudScanner, CloudScanResult
from toast_notification import ThreatToast, ToastManager, ToastConfig, ToastType
from process_monitor import ProcessAlert, BehaviorLevel
from whitelist import WhitelistEngine
from recovery import RecoveryEngine, RansomwareDetector, ShadowCopyRecovery, \
    EternalBlueChecker, WannaCryRecovery
from self_check import run_full_check, SelfCheckReport
from registry_monitor import RegistryMonitor, RegistryAlert
from boot_guard import BootGuard, BootSnapshot

# ============================================================
# 配色方案 — 浅色 / 深色双主题
# ============================================================
THEMES = {
    # 浅色主题 —— 冷灰画布 + 深色侧栏，直角、发丝级描边
    "light": {
        "bg_main": "#eceef1",
        "bg_secondary": "#ffffff",
        "bg_card": "#ffffff",
        "bg_input": "#ffffff",
        "bg_hover": "#e4e8ee",
        "border": "#d4d9e0",
        "text_primary": "#161a1f",
        "text_secondary": "#5a6470",
        "text_muted": "#8b939e",
        "accent_blue": "#2563eb",
        "accent_green": "#1f9d57",
        "accent_red": "#e23b46",
        "accent_orange": "#d97706",
        "accent_purple": "#7c3aed",
        "accent_cyan": "#0891b2",
        "danger_bg": "#e23b4614",
        "warning_bg": "#d9770614",
        "safe_bg": "#1f9d5714",
        "progress_bg": "#e4e8ee",
        "progress_fill": "#1f9d57",
        "scanning_glow": "#2563eb",
        # —— 设计系统扩展键 ——
        "accent": "#0e8f6e",          # 主品牌色（翡翠绿）
        "accent_hover": "#0b7a5c",
        "topbar_bg": "#ffffff",
        "sidebar_bg": "#f3f5f9",     # 浅灰画布侧栏
        "sidebar_bg_hover": "#e6eaf1",
        "sidebar_text": "#1a2030",
        "sidebar_text_dim": "#6b7484",
        "sidebar_active": "#0e8f6e",
    },
    # 深色主题 —— 深墨控制台
    "dark": {
        "bg_main": "#0e1216",
        "bg_secondary": "#151a21",
        "bg_card": "#151a21",
        "bg_input": "#0e1216",
        "bg_hover": "#222a33",
        "border": "#272f3a",
        "text_primary": "#e9edf2",
        "text_secondary": "#9aa4b1",
        "text_muted": "#69727f",
        "accent_blue": "#3b82f6",
        "accent_green": "#34d399",
        "accent_red": "#f85149",
        "accent_orange": "#f59e0b",
        "accent_purple": "#a78bfa",
        "accent_cyan": "#22d3ee",
        "danger_bg": "#f8514914",
        "warning_bg": "#f59e0b14",
        "safe_bg": "#34d39914",
        "progress_bg": "#222a33",
        "progress_fill": "#34d399",
        "scanning_glow": "#3b82f6",
        # —— 设计系统扩展键 ——
        "accent": "#2dd4bf",
        "accent_hover": "#5eead4",
        "topbar_bg": "#151a21",
        "sidebar_bg": "#080b10",
        "sidebar_bg_hover": "#141b24",
        "sidebar_text": "#e9edf2",
        "sidebar_text_dim": "#69727f",
        "sidebar_active": "#2dd4bf",
    },
}
# 运行期实际使用的配色（会被 _apply_theme 覆盖）
COLORS = dict(THEMES["light"])


def _theme_config_path() -> Path:
    return _get_data_dir() / "theme_config.json"


def _get_data_dir() -> Path:
    """
    返回运行时可写的数据目录（用于数据库、隔离区、白名单、配置等）。

    v21 调整：用户要求把数据目录从 %APPDATA%\\XSafe 改为 %TEMP%\\XSafe
    (C:\\Users\\<用户>\\AppData\\Local\\Temp\\XSafe)。
    原因：%APPDATA% 目录在某些用户环境下受公司/家庭策略限制（漫游、限制写入、
    权限不足），导致数据被静默重定向到 exe 同目录；%TEMP% 是当前用户自己的
    本地临时目录，几乎所有 Windows 环境下都可写，最稳定。

    关键修复（v20）：用 sys.frozen（无下划线）判断 — PyInstaller 设置的是
    sys.frozen 而不是 sys._frozen。之前用 hasattr(sys, "_frozen") 导致
    exe 模式也走源码分支，数据被错误地写到 _internal/.userdata/。
    """
    if getattr(sys, "frozen", False):
        # PyInstaller 打包：写到 %TEMP%\\XSafe (用户可写、跨会话存活、不受策略限制)
        # 优先用 TEMP 环境变量（更标准），fallback 到 TEMP 或 LOCALAPPDATA
        import tempfile as _tempfile
        base = Path(
            os.environ.get("TEMP")
            or os.environ.get("TMP")
            or _tempfile.gettempdir()
        )
        data_dir = base / "XSafe"
    else:
        # 源码运行：放在项目根的 .userdata/ 下，避免污染源码
        data_dir = Path(__file__).parent / ".userdata"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def _ensure_seeded_files():
    """首次启动时把 bundled 的可写种子文件 (ai_learning.db 等) 拷到数据目录。

    v21 新增：从 %APPDATA%\\XSafe 迁移历史用户数据到 %TEMP%\\XSafe。
    只迁移不覆盖（不覆盖新数据）— 避免数据切换目录时丢白名单/隔离记录。
    """
    data_dir = _get_data_dir()
    bundle_dir = Path(__file__).parent
    for name in ("ai_learning.db",):
        dst = data_dir / name
        src = bundle_dir / name
        if not dst.exists() and src.exists():
            try:
                shutil.copy2(str(src), str(dst))
            except Exception:
                pass

    # === v21：一次性的 %APPDATA%\\XSafe → %TEMP%\\XSafe 数据迁移 ===
    # 迁移名单：用户产生的数据（白名单、基线、云缓存等），不包括 SQLite WAL/SHM
    if getattr(sys, "frozen", False) and os.name == "nt":
        try:
            import tempfile as _tempfile
            temp_base = Path(
                os.environ.get("TEMP")
                or os.environ.get("TMP")
                or _tempfile.gettempdir()
            )
            old_dir = Path(os.environ.get("APPDATA", str(Path.home()))) / "XSafe"
            new_dir = temp_base / "XSafe"
            if old_dir.exists() and old_dir.resolve() != new_dir.resolve():
                # 只迁移不覆盖的、用户产生的关键文件
                for name in (
                    "trusted.json",          # 白名单
                    "boot_baseline.json",    # 引导区基线
                    "cloud_cache.json",      # 云端缓存
                    "cloud_config.json",     # 云配置
                    "hosts_backup.txt",      # hosts 备份
                    "settings.json",         # 通用设置
                    "quarantine",            # 隔离区（目录）
                    "ai_learning.db",        # AI 学习数据库
                ):
                    src = old_dir / name
                    dst = new_dir / name
                    if src.exists() and not dst.exists():
                        try:
                            if src.is_dir():
                                shutil.copytree(str(src), str(dst))
                            else:
                                shutil.copy2(str(src), str(dst))
                        except Exception:
                            pass
        except Exception:
            pass


def _save_theme(name: str):
    """保存主题选择到本地配置"""
    try:
        with open(_theme_config_path(), "w", encoding="utf-8") as f:
            json.dump({"theme": name}, f, ensure_ascii=False)
    except Exception:
        pass


def _load_theme() -> str:
    """读取已保存的主题，默认浅色"""
    try:
        with open(_theme_config_path(), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        name = cfg.get("theme", "light")
    except Exception:
        name = "light"
    return name if name in THEMES else "light"


def _apply_theme(name: str):
    """将指定主题应用到 COLORS（原地更新，供所有控件读取）"""
    COLORS.clear()
    COLORS.update(THEMES.get(name, THEMES["light"]))


# ============================================================
# 圆角 UI 基础组件（Canvas 绘制，真圆角 + 柔和阴影 + 悬停）
# ============================================================
def _round_rect(c, x1, y1, x2, y2, r, fill, outline=None):
    """在 Canvas 上绘制矩形：r<=1 为直角（可选 1px 描边），否则圆角。"""
    r = float(r) if r else 0
    if r <= 1:
        c.create_rectangle(x1, y1, x2, y2, outline=outline or "", fill=fill)
        return
    r = min(r, (x2 - x1) / 2.0, (y2 - y1) / 2.0)
    c.create_arc(x1, y1, x1 + 2 * r, y1 + 2 * r, start=90, extent=90,
                 style="pieslice", outline="", fill=fill)
    c.create_arc(x2 - 2 * r, y1, x2, y1 + 2 * r, start=0, extent=90,
                 style="pieslice", outline="", fill=fill)
    c.create_arc(x2 - 2 * r, y2 - 2 * r, x2, y2, start=270, extent=90,
                 style="pieslice", outline="", fill=fill)
    c.create_arc(x1, y2 - 2 * r, x1 + 2 * r, y2, start=180, extent=90,
                 style="pieslice", outline="", fill=fill)
    c.create_rectangle(x1 + r, y1, x2 - r, y2, outline="", fill=fill)
    c.create_rectangle(x1, y1 + r, x2, y2 - r, outline="", fill=fill)


def _shadow_color() -> str:
    """根据当前主题返回卡片柔和阴影色"""
    return "#c9d1d9" if COLORS["bg_main"] == "#f6f8fa" else "#000000"


def _lighten_color(hex_color: str, factor: float = 0.15) -> str:
    """调亮颜色"""
    hex_color = hex_color.lstrip("#")
    r, g, b = int(hex_color[:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    r = min(255, int(r + (255 - r) * factor))
    g = min(255, int(g + (255 - g) * factor))
    b = min(255, int(b + (255 - b) * factor))
    return f"#{r:02x}{g:02x}{b:02x}"


class RoundedCard(tk.Frame):
    """圆角卡片容器；子控件加入 .content 即可（四周自动留出圆角边距）。"""

    def __init__(self, master, bg, border=None, radius=16, shadow=False, **kw):
        super().__init__(master, bg=master.cget("bg"), bd=0, highlightthickness=0, **kw)
        self._card_bg = bg
        self._border = border if border else bg
        # 直角设计语言：统一 0 圆角、去除柔和阴影，改用发丝级 1px 描边
        self._radius = 0
        self._shadow = False
        self._pad = 14
        self._canvas = tk.Canvas(self, bg=master.cget("bg"), highlightthickness=0, bd=0)
        self._canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.content = tk.Frame(self, bg=bg, bd=0, highlightthickness=0)
        self.content.pack(fill=tk.BOTH, expand=True, padx=self._pad, pady=self._pad)
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def _redraw(self):
        self._canvas.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        # 直角：先填底色，再描 1px 发丝边
        _round_rect(self._canvas, 0, 0, w, h, 0, self._card_bg)
        if self._border and self._border != self._card_bg:
            self._canvas.create_rectangle(0, 0, w - 1, h - 1,
                                          outline=self._border, fill="")


class RoundedButton(tk.Canvas):
    """直角按钮（支持 state 禁用、悬停提亮、点击回调）。"""

    def __init__(self, master, text, command, color, radius=12, fg="#ffffff",
                 font=("Microsoft YaHei UI", 10, "bold"), height=42, width=None, **kw):
        super().__init__(master, bg=master.cget("bg"), highlightthickness=0, bd=0,
                         height=height, width=width, cursor="hand2", takefocus=0, **kw)
        self._text = text
        self._command = command
        self._color = color
        self._fg = fg
        self._font = font
        self._radius = 0  # 直角
        self._state = "normal"
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)

    def _on_enter(self, e):
        if self._state == "normal":
            self._draw(_lighten_color(self._color))

    def _on_leave(self, e):
        self._draw()

    def _on_click(self, e):
        if self._state == "normal" and self._command:
            self._command()

    def _draw(self, fill=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        if fill is None:
            fill = COLORS["bg_hover"] if self._state == "disabled" else self._color
        fg = COLORS["text_muted"] if self._state == "disabled" else self._fg
        _round_rect(self, 1, 1, w - 1, h - 1, self._radius, fill)
        self.create_text(w / 2, h / 2, text=self._text, fill=fg,
                         font=self._font, anchor="center")

    def configure(self, **kw):
        if "state" in kw:
            st = kw.pop("state")
            self._state = "disabled" if st == tk.DISABLED else "normal"
            self._draw()
        if "text" in kw:
            self._text = kw.pop("text")
            self._draw()
        if kw:
            super().configure(**kw)

    def cget(self, key):
        if key == "state":
            return tk.DISABLED if self._state == "disabled" else tk.NORMAL
        if key == "text":
            return self._text
        return super().cget(key)

    def __getitem__(self, key):
        return self.cget(key)

    def __setitem__(self, key, val):
        self.configure(**{key: val})


class RoundedProgress(tk.Canvas):
    """圆角胶囊进度条（跟随 DoubleVar 自动重绘）。"""

    def __init__(self, master, variable, maximum=100, radius=9, height=16, **kw):
        super().__init__(master, bg=master.cget("bg"), highlightthickness=0, bd=0,
                         height=height, takefocus=0, **kw)
        self._var = variable
        self._max = maximum
        self._radius = 0  # 直角
        self._var.trace_add("write", lambda *a: self._draw())
        self.bind("<Configure>", lambda e: self._draw())
        self._draw()

    def configure(self, **kw):
        # 兼容旧 ttk.Progressbar 调用（圆角进度条无 mode 概念，忽略即可）
        if "mode" in kw:
            kw.pop("mode")
        if kw:
            super().configure(**kw)

    def stop(self):
        """兼容旧 indeterminate 调用（圆角进度条始终连续，空操作）"""
        pass

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        val = max(0.0, min(float(self._max), float(self._var.get())))
        frac = val / self._max if self._max else 0
        _round_rect(self, 0.5, 0.5, w - 0.5, h - 0.5, self._radius, COLORS["progress_bg"])
        if frac > 0:
            fw = max(frac * (w - 2), self._radius * 2)
            _round_rect(self, 1, 1, 1 + fw, h - 1, self._radius, COLORS["progress_fill"])


class TabPill(tk.Canvas):
    """侧栏导航项（直角；选中态左侧高亮条 + 提亮文字；支持悬停）。"""

    def __init__(self, master, text, command, radius=10,
                 font=("Microsoft YaHei UI", 10, "bold"), height=40, **kw):
        super().__init__(master, bg=master.cget("bg"), highlightthickness=0, bd=0,
                         height=height, cursor="hand2", takefocus=0, **kw)
        self._text = text
        self._command = command
        self._font = font
        self._active = False
        self._hover = False
        # 宽度交由 pack(fill=X) 撑满侧栏，无需按文本估算
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", lambda e: self._command())
        self.bind("<Enter>", lambda e: (setattr(self, "_hover", True), self._draw()))
        self.bind("<Leave>", lambda e: (setattr(self, "_hover", False), self._draw()))

    def set_active(self, active: bool):
        self._active = active
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        # 背景：选中 > 悬停 > 默认
        if self._active:
            bg = COLORS["sidebar_bg_hover"]
            fg = COLORS["sidebar_text"]
        elif self._hover:
            bg = COLORS["sidebar_bg_hover"]
            fg = COLORS["sidebar_text"]
        else:
            bg = COLORS["sidebar_bg"]
            fg = COLORS["sidebar_text_dim"]
        self.create_rectangle(0, 0, w, h, fill=bg, outline="")
        # 选中态：左侧 3px 品牌色高亮条
        if self._active:
            self.create_rectangle(0, 0, 3, h, fill=COLORS["sidebar_active"], outline="")
        self.create_text(20, h / 2, text=self._text, fill=fg,
                         font=self._font, anchor="w")


# ============================================================
# 主应用程序
# ============================================================
class AntivirusApp:
    """杀毒软件 GUI 主程序"""

    def __init__(self):
        # 【超早期 debug】写到 exe 同目录（绝对能写），用于排查 exe 模式 init 卡在哪一步
        try:
            import sys as _sys
            self._exe_dir = os.path.dirname(_sys.executable) if getattr(_sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
            from datetime import datetime as _dt
            with open(os.path.join(self._exe_dir, "init_debug.log"), "a", encoding="utf-8") as _f:
                _f.write(f"[{_dt.now().strftime('%H:%M:%S.%f')[:-3]}] __init__ 进入 (frozen={getattr(_sys, 'frozen', False)})\n")
        except Exception as _e:
            pass

        # 应用已保存的主题（默认浅色）
        self._theme = _load_theme()
        _apply_theme(self._theme)

        # 扫描状态提前初始化，避免未扫描时点击主题按钮等场景访问到未定义属性
        self._scanning = False
        self._scan_cancelled = False
        self._progress_ticker_job = None
        self._scan_queue_job = None

        self.root = tk.Tk()
        self.root.title("X-Safe安全中心")
        self.root.geometry("1180x800")
        self.root.minsize(900, 650)
        self.root.configure(bg=COLORS["bg_main"])
        # 强制更新一次窗口，让 geometry 立即生效（避免后续报错时留下默认 200x150 的小窗口）
        self.root.update_idletasks()

        # 设置图标（如果有的话）
        self._set_app_icon()

        # 首次启动时把 bundled 的可写种子文件 (ai_learning.db) 拷到 %APPDATA%\XSafe\
        _ensure_seeded_files()

        # 初始化引擎（失败时在窗口内显示错误，不留下空白窗口）
        sig_path = Path(__file__).parent / "signatures.json"  # 只读，保留在 _internal
        # 可写数据全部放到 %APPDATA%\XSafe\，避免在只读 _internal 下触发 database is locked
        data_dir = _get_data_dir()
        quarantine_dir = data_dir / "quarantine"
        ai_db_path = str(data_dir / "ai_learning.db")
        trusted_path = str(data_dir / "trusted.json")

        try:
            self.sig_db = SignatureDB(str(sig_path))
        except Exception as e:
            self._show_fatal_init_error(f"签名库加载失败: {e}")
            return

        try:
            # AIScanner 构造时会创建 LearningDatabase，传入可写路径
            inner_scanner = AntivirusScanner(self.sig_db)
            self.scanner = AIScanner(inner_scanner, db_path=ai_db_path)
        except Exception as e:
            self._show_fatal_init_error(f"引擎初始化失败: {e}")
            return

        self.quarantine = QuarantineManager(str(quarantine_dir))

        # 白名单 / 信任区引擎
        self.whitelist = WhitelistEngine(trusted_path)
        # 将白名单注入到底层扫描引擎，受信任文件扫描时直接判定安全
        try:
            self.scanner.scanner.whitelist = self.whitelist
        except Exception:
            pass
        try:
            self.scanner.whitelist = self.whitelist
        except Exception:
            pass

        # 逆向恢复引擎（勒索软件文件恢复）
        try:
            self.recovery = RecoveryEngine()
        except Exception:
            self.recovery = None

        # 系统敏感文件防护 (System Guard)
        self.sensitive_monitor = None
        self._sensitive_ignore: dict[str, float] = {}  # 归一化路径 -> 过期时间戳
        self._hosts_backup = str(_get_data_dir() / "hosts_backup.txt")

        self.ai_learning_db = self.scanner.db

        # 云查杀引擎（cache 放到 %APPDATA%\XSafe\，避免只读 _internal 下写不进去）
        try:
            self.cloud_scanner = CloudScanner(cache_path=str(_get_data_dir() / "cloud_cache.json"))
        except Exception:
            self.cloud_scanner = None

        # 实时监控
        try:
            self.realtime_monitor = RealTimeMonitor(self.scanner.scanner, self.quarantine)
            self.realtime_monitor.set_alert_callback(self._on_threat_detected)
            self.realtime_monitor.set_proc_alert_callback(self._on_process_alert)
        except Exception:
            self.realtime_monitor = type('obj', (object,), {'running': False, 'available': False})()

        # 注册表 HOOK 监控
        self.reg_monitor = RegistryMonitor(poll_interval=8.0)
        self.reg_monitor.set_alert_callback(self._on_registry_alert)

        # 引导区保护
        self.boot_guard = BootGuard()

        # 弹窗通知管理器
        try:
            self._toast_manager = ToastManager(self.root, max_toasts=3)
        except Exception:
            self._toast_manager = None

        # 状态变量
        self._scanning = False
        self._scan_thread: threading.Thread | None = None
        self._current_results: list[ScanResult] = []
        # 每行结果直接持有 ScanResult 引用，隔离时不再依赖 _current_results 的脆弱匹配
        self._tree_results: dict[str, ScanResult] = {}  # tree item_id -> ScanResult
        self._checked: dict[str, bool] = {}  # tree item_id -> 是否勾选
        self._current_ai_scores: dict[str, ConfidenceScore] = {}  # filepath -> AI score
        self._current_features: dict[str, dict] = {}  # filepath -> detection features
        self._current_cloud_results: dict[str, CloudScanResult] = {}  # filepath -> cloud result
        self._total_files_to_scan = 0
        self._files_scanned = 0

        # 跨线程 UI 更新队列
        self._scan_queue: queue.Queue = queue.Queue()
        self._scan_queue_job: str | None = None

        # === 扫描结果轮询触发器 ===
        # 不依赖任何回调/事件链 — 每 1000ms 扫一次 result_tree，
        # 发现新增 item 就启动右下角弹窗。绝对可靠。
        self._result_tree_poll_id: str | None = None
        self._polled_tree_items: set = set()  # 已轮询过的 item_id
        # 节流：上一条弹窗时间戳（毫秒） + 已弹过的 file_path（防重）
        self._last_toast_ts: float = 0.0
        self._recently_toasted_paths: dict[str, float] = {}  # path -> ts
        # 上一批「未弹窗」的累积（扫描狂涌时合并提示）
        self._pending_burst_count: int = 0
        self._pending_burst_paths: list[str] = []
        self._last_burst_toast_ts: float = 0.0

        # 高级查杀 — 三引擎联动追踪
        self._is_advanced_scan: bool = False
        self._cloud_pending: int = 0
        self._cloud_completed: int = 0

        # 系统托盘
        self._tray_icon = None
        self._tray_thread = None

        # 构建 UI（核心步骤，失败则显示错误）
        try:
            self._init_debug("start _build_ui")
            self._build_ui()
            self._init_debug("_build_ui OK")
        except Exception as e:
            self._init_debug(f"_build_ui FAIL: {e!r}")
            self._show_fatal_init_error(f"界面构建失败: {e}")
            return

        # 初始化系统托盘（缺失依赖时静默处理）
        self._init_debug("start _init_system_tray")
        self._init_system_tray()
        self._init_debug("_init_system_tray OK")

        # 自动开启实时防护（静默启动，先确保依赖就绪）
        self.root.after(500, self._ensure_and_start_rtp)

        # 启动主线程 UI 轮询 (处理跨线程事件)
        self._init_debug("start _process_scan_queue")
        self._process_scan_queue()
        self._init_debug("_process_scan_queue OK")

        # v27 DEBUG: 启动 5 秒后自动触发一次 _show_threat_toast，证明弹窗链路
        # 仅当环境变量 XSAFE_DEBUG_TOAST=1 时启用
        if os.environ.get("XSAFE_DEBUG_TOAST") == "1":
            self.root.after(5000, self._debug_trigger_threat_toast)

        # v29 DEBUG: 启动 3 秒后自动触发快速扫描，复现用户场景
        # 仅当环境变量 XSAFE_AUTO_SCAN=1 时启用
        if os.environ.get("XSAFE_AUTO_SCAN") == "1":
            self.root.after(3000, self._debug_trigger_quick_scan)

        # 启动结果 tree 轮询触发器 — 1000ms 检查一次新增行
        self._init_debug("start _start_result_tree_polling")
        # 一次性：打印数据目录和 poll_debug 路径
        try:
            _dd = _get_data_dir()
            _lp = os.path.join(str(_dd), "poll_debug.log")
            self._init_debug(f"data_dir={_dd!r} poll_path={_lp!r} cwd={os.getcwd()!r}")
        except Exception as _e:
            self._init_debug(f"get_data_dir 失败: {_e!r}")
        self._start_result_tree_polling()
        self._init_debug("_start_result_tree_polling OK")

        # 加载初始状态
        self._refresh_quarantine_list()
        self._update_status_bar("就绪 — 等待扫描指令")

        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # === DPI / 分辨率自适应 ===
        # 监听窗口 Configure 事件，根据当前屏幕尺寸动态调整窗口最小尺寸，
        # 确保工具栏按钮在 1080p / 2K / 4K / 高 DPI 缩放下始终完整显示。
        self._last_screen_w = 0
        self._last_screen_h = 0
        self.root.bind("<Configure>", self._on_root_configure)

    def _on_root_configure(self, event=None):
        """窗口大小 / 屏幕 DPI 变化时，按当前屏幕自适应调整最小尺寸 + 字号缩放"""
        try:
            if event and event.widget is not self.root:
                return  # 只关心主窗口本身
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            if sw == self._last_screen_w and sh == self._last_screen_h:
                return
            self._last_screen_w, self._last_screen_h = sw, sh
            # 主窗口：宽度取屏幕 70%（最小 1100，最大不超过屏幕 95%），高度 80%（最小 700）
            target_w = max(1100, min(int(sw * 0.70), int(sw * 0.95)))
            target_h = max(700, min(int(sh * 0.80), int(sh * 0.95)))
            self.root.minsize(min(900, target_w - 200), 600)
            # 不强制重设 geometry —— 用户已手动拖动时不打断他
        except Exception:
            pass

    def _show_fatal_init_error(self, msg: str):
        """初始化严重失败时在窗口内显示错误，避免留下空白 'tk' 窗口"""
        # 强制窗口呈现到 1180x800 并获得焦点，避免出现默认 200x150 的小空窗口
        self.root.geometry("1180x800")
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.update_idletasks()
        self.root.configure(bg=COLORS["bg_main"])
        err_frame = tk.Frame(self.root, bg=COLORS["bg_main"])
        err_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(
            err_frame, text="⚠️ X-Safe 启动失败", font=("Microsoft YaHei UI", 16, "bold"),
            bg=COLORS["bg_main"], fg=COLORS["accent_red"],
        ).pack(pady=(0, 10))
        tk.Label(
            err_frame, text=msg, font=("Microsoft YaHei UI", 11),
            bg=COLORS["bg_main"], fg=COLORS["text_primary"], wraplength=500, justify=tk.LEFT,
        ).pack(pady=(0, 15))
        import traceback as tb_format
        tb_text = tb_format.format_exc() if sys.exc_info()[0] else ""
        if tb_text:
            details = tk.Text(err_frame, height=8, width=70, font=("Consolas", 9),
                               bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief=tk.FLAT)
            details.insert("1.0", tb_text[-800:])
            details.config(state=tk.DISABLED)
            details.pack(pady=(0, 10))
        tk.Button(
            err_frame, text="退出", command=self.root.destroy,
            font=("Microsoft YaHei UI", 10), bg=COLORS["accent_red"], fg="white",
            relief=tk.FLAT, padx=20, pady=5,
        ).pack()
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

    # ==========================================================
    # UI 构建
    # ==========================================================
    def _build_ui(self):
        """构建完整用户界面"""

        # --- 顶部标题栏 ---
        title_bar = tk.Frame(self.root, bg=COLORS["topbar_bg"], height=58)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        # 标题栏底部发丝分隔线
        sep = tk.Frame(self.root, bg=COLORS["border"], height=1)
        sep.pack(fill=tk.X, side=tk.TOP)

        title_frame = tk.Frame(title_bar, bg=COLORS["topbar_bg"])
        title_frame.pack(side=tk.LEFT, padx=20, pady=8)

        # 主品牌字（最顶上）
        tk.Label(
            title_frame, text="X-Safe", font=("Microsoft YaHei UI", 18, "bold"),
            bg=COLORS["topbar_bg"], fg=COLORS["text_primary"],
        ).pack(side=tk.LEFT)

        # 版本徽章
        ver_chip = tk.Label(
            title_frame, text=f"v{APP_VERSION}",
            font=("Microsoft YaHei UI", 8, "bold"),
            bg=COLORS["bg_hover"], fg=COLORS["accent"],
            padx=6, pady=2,
        )
        ver_chip.pack(side=tk.LEFT, padx=(8, 0))

        # 品牌字旁的细线分隔
        tk.Frame(title_frame, bg=COLORS["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y, padx=14, pady=4)

        # 当前栏目名（随左侧导航切换）
        self._section_title = tk.Label(
            title_frame, text="扫描结果", font=("Microsoft YaHei UI", 13, "bold"),
            bg=COLORS["topbar_bg"], fg=COLORS["accent"],
        )
        self._section_title.pack(side=tk.LEFT)

        # 右侧：实时防护状态
        status_frame = tk.Frame(title_bar, bg=COLORS["topbar_bg"])
        status_frame.pack(side=tk.RIGHT, padx=20, pady=12)

        # 主题切换按钮（浅色 / 深色）
        self._theme_btn = RoundedButton(
            status_frame,
            text="🌙" if self._theme == "light" else "☀️",
            command=self._switch_theme,
            color=COLORS["bg_hover"], fg=COLORS["text_primary"],
            radius=0, height=32, width=42, font=("Segoe UI", 13),
        )
        self._theme_btn.pack(side=tk.LEFT, padx=(10, 4))

        self._rtp_indicator = tk.Canvas(
            status_frame, width=10, height=10,
            bg=COLORS["topbar_bg"], highlightthickness=0,
        )
        self._rtp_indicator.pack(side=tk.LEFT, padx=(0, 6))
        self._draw_rtp_indicator(False)

        self._rtp_label = tk.Label(
            status_frame, text="实时防护: 已关闭",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["topbar_bg"], fg=COLORS["text_secondary"],
        )
        self._rtp_label.pack(side=tk.LEFT)

        # 弹窗模式指示器（顶栏右侧，让用户随时看到当前是「弹窗已启用」还是「静默处理中」，
        # 避免出现"威胁已加入结果区但右下角没弹窗"的困惑时找不到原因）
        self._rtp_mode_label = tk.Label(
            status_frame, text="🔔 弹窗已启用",
            font=("Microsoft YaHei UI", 9, "bold"),
            bg=COLORS["topbar_bg"], fg=COLORS["accent_green"],
        )
        self._rtp_mode_label.pack(side=tk.LEFT, padx=(14, 0))

        # --- 主内容区域（侧栏 + 中间面板 + 内容面板）---
        main_content = tk.Frame(self.root, bg=COLORS["bg_main"])
        main_content.pack(fill=tk.BOTH, expand=True)

        # 最左：竖向导航侧边栏（菜单栏靠左）
        nav_sidebar = tk.Frame(main_content, bg=COLORS["sidebar_bg"], width=208)
        nav_sidebar.pack(side=tk.LEFT, fill=tk.Y)
        nav_sidebar.pack_propagate(False)

        # 中间面板 — 扫描控制 + 统计
        left_panel = tk.Frame(main_content, bg=COLORS["bg_main"], width=322)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(12, 0))
        left_panel.pack_propagate(False)

        self._build_scan_panel(left_panel)
        self._build_stats_panel(left_panel)

        # 右侧面板 — 标签内容
        right_panel = tk.Frame(main_content, bg=COLORS["bg_main"])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 12))

        self._build_nav_sidebar(nav_sidebar)
        self._build_notebook(right_panel)

        # --- 底部状态栏 ---
        self._build_status_bar()

    def _build_scan_panel(self, parent):
        """扫描控制面板"""
        card = self._create_card(parent, "🔍 扫描控制")

        # 扫描类型按钮
        btn_frame = tk.Frame(card, bg=COLORS["bg_card"])
        btn_frame.pack(fill=tk.X, padx=14, pady=(8, 4))

        self._quick_scan_btn = self._create_button(
            btn_frame, "⚡ 快速扫描",
            self._start_quick_scan, COLORS["accent_blue"],
        )
        self._quick_scan_btn.pack(fill=tk.X, pady=3)

        self._cloud_scan_btn = self._create_button(
            btn_frame, "☁️ 云查杀",
            self._start_cloud_scan, COLORS["accent_cyan"],
        )
        self._cloud_scan_btn.pack(fill=tk.X, pady=3)

        self._advanced_scan_btn = self._create_button(
            btn_frame, "🔥 高级查杀",
            self._start_advanced_scan, COLORS["accent_purple"],
        )
        self._advanced_scan_btn.pack(fill=tk.X, pady=3)

        self._custom_scan_btn = self._create_button(
            btn_frame, "📁 自定义扫描",
            self._start_custom_scan, COLORS["accent_orange"],
        )
        self._custom_scan_btn.pack(fill=tk.X, pady=3)

        # 分隔线
        sep = tk.Frame(card, bg=COLORS["border"], height=1)
        sep.pack(fill=tk.X, padx=14, pady=10)

        # 扫描目标显示
        self._scan_target_label = tk.Label(
            card, text="选择扫描目标...",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["text_muted"],
            anchor="w", justify=tk.LEFT,
        )
        self._scan_target_label.pack(fill=tk.X, padx=14, pady=(0, 4))

        # 停止按钮
        self._stop_btn = self._create_button(
            card, "⏹ 停止扫描",
            self._stop_scan, COLORS["accent_red"],
        )
        self._stop_btn.pack(fill=tk.X, padx=14, pady=(6, 8))
        self._stop_btn.configure(state=tk.DISABLED)

        # 进度条 — 圆角胶囊，始终连续 0→100%
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = RoundedProgress(card, variable=self._progress_var,
                                             maximum=100, radius=9, height=16)
        self._progress_bar.pack(fill=tk.X, padx=14, pady=(0, 8))

        # 进度信息（固定两行高度，避免文字长度变化时跳来跳去）
        self._progress_label = tk.Label(
            card, text="",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
            height=2, justify=tk.LEFT, anchor="nw", wraplength=280,
        )
        self._progress_label.pack(fill=tk.X, padx=14, pady=(0, 8))

    def _build_stats_panel(self, parent):
        """统计面板"""
        card = self._create_card(parent, "📊 扫描统计")

        stats_grid = tk.Frame(card, bg=COLORS["bg_card"])
        stats_grid.pack(fill=tk.X, padx=14, pady=10)

        stats_data = [
            ("已扫描文件", "scanned"),
            ("发现威胁", "threats"),
            ("可疑文件", "suspicious"),
            ("已隔离", "quarantined"),
            ("扫描时间", "time"),
            ("扫描速度", "speed"),
        ]

        self._stat_labels: dict[str, tk.Label] = {}
        for i, (label_text, key) in enumerate(stats_data):
            row = i // 2
            col = i % 2

            frame = tk.Frame(stats_grid, bg=COLORS["bg_card"])
            frame.grid(row=row, column=col, sticky="ew", padx=4, pady=4)
            stats_grid.columnconfigure(col, weight=1)

            tk.Label(
                frame, text=label_text,
                font=("Microsoft YaHei UI", 9),
                bg=COLORS["bg_card"], fg=COLORS["text_muted"],
            ).pack(anchor="w")

            value_label = tk.Label(
                frame, text="--",
                font=("Consolas", 14, "bold"),
                bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            )
            value_label.pack(anchor="w")
            self._stat_labels[key] = value_label

        self._reset_stats_display()

    # 栏目元数据：id -> (侧栏标签, 顶栏标题, 顶栏副标题)
    _SECTIONS = [
        ("results", "扫描结果", "扫描结果", "实时威胁检测与处置"),
        ("realtime", "实时防护", "实时防护", "主动防御与实时监控"),
        ("quarantine", "隔离区", "隔离区", "可疑文件隔离与还原"),
        ("trusted", "信任区", "信任区", "白名单与信任项管理"),
        ("signatures", "特征库", "特征库", "本地特征与启发式规则"),
        ("recovery", "逆向恢复", "逆向恢复", "勒索解密与卷影恢复"),
    ]

    def _build_nav_sidebar(self, parent):
        """左侧竖向导航侧边栏（菜单栏靠左）"""
        # 品牌区
        brand = tk.Frame(parent, bg=COLORS["sidebar_bg"])
        brand.pack(fill=tk.X, padx=0, pady=(16, 4))
        tk.Label(
            brand, text="🛡", font=("Segoe UI", 22),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_active"],
        ).pack(side=tk.LEFT, padx=(18, 8))
        name_box = tk.Frame(brand, bg=COLORS["sidebar_bg"])
        name_box.pack(side=tk.LEFT)
        tk.Label(
            name_box, text="X-SAFE", font=("Microsoft YaHei UI", 15, "bold"),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_text"],
        ).pack(anchor="w")
        tk.Label(
            name_box, text="安全中心", font=("Microsoft YaHei UI", 8),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_text_dim"],
        ).pack(anchor="w")

        # 导航分组小标题
        tk.Label(
            parent, text="功  能", font=("Microsoft YaHei UI", 8, "bold"),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_text_dim"],
        ).pack(anchor="w", padx=20, pady=(14, 6))

        # 竖向导航项
        self._tab_buttons = {}
        for tab_id, nav_text, _, _ in self._SECTIONS:
            pill = TabPill(
                parent, text=nav_text,
                command=lambda tid=tab_id: self._switch_tab(tid),
                height=40,
                font=("Microsoft YaHei UI", 10, "bold"),
            )
            pill.pack(fill=tk.X)
            self._tab_buttons[tab_id] = pill

        # 底部版本脚注 + 关于按钮
        footer = tk.Frame(parent, bg=COLORS["sidebar_bg"])
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=0)

        # 分隔线
        tk.Frame(footer, bg=COLORS["border"], height=1).pack(fill=tk.X, padx=16, pady=(0, 10))

        about_btn = tk.Label(
            footer, text="ⓘ  关于 X-Safe安全中心",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_text_dim"],
            cursor="hand2",
        )
        about_btn.pack(anchor="w", padx=20, pady=(2, 6))
        about_btn.bind("<Button-1>", lambda e: self._show_about_dialog())
        about_btn.bind("<Enter>", lambda e: about_btn.configure(fg=COLORS["sidebar_active"]))
        about_btn.bind("<Leave>", lambda e: about_btn.configure(fg=COLORS["sidebar_text_dim"]))

        ver_label = tk.Label(
            footer, text=f"v{APP_VERSION}  ·  实时防护引擎",
            font=("Microsoft YaHei UI", 8),
            bg=COLORS["sidebar_bg"], fg=COLORS["sidebar_text_dim"],
        )
        ver_label.pack(anchor="w", padx=20, pady=(0, 12))
        self._footer_ver_label = ver_label

    def _build_notebook(self, parent):
        """标签内容面板（导航已移至左侧侧边栏，此处仅构建内容区）"""
        self._tabs = {}
        self._tab_frames = {}
        self._active_tab = tk.StringVar(value="results")

        # 标签内容区
        self._tab_content = tk.Frame(parent, bg=COLORS["bg_main"])
        self._tab_content.pack(fill=tk.BOTH, expand=True)

        # 结果页
        self._tab_frames["results"] = self._build_results_tab()
        # 实时防护页
        self._tab_frames["realtime"] = self._build_realtime_tab()
        # 隔离区页
        self._tab_frames["quarantine"] = self._build_quarantine_tab()
        # 信任区页
        self._tab_frames["trusted"] = self._build_trusted_tab()
        # 特征库页
        self._tab_frames["signatures"] = self._build_signatures_tab()
        # 逆向恢复页
        self._tab_frames["recovery"] = self._build_recovery_tab()

        self._switch_tab("results")

    def _build_realtime_tab(self) -> tk.Frame:
        """实时防护独立板块：总开关 + 弹窗模式 + 6个子功能复选框 + 日志区"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        # ---- 初始化状态 ----
        self._rtp_master_on = False
        self._rtp_toast_mode = tk.StringVar(value="toast")  # toast / silent
        self._rtp_apply_pending = False  # 子模块切换是否还有未执行的应用任务
        self._rtp_sub_vars = {
            "standard": tk.BooleanVar(value=True),
            "download": tk.BooleanVar(value=True),
            "registry": tk.BooleanVar(value=True),
            "boot": tk.BooleanVar(value=True),
            "sensitive": tk.BooleanVar(value=True),
            "process": tk.BooleanVar(value=True),
        }

        # ---- 顶部卡片：总开关 + 弹窗模式 ----
        ctrl_card = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                                radius=14, shadow=True)
        ctrl_card.pack(fill=tk.X, padx=2, pady=(2, 8))

        # 总开关行
        master_row = tk.Frame(ctrl_card.content, bg=COLORS["bg_card"])
        master_row.pack(fill=tk.X, padx=16, pady=(14, 8))
        # 左侧：标题 + 副标题（垂直两行，标题独占一行，副标题 wrap 换行）
        master_left = tk.Frame(master_row, bg=COLORS["bg_card"])
        master_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(
            master_left, text="🛡️  实时防护总开关",
            font=("Microsoft YaHei UI", 13, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            anchor="w",
        ).pack(fill=tk.X)
        tk.Label(
            master_left, text="开启后自动拦截恶意文件、注册表篡改、引导区修改等威胁",
            font=("Microsoft YaHei UI", 8),
            bg=COLORS["bg_card"], fg=COLORS["text_muted"],
            anchor="w", wraplength=520, justify="left",
        ).pack(fill=tk.X, pady=(2, 0))

        self._rtp_master_btn = tk.Label(
            master_row, text="  🔴  已关闭  ",
            font=("Microsoft YaHei UI", 10, "bold"),
            bg=COLORS["accent_red"], fg="#ffffff",
            padx=16, pady=8, cursor="hand2",
        )
        self._rtp_master_btn.pack(side=tk.RIGHT, padx=(8, 0))
        self._rtp_master_btn.bind("<Button-1>", lambda e: self._toggle_rtp_master())
        self._rtp_master_btn.bind("<Enter>", lambda e: self._rtp_master_btn.configure(
            bg=_lighten_color(COLORS["accent_red"], 0.15)))
        self._rtp_master_btn.bind("<Leave>", lambda e: self._rtp_master_btn.configure(
            bg=COLORS["accent_red"] if not self._rtp_master_on else COLORS["accent_green"]))

        # 分隔线
        tk.Frame(ctrl_card.content, bg=COLORS["border"], height=1).pack(
            fill=tk.X, padx=16, pady=4)

        # v25: 移除「弹窗模式」整行 — 用户不要这个 UI 元件

        # ---- 开机自启动行（v15 新增） ----
        autostart_row = tk.Frame(ctrl_card.content, bg=COLORS["bg_card"])
        autostart_row.pack(fill=tk.X, padx=16, pady=(0, 14))
        tk.Label(
            autostart_row, text="🚀  开机自启动",
            font=("Microsoft YaHei UI", 11, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
        ).pack(side=tk.LEFT)
        tk.Label(
            autostart_row, text="系统登录后自动启动 X-Safe 并开启实时防护（写入 HKCU Run）",
            font=("Microsoft YaHei UI", 8),
            bg=COLORS["bg_card"], fg=COLORS["text_muted"],
        ).pack(side=tk.LEFT, padx=(12, 0))

        # 自启动开关按钮（toggle 形态）
        self._autostart_btn = tk.Label(
            autostart_row, text="  ⬜  关 闭  ",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_hover"], fg=COLORS["text_secondary"],
            padx=12, pady=5, cursor="hand2",
        )
        self._autostart_btn.pack(side=tk.RIGHT)
        self._autostart_btn.bind("<Button-1>", lambda e: self._toggle_autostart())

        # 初始化开关状态（从注册表 / 配置文件读）
        self._refresh_autostart_btn()

        # ---- 中间卡片：6个子功能复选框 ----
        modules_card = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                                   radius=14, shadow=True)
        modules_card.pack(fill=tk.X, padx=2, pady=(0, 8))

        mod_head = tk.Frame(modules_card.content, bg=COLORS["bg_card"])
        mod_head.pack(fill=tk.X, padx=16, pady=(14, 6))
        tk.Frame(mod_head, bg=COLORS["accent"], width=3, height=15).pack(
            side=tk.LEFT, padx=(0, 8))
        tk.Label(
            mod_head, text="⚙️  监控模块",
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
        ).pack(side=tk.LEFT)

        sub_modules = [
            ("standard",  "标准实时监控",      "监控桌面 / 文档等基础目录的文件变化"),
            ("download",  "解压 / 下载文件监控", "监控 Downloads 目录，拦截下载解压的恶意文件"),
            ("registry",  "注册表实时监控",     "Run / IFEO / Winlogon Shell / AppInit_DLLs 等关键键"),
            ("boot",      "引导区实时监控",     "MBR / VBR 哈希快照，发现篡改立即告警"),
            ("sensitive", "系统敏感文件监控",   "hosts / drivers / etc 等系统关键文件"),
            ("process",   "应用异常行为监控",   "进程注入 / 加密写文件 / 异常父子进程等"),
        ]
        for key, label, desc in sub_modules:
            row = tk.Frame(modules_card.content, bg=COLORS["bg_card"])
            row.pack(fill=tk.X, padx=16, pady=4)
            cb = tk.Checkbutton(
                row, text=label, variable=self._rtp_sub_vars[key],
                font=("Microsoft YaHei UI", 10, "bold"),
                bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                selectcolor=COLORS["bg_hover"],
                activebackground=COLORS["bg_card"],
                activeforeground=COLORS["text_primary"],
                command=lambda k=key: self._on_rtp_sub_toggle(k),
            )
            cb.pack(side=tk.LEFT)
            tk.Label(
                row, text=desc,
                font=("Microsoft YaHei UI", 8),
                bg=COLORS["bg_card"], fg=COLORS["text_muted"],
            ).pack(side=tk.LEFT, padx=(10, 0))

        # 底部留白
        tk.Frame(modules_card.content, bg=COLORS["bg_card"], height=6).pack()

        # ---- 底部卡片：日志区 ----
        log_card = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                               radius=14, shadow=True)
        log_card.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        log_head = tk.Frame(log_card.content, bg=COLORS["bg_card"])
        log_head.pack(fill=tk.X, padx=16, pady=(14, 6))
        tk.Frame(log_head, bg=COLORS["accent"], width=3, height=15).pack(
            side=tk.LEFT, padx=(0, 8))
        tk.Label(
            log_head, text="📋  实时防护日志",
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
        ).pack(side=tk.LEFT)

        clear_btn = tk.Label(
            log_head, text="  清空日志  ",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_hover"], fg=COLORS["text_secondary"],
            padx=10, pady=4, cursor="hand2",
        )
        clear_btn.pack(side=tk.RIGHT)
        clear_btn.bind("<Button-1>", lambda e: self._clear_rtp_log())
        clear_btn.bind("<Enter>", lambda e: clear_btn.configure(bg=COLORS["accent"], fg="#ffffff"))
        clear_btn.bind("<Leave>", lambda e: clear_btn.configure(bg=COLORS["bg_hover"], fg=COLORS["text_secondary"]))

        self._rtp_log = scrolledtext.ScrolledText(
            log_card.content, wrap=tk.WORD, height=10,
            font=("Consolas", 9),
            bg=COLORS["bg_main"], fg=COLORS["text_primary"],
            relief=tk.FLAT, borderwidth=0,
            padx=12, pady=10,
        )
        self._rtp_log.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 14))
        self._rtp_log.configure(state="disabled")

        # 初始日志
        self._log_rtp_event("INFO", "实时防护面板已就绪 — 点击总开关开启防护")

        return frame

    def _build_results_tab(self) -> tk.Frame:
        """扫描结果标签页"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 6))

        # 【弹性自适应】检测结果计数 Label 占满中间剩余空间，靠右对齐
        # —— 窗口无论多窄，右侧 4 个操作按钮始终可见、不被切；窗口变宽时
        # 计数 Label 自动扩展显示完整数字（不被截断）。
        self._result_count_label = tk.Label(
            toolbar, text="检测结果: 0 个威胁",
            font=("Microsoft YaHei UI", 10, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            anchor="e",  # 文字右对齐：靠近右侧按钮
        )
        self._result_count_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        # 隔离选中按钮
        quarantine_sel_btn = tk.Label(
            toolbar, text="🔒 隔离选中",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_red"],
            padx=10, pady=4, cursor="hand2",
        )
        quarantine_sel_btn.pack(side=tk.RIGHT, padx=2)
        quarantine_sel_btn.bind("<Button-1>", lambda e: self._quarantine_selected())
        self._quarantine_sel_btn = quarantine_sel_btn

        # 删除选中文件按钮（永久删除磁盘上的威胁文件）
        delete_sel_btn = tk.Label(
            toolbar, text="🗑️ 删除选中",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_red"],
            padx=10, pady=4, cursor="hand2",
        )
        delete_sel_btn.pack(side=tk.RIGHT, padx=2)
        delete_sel_btn.bind("<Button-1>", lambda e: self._delete_selected_result_files())

        # 信任选中文件按钮（加入白名单/信任区，后续扫描不再误报）
        trust_sel_btn = tk.Label(
            toolbar, text="✅ 信任选中",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_green"],
            padx=10, pady=4, cursor="hand2",
        )
        trust_sel_btn.pack(side=tk.RIGHT, padx=4)
        trust_sel_btn.bind("<Button-1>", lambda e: self._trust_selected_result_files())

        # 全选按钮
        select_all_btn = tk.Label(
            toolbar, text="☑️ 全选/取消",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            padx=10, pady=4, cursor="hand2",
        )
        select_all_btn.pack(side=tk.RIGHT, padx=2)
        select_all_btn.bind("<Button-1>", lambda e: self._select_all_results())

        export_btn = tk.Label(
            toolbar, text="💾 导出报告",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            padx=10, pady=4, cursor="hand2",
        )
        export_btn.pack(side=tk.RIGHT, padx=2)
        export_btn.bind("<Button-1>", lambda e: self._export_report())

        # 结果列表（Treeview）放在圆角卡片内
        list_frame = tk.Frame(panel.content, bg=COLORS["bg_card"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("check", "level", "name", "threat", "method", "path", "size")
        self._result_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings",
            selectmode="extended",
        )

        # 列标题（第一列为勾选框）
        col_config = [
            ("check", "☑", 36),
            ("level", "等级", 70),
            ("name", "文件名", 200),
            ("threat", "威胁名称", 180),
            ("method", "检测方式", 120),
            ("path", "路径", 300),
            ("size", "大小", 80),
        ]
        for col_id, col_text, col_width in col_config:
            self._result_tree.heading(col_id, text=col_text)
            self._result_tree.column(col_id, width=col_width, minwidth=40)

        # 滚动条
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self._result_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self._result_tree.xview)
        self._result_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._result_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        # 双击查看详情
        self._result_tree.bind("<Double-1>", self._on_result_double_click)
        # 点击勾选框列切换勾选状态（选择框那种）
        self._result_tree.bind("<Button-1>", self._on_result_click)

        # 右键菜单
        self._result_menu = tk.Menu(self.root, tearoff=0, bg=COLORS["bg_card"],
                                     fg=COLORS["text_primary"])
        self._result_menu.add_command(label="🔒 隔离此文件", command=self._quarantine_context)
        self._result_menu.add_command(label="☁️ 云查杀此文件", command=self._cloud_scan_selected)
        self._result_menu.add_command(label="📋 复制路径", command=self._copy_selected_path)
        self._result_menu.add_separator()
        self._result_menu.add_command(label="🤖 AI: 标记为误报 (学入)", command=lambda: self._ai_feedback(FeedbackType.FALSE_POSITIVE))
        self._result_menu.add_command(label="🤖 AI: 确认威胁 (加权)", command=lambda: self._ai_feedback(FeedbackType.CONFIRM_THREAT))
        self._result_menu.add_command(label="🤖 AI: 加入白名单", command=lambda: self._ai_feedback(FeedbackType.MARK_SAFE))
        self._result_menu.add_separator()
        self._result_menu.add_command(label="ℹ️ 查看详情", command=self._show_selected_detail)
        self._result_tree.bind("<Button-3>", self._on_result_right_click)

        return frame

    def _build_quarantine_tab(self) -> tk.Frame:
        """隔离区标签页"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 6))

        self._q_count_label = tk.Label(
            toolbar, text="隔离文件: 0",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
        )
        self._q_count_label.pack(side=tk.LEFT)

        for text, cmd in [
            ("🔄 恢复", self._restore_quarantined),
            ("🗑️ 删除", self._delete_quarantined),
        ]:
            btn = tk.Label(
                toolbar, text=text,
                font=("Microsoft YaHei UI", 9),
                bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
                padx=10, cursor="hand2",
            )
            btn.pack(side=tk.RIGHT, padx=4)
            btn.bind("<Button-1>", lambda e, c=cmd: c())

        # 隔离区列表
        list_frame = tk.Frame(panel.content, bg=COLORS["bg_card"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("qname", "oname", "threat", "path", "size", "time")
        self._quarantine_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings",
            selectmode="browse",
        )
        self._quarantine_item_ids: dict[str, str] = {}  # tree item iid -> 真实隔离名

        qcol_config = [
            ("qname", "隔离ID", 100),
            ("oname", "原文件名", 200),
            ("threat", "威胁名称", 180),
            ("path", "原始路径", 300),
            ("size", "大小", 80),
            ("time", "隔离时间", 160),
        ]
        for col_id, col_text, col_width in qcol_config:
            self._quarantine_tree.heading(col_id, text=col_text)
            self._quarantine_tree.column(col_id, width=col_width, minwidth=40)

        q_vsb = ttk.Scrollbar(list_frame, orient="vertical",
                              command=self._quarantine_tree.yview)
        q_hsb = ttk.Scrollbar(list_frame, orient="horizontal",
                              command=self._quarantine_tree.xview)
        self._quarantine_tree.configure(yscrollcommand=q_vsb.set, xscrollcommand=q_hsb.set)

        self._quarantine_tree.grid(row=0, column=0, sticky="nsew")
        q_vsb.grid(row=0, column=1, sticky="ns")
        q_hsb.grid(row=1, column=0, sticky="ew")

        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        return frame

    def _build_trusted_tab(self) -> tk.Frame:
        """信任区（白名单）标签页"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 6))

        self._trusted_count_label = tk.Label(
            toolbar, text="信任文件: 0",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
        )
        self._trusted_count_label.pack(side=tk.LEFT)

        for text, cmd in [
            ("📁 添加信任", self._add_trusted_file),
            ("🗑️ 移除选中", self._remove_trusted),
            ("🔄 刷新", self._refresh_trusted_list),
        ]:
            btn = tk.Label(
                toolbar, text=text,
                font=("Microsoft YaHei UI", 9),
                bg=COLORS["bg_card"], fg=COLORS["accent_green"],
                padx=10, cursor="hand2",
            )
            btn.pack(side=tk.RIGHT, padx=4)
            btn.bind("<Button-1>", lambda e, c=cmd: c())

        # 提示
        hint = tk.Label(
            panel.content,
            text="信任区中的文件在扫描时会被直接判定为安全，不会被实时防护或手动扫描误报。",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
            anchor="w",
        )
        hint.pack(fill=tk.X, padx=12, pady=(0, 6))

        # 信任区列表
        list_frame = tk.Frame(panel.content, bg=COLORS["bg_card"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("tid", "tname", "tpath", "thash", "ttime")
        self._trusted_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings",
            selectmode="browse",
        )

        tcol_config = [
            ("tid", "ID", 0),
            ("tname", "文件名", 200),
            ("tpath", "路径", 380),
            ("thash", "SHA-256(前16位)", 160),
            ("ttime", "加入时间", 150),
        ]
        for col_id, col_text, col_width in tcol_config:
            self._trusted_tree.heading(col_id, text=col_text)
            if col_width == 0:
                self._trusted_tree.column(col_id, width=0, minwidth=0, stretch=tk.NO)
            else:
                self._trusted_tree.column(col_id, width=col_width, minwidth=40)

        t_vsb = ttk.Scrollbar(list_frame, orient="vertical",
                              command=self._trusted_tree.yview)
        t_hsb = ttk.Scrollbar(list_frame, orient="horizontal",
                              command=self._trusted_tree.xview)
        self._trusted_tree.configure(yscrollcommand=t_vsb.set, xscrollcommand=t_hsb.set)

        self._trusted_tree.grid(row=0, column=0, sticky="nsew")
        t_vsb.grid(row=0, column=1, sticky="ns")
        t_hsb.grid(row=1, column=0, sticky="ew")

        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self._trusted_item_ids: dict[str, str] = {}  # tree item -> 条目 id
        self._refresh_trusted_list()
        return frame

    def _refresh_trusted_list(self):
        """刷新信任区列表"""
        if not hasattr(self, "_trusted_tree"):
            return
        for item in self._trusted_tree.get_children():
            self._trusted_tree.delete(item)
        self._trusted_item_ids.clear()

        for entry in self.whitelist.list_entries():
            sha = (entry.get("sha256") or "")[:16]
            iid = self._trusted_tree.insert("", tk.END, values=(
                entry.get("id", ""),
                entry.get("name", ""),
                entry.get("path", ""),
                sha,
                entry.get("added_at", ""),
            ))
            self._trusted_item_ids[iid] = entry.get("id", "")

        self._trusted_count_label.configure(
            text=f"信任文件: {self.whitelist.count}"
        )

    def _add_trusted_file(self):
        """通过文件选择对话框将文件加入信任区"""
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="选择要加入信任区的文件",
            filetypes=[("所有文件", "*.*")],
        )
        if not path:
            return
        entry = self.whitelist.add(path, note="用户手动添加")
        self._refresh_trusted_list()
        self._update_status_bar(f"✅ 已加入信任区: {entry['name']}")

    def _remove_trusted(self):
        """移除选中的信任条目"""
        if not hasattr(self, "_trusted_tree"):
            return
        selection = self._trusted_tree.selection()
        if not selection:
            return
        entry_id = self._trusted_item_ids.get(selection[0], "")
        if not entry_id:
            return
        if not messagebox.askyesno("移除信任", "确定将选中文件移出信任区吗？\n移出后该文件将重新参与扫描。"):
            return
        if self.whitelist.remove(entry_id):
            self._refresh_trusted_list()
            self._update_status_bar("🗑️ 已移出信任区")

    # ==========================================================
    # 逆向恢复标签页（勒索软件文件恢复）
    # ==========================================================
    def _build_recovery_tab(self) -> tk.Frame:
        """逆向恢复标签页：卷影副本恢复 / 永恒之蓝检测加固 / WannaCry 内存密钥逆向。"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        if not self.recovery:
            tk.Label(frame, text="⚠ 逆向恢复模块加载失败（recovery.py 缺失或异常）。",
                     bg=COLORS["bg_main"], fg=COLORS["accent_red"],
                     font=("Microsoft YaHei UI", 11)).pack(padx=20, pady=20)
            return frame

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 4))
        self._recovery_scan_btn = self._create_button(
            toolbar, "🔍 扫描加密文件", self._recovery_scan, COLORS["accent_blue"])
        self._recovery_scan_btn.pack(side=tk.LEFT, padx=4)
        self._create_button(
            toolbar, "📦 卷影副本恢复", self._recovery_shadow_info,
            COLORS["accent_cyan"]).pack(side=tk.LEFT, padx=4)
        self._create_button(
            toolbar, "🛡️ 永恒之蓝检测", self._recovery_check_eternalblue,
            COLORS["accent_purple"]).pack(side=tk.LEFT, padx=4)
        self._create_button(
            toolbar, "🧬 WannaCry 内存恢复", self._recovery_wannacry_recover,
            COLORS["accent_red"]).pack(side=tk.LEFT, padx=4)

        hint = tk.Label(
            panel.content,
            text="说明：本工具无法「通杀」所有勒索软件（无密钥则无法解密）。但它提供三条真实可行的恢复路径："
                 "① 卷影副本(以前版本)恢复原文件；② 检测并加固永恒之蓝(MS17-010)漏洞；"
                 "③ 利用 WannaCry 内存质数残留(WannaKey 原理)逆向私钥解密。",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"], anchor="w",
            wraplength=900, justify="left")
        hint.pack(fill=tk.X, padx=12, pady=(2, 8))

        # 中部：疑似文件列表填满整个宽度（永恒之蓝/WannaCry 卡片已挪到下方 cards_row）
        # —— 之前 middle.columnconfigure(1, minsize=320) 会留 320px 空列，
        #    导致列表在高 DPI / 窄窗口下显示不全；现在 left 占满全部水平空间。
        middle = tk.Frame(panel.content, bg=COLORS["bg_card"])
        middle.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))
        middle.columnconfigure(0, weight=1)   # 列表占满 100%
        middle.rowconfigure(0, weight=1)

        # 左：疑似被加密文件
        left = tk.Frame(middle, bg=COLORS["bg_card"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(left, text="疑似被加密文件", font=("Microsoft YaHei UI", 11, "bold"),
                 bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                 anchor="w").pack(fill=tk.X, padx=2, pady=(0, 4))

        list_frame = tk.Frame(left, bg=COLORS["bg_card"])
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("rname", "rfamily", "rentropy", "rsize", "rpath")
        self._recovery_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", selectmode="extended")
        for col_id, col_text, col_width in [
            ("rname", "文件名", 170), ("rfamily", "家族", 110),
            ("rentropy", "熵", 60), ("rsize", "大小", 80), ("rpath", "路径", 260),
        ]:
            self._recovery_tree.heading(col_id, text=col_text)
            self._recovery_tree.column(col_id, width=col_width, minwidth=40)
        r_vsb = ttk.Scrollbar(list_frame, orient="vertical",
                               command=self._recovery_tree.yview)
        r_hsb = ttk.Scrollbar(list_frame, orient="horizontal",
                               command=self._recovery_tree.xview)
        self._recovery_tree.configure(yscrollcommand=r_vsb.set, xscrollcommand=r_hsb.set)
        self._recovery_tree.grid(row=0, column=0, sticky="nsew")
        r_vsb.grid(row=0, column=1, sticky="ns")
        r_hsb.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self._recovery_item_ids: dict[str, str] = {}

        btn_row = tk.Frame(left, bg=COLORS["bg_card"])
        btn_row.pack(fill=tk.X, pady=(6, 2))
        pick = tk.Label(btn_row, text="📁 选择目录扫描",
                        font=("Microsoft YaHei UI", 9), bg=COLORS["bg_card"],
                        fg=COLORS["accent_blue"], padx=10, cursor="hand2")
        pick.pack(side=tk.LEFT, padx=4)
        pick.bind("<Button-1>", lambda e: self._recovery_scan())
        restore = tk.Label(btn_row, text="🔓 用卷影副本恢复选中",
                           font=("Microsoft YaHei UI", 9), bg=COLORS["bg_card"],
                           fg=COLORS["accent_green"], padx=10, cursor="hand2")
        restore.pack(side=tk.LEFT, padx=4)
        restore.bind("<Button-1>", lambda e: self._recovery_restore_selected())

        # 两个状态卡片从 right 区域移到下方，并排铺满全宽（grid 两列均分）
        cards_row = tk.Frame(panel.content, bg=COLORS["bg_card"])
        cards_row.pack(fill=tk.X, padx=10, pady=(0, 6))
        cards_row.columnconfigure(0, weight=1, uniform="recovery_card")
        cards_row.columnconfigure(1, weight=1, uniform="recovery_card")
        cards_row.rowconfigure(0, weight=1)

        # 永恒之蓝卡片（左列）
        eb_card = RoundedCard(cards_row, bg=COLORS["bg_card"], border=COLORS["border"],
                              radius=14, shadow=False)
        eb_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        tk.Label(eb_card.content, text="🛡️ 永恒之蓝 (MS17-010)",
                 font=("Microsoft YaHei UI", 11, "bold"), bg=COLORS["bg_card"],
                 fg=COLORS["text_primary"], anchor="w").pack(fill=tk.X, padx=4, pady=(4, 2))
        self._eb_status = tk.Label(eb_card.content, text="未检测",
                                    font=("Microsoft YaHei UI", 9),
                                    bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
                                    anchor="w", wraplength=300, justify="left")
        self._eb_status.pack(fill=tk.X, padx=4, pady=(0, 6))
        self._eb_harden_btn = self._create_button(
            eb_card.content, "🛡️ 一键加固 (禁SMBv1+封445)",
            self._recovery_harden_eternalblue, COLORS["accent_purple"])
        self._eb_harden_btn.pack(fill=tk.X, padx=4, pady=(0, 8))

        # WannaCry 卡片（右列）
        wc_card = RoundedCard(cards_row, bg=COLORS["bg_card"], border=COLORS["border"],
                              radius=14, shadow=False)
        wc_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        tk.Label(wc_card.content, text="🧬 WannaCry 内存密钥逆向",
                 font=("Microsoft YaHei UI", 11, "bold"), bg=COLORS["bg_card"],
                 fg=COLORS["text_primary"], anchor="w").pack(fill=tk.X, padx=4, pady=(4, 2))
        self._wc_status = tk.Label(wc_card.content, text="未逆向",
                                    font=("Microsoft YaHei UI", 9),
                                    bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
                                    anchor="w", wraplength=300, justify="left")
        self._wc_status.pack(fill=tk.X, padx=4, pady=(0, 6))
        self._create_button(wc_card.content, "🧬 从进程内存提取私钥",
                            self._recovery_wannacry_recover,
                            COLORS["accent_red"]).pack(fill=tk.X, padx=4, pady=(0, 4))
        self._wc_decrypt_btn = self._create_button(
            wc_card.content, "🔓 解密选中 .wncry 文件",
            self._recovery_decrypt_selected, COLORS["accent_green"])
        self._wc_decrypt_btn.pack(fill=tk.X, padx=4, pady=(0, 8))
        self._wc_decrypt_btn.configure(state=tk.DISABLED)

        # 日志区
        log_frame = tk.Frame(panel.content, bg=COLORS["bg_card"], height=130)
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        log_frame.pack_propagate(False)
        tk.Label(log_frame, text="操作日志", font=("Microsoft YaHei UI", 9, "bold"),
                 bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
                 anchor="w").pack(fill=tk.X, padx=2)
        self._recovery_log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, height=6,
            font=("Consolas", 9),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"], relief=tk.FLAT, borderwidth=0)
        self._recovery_log_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self._recovery_log_text.configure(state=tk.DISABLED)

        self._recovery_log("🔓 逆向恢复模块已就绪。建议顺序：扫描加密文件 → 用卷影副本恢复 → "
                           "若确认为 WannaCry 且进程仍在运行，尝试内存密钥逆向。")
        return frame

    def _recovery_run(self, target, on_done):
        """在后台线程执行 target，完成后切回主线程调用 on_done(result)。"""
        def _worker():
            try:
                result = target()
            except Exception as e:
                result = {"_error": str(e)}
            self.root.after(0, lambda: on_done(result))
        threading.Thread(target=_worker, daemon=True).start()

    def _recovery_log(self, msg: str):
        def _append():
            try:
                self._recovery_log_text.configure(state=tk.NORMAL)
                self._recovery_log_text.insert(tk.END, msg + "\n")
                self._recovery_log_text.configure(state=tk.DISABLED)
                self._recovery_log_text.see(tk.END)
            except Exception:
                pass
        if threading.current_thread() is threading.main_thread():
            _append()
        else:
            self.root.after(0, _append)

    def _recovery_scan(self):
        """选择目录并扫描疑似被加密文件。"""
        if not self.recovery:
            return
        from tkinter import filedialog
        d = filedialog.askdirectory(
            title="选择要扫描的目录（排查被加密文件）",
            initialdir=str(Path.home()))
        if not d:
            return
        self._recovery_log(f"🔍 正在扫描: {d}")
        self._recovery_scan_btn.configure(state=tk.DISABLED)
        self._update_status_bar(f"🔍 正在排查加密文件: {d}")

        def work():
            return self.recovery.detector.scan(d, recursive=True, max_files=20000)

        def done(res):
            self._recovery_scan_btn.configure(state=tk.NORMAL)
            self._refresh_recovery_tree(res)
            self._recovery_log(res["summary"])
            if res["wannacry_detected"]:
                self._recovery_log("⚠ 检测到 WannaCry！可尝试「内存密钥逆向」或「卷影副本恢复」。")
            self._update_status_bar("✅ 加密文件排查完成")

        self._recovery_run(work, done)

    def _refresh_recovery_tree(self, res: dict):
        try:
            for item in self._recovery_tree.get_children():
                self._recovery_tree.delete(item)
            self._recovery_item_ids.clear()
            for s in res.get("suspects", []):
                iid = self._recovery_tree.insert("", tk.END, values=(
                    s.get("name", ""), s.get("family", ""),
                    s.get("entropy", ""), self._format_size(s.get("size", 0)),
                    s.get("path", ""),
                ))
                self._recovery_item_ids[iid] = s.get("path", "")
        except Exception:
            pass

    def _recovery_restore_selected(self):
        """用卷影副本恢复选中的被加密文件（恢复其加密前的原版本）。"""
        if not self.recovery:
            return
        sel = self._recovery_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在上方列表中选择要恢复的文件。")
            return
        from tkinter import filedialog
        dest = filedialog.askdirectory(
            title="选择恢复文件保存目录",
            initialdir=str(_get_data_dir() / "recovered"))
        if not dest:
            return
        ok = fail = 0
        for iid in sel:
            p = self._recovery_item_ids.get(iid, "")
            if not p:
                continue
            r, msg = ShadowCopyRecovery.restore_file(p, dest)
            if r:
                ok += 1
                self._recovery_log(f"✅ 已恢复: {msg}")
            else:
                fail += 1
                self._recovery_log(f"❌ 恢复失败 {p}: {msg}")
        messagebox.showinfo("卷影副本恢复", f"成功恢复 {ok} 个，失败 {fail} 个。")
        self._update_status_bar(f"🔓 卷影副本恢复：成功 {ok} / 失败 {fail}")

    def _recovery_shadow_info(self):
        """列出系统卷影副本并给出恢复指引。"""
        if not self.recovery:
            return
        self._recovery_log("📦 正在查询系统卷影副本（以前版本）...")
        shadows = ShadowCopyRecovery.list_shadows()
        if not shadows:
            self._recovery_log("⚠ 未发现卷影副本。若勒索软件已删除 VSS（vssadmin delete shadows），"
                               "则只能依赖内存密钥逆向或备份。")
            self._recovery_log("💡 可在被加密文件上点右键 →『属性 → 以前版本』手动查看是否有快照。")
        else:
            self._recovery_log(f"发现 {len(shadows)} 个卷影副本：")
            for sh in shadows:
                self._recovery_log(f"  • {sh.get('device','')}  创建于 {sh.get('created','')}")
            self._recovery_log("👆 在上方列表选中被加密文件，点击『用卷影副本恢复选中』即可还原原版本。")

    def _recovery_check_eternalblue(self):
        """检测永恒之蓝(MS17-010)漏洞状态。"""
        if not self.recovery:
            return
        self._recovery_log("🛡️ 正在检测永恒之蓝(MS17-010)...")
        self._eb_status.configure(text="检测中...")

        def work():
            return self.recovery.eternal.check()

        def done(rep):
            smb = rep.get("smb1_enabled")
            smb_s = "开启(危险)" if smb is True else ("已关闭" if smb is False else "未知")
            vuln = rep.get("vulnerable")
            self._eb_status.configure(
                text=(f"风险状态: {'⚠ 存在风险' if vuln else '✅ 已防护'}\n"
                      f"MS17-010 补丁: {'已安装' if rep.get('patched') else '未安装'}\n"
                      f"SMBv1: {smb_s}\n"
                      f"系统: {rep.get('os','')}"),
                fg=COLORS["accent_red"] if vuln else COLORS["accent_green"])
            for r in rep.get("reasons", []):
                self._recovery_log("  • " + r)
            self._recovery_log("🔍 永恒之蓝检测完成。")
            self._update_status_bar("🛡️ 永恒之蓝检测完成")

        self._recovery_run(work, done)

    def _recovery_harden_eternalblue(self):
        """一键加固：禁用 SMBv1 + 阻断入站 445。"""
        if not self.recovery:
            return
        if not messagebox.askyesno(
                "一键加固",
                "将执行以下操作（需管理员权限）：\n  1. 禁用 SMBv1 协议\n  "
                "2. 在防火墙阻断入站 TCP 445\n\n确定继续？"):
            return
        self._recovery_log("🔧 正在加固系统（禁用 SMBv1 + 阻断 445）...")

        def work():
            return self.recovery.eternal.harden()

        def done(res):
            if isinstance(res, dict) and "_error" in res:
                self._recovery_log("❌ 加固异常: " + res["_error"])
                return
            ok, msg, _ = res
            self._recovery_log(msg)
            if not ok and "管理员" in msg:
                messagebox.showwarning("需要管理员权限",
                                       "请右键以「管理员身份运行」X-Safe 后再执行加固。")
            self._recovery_check_eternalblue()

        self._recovery_run(work, done)

    def _recovery_wannacry_recover(self):
        """从 WannaCry 进程内存提取 RSA 私钥（WannaKey 原理）。"""
        if not self.recovery:
            return
        self._recovery_log("🧬 正在从 WannaCry 进程内存提取 RSA 私钥（WannaKey 原理）...")
        self._wc_status.configure(text="逆向中...")
        self._wc_decrypt_btn.configure(state=tk.DISABLED)

        def work():
            return self.recovery.wannacry.recover_keys()

        def done(res):
            if res.get("success"):
                self._wc_status.configure(
                    text=f"✅ 私钥已还原（进程 {res.get('pid')}）\n可解密 .wncry 文件",
                    fg=COLORS["accent_green"])
                self._wc_decrypt_btn.configure(state=tk.NORMAL)
                self._recovery_log("✅ 成功从内存提取质数并重构 RSA 私钥！现在可解密 .wncry 文件。")
            else:
                self._wc_status.configure(text="❌ 未能获取私钥",
                                          fg=COLORS["accent_red"])
                self._recovery_log("❌ " + res.get("error", "未知错误"))
                if res.get("fallback") == "shadow":
                    self._recovery_log("💡 进程内存残留已不可用，建议改用「卷影副本恢复」恢复原文件。")
            self._update_status_bar("🧬 WannaCry 内存逆向完成")

        self._recovery_run(work, done)

    def _recovery_decrypt_selected(self):
        """解密选中的 .wncry 文件。需先完成内存密钥逆向。"""
        if not self.recovery:
            return
        if self.recovery.wannacry._private_d is None:
            messagebox.showwarning("请先逆向", "请先点击『从进程内存提取私钥』获取私钥。")
            return
        from tkinter import filedialog
        files = filedialog.askopenfilenames(
            title="选择要解密的 .wncry 文件",
            filetypes=[("WannaCry 加密文件", "*.wncry"), ("所有文件", "*.*")])
        if not files:
            return
        dest = filedialog.askdirectory(
            title="选择解密后文件保存目录",
            initialdir=str(_get_data_dir() / "recovered"))
        if not dest:
            return
        ok = fail = 0
        for f in files:
            r, msg = self.recovery.wannacry.decrypt_file(f, dest)
            if r:
                ok += 1
                self._recovery_log(f"✅ 已解密: {msg}")
            else:
                fail += 1
                self._recovery_log(f"❌ 解密失败 {f}: {msg}")
        messagebox.showinfo("WannaCry 解密", f"成功 {ok} 个，失败 {fail} 个。")
        self._update_status_bar(f"🔓 WannaCry 解密：成功 {ok} / 失败 {fail}")

    def _build_signatures_tab(self) -> tk.Frame:
        """特征库标签页"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 6))

        sig_count = (self.sig_db.hash_count + self.sig_db.pattern_count)
        ai_stats = self.scanner.learning_stats
        sig_label = tk.Label(
            toolbar, text=f"特征库: {sig_count} 条签名 | "
                          f"哈希: {self.sig_db.hash_count} | "
                          f"规则: {self.sig_db.pattern_count} | "
                          f"🧠 AI学习: {ai_stats['total_feedback']}次反馈",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
        )
        sig_label.pack(side=tk.LEFT)

        reload_btn = tk.Label(
            toolbar, text="🔄 重新加载",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            padx=12, cursor="hand2",
        )
        reload_btn.pack(side=tk.RIGHT, padx=10)
        reload_btn.bind("<Button-1>", lambda e: self._reload_signatures())

        # 特征库内容
        text_frame = tk.Frame(panel.content, bg=COLORS["bg_card"])
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self._sig_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD,
            font=("Consolas", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief=tk.FLAT, borderwidth=0,
        )
        self._sig_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 加载特征库内容
        self._display_signatures()

        return frame

    def _build_status_bar(self):
        """底部状态栏"""
        # 状态栏顶部柔和分隔线
        top_sep = tk.Frame(self.root, bg=COLORS["border"], height=1)
        top_sep.pack(fill=tk.X, side=tk.BOTTOM)
        bar = tk.Frame(self.root, bg=COLORS["bg_secondary"], height=28)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._status_text = tk.Label(
            bar, text="",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_secondary"], fg=COLORS["text_secondary"],
        )
        self._status_text.pack(side=tk.LEFT, padx=14)

        # 实时防护开关
        rtp_frame = tk.Frame(bar, bg=COLORS["bg_secondary"])
        rtp_frame.pack(side=tk.RIGHT, padx=14)

        # 主动防御自测入口（零风险验证右下角弹窗，无需真实威胁）
        self._selftest_btn = tk.Label(
            rtp_frame, text="🧪 自测防御",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_secondary"], fg=COLORS["accent_blue"],
            cursor="hand2",
        )
        self._selftest_btn.pack(side=tk.RIGHT, padx=(0, 10))
        self._selftest_btn.bind("<Button-1>", lambda e: self._self_test_defense())

        self._rtp_switch_btn = tk.Label(
            rtp_frame, text="🔴 开启实时防护",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_secondary"], fg=COLORS["accent_green"],
            cursor="hand2",
        )
        self._rtp_switch_btn.pack(side=tk.RIGHT)
        self._rtp_switch_btn.bind("<Button-1>", lambda e: self._toggle_rtp())

    # ==========================================================
    # 辅助 UI 方法
    # ==========================================================
    def _create_card(self, parent, title: str) -> tk.Frame:
        """创建直角卡片容器，返回 .content 供子控件使用"""
        card = RoundedCard(parent, bg=COLORS["bg_card"], border=COLORS["border"],
                           radius=0, shadow=False)
        card.pack(fill=tk.X, pady=(0, 12))

        # 标题行：品牌色装饰小条 + 标题文字
        head = tk.Frame(card.content, bg=COLORS["bg_card"])
        head.pack(fill=tk.X, padx=2, pady=(6, 8))
        tk.Frame(head, bg=COLORS["accent"], width=3, height=15).pack(
            side=tk.LEFT, padx=(2, 8))
        tk.Label(
            head, text=title,
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            anchor="w",
        ).pack(side=tk.LEFT)

        return card.content

    def _create_button(self, parent, text: str, command, color: str) -> RoundedButton:
        """创建直角按钮（未指定宽度时按文本估算，确保不 fill 也可见）"""
        width = 0
        for ch in text:
            width += 14 if ord(ch) > 0x2E80 else 8
        width += 28
        return RoundedButton(
            parent, text=text, command=command, color=color,
            radius=0, height=42, width=width,
            font=("Microsoft YaHei UI", 10, "bold"),
        )

    @staticmethod
    def _lighten_color(hex_color: str, factor: float = 0.15) -> str:
        """调亮颜色（保留以兼容历史调用）"""
        return _lighten_color(hex_color, factor)

    def _draw_rtp_indicator(self, active: bool):
        """绘制实时防护状态指示灯"""
        self._rtp_indicator.delete("all")
        color = COLORS["accent_green"] if active else COLORS["text_muted"]
        self._rtp_indicator.create_oval(1, 1, 9, 9, fill=color, outline="")

    # ==========================================================
    # 扫描操作
    # ==========================================================
    def _start_quick_scan(self):
        """开始快速扫描"""
        self._scan_target_label.configure(text="扫描目标: 关键目录 (下载/桌面/文档/临时文件)")
        self._start_scan_thread(lambda: self.scanner.quick_scan())

    def _start_cloud_scan(self):
        """独立云查杀 — 选择文件后上传哈希到云端引擎查询"""
        if self._scanning:
            return

        filepath = filedialog.askopenfilename(
            title="选择要云查杀的文件",
            filetypes=[
                ("可执行文件", "*.exe *.dll *.sys *.com *.scr *.msi"),
                ("脚本文件", "*.bat *.cmd *.ps1 *.vbs *.js *.py *.php"),
                ("所有文件", "*.*"),
            ],
        )
        if not filepath:
            return

        self._scan_target_label.configure(text=f"云查杀目标: {os.path.basename(filepath)}")
        self._scanning = True
        self._cloud_scan_btn.configure(state=tk.DISABLED)
        self._quick_scan_btn.configure(state=tk.DISABLED)
        self._advanced_scan_btn.configure(state=tk.DISABLED)
        self._custom_scan_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.DISABLED)

        self._update_status_bar("☁️ 正在云端查杀...")
        self._progress_label.configure(text="正在连接云端引擎查询...")

        # 异步云查杀
        def on_cloud_done(result: CloudScanResult):
            self._scan_queue.put(("cloud_standalone_done", filepath, result))

        self.cloud_scanner.scan_file_cloud_async(filepath, on_cloud_done)

    def _start_advanced_scan(self):
        """高级查杀 — 全盘扫描 + AI + 云引擎三引擎联动"""
        if not messagebox.askyesno(
            "🔥 高级查杀",
            "高级查杀将对全盘进行深度扫描，同时调用以下三个引擎:\n\n"
            "  1. 🔍 本地特征引擎 — 哈希签名 + 模式匹配 + 启发式\n"
            "  2. 🧠 AI 自学习引擎 — 10维特征贝叶斯评分\n"
            "  3. ☁️ 云端引擎 — 360云 + VirusTotal 在线验证\n\n"
            "扫描时间较长（几分钟到几十分钟），每个可疑文件都会经过三重确认。\n\n确定要开始吗？",
        ):
            return

        self._cloud_pending = 0          # 待完成的云查杀计数
        self._cloud_completed = 0        # 已完成的云查杀计数
        self._is_advanced_scan = True    # 标记为高级查杀模式
        self._scan_target_label.configure(
            text="扫描目标: 全盘 (三引擎联动: 本地+AI+云端)"
        )

        def advanced_scan_worker():
            # 在扫描线程中执行全盘扫描
            results = self.scanner.full_scan()

            # 等待所有云查杀完成后，再标记扫描结束
            self._scan_queue.put(("advanced_scan_complete", results))

        self._start_scan_thread(advanced_scan_worker)

    def _start_custom_scan(self):
        """自定义扫描"""
        target = filedialog.askdirectory(title="选择要扫描的文件夹")
        if not target:
            return

        self._scan_target_label.configure(text=f"扫描目标: {target}")
        self._start_scan_thread(lambda: self.scanner.scan_directory(target, recursive=True))

    def _run_pre_scan_check(self) -> str:
        """ESET 风格：扫描前快速系统健康检查（1-2秒完成）。
        检查关键区域并返回摘要文本，立即写入日志区让用户看到。
        纯只读检查，不做任何修改。"""
        import winreg
        findings = []
        checked = 0

        # 1. 检查注册表自启动项（Run / RunOnce）
        try:
            suspicious_entries = []
            for hive_path, hive in [
                (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.HKEY_CURRENT_USER),
                (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.HKEY_LOCAL_MACHINE),
                (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", winreg.HKEY_CURRENT_USER),
            ]:
                try:
                    key = winreg.OpenKey(hive, hive_path, 0, winreg.KEY_READ)
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        checked += 1
                        # 标记可疑特征：无引号路径含空格、临时目录、奇怪扩展名
                        val_lower = value.lower() if isinstance(value, str) else ""
                        if any(s in val_lower for s in ["temp", "appdata\\local\\temp", "%tmp%",
                                                            "powershell -enc", "bitsadmin",
                                                            "certutil -decode"]):
                            suspicious_entries.append(f"  ⚠️ {name} = {value[:80]}")
                    winreg.CloseKey(key)
                except Exception:
                    pass
            if suspicious_entries:
                findings.append(f"🔍 注册表自启动: 发现 {len(suspicious_entries)} 条可疑项")
                for s in suspicious_entries[:5]:
                    findings.append(s)
            else:
                findings.append(f"✅ 注册表自启动: {checked} 项正常")
        except Exception:
            findings.append("ℹ️ 注册表自启动: 跳过（无权限）")

        # 2. 检查临时目录可疑文件
        import tempfile
        temp_dir = tempfile.gettempdir()
        try:
            temp_exes = []
            temp_count = 0
            now = time.time()
            for f in os.listdir(temp_dir):
                fp = os.path.join(temp_dir, f)
                if not os.path.isfile(fp):
                    continue
                temp_count += 1
                ext = os.path.splitext(f)[1].lower()
                if ext in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"):
                    try:
                        mtime = os.path.getmtime(fp)
                        age_hours = (now - mtime) / 3600
                        if age_hours < 24:  # 24小时内新建/修改的
                            temp_exes.append((f, age_hours))
                    except Exception:
                        pass
            if temp_exes:
                findings.append(f"📁 临时目录: 发现 {len(temp_exes)} 个近期可执行文件（近24h）")
                for fname, age in sorted(temp_exes, key=lambda x: x[1])[:3]:
                    findings.append(f"  📄 {fname} ({age:.0f}h前)")
            else:
                findings.append(f"✅ 临时目录: {temp_count} 个文件，无可疑可执行文件")
        except Exception:
            findings.append("ℹ️ 临时目录: 跳过")

        # 3. 检查 hosts 文件大小（异常大可能被劫持）
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            if os.path.exists(hosts_path):
                size = os.path.getsize(hosts_path)
                # 正常 hosts 通常 < 2KB；被劫持的可能 > 10KB
                if size > 10240:
                    findings.append(f"⚠️ Hosts 文件异常: {size/1024:.0f}KB（正常 < 10KB，可能被 DNS 劫持）")
                elif size > 2048:
                    findings.append(f"📝 Hosts 文件较大: {size/1024:.1f}KB")
                else:
                    findings.append(f"✅ Hosts 文件: 正常 ({size}B)")
        except Exception:
            pass

        # 4. 快速进程内存扫描提示（高内存占用 + 非系统进程）
        try:
            import ctypes
            high_mem_procs = []
            # 用简单的 WMI-less 方式枚举进程
            result = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True, timeout=10,
            )
            for line in result.stdout.decode("gbk", errors="replace").splitlines():
                parts = [p.strip().strip('"') for p in line.split('","')]
                if len(parts) >= 5:
                    pname, pid_str, mem_str = parts[0], parts[1], parts[4]
                    mem_mb = 0
                    try:
                        mem_str = mem_str.rstrip(" K").replace(",", "")
                        mem_mb = int(mem_str) // 1024
                    except ValueError:
                        pass
                    if mem_mb > 200 and pname.lower() not in (
                        "svchost.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
                        "dwm.exe", "taskhostw.exe", "system", "python.exe", "pythonw.exe",
                    ):
                        high_mem_procs.append(f"{pname}(PID:{pid_str}, {mem_mb}MB)")
            if high_mem_procs:
                findings.append(f"💻 高内存非系统进程 (>200MB): {len(high_mem_procs)} 个")
                for hp in high_mem_procs[:3]:
                    findings.append(f"  🔷 {hp}")
        except Exception:
            pass

        summary = "\n".join(findings)
        return summary

    def _start_scan_thread(self, scan_fn):
        """启动扫描线程"""
        if self._scanning:
            return

        self._scanning = True
        self._scan_cancelled = False
        self._current_results = []
        self._files_scanned = 0
        self._total_files_to_scan = 0
        self._current_cloud_results = {}   # 重置云端结果缓存（避免跨扫描去重串扰）
        self._cloud_pending = 0
        self._cloud_completed = 0

        # 清空结果列表
        for item in self._result_tree.get_children():
            self._result_tree.delete(item)
        self._tree_results.clear()
        self._checked.clear()

        # 更新 UI 状态
        self._quick_scan_btn.configure(state=tk.DISABLED)
        self._cloud_scan_btn.configure(state=tk.DISABLED)
        self._advanced_scan_btn.configure(state=tk.DISABLED)
        self._custom_scan_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._progress_var.set(0)
        self._progress_bar.configure(mode="determinate")  # 始终用连续进度条，不脉动

        self._update_status_bar("🔄 正在启动扫描...")
        self._start_progress_ticker()  # 进度心跳：直接读取扫描器实时统计驱动进度条
        self._progress_label.configure(text="🏥 正在执行系统预检...")

        # 重置扫描器
        self.scanner.reset()
        self.scanner.set_progress_callback(self._on_scan_progress)

        # 在线程中执行扫描（含预检）
        def scan_worker():
            try:
                # ESET 风格：先跑快速预检，结果立即推送到主线程显示
                pre_check = self._run_pre_scan_check()
                self._scan_queue.put(("pre_scan_check", pre_check))

                # 预检完成，开始正式扫描
                results = scan_fn()
                self._scan_queue.put(("complete", results))
            except Exception as e:
                self._scan_queue.put(("error", str(e)))

        self._scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self._scan_thread.start()

    # ----------------------------------------------------------
    # 进度心跳（与事件队列解耦，保证进度条平滑同步、停止即时响应）
    # ----------------------------------------------------------
    def _start_progress_ticker(self):
        """启动轻量进度心跳：直接读取扫描器实时统计更新进度条与标签。
        与跨线程事件队列解耦 —— 即使队列积压海量事件，进度条依然平滑同步；
        收到停止后扫描线程瞬间中断，心跳也会立刻收尾，停止不再"卡顿"。"""
        self._progress_ticker_job = None
        self._tick_progress()

    def _tick_progress(self):
        if not self._scanning:
            self._progress_ticker_job = None
            return
        try:
            stats = self.scanner.stats
            # 当前正在扫描的文件（ESET 风格：显示文件名）
            cur = stats.current_file or ""
            cur_display = os.path.basename(cur) if cur else ""

            if stats.total_files > 0:
                pct = min(100.0, (stats.scanned_files / stats.total_files) * 100)
                self._progress_var.set(pct)
                text = (
                    f"已扫描: {stats.scanned_files}/{stats.total_files} ({pct:.0f}%) | "
                    f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found}"
                )
                if cur_display:
                    text += f"\n📄 {cur_display}"
            else:
                # 流式模式早期（全盘扫描）：total_files 尚在增长中，显示动态计数
                text = (
                    f"🔍 正在扫描... 已处理 {stats.scanned_files} 个文件 | "
                    f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found}"
                )
                if cur_display:
                    text += f"\n📄 {cur_display}"
                # 进度条用脉动表示"正在工作、总数未定"
                self._progress_var.configure  # no-op (keep determinate, let it sit at 0)
            if self._cloud_pending > 0:
                text += f" | ☁️ 云端验证中: {self._cloud_pending}"
            self._progress_label.configure(text=text)
        except Exception:
            pass
        try:
            self._progress_ticker_job = self.root.after(50, self._tick_progress)
        except (tk.TclError, RuntimeError):
            self._progress_ticker_job = None

    def _stop_progress_ticker(self):
        """停止进度心跳"""
        job = getattr(self, "_progress_ticker_job", None)
        if job is not None:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
            self._progress_ticker_job = None

    def _stop_scan(self):
        """停止扫描"""
        if self._scanning:
            self.scanner.cancel_scan()           # 设置取消标志，扫描线程会在下一个检查点立即中断
            self._scan_cancelled = True          # 标记为用户取消，收尾时显示「已取消」而非「完成」
            self._progress_bar.configure(mode="determinate")  # 确保是连续模式
            self._update_status_bar("⏹ 正在停止扫描...")

    def _on_scan_progress(self, result: ScanResult):
        """扫描进度回调 (在扫描线程中调用, 线程安全)"""
        self._files_scanned += 1
        stats = self.scanner.stats

        # ⚡ 关键: 进度事件【立即】入队, 不等 AI 二次全文件扫描
        # 这样进度条每扫一个文件就往前走, 停止按钮也能即时响应
        self._scan_queue.put(("progress", result, stats))

        # AI 评分放到【独立线程】异步做, 避免阻塞扫描线程 / 卡住进度条
        if result.is_threat and not self.scanner.is_cancelled():
            def _ai_job():
                try:
                    ai_result, ai_score, features = self.scanner.scan_file(
                        result.file_path,
                        should_cancel=self.scanner.is_cancelled,
                    )
                    self._current_ai_scores[result.file_path] = ai_score
                    self._current_features[result.file_path] = features
                    # 二次扫描完成 → 把 AI 评分回传主线程, 更新结果行
                    self._scan_queue.put(
                        ("ai_ready", result.file_path, ai_result, ai_score)
                    )
                except ScanCancelled:
                    pass
                except Exception:
                    pass
            threading.Thread(target=_ai_job, daemon=True).start()

    def _process_scan_queue(self):
        """主线程轮询队列, 安全更新 UI"""
        try:
            processed = 0
            # 每帧最多处理 CAP 个事件: 避免一次性排空海量事件导致界面冻结
            # (之前会卡住, 表现为进度条跳跃 + 停止后 UI 长时间无响应)
            CAP = 400
            while not self._scan_queue.empty() and processed < CAP:
                try:
                    item = self._scan_queue.get_nowait()
                except queue.Empty:
                    break

                event_type = item[0]
                # 终态事件（完成/出错/隔离完成/云端完成）优先处理:
                # 即便队列有积压也先让扫描收尾, 保证「停止」即时响应
                if event_type in (
                    "complete", "error", "advanced_scan_complete",
                    "cloud_done", "quarantine_done",
                ):
                    self._dispatch_scan_event(item)
                    break

                self._dispatch_scan_event(item)
                processed += 1
        except Exception:
            # 队列处理异常不应中断主循环
            pass

        # 继续轮询（间隔缩短到 30ms, 事件更跟手）
        try:
            self._scan_queue_job = self.root.after(30, self._process_scan_queue)
        except (tk.TclError, RuntimeError):
            self._scan_queue_job = None

    # === 扫描结果 tree 轮询触发器（不依赖任何回调） ===
    def _init_debug(self, msg: str):
        """超早期 debug — 写到 exe 同目录/init_debug.log，排查 init 卡在哪"""
        try:
            from datetime import datetime as _dt
            log_path = os.path.join(getattr(self, "_exe_dir", os.getcwd()), "init_debug.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{_dt.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")
        except Exception:
            pass

    def _poll_debug_log(self, msg: str):
        """写调试日志到数据目录/poll_debug.log — 排查弹窗为什么没触发"""
        try:
            from datetime import datetime as _dt
            data_dir = _get_data_dir()
            log_path = os.path.join(str(data_dir), "poll_debug.log")
            ts = _dt.now().strftime("%H:%M:%S.%f")[:-3]
            line = f"[{ts}] {msg}\n"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
            # 成功：也写一份到 exe 同目录方便查
            try:
                fb = os.path.join(getattr(self, "_exe_dir", os.getcwd()), "poll_debug.log")
                with open(fb, "a", encoding="utf-8") as f2:
                    f2.write(f"[{ts}] {msg}\n")
            except Exception:
                pass
        except Exception as e:
            # 最后兜底：写到 exe 同目录（绝对能写）
            try:
                from datetime import datetime as _dt2
                log_path2 = os.path.join(getattr(self, "_exe_dir", os.getcwd()), "poll_debug.log")
                ts2 = _dt2.now().strftime("%H:%M:%S.%f")[:-3]
                with open(log_path2, "a", encoding="utf-8") as f:
                    f.write(f"[{ts2}] FALLBACK data_dir={data_dir!r} log_path={log_path!r} err={e!r} msg={msg}\n")
            except Exception:
                pass

    def _start_result_tree_polling(self):
        """启动定时轮询 — 每 1000ms 扫描结果区，发现新增项目就弹窗

        关键修复（v16）：
          - 用 _poll_tick_wrapper 包一层，保证 after 链永不断裂
          - 即使 _poll_result_tree_once 抛异常，after 也会重新注册
          - 用 lambda 保持引用，避免 bound method 被 GC 后 Tcl command 失效
        """
        if not hasattr(self, "_result_tree_poll_id"):
            self._result_tree_poll_id = None
        if not hasattr(self, "_polled_tree_items"):
            self._polled_tree_items = set()
        if not hasattr(self, "_last_toast_ts"):
            self._last_toast_ts = 0.0
        if not hasattr(self, "_recently_toasted_paths"):
            self._recently_toasted_paths = {}
        if not hasattr(self, "_pending_burst_count"):
            self._pending_burst_count = 0
        if not hasattr(self, "_pending_burst_paths"):
            self._pending_burst_paths = []
        if not hasattr(self, "_last_burst_toast_ts"):
            self._last_burst_toast_ts = 0.0
        if not hasattr(self, "_poll_heartbeat_ts"):
            self._poll_heartbeat_ts = 0.0
        if not hasattr(self, "_poll_tick_count"):
            self._poll_tick_count = 0
        # 初次启动时把当前已存在的 item 全标记为已轮询
        try:
            if hasattr(self, "_result_tree") and self._result_tree.winfo_exists():
                for item in self._result_tree.get_children():
                    self._polled_tree_items.add(item)
        except Exception:
            pass
        self._poll_debug_log(f"=== 轮询启动 — 初始已轮询 {len(self._polled_tree_items)} 个 item ===")
        # 启动 after 链（用 wrapper 保证永不断裂）
        try:
            self._result_tree_poll_id = self.root.after(1000, self._poll_tick_wrapper)
        except Exception as e:
            self._poll_debug_log(f"启动 after 失败: {e!r}")

    def _poll_tick_wrapper(self):
        """轮询包装器 — 保证即使出错也重新注册 after，轮询永不停止

        解决 Tcl 'invalid command name' 问题：
        - 不直接把 bound method 传给 after（会被 Tk 注册成临时 command，GC 后失效）
        - 用 wrapper + lambda 保持引用
        - 即使 _poll_result_tree_once 抛异常，after 链也不断
        """
        self._init_debug("tick_wrapper enter")
        try:
            self._poll_result_tree_once()
        except Exception as e:
            try:
                self._poll_debug_log(f"tick 异常: {e!r}")
            except Exception:
                pass
        # 无论成功失败，1 秒后继续轮询（用 lambda 保持引用，防止 GC）
        try:
            self._result_tree_poll_id = self.root.after(1000, lambda: self._poll_tick_wrapper())
        except (tk.TclError, RuntimeError) as e:
            self._poll_debug_log(f"after 注册失败（root 可能已销毁）: {e!r}")
            self._result_tree_poll_id = None
        except Exception as e:
            self._poll_debug_log(f"after 注册未知异常: {e!r}")
            self._result_tree_poll_id = None


    def _poll_result_tree_once(self):
        """单次轮询 — 由 _poll_tick_wrapper 调用，不需要自己注册 after

        v24: 移除所有静默逻辑，强制弹窗
        - silent_mode 检测已删除
        - 1-2 条新威胁：直接走 _show_threat_toast（带 1.5s 节流）
        - ≥3 条：burst 摘要弹窗（带 1.8s 节流）
        - 60s 内同 file_path 去重
        """
        self._poll_tick_count = getattr(self, "_poll_tick_count", 0) + 1
        now = self._now_ms()
        # 心跳日志：每 5 秒（~5 tick）写一次，确认轮询在跑
        if now - getattr(self, "_poll_heartbeat_ts", 0.0) > 5000:
            self._poll_heartbeat_ts = now
            try:
                tree_count = len(self._result_tree.get_children()) if hasattr(self, "_result_tree") else 0
            except Exception:
                tree_count = -1
            self._poll_debug_log(
                f"心跳 tick#{self._poll_tick_count} — tree有{tree_count}行, "
                f"已轮询{len(getattr(self, '_polled_tree_items', set()))}行"
            )

        try:
            if hasattr(self, "_result_tree") and self._result_tree.winfo_exists():
                current = set(self._result_tree.get_children())
                new_items = current - self._polled_tree_items
                if new_items:
                    # 过滤出真正的威胁（按 file_path 去重 60s 内不重弹）
                    new_threats: list = []
                    now = self._now_ms()
                    for p, ts in list(self._recently_toasted_paths.items()):
                        if now - ts > 60000:
                            del self._recently_toasted_paths[p]

                    for item_id in new_items:
                        try:
                            result = self._tree_results.get(item_id)
                            # v29 DEBUG: 排查 _tree_results 字典
                            self._poll_debug_log(
                                f"轮询: item_id={item_id}, "
                                f"result_in_dict={result is not None}, "
                                f"is_threat={getattr(result, 'is_threat', 'NO_ATTR')}, "
                                f"threat_level={getattr(result, 'threat_level', 'NO_ATTR')}"
                            )
                            if not result:
                                continue
                            if not getattr(result, "is_threat", False):
                                continue
                            fp = getattr(result, "file_path", "") or ""
                            if fp and fp in self._recently_toasted_paths:
                                continue
                            new_threats.append((item_id, result, fp))
                        except Exception:
                            pass

                    self._poll_debug_log(
                        f"tick: current={len(current)}, new={len(new_items)}, "
                        f"new_threats={len(new_threats)}"
                    )

                    if not new_threats:
                        self._polled_tree_items = current
                        return

                    # === 决策 1：狂涌（≥3 条新威胁） → 必弹 burst 摘要 ===
                    if len(new_threats) >= 3:
                        if now - self._last_burst_toast_ts >= 1800:
                            total = self._pending_burst_count + len(new_threats)
                            sample_paths = (
                                self._pending_burst_paths
                                + [t[2] for t in new_threats]
                            )[:5]
                            self._poll_debug_log(
                                f"BURST TRIGGER: {total} 个新威胁 (pending={self._pending_burst_count}, new={len(new_threats)})"
                            )
                            try:
                                self._show_burst_threat_toast(total, sample_paths)
                                self._poll_debug_log("BURST toast 弹出成功")
                            except Exception as e:
                                self._poll_debug_log(f"BURST toast 失败: {e!r}")
                                for _i, _r, _fp in new_threats[:5]:
                                    try:
                                        self._show_simple_threat_toast(_r)
                                    except Exception:
                                        pass
                            self._last_burst_toast_ts = now
                            for item_id, result, fp in new_threats:
                                if fp:
                                    self._recently_toasted_paths[fp] = now
                            self._pending_burst_count = 0
                            self._pending_burst_paths = []
                        else:
                            self._pending_burst_count += len(new_threats)
                            self._pending_burst_paths = (
                                self._pending_burst_paths
                                + [t[2] for t in new_threats]
                            )[:20]

                    # === 决策 2：1-2 条新威胁 → 强制单条弹窗（无静默） ===
                    elif new_threats:
                        if now - self._last_toast_ts >= 1500:
                            item_id, result, fp = new_threats[0]
                            try:
                                self._show_threat_toast(result, source="realtime")
                                self._poll_debug_log(
                                    f"SINGLE toast 弹出: {result.file_name[:30]}"
                                )
                            except Exception:
                                try:
                                    self._show_simple_threat_toast(result)
                                except Exception:
                                    pass
                            self._last_toast_ts = now
                            if fp:
                                self._recently_toasted_paths[fp] = now
                            for _item, _res, _fp in new_threats[1:]:
                                self._pending_burst_count += 1
                                if _fp:
                                    self._pending_burst_paths.append(_fp)
                        else:
                            for _item, _res, _fp in new_threats:
                                self._pending_burst_count += 1
                                if _fp:
                                    self._pending_burst_paths.append(_fp)

                # 始终把当前集合存下来
                self._polled_tree_items = current
        except Exception as e:
            try:
                self._poll_debug_log(f"poll_result_tree 异常: {e!r}")
            except Exception:
                pass
        # after 由 _poll_tick_wrapper 统一注册，这里不再处理

    @staticmethod
    def _now_ms() -> float:
        """毫秒时间戳（用于节流）"""
        import time as _t
        return _t.time() * 1000.0

    def _show_burst_threat_toast(self, count: int, sample_paths: list[str]):
        """批处理弹窗：扫描狂涌时合并提示，不卡 Tk

        Args:
            count: 这次累积的新威胁总数
            sample_paths: 最多 5 个样本文件路径（显示前 5 个文件名）
        """
        try:
            top = tk.Toplevel(self.root)
            top.title("")
            top.overrideredirect(True)
            top.configure(bg="#f85149")
            top.resizable(False, False)
            top.minsize(420, 220)
            top.maxsize(420, 220)

            # 位置：右下角
            screen_w = top.winfo_screenwidth()
            screen_h = top.winfo_screenheight()
            x = screen_w - 420 - 20
            y = screen_h - 220 - 60
            top.geometry(f"420x220+{x}+{y}")
            top.update_idletasks()
            top.geometry(f"420x220+{x}+{y}")

            # 主容器
            main = tk.Frame(top, bg="#161b22", bd=0)
            main.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

            # 头部
            header = tk.Frame(main, bg="#161b22", height=44)
            header.pack(fill=tk.X)
            header.pack_propagate(False)
            accent_bar = tk.Frame(header, bg="#f85149", width=4)
            accent_bar.pack(side=tk.LEFT, fill=tk.Y)
            tk.Label(
                header, text=f"🚨 批量检测到 {count} 个威胁",
                font=("Microsoft YaHei UI", 13, "bold"),
                bg="#161b22", fg="#e6edf3",
            ).pack(side=tk.LEFT, padx=(10, 4), pady=10)
            close_btn = tk.Label(
                header, text="✕",
                font=("Segoe UI", 14, "bold"),
                bg="#161b22", fg="#8b949e", cursor="hand2",
                padx=14, pady=4,
            )
            close_btn.pack(side=tk.RIGHT)
            close_btn.bind("<Button-1>", lambda e: self._dismiss_simple_toast(top))
            close_btn.bind("<Enter>", lambda e: close_btn.configure(fg="#f85149"))
            close_btn.bind("<Leave>", lambda e: close_btn.configure(fg="#8b949e"))

            # 详情区
            detail = tk.Frame(main, bg="#161b22")
            detail.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 4))
            tk.Label(
                detail, text="已自动隔离 — 全部威胁可在「扫描结果」区查看并处置",
                font=("Microsoft YaHei UI", 9, "bold"),
                bg="#161b22", fg="#d29922", anchor="w",
            ).pack(fill=tk.X, pady=(2, 6))

            # 样本列表（最多 5 个文件名）
            tk.Label(
                detail, text="最新样本（前 5 个）:",
                font=("Microsoft YaHei UI", 8),
                bg="#161b22", fg="#8b949e", anchor="w",
            ).pack(fill=tk.X, pady=(0, 2))
            for fp in sample_paths[:5]:
                fname = os.path.basename(fp) if fp else "未知"
                if len(fname) > 50:
                    fname = fname[:47] + "..."
                tk.Label(
                    detail, text=f"  • {fname}",
                    font=("Microsoft YaHei UI", 8),
                    bg="#161b22", fg="#e6edf3", anchor="w",
                ).pack(fill=tk.X, pady=0)
            if count > 5:
                tk.Label(
                    detail, text=f"  …及其他 {count - 5} 个",
                    font=("Microsoft YaHei UI", 8),
                    bg="#161b22", fg="#8b949e", anchor="w",
                ).pack(fill=tk.X, pady=0)

            # 底部按钮
            btn_frame = tk.Frame(main, bg="#161b22", height=48)
            btn_frame.pack(fill=tk.X, padx=14, pady=(0, 8))
            btn_frame.pack_propagate(False)

            def mkbtn(parent, text, bg, fg, cmd):
                b = tk.Label(
                    parent, text=text,
                    font=("Microsoft YaHei UI", 9, "bold"),
                    bg=bg, fg=fg, padx=12, pady=5, cursor="hand2",
                )
                b.bind("<Button-1>", lambda e: cmd())
                return b

            def open_results_tab():
                """跳转到扫描结果页（用户手动处置）"""
                try:
                    if hasattr(self, "_switch_tab"):
                        self._switch_tab("results")
                except Exception:
                    pass
                self._dismiss_simple_toast(top)

            mkbtn(btn_frame, "📋 查看扫描结果", "#d29922", "#ffffff", open_results_tab).pack(side=tk.LEFT)
            mkbtn(btn_frame, "✕ 忽略", "#21262d", "#8b949e",
                  lambda: self._dismiss_simple_toast(top)).pack(side=tk.RIGHT)

            # 30 秒自动关闭
            top.after(30000, lambda: self._dismiss_simple_toast(top))

            # 置顶 + 蜂鸣
            try:
                top.attributes("-topmost", True)
            except Exception:
                pass
            top.lift()
            top.bell()
            top.after(50, lambda: top.geometry(f"420x220+{x}+{y}"))
            top.after(200, lambda: top.geometry(f"420x220+{x}+{y}"))
        except Exception as e:
            print(f"[burst toast] failed: {e}")

    def _show_simple_threat_toast(self, result):
        """极简弹窗 — 纯 Label 拼装，锁死尺寸 380x180，绝对不出黑块"""
        try:
            # 主 Toplevel
            top = tk.Toplevel(self.root)
            top.title("")
            top.overrideredirect(True)
            top.configure(bg="#f85149")
            # 锁死尺寸 380x180
            top.resizable(False, False)
            top.minsize(380, 180)
            top.maxsize(380, 180)
            # 位置：右下角
            screen_w = top.winfo_screenwidth()
            screen_h = top.winfo_screenheight()
            x = screen_w - 380 - 20
            y = screen_h - 180 - 60
            top.geometry(f"380x180+{x}+{y}")
            top.update_idletasks()
            top.geometry(f"380x180+{x}+{y}")

            # 主容器
            main = tk.Frame(top, bg="#161b22", bd=0)
            main.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

            # 头部
            header = tk.Frame(main, bg="#161b22", height=44)
            header.pack(fill=tk.X)
            header.pack_propagate(False)
            accent_bar = tk.Frame(header, bg="#f85149", width=4)
            accent_bar.pack(side=tk.LEFT, fill=tk.Y)
            tk.Label(
                header, text="🛡️ 检测到威胁",
                font=("Microsoft YaHei UI", 13, "bold"),
                bg="#161b22", fg="#e6edf3",
            ).pack(side=tk.LEFT, padx=(10, 4), pady=10)
            close_btn = tk.Label(
                header, text="✕",
                font=("Segoe UI", 14, "bold"),
                bg="#161b22", fg="#8b949e", cursor="hand2",
                padx=14, pady=4,
            )
            close_btn.pack(side=tk.RIGHT)
            close_btn.bind("<Button-1>", lambda e: self._dismiss_simple_toast(top))
            close_btn.bind("<Enter>", lambda e: close_btn.configure(fg="#f85149"))
            close_btn.bind("<Leave>", lambda e: close_btn.configure(fg="#8b949e"))

            # 详情区
            detail = tk.Frame(main, bg="#161b22")
            detail.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 4))
            try:
                fname = os.path.basename(result.file_path) if hasattr(result, "file_path") else "未知文件"
            except Exception:
                fname = "未知文件"
            try:
                threat_name = getattr(result, "threat_name", "恶意软件") or "恶意软件"
            except Exception:
                threat_name = "恶意软件"
            tk.Label(
                detail, text=f"威胁: {threat_name}",
                font=("Microsoft YaHei UI", 10, "bold"),
                bg="#161b22", fg="#f85149", anchor="w",
            ).pack(fill=tk.X, pady=(2, 2))
            tk.Label(
                detail, text=f"文件: {fname}",
                font=("Microsoft YaHei UI", 9),
                bg="#161b22", fg="#e6edf3", anchor="w",
            ).pack(fill=tk.X, pady=1)
            tk.Label(
                detail, text=f"路径: {(getattr(result, 'file_path', '') or '')[:60]}",
                font=("Microsoft YaHei UI", 8),
                bg="#161b22", fg="#8b949e", anchor="w",
            ).pack(fill=tk.X, pady=1)

            # 底部按钮
            btn_frame = tk.Frame(main, bg="#161b22", height=48)
            btn_frame.pack(fill=tk.X, padx=14, pady=(0, 8))
            btn_frame.pack_propagate(False)

            def mkbtn(parent, text, bg, fg, cmd):
                b = tk.Label(
                    parent, text=text,
                    font=("Microsoft YaHei UI", 9, "bold"),
                    bg=bg, fg=fg, padx=12, pady=5, cursor="hand2",
                )
                b.bind("<Button-1>", lambda e: cmd())
                return b

            mkbtn(btn_frame, "🔒 隔离文件", "#d29922", "#ffffff",
                   lambda: self._simple_toast_quarantine(result, top)).pack(side=tk.LEFT)
            mkbtn(btn_frame, "🗑 立即删除", "#f85149", "#ffffff",
                   lambda: self._simple_toast_delete(result, top)).pack(side=tk.LEFT, padx=(6, 0))
            mkbtn(btn_frame, "✕ 忽略", "#21262d", "#8b949e",
                   lambda: self._dismiss_simple_toast(top)).pack(side=tk.RIGHT)

            # 30 秒自动关闭
            top.after(30000, lambda: self._dismiss_simple_toast(top))

            # 置顶 + 蜂鸣
            try:
                top.attributes("-topmost", True)
            except Exception:
                pass
            top.lift()
            top.bell()
            top.after(50, lambda: top.geometry(f"380x180+{x}+{y}"))
            top.after(200, lambda: top.geometry(f"380x180+{x}+{y}"))
        except Exception as e:
            print(f"[simple toast] failed: {e}")
            import traceback
            traceback.print_exc()

    def _dismiss_simple_toast(self, top):
        try:
            top.destroy()
        except Exception:
            pass

    def _simple_toast_quarantine(self, result, top):
        """隔离按钮"""
        try:
            self._dismiss_simple_toast(top)
            # 调主程序的隔离流程
            for method_name in ("_quarantine_result", "_isolate_file", "_quarantine_file"):
                if hasattr(self, method_name):
                    method = getattr(self, method_name)
                    try:
                        if method_name == "_quarantine_result":
                            method(result)
                        else:
                            method(result.file_path)
                    except Exception:
                        pass
                    break
        except Exception as e:
            print(f"[simple toast quarantine] failed: {e}")

    def _simple_toast_delete(self, result, top):
        """删除按钮"""
        try:
            self._dismiss_simple_toast(top)
            for method_name in ("_delete_result_file", "_delete_file", "delete_file"):
                if hasattr(self, method_name):
                    method = getattr(self, method_name)
                    try:
                        method(result.file_path)
                    except Exception:
                        pass
                    break
        except Exception as e:
            print(f"[simple toast delete] failed: {e}")

    def _dispatch_scan_event(self, item):
        """分发单个跨线程事件到对应 UI 处理器"""
        event_type = item[0]
        if event_type == "progress":
            _, result, stats = item
            self._update_scan_ui(result, stats)
        elif event_type == "ai_ready":
            # AI 二次扫描完成, 把评分回填到对应结果行
            _, file_path, ai_result, ai_score = item
            self._apply_ai_score(file_path, ai_result, ai_score)
        elif event_type == "threat":
            _, result = item
            # _show_threat_alert 内部调 _add_result_to_tree，后者会自动弹右下角弹窗
            # （弹窗逻辑已统一收敛到 _add_result_to_tree，无需在此重复调用）
            self._show_threat_alert(result)
            # 强制刷新 Treeview（add_result_to_tree 仅入队，不立即 paint）
            try:
                self.root.update_idletasks()
            except Exception:
                pass
        elif event_type == "pre_scan_check":
            _, pre_summary = item
            # ESET 风格：预检结果摘要写入进度标签（两行内），详情走状态栏
            lines = pre_summary.split("\n")
            warn_count = sum(1 for l in lines if "⚠️" in l)
            # 进度标签固定两行：第一行预检状态，第二行注意事项数
            if warn_count > 0:
                display = f"🏥 系统预检: 发现 {warn_count} 项注意事项\n📄 正在开始正式文件扫描..."
                self._update_status_bar(f"🏅 预检完成 — 发现 {warn_count} 项注意事项 | {pre_summary.replace(chr(10), ' | ')}")
            else:
                display = f"🏥 系统预检通过\n📄 正在开始正式文件扫描..."
                self._update_status_bar(f"🏅 预检通过 — 正在开始正式文件扫描...")
            self._progress_label.configure(text=display)
        elif event_type == "proc_alert":
            _, alert = item
            self._on_proc_alert_ui(alert)
        elif event_type == "complete":
            _, results = item
            self._on_scan_complete(results)
        elif event_type == "advanced_scan_complete":
            _, results = item
            self._on_advanced_scan_complete(results)
        elif event_type == "error":
            _, msg = item
            self._on_scan_error(msg)
        elif event_type == "quarantine_done":
            _, success, failed, done_ids = item
            self._on_quarantine_done(success, failed, done_ids)
        elif event_type == "cloud_done":
            _, file_path, result = item
            self._on_cloud_done(file_path, result)
        elif event_type == "cloud_result":
            # 高级查杀云端验证结果
            _, file_path, result = item
            self._on_cloud_result(file_path, result)
        elif event_type == "cloud_standalone_done":
            # 独立云查杀完成
            _, file_path, result = item
            self._on_cloud_standalone_done(file_path, result)
        elif event_type == "ai_score_ready":
            # 三引擎联动收尾 — AI 评分异步回填
            _, file_path = item
            self._apply_ai_score(file_path)

    def _update_scan_ui(self, result: ScanResult, stats: ScanStats):
        """在主线程更新扫描进度 UI (进度事件即时到达, 无需等待 AI 二次扫描)"""
        # v29 DEBUG: 记录每次 _update_scan_ui 调用
        try:
            self._poll_debug_log(
                f"_update_scan_ui: file={result.file_name[:30] if result else 'None'}, "
                f"is_threat={getattr(result, 'is_threat', 'NO_ATTR')}, "
                f"threat_level={getattr(result, 'threat_level', 'NO_ATTR')}, "
                f"_tree_results.len={len(self._tree_results)}"
            )
        except Exception:
            pass
        elapsed = stats.elapsed_seconds
        if elapsed > 60:
            time_str = f"{int(elapsed // 60)}分{int(elapsed % 60)}秒"
        else:
            time_str = f"{elapsed:.0f}秒"

        # 进度条: 始终连贯 0→100%
        if stats.total_files > 0:
            pct = min(100.0, (stats.scanned_files / stats.total_files) * 100)
            self._progress_var.set(pct)
            progress_text = (
                f"已扫描: {stats.scanned_files}/{stats.total_files} ({pct:.0f}%) | "
                f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found} | ⏱ {time_str}"
            )
        else:
            # 仍在统计文件数阶段
            progress_text = (
                f"已扫描: {stats.scanned_files} 个文件 | "
                f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found} | ⏱ {time_str}"
            )

        cloud_info = ""
        if self._cloud_pending > 0:
            cloud_info = f" | ☁️ 云端验证中: {self._cloud_pending}"

        self._progress_label.configure(text=progress_text + cloud_info)

        # 发现威胁 → 立即加入结果列表 (用原始扫描结果, AI 评分稍后异步补充)
        if result.is_threat:
            self._add_result_to_tree(result, None)

            # 对所有威胁文件触发云端验证（云引擎为主判定）
            self._trigger_cloud_query(result.file_path)
            # 右下角威胁弹窗由 _add_result_to_tree 内部统一触发，无需在此重复调用

        # 实时更新统计
        self._update_stats_display(stats)
        self._result_count_label.configure(
            text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
        )

    def _trigger_cloud_query(self, filepath: str):
        """触发云端引擎异步查询（高级查杀用）"""
        # 去重：同一文件不重复查询
        if filepath in self._current_cloud_results:
            return

        self._cloud_pending += 1

        def on_cloud_result(result: CloudScanResult):
            self._scan_queue.put(("cloud_result", filepath, result))

        self.cloud_scanner.scan_file_cloud_async(filepath, on_cloud_result)

    def _on_scan_complete(self, results: list[ScanResult]):
        """扫描完成 — 若仍有云端验证在途，先等待（云引擎为主判定）"""
        self._scanning = False
        stats = self.scanner.stats

        # 用户已取消 — 直接收尾，显示「已取消」（不再等云端验证）
        if self._scan_cancelled:
            self._finalize_scan()
            return

        # 云引擎为主: 等待所有云端验证返回后再给出最终结论
        if self._cloud_pending > 0:
            self._update_status_bar(
                f"🔄 本地扫描完成，云端验证中... ({self._cloud_pending} 个文件)"
            )
            self._progress_label.configure(
                text=f"☁️ 云端验证中... 剩余 {self._cloud_pending} 个文件"
            )
            return

        self._finalize_scan()

    def _finalize_scan(self):
        """扫描最终收尾（恢复 UI + 显示结论）"""
        self._stop_progress_ticker()
        stats = self.scanner.stats

        # 恢复 UI（通用部分）
        self._quick_scan_btn.configure(state=tk.NORMAL)
        self._cloud_scan_btn.configure(state=tk.NORMAL)
        self._advanced_scan_btn.configure(state=tk.NORMAL)
        self._custom_scan_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._progress_bar.configure(mode="determinate")  # 确保连续模式

        # 用户手动取消 — 保留当前进度百分比，不跳到 100%
        if self._scan_cancelled:
            if stats.total_files > 0:
                pct = min(100.0, (stats.scanned_files / stats.total_files) * 100)
                self._progress_var.set(pct)
            self._update_stats_display(stats)
            self._update_status_bar("⏹ 扫描已取消")
            self._progress_label.configure(
                text=f"⏹ 扫描已手动停止 — 已扫描 {stats.scanned_files} 个文件"
            )
            self._result_count_label.configure(
                text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
            )
            return

        self._progress_var.set(100)

        # 更新统计
        self._update_stats_display(stats)

        # 更新状态
        if stats.threats_found > 0:
            self._update_status_bar(
                f"⚠️ 扫描完成 — 发现 {stats.threats_found} 个威胁！(已排除云端确认的误报)"
            )
            self._progress_label.configure(
                text=f"⚠️ 发现 {stats.threats_found} 个威胁！请查看扫描结果并处理。"
            )
            # v23 兜底修复：扫描完成时**强制弹**批处理摘要（不被静默模式拦截），
            # 即使用户处于「静默处理中」也能看到「扫描完成发现 N 个威胁」汇总。
            try:
                # 取前 5 个威胁的文件名作为样本
                sample = []
                for r in (self._current_results or []):
                    if getattr(r, "is_threat", False):
                        sample.append(r.file_path or r.file_name)
                        if len(sample) >= 5:
                            break
                self._show_burst_threat_toast(int(stats.threats_found), sample)
            except Exception as _e:
                try:
                    self._poll_debug_log(f"扫描完成 burst 弹窗失败: {_e!r}")
                except Exception:
                    pass
        else:
            self._update_status_bar(
                f"✅ 扫描完成 — 共扫描 {stats.scanned_files} 个文件，未发现威胁"
            )
            self._progress_label.configure(
                text=f"✅ 扫描完成 — 系统安全！共扫描 {stats.scanned_files} 个文件"
            )

        self._result_count_label.configure(
            text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
        )

        self._switch_tab("results")

    def _on_scan_error(self, error_msg: str):
        """扫描出错"""
        self._scanning = False
        self._quick_scan_btn.configure(state=tk.NORMAL)
        self._cloud_scan_btn.configure(state=tk.NORMAL)
        self._advanced_scan_btn.configure(state=tk.NORMAL)
        self._custom_scan_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)

        self._update_status_bar(f"❌ 扫描出错: {error_msg}")
        self._progress_bar.configure(mode="determinate")
        self._progress_var.set(0)
        messagebox.showerror("扫描错误", f"扫描过程发生错误:\n{error_msg}")

    def _add_result_to_tree(self, result: ScanResult, ai_score: ConfidenceScore = None):
        """将结果添加到 Treeview — AI 增强版"""
        # 威胁等级标签
        level_map = {
            ThreatLevel.MALICIOUS: ("🔴 恶意", COLORS["accent_red"]),
            ThreatLevel.HIGH_RISK: ("🟠 高危", COLORS["accent_orange"]),
            ThreatLevel.SUSPICIOUS: ("🟡 可疑", COLORS["accent_orange"]),
        }
        level_text, _ = level_map.get(result.threat_level, ("⚪ 未知", COLORS["text_secondary"]))

        # AI 置信度
        if ai_score:
            ai_conf = f"AI:{ai_score.adjusted_score:.0%}"
            # AI 判断与原始判断是否一致
            if ai_score.similar_to_fp:
                ai_conf += " ⚠️相似误报"
            if ai_score.learning_note:
                method = f"{result.detection_method} | {ai_conf}"
            else:
                method = f"{result.detection_method} | {ai_conf}"
        else:
            method = result.detection_method

        # 格式化文件大小
        size_str = self._format_size(result.file_size)

        item_id = self._result_tree.insert("", tk.END, values=(
            "☐",  # 勾选框
            level_text,
            result.file_name,
            result.threat_name,
            method,
            result.file_path,
            size_str,
        ))
        try:
            self._poll_debug_log(f"_add_result_to_tree: insert OK, item_id={item_id}")
        except Exception:
            pass

        # 根据威胁等级着色
        tag = result.threat_level.value
        # v29d: 用 try/except 隔离 tag_configure 异常 — 不影响 _tree_results set
        try:
            if tag == "malicious":
                self._result_tree.tag_configure("malicious", background="#da363320")
            elif tag == "high_risk":
                self._result_tree.tag_configure("high_risk", background="#bb800910")
            elif tag == "suspicious":
                self._result_tree.tag_configure("suspicious", background="#bb800908")
            self._result_tree.item(item_id, tags=(tag,))
        except Exception as _e:
            try:
                self._poll_debug_log(f"_add_result_to_tree: tag 失败: {_e!r}")
            except Exception:
                pass

        # 直接持有该行对应的 ScanResult 引用，隔离时据此隔离
        # v29d 关键修复：无论 tag_configure 成不成功，都 set 进 _tree_results
        # 之前 v29b 之前版本因为某种原因这里没执行，导致弹窗链路断裂
        self._tree_results[item_id] = result
        self._checked[item_id] = False
        self._current_results.append(result)
        # v29 DEBUG: 记录 _tree_results 状态
        try:
            self._poll_debug_log(
                f"_add_result_to_tree: SET OK item_id={item_id}, "
                f"is_threat={result.is_threat}, "
                f"_tree_results.len={len(self._tree_results)}"
            )
        except Exception:
            pass

        # 【统一弹窗触发】任何扫描路径（手动/实时/定时/云回调）只要往结果区
        # 加入威胁项目，都立刻弹右下角威胁弹窗。收敛到这里，避免每条调用
        # 路径都手动调 _show_threat_toast —— 一劳永逸，不会再漏弹。
        if result.is_threat:
            # v23 debug：记录每次进入弹窗路径的状态
            try:
                tm = getattr(self, "_rtp_toast_mode", None)
                tm_val = tm.get() if tm else "no_toast_mode"
                self._poll_debug_log(
                    f"_add_result_to_tree ENTER: file={result.file_name[:30]}, "
                    f"level={result.threat_level.value}, toast_mode={tm_val}"
                )
            except Exception:
                pass
            try:
                # 先强制 paint Treeview，让用户先看到新行出现
                self._result_tree.update_idletasks()
            except Exception:
                pass
            # 注意：不去标 _recently_toasted_paths — 留给后台轮询器统一去重
            # （狂涌时 _show_threat_toast 内部因 max_toasts=3 多数 toast 会被挤掉，
            #  用户可能看不到。轮询器作为兜底：节流后每 1.5s 弹 1 条单威胁弹窗，
            #  或 95+ 条时合并成 1 条「批量检测到 N 个威胁」摘要弹窗）
            # v28: 改 source="manual_scan" — 走累积摘要弹窗（避免 516 个被 max_toasts 顶掉）
            try:
                self._show_threat_toast(result, source="manual_scan")
                try:
                    self._poll_debug_log(
                        f"_add_result_to_tree EXIT: _show_threat_toast (manual_scan) 返回正常"
                    )
                except Exception:
                    pass
            except Exception as e:
                try:
                    self._poll_debug_log(
                        f"_add_result_to_tree EXIT: _show_threat_toast 异常: {e!r}"
                    )
                except Exception:
                    pass

    def _apply_ai_score(self, file_path: str, ai_result: ScanResult = None, ai_score: ConfidenceScore = None):
        """AI 二次扫描完成后, 把评分回填到结果行 (方法列追加 AI 置信度)
        新版三引擎联动收尾时只传 file_path，从 self._current_ai_scores 取分数。"""
        # 找到对应行
        target_item = None
        for item_id in self._result_tree.get_children():
            values = self._result_tree.item(item_id)["values"]
            if len(values) > 5 and values[5] == file_path:
                target_item = item_id
                break
        if target_item is None:
            return

        # 兼容旧调用（直接传 ai_result / ai_score）和新调用（只传 file_path）
        if ai_score is None:
            ai_score = self._current_ai_scores.get(file_path)
        if ai_result is None:
            ai_result = self._tree_results.get(target_item)

        values = list(self._result_tree.item(target_item)["values"])
        new_method = (
            ai_result.detection_method if ai_result and ai_result.detection_method
            else values[4]
        )
        if ai_score:
            new_method = f"{new_method} | AI:{ai_score.adjusted_score:.0%}"
            if ai_score.similar_to_fp:
                new_method += " ⚠️相似误报"
        values[4] = new_method
        self._result_tree.item(target_item, values=tuple(values))

        # 如果 AI 判定为已知安全 (误报), 从结果列表移除该行
        if ai_score and ai_score.is_known_safe:
            self._remove_tree_item(target_item)
            self._update_status_bar(
                f"🤖 AI 复评: {os.path.basename(file_path)} 为已知安全文件，已从结果移除"
            )
        else:
            self._update_status_bar(
                f"🤖 AI 复评完成: {os.path.basename(file_path)} 置信度 {ai_score.adjusted_score:.0%}" if ai_score else
                f"🤖 AI 复评完成: {os.path.basename(file_path)}"
            )

    # ==========================================================
    # 统计显示
    # ==========================================================
    def _reset_stats_display(self):
        """重置统计显示"""
        for key in self._stat_labels:
            self._stat_labels[key].configure(text="--")

    def _update_stats_display(self, stats: ScanStats):
        """更新统计面板"""
        self._stat_labels["scanned"].configure(text=str(stats.scanned_files))
        self._stat_labels["threats"].configure(
            text=str(stats.threats_found),
            fg=COLORS["accent_red"] if stats.threats_found > 0 else COLORS["text_primary"],
        )
        self._stat_labels["suspicious"].configure(text=str(stats.suspicious_found))
        self._stat_labels["quarantined"].configure(text=str(stats.quarantined))

        elapsed = stats.elapsed_seconds
        if elapsed > 60:
            self._stat_labels["time"].configure(
                text=f"{int(elapsed // 60)}分{int(elapsed % 60)}秒"
            )
        else:
            self._stat_labels["time"].configure(text=f"{elapsed:.1f}秒")

        self._stat_labels["speed"].configure(
            text=f"{stats.scan_speed:.0f} 文件/秒"
        )

    # ==========================================================
    # 隔离区操作
    # ==========================================================
    def _select_all_results(self):
        """全选 / 取消全选（切换勾选框）"""
        all_items = self._result_tree.get_children()
        if not all_items:
            return
        # 若已全部勾选 -> 全部取消；否则 -> 全部勾选
        all_checked = all(self._checked.get(i, False) for i in all_items)
        new_state = not all_checked
        for item_id in all_items:
            self._set_checked(item_id, new_state)
        if new_state:
            self._update_status_bar(f"已勾选全部 {len(all_items)} 个结果")
        else:
            self._update_status_bar("已取消全部勾选")

    def _set_checked(self, item_id: str, state: bool):
        """设置某行的勾选状态（更新勾选框列 + 记录）"""
        self._checked[item_id] = state
        values = list(self._result_tree.item(item_id)["values"])
        values[0] = "☑" if state else "☐"
        self._result_tree.item(item_id, values=tuple(values))

    def _on_result_click(self, event):
        """点击勾选框列 -> 切换该行勾选状态"""
        region = self._result_tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self._result_tree.identify_column(event.x)
        if col != "#1":  # 第一列是勾选框
            return
        item = self._result_tree.identify_row(event.y)
        if not item:
            return
        self._set_checked(item, not self._checked.get(item, False))

    def _quarantine_selected(self):
        """隔离选中的文件 — 兼容勾选框 + 高亮选中两种方式"""
        # 优先使用勾选框，回退到 Treeview 高亮选中（兼容用户习惯）
        checked_ids = [
            i for i in self._result_tree.get_children()
            if self._checked.get(i, False)
        ]
        if not checked_ids:
            # 没有勾选 → 用高亮选中项作为回退
            checked_ids = list(self._result_tree.selection())

        if not checked_ids:
            messagebox.showinfo(
                "提示",
                "没有选中的文件。\n\n"
                "请点击左侧 ☑ 勾选框选择要隔离的威胁，\n"
                "或直接单击行高亮后再点「🔒 隔离选中」。",
            )
            return

        # 收集所有可用的 result 引用
        items_to_quarantine = []  # [(item_id, ScanResult)]
        missing = []
        for item_id in checked_ids:
            result = self._tree_results.get(item_id)
            if result is not None:
                items_to_quarantine.append((item_id, result))
            else:
                # 回退：从行数据中构造一个最小 ScanResult
                values = self._result_tree.item(item_id)["values"]
                if len(values) >= 6:
                    from engine import ScanResult, ThreatLevel
                    fallback = ScanResult(
                        file_path=values[5],
                        file_name=values[2] if len(values) > 2 else values[5].rsplit("\\", 1)[-1],
                        file_size=0,
                        timestamp="",
                    )
                    fallback.threat_name = values[3] if len(values) > 3 else "Unknown"
                    items_to_quarantine.append((item_id, fallback))
                else:
                    missing.append(item_id)

        if not items_to_quarantine:
            messagebox.showinfo("提示", "结果列表中没有可隔离的有效文件。")
            return

        count = len(items_to_quarantine)
        if not messagebox.askyesno(
            "隔离选中文件",
            f"确定要隔离选中的 {count} 个威胁文件吗？\n\n"
            f"隔离后文件将被加密移动到隔离区，可通过隔离区恢复。",
        ):
            return

        # 立即给出反馈 + 禁用按钮, 避免用户以为"卡死"
        self._update_status_bar(f"🔒 正在隔离 {count} 个文件...")
        self.root.after(0, self._disable_quarantine_controls)

        # 后台批量隔离
        def worker():
            success = 0
            failed = 0
            done_ids = []
            for item_id, result in items_to_quarantine:
                try:
                    if self.quarantine.quarantine_file(result):
                        success += 1
                        done_ids.append(item_id)
                    else:
                        failed += 1
                except Exception as ex:
                    failed += 1
            self._scan_queue.put(("quarantine_done", success, failed, done_ids))

        threading.Thread(target=worker, daemon=True).start()

    def _trust_selected_result_files(self):
        """将选中的扫描结果文件加入信任区（白名单）"""
        checked_ids = [
            i for i in self._result_tree.get_children()
            if self._checked.get(i, False)
        ]
        if not checked_ids:
            checked_ids = list(self._result_tree.selection())
        if not checked_ids:
            messagebox.showinfo(
                "提示",
                "没有选中的文件。\n\n请点击左侧 ☑ 勾选框，或单击行高亮后再点「✅ 信任选中」。",
            )
            return

        added = 0
        for item_id in checked_ids:
            result = self._tree_results.get(item_id)
            if result is None:
                values = self._result_tree.item(item_id)["values"]
                if len(values) >= 6 and values[5]:
                    result = type("R", (), {"file_path": values[5]})()
            if result is not None and getattr(result, "file_path", ""):
                self.whitelist.add(result.file_path, note="扫描结果信任")
                added += 1

        if added:
            self._refresh_trusted_list()
            self._update_status_bar(f"✅ 已将 {added} 个文件加入信任区")
        else:
            messagebox.showinfo("提示", "没有可信任的有效文件。")

    def _delete_selected_result_files(self):
        """永久删除选中的扫描结果文件（从磁盘移除，不可恢复）"""
        checked_ids = [
            i for i in self._result_tree.get_children()
            if self._checked.get(i, False)
        ]
        if not checked_ids:
            checked_ids = list(self._result_tree.selection())
        if not checked_ids:
            messagebox.showinfo(
                "提示",
                "没有选中的文件。\n\n请点击左侧 ☑ 勾选框，或单击行高亮后再点「🗑️ 删除选中」。",
            )
            return

        targets = []
        for item_id in checked_ids:
            result = self._tree_results.get(item_id)
            path = None
            if result is not None:
                path = getattr(result, "file_path", None)
            if not path:
                values = self._result_tree.item(item_id)["values"]
                if len(values) >= 6:
                    path = values[5]
            if path:
                targets.append((item_id, path))

        if not targets:
            messagebox.showinfo("提示", "没有可删除的有效文件。")
            return

        if not messagebox.askyesno(
            "永久删除",
            f"确定要永久删除选中的 {len(targets)} 个文件吗？\n\n"
            f"⚠️ 此操作不可撤销，文件将从磁盘彻底移除！",
        ):
            return

        ok = 0
        for item_id, path in targets:
            try:
                if os.path.exists(path):
                    os.remove(path)
                ok += 1
                self._remove_tree_item(item_id)
            except Exception as e:
                self._update_status_bar(f"⚠️ 删除失败: {os.path.basename(path)} — {e}")
        self._update_status_bar(f"🗑️ 已永久删除 {ok} 个文件")
        if ok:
            messagebox.showinfo("已删除", f"✅ 已永久删除 {ok} 个文件")

    def _restore_quarantined(self):
        """恢复隔离文件"""
        selection = self._quarantine_tree.selection()
        if not selection:
            return

        iid = selection[0]
        qname = self._quarantine_item_ids.get(iid)
        if not qname:
            return
        oname = self._quarantine_tree.item(iid)["values"][1]

        if not messagebox.askyesno(
            "恢复文件",
            f"确定要恢复文件 {oname} 吗？\n\n⚠️ 该文件被检测为威胁，恢复可能导致安全风险！",
        ):
            return

        if self.quarantine.restore_file(qname):
            self._refresh_quarantine_list()
            self._update_status_bar(f"✅ 已恢复: {oname}")
        else:
            messagebox.showerror("恢复失败", f"无法恢复文件: {oname}")

    def _delete_quarantined(self):
        """永久删除隔离文件"""
        selection = self._quarantine_tree.selection()
        if not selection:
            return

        iid = selection[0]
        qname = self._quarantine_item_ids.get(iid)
        if not qname:
            return
        oname = self._quarantine_tree.item(iid)["values"][1]

        if not messagebox.askyesno(
            "永久删除",
            f"确定要永久删除 {oname} 吗？\n\n⚠️ 此操作不可撤销！",
        ):
            return

        if self.quarantine.delete_quarantined(qname):
            self._refresh_quarantine_list()
            self._update_status_bar(f"🗑️ 已永久删除: {oname}")
        else:
            messagebox.showerror("删除失败", f"无法删除: {oname}")

    def _refresh_quarantine_list(self):
        """刷新隔离区列表"""
        if not hasattr(self, "_quarantine_item_ids"):
            self._quarantine_item_ids = {}
        self._quarantine_item_ids.clear()
        for item in self._quarantine_tree.get_children():
            self._quarantine_tree.delete(item)

        for entry in self.quarantine.list_quarantined():
            size_str = self._format_size(entry.get("file_size", 0))
            qname = entry["quarantine_name"]
            iid = self._quarantine_tree.insert("", tk.END, values=(
                qname[:16] + ("..." if len(qname) > 16 else ""),
                entry["original_name"],
                entry["threat_name"],
                entry["original_path"],
                size_str,
                entry["quarantined_at"][:19],
            ))
            self._quarantine_item_ids[iid] = qname

        self._q_count_label.configure(
            text=f"隔离文件: {self.quarantine.count}"
        )

    # ==========================================================
    # 实时防护
    # ==========================================================
    def _toggle_rtp(self):
        """旧接口兼容 — 转发到新的总开关逻辑"""
        self._toggle_rtp_master()

    def _toggle_rtp_master(self):
        """实时防护总开关 — 根据子模块复选框状态启动/停止对应引擎"""
        if getattr(self, "_rtp_master_on", False):
            # ---- 关闭 ----
            self._stop_all_rtp_engines()
            self._rtp_master_on = False
            self._update_rtp_ui_state()
            self._log_rtp_event("INFO", "实时防护已关闭")
            self._update_status_bar("实时防护已关闭")
        else:
            # ---- 开启 ----
            if not self.realtime_monitor.available:
                self._update_status_bar("🔧 正在安装实时防护依赖，请稍候...")
                self._rtp_label.configure(text="实时防护: 安装依赖中...")
                self._ensure_and_start_rtp()
                return
            self._rtp_master_on = True
            self._apply_rtp_settings()
            self._update_rtp_ui_state()
            self._log_rtp_event("INFO", "实时防护已开启")

    def _apply_rtp_settings(self):
        """根据子开关复选框状态，启动对应的监控引擎"""
        if not getattr(self, "_rtp_master_on", False):
            return

        # 先停所有引擎（再按需重启）
        self._stop_all_rtp_engines()

        # ---- 收集文件监控路径 ----
        paths = []
        if self._rtp_sub_vars["standard"].get():
            paths.append(str(Path.home() / "Desktop"))
            paths.append(str(Path.home() / "Documents"))
        if self._rtp_sub_vars["download"].get():
            paths.append(str(Path.home() / "Downloads"))
        if self._rtp_sub_vars["sensitive"].get():
            win = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            paths.append(str(win / "System32" / "drivers"))
            paths.append(str(win / "System32" / "drivers" / "etc"))

        existing_paths = [p for p in paths if os.path.exists(p)]
        enable_proc = self._rtp_sub_vars["process"].get()

        started = []

        # 文件监控（watchdog）
        if existing_paths and self.realtime_monitor.available:
            try:
                self.realtime_monitor.start(existing_paths, enable_proc_monitor=enable_proc)
                started.append(f"文件({len(existing_paths)}目录)")
                if enable_proc:
                    started.append("进程行为")
                self._log_rtp_event("INFO",
                    f"文件监控启动: {len(existing_paths)} 个目录, 进程监控: {'开' if enable_proc else '关'}")
            except Exception as e:
                self._log_rtp_event("ERROR", f"文件监控启动失败: {e}")

        # 注册表监控
        if self._rtp_sub_vars["registry"].get():
            try:
                self.reg_monitor.start()
                started.append("注册表")
                self._log_rtp_event("INFO", "注册表 HOOK 监控已启动")
            except Exception as e:
                self._log_rtp_event("ERROR", f"注册表监控启动失败: {e}")

        # 引导区监控
        if self._rtp_sub_vars["boot"].get():
            try:
                self._refresh_boot_baseline()
                started.append("引导区")
            except Exception as e:
                self._log_rtp_event("ERROR", f"引导区监控失败: {e}")

        # 系统敏感文件防护
        if self._rtp_sub_vars["sensitive"].get():
            try:
                self._start_sensitive_guard()
                started.append("敏感文件")
            except Exception as e:
                self._log_rtp_event("ERROR", f"敏感文件防护失败: {e}")

        summary = " + ".join(started) if started else "无模块启用"
        # 状态栏更新推到主线程（此函数现在可能从后台线程被调用）
        try:
            self.root.after(0, lambda: self._update_status_bar(
                f"🛡️ 实时防护运行中 — {summary}"))
        except Exception:
            self._update_status_bar(f"🛡️ 实时防护运行中 — {summary}")

    def _stop_all_rtp_engines(self):
        """停止所有实时防护引擎"""
        try:
            if self.realtime_monitor.running:
                self.realtime_monitor.stop()
        except Exception:
            pass
        try:
            self.reg_monitor.stop()
        except Exception:
            pass
        try:
            if hasattr(self, "sensitive_monitor") and self.sensitive_monitor and \
               getattr(self.sensitive_monitor, "running", False):
                self.sensitive_monitor.stop()
        except Exception:
            pass

    def _on_rtp_sub_toggle(self, key: str):
        """子模块复选框变化回调（立即刷新 UI，引擎切换放后台线程）

        关键修复（v16）：在主线程预先读取所有子模块 tkinter 变量，
        以字典形式传给 worker — 避免 worker 在子线程里调
        BooleanVar.get() 触发 'main thread is not in main loop'。
        """
        names = {
            "standard": "标准实时监控", "download": "解压/下载监控",
            "registry": "注册表监控", "boot": "引导区监控",
            "sensitive": "系统敏感文件监控", "process": "应用异常行为监控",
        }
        state = "开启" if self._rtp_sub_vars[key].get() else "关闭"
        self._log_rtp_event("INFO", f"{names.get(key, key)} 已{state}")
        # 立即刷新 UI（让打勾视觉立刻生效，不会被后续 join 卡住）
        try:
            self.root.update_idletasks()
        except Exception:
            pass
        # 总开关已开启时，动态重新应用设置
        if getattr(self, "_rtp_master_on", False):
            # 【关键】在主线程一次性读取所有子模块变量 → 转成普通 dict
            try:
                sub_states = {k: bool(v.get()) for k, v in self._rtp_sub_vars.items()}
            except Exception:
                sub_states = {k: False for k in self._rtp_sub_vars.keys()}
            # 标记 pending（debounce 用）
            self._rtp_apply_pending = True
            # 后台线程只接收纯 dict，不再触碰任何 tkinter 变量
            threading.Thread(target=self._apply_rtp_settings_worker,
                             args=(sub_states,),
                             daemon=True, name="RTP-Apply").start()

    def _apply_rtp_settings_worker(self, sub_states: dict):
        """后台线程：根据子模块状态启动/停止引擎

        【关键】本函数绝不调任何 tkinter 变量（BooleanVar.get() / StringVar.get() 等），
        所有 UI 更新通过 self.root.after(0, ...) 推回主线程。
        """
        try:
            time.sleep(0.15)  # debounce
            if not getattr(self, "_rtp_apply_pending", False):
                return
            self._rtp_apply_pending = False
            # 调内部纯逻辑版本（接收 sub_states dict，不读 tkinter 变量）
            self._apply_rtp_settings_pure(sub_states)
        except Exception as e:
            import traceback
            err = f"{e}\n{traceback.format_exc()}"
            try:
                self.root.after(0, lambda: self._log_rtp_event("ERROR",
                    f"实时防护子模块切换失败: {err[:200]}"))
            except Exception:
                pass

    def _apply_rtp_settings_pure(self, sub_states: dict):
        """纯逻辑版本：根据 sub_states dict 启动/停止监控引擎（不读 tkinter 变量）

        所有 UI 更新用 self.root.after(0, ...) 推回主线程。
        """
        # ---- 收集文件监控路径 ----
        paths = []
        if sub_states.get("standard"):
            paths.append(str(Path.home() / "Desktop"))
            paths.append(str(Path.home() / "Documents"))
        if sub_states.get("download"):
            paths.append(str(Path.home() / "Downloads"))
        if sub_states.get("sensitive"):
            win = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            paths.append(str(win / "System32" / "drivers"))
            paths.append(str(win / "System32" / "drivers" / "etc"))

        existing_paths = [p for p in paths if os.path.exists(p)]
        enable_proc = sub_states.get("process", False)

        started = []

        # ---- 先停所有引擎（耗时操作放子线程，避免卡 UI） ----
        try:
            if self.realtime_monitor.running:
                self.realtime_monitor.stop()
        except Exception as e:
            self.root.after(0, lambda: self._log_rtp_event("ERROR", f"停止文件监控: {e!r}"))
        try:
            self.reg_monitor.stop()
        except Exception as e:
            self.root.after(0, lambda: self._log_rtp_event("ERROR", f"停止注册表监控: {e!r}"))
        try:
            if hasattr(self, "sensitive_monitor") and self.sensitive_monitor and \
               getattr(self.sensitive_monitor, "running", False):
                self.sensitive_monitor.stop()
        except Exception as e:
            self.root.after(0, lambda: self._log_rtp_event("ERROR", f"停止敏感文件监控: {e!r}"))

        # ---- 文件监控（watchdog） ----
        if existing_paths and self.realtime_monitor.available:
            try:
                self.realtime_monitor.start(existing_paths, enable_proc_monitor=enable_proc)
                started.append(f"文件({len(existing_paths)}目录)")
                if enable_proc:
                    started.append("进程行为")
                self.root.after(0, lambda n=len(existing_paths), p=enable_proc:
                    self._log_rtp_event("INFO",
                        f"文件监控启动: {n} 个目录, 进程监控: {'开' if p else '关'}"))
            except Exception as e:
                self.root.after(0, lambda err=e:
                    self._log_rtp_event("ERROR", f"文件监控启动失败: {err!r}"))

        # ---- 注册表监控 ----
        if sub_states.get("registry"):
            try:
                self.reg_monitor.start()
                started.append("注册表")
                self.root.after(0, lambda:
                    self._log_rtp_event("INFO", "注册表 HOOK 监控已启动"))
            except Exception as e:
                self.root.after(0, lambda err=e:
                    self._log_rtp_event("ERROR", f"注册表监控启动失败: {err!r}"))

        # ---- 引导区监控 ----
        if sub_states.get("boot"):
            try:
                self._refresh_boot_baseline()
                started.append("引导区")
            except Exception as e:
                self.root.after(0, lambda err=e:
                    self._log_rtp_event("ERROR", f"引导区监控失败: {err!r}"))

        # ---- 系统敏感文件防护 ----
        if sub_states.get("sensitive"):
            try:
                self._start_sensitive_guard()
                started.append("敏感文件")
            except Exception as e:
                self.root.after(0, lambda err=e:
                    self._log_rtp_event("ERROR", f"敏感文件防护失败: {err!r}"))

        summary = " + ".join(started) if started else "无模块启用"
        # 状态栏更新推回主线程
        self.root.after(0, lambda s=summary:
            self._update_status_bar(f"🛡️ 实时防护运行中 — {s}"))

    def _set_toast_mode(self, mode: str):
        """v24: 静默模式已移除 — 此方法保留为 no-op 兼容旧调用，强制 toast 模式"""
        # 不再切换模式，固定 toast（弹窗已启用）
        try:
            self._log_rtp_event("INFO", "弹窗模式固定为「弹窗显示」（静默模式已移除）")
        except Exception:
            pass
        self._update_rtp_ui_state()

    def _update_rtp_ui_state(self):
        """统一更新所有实时防护 UI 元素（顶栏指示器/文字、工具栏按钮、面板总开关、弹窗模式指示）"""
        on = getattr(self, "_rtp_master_on", False)
        # 顶栏
        try:
            self._draw_rtp_indicator(on)
            self._rtp_label.configure(text="实时防护: 运行中" if on else "实时防护: 已关闭")
        except Exception:
            pass
        # v25: 移除「弹窗已启用（强制）」顶栏指示器 — 用户不要了
        pass
        # 扫描结果页工具栏按钮
        try:
            self._rtp_switch_btn.configure(text="🟢 关闭实时防护" if on else "🔴 开启实时防护")
        except Exception:
            pass
        # 实时防护面板总开关按钮
        try:
            self._rtp_master_btn.configure(
                text="  🟢  运行中  " if on else "  🔴  已关闭  ",
                bg=COLORS["accent_green"] if on else COLORS["accent_red"])
        except Exception:
            pass

    def _log_rtp_event(self, level: str, message: str):
        """写入实时防护日志（线程安全：通过 after 在主线程执行）"""
        def _do_log():
            try:
                if not hasattr(self, "_rtp_log") or not self._rtp_log.winfo_exists():
                    return
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                level_emoji = {
                    "INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌",
                    "THREAT": "🔴", "QUARANTINE": "🔒",
                }.get(level, "ℹ️")
                line = f"[{timestamp}] {level_emoji} {message}\n"
                self._rtp_log.configure(state="normal")
                self._rtp_log.insert(tk.END, line)
                self._rtp_log.see(tk.END)
                self._rtp_log.configure(state="disabled")
                # 限制日志条数（保留最后 500 行）
                lines = int(self._rtp_log.index("end-1c").split(".")[0])
                if lines > 500:
                    self._rtp_log.configure(state="normal")
                    self._rtp_log.delete("1.0", f"{lines - 500}.0")
                    self._rtp_log.configure(state="disabled")
            except Exception:
                pass
        try:
            self.root.after(0, _do_log)
        except Exception:
            pass

    def _clear_rtp_log(self):
        """清空实时防护日志"""
        try:
            self._rtp_log.configure(state="normal")
            self._rtp_log.delete("1.0", tk.END)
            self._rtp_log.configure(state="disabled")
            self._log_rtp_event("INFO", "日志已清空")
        except Exception:
            pass

    def _refresh_boot_baseline(self):
        """建立/对比 引导区基线。首次建基线静默；后续发现变化则告警。"""
        try:
            snap = self.boot_guard.snapshot()
            if not snap.entries:
                return
            diff = self.boot_guard.diff_baseline(snap)
            if diff is None:
                # 首次建基线
                self.boot_guard.save_baseline(snap)
                self._update_status_bar(
                    f"🛡 引导区基线已建立 ({len(snap.entries)} 项)，后续变化会被告警"
                )
                self._log_rtp_event("INFO", f"引导区基线已建立 ({len(snap.entries)} 项)")
            elif diff:
                # 已有基线但发生变更 — 强告警
                msg = " | ".join(diff[:3])
                self._update_status_bar(f"⚠️ 引导区被篡改: {msg}")
                self._log_rtp_event("THREAT", f"引导区被篡改: {msg}")
                # v24: 移除静默模式判断 — 引导区被篡改是高危，必须弹窗
                if self._toast_manager:
                    cfg = ToastConfig(
                        title="⚠️ 引导区疑似被篡改",
                        subtitle=f"{len(diff)} 项与基线不一致",
                        details=("\n".join(diff)),
                        toast_type=ToastType.DANGER,
                        auto_dismiss=0,  # 不自动消失
                        on_ignore=lambda: None,
                    )
                    try:
                        self._toast_manager.show_toast(cfg)
                    except Exception:
                        pass
        except Exception as e:
            self._update_status_bar(f"⚠️ 引导区基线建立失败: {e!r}")
            self._log_rtp_event("ERROR", f"引导区基线失败: {e!r}")

    def _on_threat_detected(self, result: ScanResult):
        """实时防护检测到威胁 — 通过队列交给主线程处理"""
        self._scan_queue.put(("threat", result))

    def _on_process_alert(self, alert: ProcessAlert):
        """进程行为监控检测到可疑操作 — 通过队列交给主线程处理"""
        self._scan_queue.put(("proc_alert", alert))

    def _fallback_toast(self, title: str, subtitle: str, details: str, kind: str = "warning"):
        """轻量右下角兜底弹窗。

        当 ToastManager 不可用（构造失败/依赖缺失）或 show_toast 抛异常时，
        仍然保证「检测到可疑程序 -> 右下角弹窗」这条主动防御链路生效，
        不留静默死角。"""
        try:
            palette = {
                "danger": ("#7f1d1d", "#ef4444"),
                "warning": ("#78350f", "#f59e0b"),
                "info": ("#064e3b", "#22c55e"),
            }
            bg, accent = palette.get(kind, palette["warning"])
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            w, h = 360, 132
            x = sw - w - 24
            y = sh - h - 24
            top = tk.Toplevel(self.root)
            top.wm_overrideredirect(True)
            top.wm_attributes("-topmost", True)
            top.geometry(f"{w}x{h}+{x}+{y}")
            top.configure(bg=bg, highlightthickness=0)
            # 强调色左边条
            bar = tk.Frame(top, bg=accent, width=6)
            bar.pack(side=tk.LEFT, fill=tk.Y)
            body = tk.Frame(top, bg=bg)
            body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=12, pady=10)
            tk.Label(body, text=title, bg=bg, fg="#f8fafc",
                     font=("Microsoft YaHei UI", 11, "bold"),
                     anchor="w", justify="left").pack(anchor="w", fill=tk.X)
            tk.Label(body, text=subtitle, bg=bg, fg="#e2e8f0",
                     font=("Microsoft YaHei UI", 9), anchor="w",
                     justify="left", wraplength=300).pack(anchor="w", fill=tk.X, pady=(2, 0))
            d = (details or "").strip()
            if d:
                tk.Label(body, text=d, bg=bg, fg="#cbd5e1",
                         font=("Microsoft YaHei UI", 8), anchor="w",
                         justify="left", wraplength=300).pack(anchor="w", fill=tk.X, pady=(4, 0))
            tk.Label(body, text="点击关闭 · X-Safe 主动防御", bg=bg, fg="#64748b",
                     font=("Microsoft YaHei UI", 8), anchor="e").pack(anchor="e", side=tk.BOTTOM)

            def _close():
                try:
                    top.destroy()
                except Exception:
                    pass

            top.bind("<Button-1>", lambda e: _close())
            top.after(12000, _close)  # 12 秒后自动消失
        except Exception:
            pass

    # ----------------------------------------------------------
    # Toast 弹窗通知 — 右下角实时告警
    # ----------------------------------------------------------
    def _show_threat_toast(self, result: ScanResult, source: str = "realtime"):
        """对文件威胁显示弹窗 — v26 改用 ThreatToast（屏幕右下方 420x340）
        v28: 手动扫描模式（manual_scan/scheduled）只弹 1 个累积摘要，不创建 N 个
            实时监控模式（realtime）每个都弹
        用户明确要求：复用「检测到可疑操作」弹窗（ThreatToast），不自动隔离。
        source:
          - "realtime"      实时防护触发（解压/下载/移动），每个都弹
          - "manual_scan"   手动快速扫描触发，**累积摘要弹窗**（避免狂涌 516 个被顶掉）
          - "scheduled"     定时扫描触发，同 manual_scan
        """
        # ---- 写入实时防护日志 ----
        self._log_rtp_event("THREAT",
            f"检测到威胁: {result.threat_name} — {result.file_name} ({result.threat_level.value})")

        # ---- v28: 手动扫描模式 = 累积摘要弹窗 ----
        # 真相：用户跑快速扫描，扫描线程在 30ms 内入队 516 个 progress 事件，
        #       主线程一次 tick 处理 400 个 → 30ms 内创建 516 个 ThreatToast →
        #       max_toasts=8 顶替逻辑把旧的秒秒钟顶掉 → 用户看到 0 个弹窗
        # 修复：手动扫描时只弹 1 个「累计 N 个威胁」摘要弹窗（节流 1.5s 弹一次）
        if source in ("manual_scan", "scheduled"):
            self._show_scan_summary_toast(result)
            return

        # ---- 实时模式：每个都弹 ----
        try:
            self._poll_debug_log(
                f"_show_threat_toast: 弹出 ThreatToast (file={result.file_name[:30]}, source={source})"
            )
        except Exception:
            pass

        # 等级 → toast_type 映射
        level_to_type = {
            "malicious": ToastType.DANGER,
            "high_risk": ToastType.DANGER,
            "suspicious": ToastType.WARNING,
        }
        toast_type = level_to_type.get(result.threat_level.value, ToastType.WARNING)

        # ThreatToast 配置（与 _show_process_toast 风格一致）
        config = ToastConfig(
            title=self._toast_title(result),
            subtitle=f"{result.threat_name} | {result.file_name}",
            details=(
                f"📁 路径: {result.file_path}\n"
                f"🔍 检测方式: {result.detection_method}\n"
                f"⚠️ 威胁等级: {result.threat_level.value}\n"
                f"📏 文件大小: {self._format_size(result.file_size)}\n"
                f"🕐 检测时间: {result.timestamp[:19]}\n\n"
                f"🛡️ 主动防御：未隔离 — 请选择处置方式\n"
                f"{result.details or ''}"
            ),
            toast_type=toast_type,
            auto_dismiss=0,  # 0 = 不自动消失（用户必须主动关）
            pre_isolated=False,  # v26 明确告诉用户「未隔离」
            on_delete=(lambda r=result: self._delete_threat_file(r)),
            on_restore=None,  # 没隔离就没恢复
            on_self_check=lambda r=result: self._popup_self_check_for(r),
            on_quarantine=(lambda r=result: self._quarantine_single_threat(r)),
            on_ignore=lambda r=result: self._update_status_bar(
                f"⚠️ 已忽略威胁: {r.file_name}（文件未隔离，请自行处理）"
            ),
        )
        if self._toast_manager:
            try:
                self._toast_manager.show_toast(config)
                return
            except Exception as e:
                self._poll_debug_log(f"ThreatToast 弹出失败: {e!r}")
        # 兜底：ToastManager 不可用时用 _fallback_toast
        kind = "danger" if toast_type == ToastType.DANGER else "warning"
        self._fallback_toast(
            self._toast_title(result),
            f"{result.threat_name} | {result.file_name}",
            (f"🛡️ 主动防御：未隔离 — 请选择处置方式\n" + (result.details or "")),
            kind,
        )

    def _show_scan_summary_toast(self, result: ScanResult):
        """v28: 手动扫描模式 = 累积摘要弹窗
        解决「快速扫描发现 516 个威胁 → 30ms 内创建 516 个 ThreatToast → 全部被 max_toasts 顶掉 → 用户看不到」
        策略：1.5s 节流内累积所有威胁，每 1.5s 弹 1 个「🚨 扫描发现 N 个威胁」摘要弹窗
        """
        try:
            now = self._now_ms()
            # 初始化累积状态
            if not hasattr(self, "_scan_acc_count"):
                self._scan_acc_count = 0
            if not hasattr(self, "_scan_acc_samples"):
                self._scan_acc_samples = []
            if not hasattr(self, "_scan_acc_first_ts"):
                self._scan_acc_first_ts = now
            if not hasattr(self, "_last_scan_summary_toast_ts"):
                self._last_scan_summary_toast_ts = 0.0

            # 累积本次威胁
            self._scan_acc_count += 1
            # 保留前 3 个 + 最新 1 个样本
            if len(self._scan_acc_samples) < 4:
                self._scan_acc_samples.append(result)
            # 把最新的也放进去（如果还没满）
            if len(self._scan_acc_samples) >= 4 and result not in self._scan_acc_samples:
                self._scan_acc_samples[-1] = result

            # 节流：1.5s 内只弹 1 次（避免狂涌时弹窗堆叠）
            if now - self._last_scan_summary_toast_ts < 1500:
                # 还在节流窗口内：仅累积，等下次 tick
                try:
                    self._update_status_bar(
                        f"🔄 扫描中... 已发现 {self._scan_acc_count} 个威胁（1.5s 后弹摘要）"
                    )
                except Exception:
                    pass
                return

            self._last_scan_summary_toast_ts = now
            count = self._scan_acc_count
            samples = self._scan_acc_samples
            elapsed_sec = (now - self._scan_acc_first_ts) / 1000.0

            # 弹窗标题 + 详情
            title = f"🚨 扫描发现 {count} 个威胁"
            subtitle = f"最新: {result.threat_name} | {result.file_name}"
            sample_lines = "\n".join(
                f"  • {s.file_name} — {s.threat_name} ({s.threat_level.value})"
                for s in samples[:5]
            )
            details = (
                f"📊 本次扫描累积: {count} 个威胁\n"
                f"⏱ 扫描用时: {elapsed_sec:.1f} 秒\n"
                f"📋 前几个样本:\n{sample_lines}\n\n"
                f"🛡️ 主动防御：未隔离 — 请在扫描结果区查看全部"
            )

            # 等级用最高的一个
            level_priority = {"malicious": 3, "high_risk": 2, "suspicious": 1}
            worst_level = max(
                (s.threat_level.value for s in samples),
                key=lambda lv: level_priority.get(lv, 0),
                default="suspicious",
            )
            toast_type = ToastType.DANGER if worst_level in ("malicious", "high_risk") else ToastType.WARNING

            config = ToastConfig(
                title=title,
                subtitle=subtitle,
                details=details,
                toast_type=toast_type,
                auto_dismiss=0,  # 不自动消失
                pre_isolated=False,
                on_ignore=lambda: self._update_status_bar(
                    f"📋 已忽略 {count} 个威胁，请在扫描结果区查看"
                ),
                on_self_check=lambda r=result: self._popup_self_check_for(r),
            )

            # 关键：先清空现有 toast 队列（避免叠加 8 个）
            if self._toast_manager:
                try:
                    self._toast_manager.clear_all()
                except Exception:
                    pass
                try:
                    self._toast_manager.show_toast(config)
                    self._poll_debug_log(
                        f"扫描摘要弹窗: {count} 个威胁 (样本 {len(samples)})"
                    )
                except Exception as e:
                    self._poll_debug_log(f"扫描摘要弹窗失败: {e!r}")
            else:
                # 兜底：fallback_toast
                kind = "danger" if worst_level in ("malicious", "high_risk") else "warning"
                self._fallback_toast(title, subtitle, details, kind)

            # 重置累积（但保留 first_ts 以便下个 1.5s 周期能正确显示「扫描用时」）
            self._scan_acc_count = 0
            self._scan_acc_samples = []
        except Exception as e:
            try:
                self._poll_debug_log(f"_show_scan_summary_toast 失败: {e!r}")
            except Exception:
                pass

    def _debug_trigger_threat_toast(self):
        """v27 DEBUG: 启动 5 秒后自动调一次 _show_threat_toast（用环境变量 XSAFE_DEBUG_TOAST=1 启用）"""
        try:
            from engine import ScanResult, ThreatLevel
            result = ScanResult(
                file_path=r"C:\Users\Public\eicar_test.com",
                file_name="eicar_test.com",
                threat_name="EICAR-Test-File (DEBUG 自检)",
                threat_level=ThreatLevel.MALICIOUS,
                detection_method="DEBUG: v27 自动触发",
                file_size=68,
                hash_md5="44d88612fea8a8f36de82e1278abb02f",
                details="v27 自检弹窗 — 如果你看到这个弹窗，说明 ThreatToast 链路完全正常。",
                timestamp=__import__("datetime").datetime.now().isoformat(),
            )
            self._init_debug(f"DEBUG: 触发 _show_threat_toast (file={result.file_name})")
            self._show_threat_toast(result, source="debug")
            self._init_debug("DEBUG: _show_threat_toast 调用完成")
        except Exception as e:
            self._init_debug(f"DEBUG 失败: {e!r}")

    def _debug_trigger_quick_scan(self):
        """v29 DEBUG: 启动 3 秒后自动调 _start_quick_scan（用环境变量 XSAFE_AUTO_SCAN=1 启用）"""
        try:
            self._init_debug("DEBUG: 触发 _start_quick_scan")
            self._start_quick_scan()
            self._init_debug("DEBUG: _start_quick_scan 已调用")
        except Exception as e:
            self._init_debug(f"DEBUG 扫描失败: {e!r}")

    def _delete_threat_file(self, result: ScanResult):
        """v26: ThreatToast 「删除」按钮 — 永久删除威胁文件（不经回收站）"""
        try:
            fp = result.file_path
            if fp and os.path.exists(fp):
                try:
                    os.remove(fp)
                    self._update_status_bar(f"🗑 已永久删除: {result.file_name}")
                    self._log_rtp_event("INFO", f"用户删除: {result.file_name}")
                except Exception as e:
                    self._update_status_bar(f"⚠️ 删除失败: {e!r}")
            else:
                self._update_status_bar(f"⚠️ 文件不存在: {result.file_name}")
        except Exception as e:
            self._update_status_bar(f"⚠️ 删除失败: {e!r}")

    # ----------------------------------------------------------
    # 隔离区操作（用户从主动防御弹窗选 删除 / 恢复 时调用）
    # ----------------------------------------------------------
    def _delete_quarantined_threat(self, q_name: str, result: ScanResult):
        """主动防御弹窗 — 用户点「删除」：永久清除隔离区中的病毒文件"""
        if self.quarantine.delete_quarantined(q_name):
            self._refresh_quarantine_list()
            self._update_status_bar(
                f"🗑 已永久删除: {result.file_name} (隔离副本: {q_name[:12]}…)"
            )
        else:
            self._update_status_bar(
                f"⚠️ 删除失败: {q_name[:16]}"
            )

    def _restore_quarantined_threat(self, q_name: str, result: ScanResult):
        """主动防御弹窗 — 用户点「恢复」：把隔离文件还原到原路径"""
        if self.quarantine.restore_file(q_name):
            self._refresh_quarantine_list()
            self._update_status_bar(
                f"↩ 已恢复: {result.file_name}（如属误报请加入信任区）"
            )
        else:
            self._update_status_bar(
                f"⚠️ 恢复失败: {q_name[:16]} — 目标路径可能被占用"
            )

            # ---- 顶栏（红色 — 强调这是威胁） ----
            topbar = tk.Frame(win, bg=level_color, height=64)
            topbar.pack(fill=tk.X)
            topbar.pack_propagate(False)
            tk.Label(
                topbar, text="🛡️ X-Safe 主动防御",
                font=("Microsoft YaHei UI", 13, "bold"),
                bg=level_color, fg="#ffffff",
            ).pack(side=tk.LEFT, padx=18, pady=18)
            tk.Label(
                topbar, text=level_text,
                font=("Microsoft YaHei UI", 14, "bold"),
                bg=level_color, fg="#ffffff",
            ).pack(side=tk.RIGHT, padx=18, pady=18)

            # ---- 副标题：威胁名 + 文件名 ----
            sub = tk.Frame(win, bg=COLORS.get("bg_card", "#ffffff"))
            sub.pack(fill=tk.X, padx=16, pady=(14, 4))
            tk.Label(
                sub, text=f"{result.threat_name}",
                font=("Microsoft YaHei UI", 12, "bold"),
                bg=COLORS.get("bg_card", "#ffffff"),
                fg=COLORS.get("accent_red", "#dc2626"),
                anchor="w",
            ).pack(fill=tk.X)
            tk.Label(
                sub, text=f"📄 {result.file_name}",
                font=("Microsoft YaHei UI", 10),
                bg=COLORS.get("bg_card", "#ffffff"),
                fg=COLORS.get("text_primary", "#222"),
                anchor="w",
            ).pack(fill=tk.X, pady=(2, 0))

            # ---- 详情信息（只读 Text） ----
            body = tk.Frame(win, bg=COLORS.get("bg_card", "#ffffff"))
            body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 8))
            details_text = (
                f"📁 路径: {result.file_path}\n"
                f"🔍 检测方式: {result.detection_method}\n"
                f"⚠️ 威胁等级: {result.threat_level.value}\n"
                f"📏 文件大小: {self._format_size(result.file_size)}\n"
                f"🕐 检测时间: {result.timestamp[:19]}\n\n"
                f"检测原因: {result.details or '(无)'}"
            )
            tk.Label(
                body, text=details_text,
                font=("Consolas", 9),
                bg=COLORS.get("bg_card", "#ffffff"),
                fg=COLORS.get("text_secondary", "#444"),
                justify=tk.LEFT, anchor="nw",
                wraplength=520,
            ).pack(fill=tk.BOTH, expand=True)

            # ---- 按钮区 ----
            btn_row = tk.Frame(win, bg=COLORS.get("bg_main", "#f5f5f5"))
            btn_row.pack(fill=tk.X, padx=16, pady=(0, 16))

            def close_and_run(fn):
                def _do():
                    try:
                        win.destroy()
                    except Exception:
                        pass
                    try:
                        fn()
                    except Exception:
                        pass
                return _do

            def on_delete():
                # 真正删除文件（移入回收站 / 永久删除）
                try:
                    fp = result.file_path
                    if fp and os.path.exists(fp):
                        try:
                            import send2trash
                            send2trash.send2trash(fp)
                            self._update_status_bar(f"🗑 已移入回收站: {result.file_name}")
                            self._log_rtp_event("INFO", f"用户删除: {result.file_name}")
                        except Exception:
                            try:
                                os.remove(fp)
                                self._update_status_bar(f"🗑 已永久删除: {result.file_name}")
                                self._log_rtp_event("INFO", f"用户永久删除: {result.file_name}")
                            except Exception as e:
                                self._update_status_bar(f"⚠️ 删除失败: {e!r}")
                    else:
                        self._update_status_bar(f"⚠️ 文件不存在: {result.file_name}")
                except Exception as e:
                    self._update_status_bar(f"⚠️ 删除失败: {e!r}")

            def on_trust():
                # 加入白名单
                try:
                    fp = result.file_path or ""
                    if fp and hasattr(self, "whitelist") and self.whitelist:
                        try:
                            self.whitelist.add_trusted_path(fp)
                            self._update_status_bar(f"✅ 已加入白名单: {result.file_name}")
                            self._log_rtp_event("INFO", f"用户信任: {result.file_name}")
                        except Exception as e:
                            self._update_status_bar(f"⚠️ 加白失败: {e!r}")
                    else:
                        self._update_status_bar(f"⚠️ 无法加白（路径为空或无白名单模块）")
                except Exception as e:
                    self._update_status_bar(f"⚠️ 加白失败: {e!r}")

            def on_ignore():
                self._update_status_bar(f"⚠️ 已忽略威胁: {result.file_name}")
                self._log_rtp_event("INFO", f"用户忽略: {result.file_name}")

            def on_self_check():
                # 自检（沿用现有的 _popup_self_check_for）
                self._popup_self_check_for(result)

            # v26: 删除 _show_active_defense_popup 残留代码（按钮/函数体）

    def _popup_self_check_for(self, result: ScanResult):
        """主动防御弹窗 — 用户点「自检」：弹窗展示自检报告（不阻塞、不消失 toast）"""
        try:
            report = run_full_check(self)
            win = tk.Toplevel(self.root)
            win.title("X-Safe 自检报告")
            win.configure(bg=COLORS["bg_main"])
            win.geometry("720x540")
            head = tk.Frame(win, bg=COLORS["topbar_bg"], height=46)
            head.pack(fill=tk.X)
            head.pack_propagate(False)
            tk.Label(
                head, text="🔍 X-Safe 自检报告",
                font=("Microsoft YaHei UI", 13, "bold"),
                bg=COLORS["topbar_bg"], fg=COLORS["text_primary"],
            ).pack(side=tk.LEFT, padx=14, pady=10)
            tk.Label(
                head, text=f"结论: {report.overall}",
                font=("Microsoft YaHei UI", 10, "bold"),
                bg=COLORS["topbar_bg"],
                fg=(COLORS["accent_green"] if report.overall == "PASS"
                    else COLORS["accent_red"] if report.overall == "FAIL"
                    else COLORS["accent_orange"]),
            ).pack(side=tk.RIGHT, padx=14)
            body = tk.Text(
                win, font=("Consolas", 10),
                bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                relief=tk.FLAT, borderwidth=0, wrap=tk.NONE,
                padx=14, pady=12,
            )
            body.pack(fill=tk.BOTH, expand=True)
            body.insert("1.0", report.render())
            body.configure(state=tk.DISABLED)
        except Exception as e:
            self._update_status_bar(f"⚠️ 自检失败: {e!r}")

    # ----------------------------------------------------------
    # 注册表 HOOK 告警回调（主线程）
    # ----------------------------------------------------------
    def _on_registry_alert(self, alert: RegistryAlert):
        """注册表变更告警：日志 + 状态栏 + 右下角 toast（v24 强制弹窗）"""
        text = alert.to_text()
        self._update_status_bar(f"🔐 注册表变更: {text}")
        # 写入实时防护日志
        self._log_rtp_event("WARN",
            f"注册表变更: {alert.target_label} — {alert.change} ({alert.value_name})")
        # v24: 移除静默模式判断 — 有文件/事件就必须弹窗
        # 注册表告警走进程级 toast：复用 toast 体系但用 INFO 等级
        if self._toast_manager:
            try:
                cfg = ToastConfig(
                    title="注册表 HOOK 告警",
                    subtitle=alert.target_label,
                    details=(
                        f"变更: {alert.change}\n"
                        f"项名: {alert.value_name}\n"
                        f"原值: {alert.old_data or '(无)'}\n"
                        f"新值: {alert.new_data or '(无)'}\n"
                        f"时间: {alert.timestamp}"
                    ),
                    toast_type=ToastType.WARNING,
                    auto_dismiss=20,
                    on_ignore=lambda: None,
                )
                self._toast_manager.show_toast(cfg)
            except Exception:
                pass

    def _show_process_toast(self, alert: ProcessAlert):
        """对进程行为威胁显示右下角弹窗（v24 强制弹窗）"""
        # 写入实时防护日志
        self._log_rtp_event("THREAT",
            f"进程异常: {alert.name} (PID:{alert.pid}) — {alert.reason}")
        # v24: 移除静默模式判断 — 有异常就弹窗
        if not self._toast_manager:
            return
        level_to_type = {
            BehaviorLevel.MALICIOUS: ToastType.DANGER,
            BehaviorLevel.HIGH_RISK: ToastType.DANGER,
            BehaviorLevel.SUSPICIOUS: ToastType.WARNING,
        }
        toast_type = level_to_type.get(alert.level, ToastType.WARNING)

        # 构建详情文本
        parent_info = ""
        if alert.parent_name:
            parent_info = (
                f"👤 父进程: {alert.parent_name} (PID: {alert.parent_pid})\n"
            )

        config = ToastConfig(
            title=self._proc_toast_title(alert),
            subtitle=f"{alert.name} (PID: {alert.pid})",
            details=(
                f"📂 程序路径: {alert.exe_path}\n"
                f"💻 命令行: {alert.cmdline[:200]}\n"
                f"{parent_info}"
                f"👤 用户: {alert.username}\n"
                f"⚠️ 威胁等级: {alert.level.value}\n"
                f"🕐 检测时间: {alert.timestamp[:19]}\n\n"
                f"检测原因: {alert.reason}\n"
                f"{alert.details}"
            ),
            toast_type=toast_type,
            auto_dismiss=25,
            on_block=lambda: self._block_and_quarantine_process(alert),
            on_quarantine=lambda: self._block_and_quarantine_process(alert),
            on_ignore=lambda: self._update_status_bar(
                f"⚠️ 已忽略可疑进程: {alert.name} (PID: {alert.pid})"
            ),
        )
        if self._toast_manager:
            try:
                self._toast_manager.show_toast(config)
                return
            except Exception:
                pass
        # 兜底弹窗：ToastManager 不可用时也保证右下角有提示
        kind = "danger" if toast_type == ToastType.DANGER else "warning"
        self._fallback_toast(
            self._proc_toast_title(alert),
            f"{alert.name} (PID: {alert.pid})",
            alert.details or "",
            kind,
        )

    def _block_and_quarantine_process(self, alert: ProcessAlert):
        """阻止进程运行 + 隔离可执行文件"""
        pid = alert.pid
        name = alert.name
        exe_path = alert.exe_path

        # 1. 终止进程树
        success, failed = self.realtime_monitor.block_process_tree(pid)
        self._update_status_bar(
            f"⛔ 已阻止进程: {name} (PID: {pid}) — 终止 {success} 个子进程"
        )

        # 2. 隔离可执行文件
        if exe_path and os.path.exists(exe_path):
            try:
                result = self.scanner.scanner.scan_file(exe_path)
                self.quarantine.quarantine_file(result)
                self._refresh_quarantine_list()
                self._update_status_bar(
                    f"🔒 已隔离文件: {os.path.basename(exe_path)} — {name} 已被清理"
                )
            except Exception as e:
                self._update_status_bar(
                    f"⚠️ 隔离失败: {os.path.basename(exe_path)} — {e}"
                )
        else:
            self._update_status_bar(
                f"⛔ 进程 {name} (PID: {pid}) 已终止"
            )

        # 弹个小确认框 (非阻塞)
        def _confirm():
            self.root.after(0, lambda: messagebox.showinfo(
                "操作完成",
                f"✅ 已完成安全操作:\n\n"
                f"1. 已终止进程: {name} (PID: {pid})\n"
                f"2. 已隔离文件: {os.path.basename(exe_path) if exe_path else '无'}\n\n"
                f"系统已受到保护。"
            ))

        threading.Thread(target=_confirm, daemon=True).start()

    def _quarantine_single_threat(self, result: ScanResult):
        """隔离单个文件威胁"""
        if self.quarantine.quarantine_file(result):
            self._refresh_quarantine_list()
            self._update_status_bar(f"🔒 已隔离: {result.file_name}")
            # 从当前结果列表与结果树移除（若存在该行）
            if result in self._current_results:
                self._current_results.remove(result)
            for item_id in list(self._tree_results):
                if self._tree_results[item_id].file_path == result.file_path:
                    self._remove_tree_item(item_id)
        else:
            self._update_status_bar(f"⚠️ 隔离失败: {result.file_name}")
            self.root.after(0, lambda: messagebox.showerror(
                "隔离失败", f"无法隔离文件:\n{result.file_path}"
            ))

    @staticmethod
    def _toast_title(result: ScanResult) -> str:
        """文件威胁弹窗标题"""
        level = result.threat_level.value
        if level == "malicious":
            return "🚨 检测到恶意软件！"
        elif level == "high_risk":
            return "⚠️ 检测到高危威胁！"
        else:
            return "🔍 检测到可疑文件"

    @staticmethod
    def _proc_toast_title(alert: ProcessAlert) -> str:
        """进程行为弹窗标题"""
        if alert.level == BehaviorLevel.MALICIOUS:
            return "🚨 检测到恶意行为！"
        elif alert.level == BehaviorLevel.HIGH_RISK:
            return "⚠️ 检测到高危操作！"
        else:
            return "🔍 检测到可疑操作"

    def _show_threat_alert(self, result: ScanResult):
        """显示威胁告警"""
        self._add_result_to_tree(result)
        self._refresh_quarantine_list()

        level_emoji = {
            ThreatLevel.MALICIOUS: "🔴",
            ThreatLevel.HIGH_RISK: "🟠",
            ThreatLevel.SUSPICIOUS: "🟡",
        }.get(result.threat_level, "⚪")

        self._update_status_bar(
            f"{level_emoji} 实时防护检测到威胁: {result.threat_name} — {result.file_name}"
        )

    def _on_proc_alert_ui(self, alert: ProcessAlert):
        """在主线程处理进程行为告警"""
        # 记录告警到统计
        level_emoji = {
            BehaviorLevel.MALICIOUS: "🔴",
            BehaviorLevel.HIGH_RISK: "🟠",
            BehaviorLevel.SUSPICIOUS: "🟡",
        }.get(alert.level, "⚪")

        self._update_status_bar(
            f"{level_emoji} 行为监控告警: {alert.reason} — {alert.name} (PID: {alert.pid})"
        )

        # 右下角弹窗通知
        self._show_process_toast(alert)

    # ==========================================================
    # 特征库
    # ==========================================================
    def _display_signatures(self):
        """显示特征库内容"""
        self._sig_text.delete(1.0, tk.END)

        sig_path = Path(__file__).parent / "signatures.json"
        try:
            with open(sig_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 哈希签名
            self._sig_text.insert(tk.END, "=" * 60 + "\n")
            self._sig_text.insert(tk.END, "  哈希签名 (Hash Signatures)\n")
            self._sig_text.insert(tk.END, "=" * 60 + "\n\n")
            for entry in data.get("hash_signatures", []):
                md5 = entry.get("md5", "")[:32]
                sha256 = entry.get("sha256", "")[:64]
                hash_val = md5 or sha256
                self._sig_text.insert(tk.END, f"  [{entry.get('severity', 'N/A').upper()}]\n")
                self._sig_text.insert(tk.END, f"  名称: {entry.get('name', 'N/A')}\n")
                self._sig_text.insert(tk.END, f"  哈希: {hash_val}\n")
                self._sig_text.insert(tk.END, f"  描述: {entry.get('description', 'N/A')}\n")
                self._sig_text.insert(tk.END, "\n")

            # 模式签名
            self._sig_text.insert(tk.END, "=" * 60 + "\n")
            self._sig_text.insert(tk.END, "  模式签名 (Pattern Signatures)\n")
            self._sig_text.insert(tk.END, "=" * 60 + "\n\n")
            for entry in data.get("pattern_signatures", []):
                self._sig_text.insert(tk.END, f"  [{entry.get('severity', 'N/A').upper()}]\n")
                self._sig_text.insert(tk.END, f"  名称: {entry.get('name', 'N/A')}\n")
                self._sig_text.insert(tk.END, f"  类型: {entry.get('type', 'N/A')}\n")
                self._sig_text.insert(tk.END, f"  描述: {entry.get('description', 'N/A')}\n\n")

            # 统计
            self._sig_text.insert(tk.END, "=" * 60 + "\n")
            self._sig_text.insert(tk.END, f"  总计: {self.sig_db.hash_count} 条哈希签名, "
                                           f"{self.sig_db.pattern_count} 条模式规则\n")

            # AI 学习统计
            ai_stats = self.scanner.learning_stats
            self._sig_text.insert(tk.END, "\n" + "=" * 60 + "\n")
            self._sig_text.insert(tk.END, "  🤖 AI 学习统计\n")
            self._sig_text.insert(tk.END, "=" * 60 + "\n\n")
            self._sig_text.insert(tk.END, f"  总反馈次数: {ai_stats['total_feedback']}\n")
            self._sig_text.insert(tk.END, f"  误报反馈: {ai_stats['false_positives']}\n")
            self._sig_text.insert(tk.END, f"  确认威胁: {ai_stats['confirmed_threats']}\n")
            self._sig_text.insert(tk.END, f"  白名单文件: {ai_stats['whitelist_count']}\n")
            self._sig_text.insert(tk.END, f"  已学良性模式: {ai_stats['benign_patterns']}\n")
            self._sig_text.insert(tk.END, f"  当前误报率: {self.scanner.false_positive_rate:.1%}\n")

            # 特征权重详情
            self._sig_text.insert(tk.END, f"\n  特征权重 (AI 动态调整):\n")
            for name, w in ai_stats.get('feature_weights', {}).items():
                bar_len = int(w['current_weight'] * 20)
                bar = '█' * bar_len + '░' * (20 - bar_len)
                self._sig_text.insert(tk.END,
                    f"  {name:35s} [{bar}] {w['current_weight']:.2f}"
                    f" (置信度:{w['confidence']:.2f})\n")

        except Exception as e:
            self._sig_text.insert(tk.END, f"加载失败: {e}")

    def _reload_signatures(self):
        """重新加载特征库"""
        sig_path = Path(__file__).parent / "signatures.json"
        self.sig_db.load(str(sig_path))
        self._display_signatures()
        self._update_status_bar("✅ 特征库已重新加载")

    # ==========================================================
    # AI 反馈学习
    # ==========================================================
    def _ai_feedback(self, feedback_type: FeedbackType):
        """用户通过右键菜单提供 AI 反馈"""
        selection = self._result_tree.selection()
        if not selection:
            return

        item = self._result_tree.item(selection[0])
        file_path = item["values"][5]

        # 找到对应的 ScanResult
        target_result = None
        for result in self._current_results:
            if result.file_path == file_path:
                target_result = result
                break

        if not target_result:
            messagebox.showwarning("未找到", "无法找到对应的扫描结果")
            return

        # 获取 AI 特征数据
        features = self._current_features.get(file_path, {})

        # 确认对话框
        feedback_names = {
            FeedbackType.FALSE_POSITIVE: "标记为误报",
            FeedbackType.CONFIRM_THREAT: "确认为威胁",
            FeedbackType.MARK_SAFE: "加入白名单",
        }
        name = feedback_names.get(feedback_type, "反馈")

        if not messagebox.askyesno(
            f"AI 学习 — {name}",
            f"确定要将 {target_result.file_name} {name}吗？\n\n"
            f"威胁: {target_result.threat_name}\n"
            f"路径: {target_result.file_path}\n\n"
            f"AI 将从本次反馈中学习，持续优化检测准确率。"
        ):
            return

        # 执行 AI 学习
        count = self.scanner.provide_feedback(
            result=target_result,
            filepath=file_path,
            features=features,
            feedback=feedback_type,
        )

        # 如果标记为误报或安全，从结果列表移除
        if feedback_type in (FeedbackType.FALSE_POSITIVE, FeedbackType.MARK_SAFE):
            self._remove_tree_item(selection[0])
            if target_result in self._current_results:
                self._current_results.remove(target_result)

        # 更新学习统计
        stats = self.scanner.learning_stats
        self._update_status_bar(
            f"🧠 AI 已学习 ({name}): {target_result.file_name} | "
            f"总反馈: {stats['total_feedback']} | "
            f"误报率: {self.scanner.false_positive_rate:.1%} | "
            f"白名单: {stats['whitelist_count']}"
        )

        # 更新结果显示
        remaining = len(self._current_results)
        orig_stats = self.scanner.stats
        self._result_count_label.configure(
            text=f"检测结果: {remaining} 个威胁 (AI 过滤后) | "
                 f"AI 学习次数: {stats['total_feedback']}"
        )

    # ==========================================================
    # 导出报告
    # ==========================================================
    def _export_report(self):
        """导出扫描报告"""
        if not self._current_results:
            messagebox.showinfo("无数据", "没有威胁结果可导出")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON 报告", "*.json"), ("文本报告", "*.txt")],
            initialfile=f"scan_report_{datetime.datetime.now():%Y%m%d_%H%M%S}",
        )
        if not filepath:
            return

        try:
            stats = self.scanner.stats
            report = {
                "scan_time": datetime.datetime.now().isoformat(),
                "scan_stats": {
                    "total_files": stats.total_files,
                    "scanned_files": stats.scanned_files,
                    "threats_found": stats.threats_found,
                    "suspicious_found": stats.suspicious_found,
                    "elapsed_seconds": stats.elapsed_seconds,
                },
                "threats": [r.to_dict() for r in self._current_results],
            }

            with open(filepath, "w", encoding="utf-8") as f:
                if filepath.endswith(".txt"):
                    f.write("=" * 70 + "\n")
                    f.write("  X-Safe — 扫描报告\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(f"扫描时间: {report['scan_time']}\n")
                    f.write(f"扫描文件: {stats.scanned_files}\n")
                    f.write(f"发现威胁: {stats.threats_found}\n")
                    f.write(f"可疑文件: {stats.suspicious_found}\n")
                    f.write(f"扫描用时: {stats.elapsed_seconds:.1f}秒\n")
                    f.write("=" * 70 + "\n\n")

                    for i, r in enumerate(self._current_results, 1):
                        f.write(f"--- 威胁 #{i} ---\n")
                        f.write(f"文件名: {r.file_name}\n")
                        f.write(f"路径: {r.file_path}\n")
                        f.write(f"威胁: {r.threat_name}\n")
                        f.write(f"等级: {r.threat_level.value}\n")
                        f.write(f"方法: {r.detection_method}\n")
                        f.write(f"大小: {self._format_size(r.file_size)}\n")
                        f.write(f"MD5: {r.hash_md5}\n")
                        f.write(f"SHA256: {r.hash_sha256}\n")
                        f.write(f"详情: {r.details}\n\n")
                else:
                    json.dump(report, f, ensure_ascii=False, indent=2)

            self._update_status_bar(f"✅ 报告已导出: {filepath}")
            messagebox.showinfo("导出成功", f"扫描报告已保存到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ==========================================================
    # 事件处理
    # ==========================================================
    def _on_result_right_click(self, event):
        """右键菜单"""
        item = self._result_tree.identify_row(event.y)
        if item:
            self._result_tree.selection_set(item)
            self._context_item = item
            self._result_menu.post(event.x_root, event.y_root)

    def _quarantine_context(self):
        """右键菜单「隔离此文件」— 隔离当前右键项"""
        item = getattr(self, "_context_item", None)
        if not item or item not in self._tree_results:
            return
        result = self._tree_results[item]
        if not messagebox.askyesno(
            "隔离此文件",
            f"确定要隔离 {result.file_name} 吗？\n\n"
            f"隔离后文件将被加密移动到隔离区，可通过隔离区恢复。",
        ):
            return

        def worker():
            ok = False
            try:
                ok = self.quarantine.quarantine_file(result)
            except Exception:
                ok = False
            self._scan_queue.put(
                ("quarantine_done", 1 if ok else 0, 0 if ok else 1, [item] if ok else [])
            )

        threading.Thread(target=worker, daemon=True).start()

    def _on_result_double_click(self, event):
        """双击查看详情"""
        self._show_selected_detail()

    def _show_selected_detail(self):
        """显示选定文件的详细信息 — AI 增强版"""
        selection = self._result_tree.selection()
        if not selection:
            return

        item = self._result_tree.item(selection[0])
        file_path = item["values"][5]

        for result in self._current_results:
            if result.file_path == file_path:
                # AI 评分信息
                ai_score = self._current_ai_scores.get(file_path)
                ai_info = ""
                if ai_score:
                    ai_info = (
                        f"\n{'='*40}\n"
                        f"🤖 AI 智能分析\n"
                        f"{'='*40}\n"
                        f"原始评分: {ai_score.raw_score:.3f}\n"
                        f"调整评分: {ai_score.adjusted_score:.3f}\n"
                        f"模型置信度: {ai_score.confidence:.1%}\n"
                        f"AI 判断: {'⚠️ 威胁' if ai_score.is_threat else '✅ 安全'}\n"
                        f"已知安全文件: {'是' if ai_score.is_known_safe else '否'}\n"
                        f"与历史误报相似: {'是' if ai_score.similar_to_fp else '否'}\n"
                    )
                    if ai_score.feature_scores:
                        ai_info += "特征评分:\n"
                        for k, v in ai_score.feature_scores.items():
                            ai_info += f"  - {k}: {v:.3f}\n"
                    if ai_score.learning_note:
                        ai_info += f"AI 备注: {ai_score.learning_note}\n"

                detail_text = (
                    f"文件名: {result.file_name}\n"
                    f"完整路径: {result.file_path}\n"
                    f"文件大小: {self._format_size(result.file_size)}\n"
                    f"威胁名称: {result.threat_name}\n"
                    f"威胁等级: {result.threat_level.value}\n"
                    f"检测方法: {result.detection_method}\n"
                    f"熵值: {result.entropy:.2f}\n"
                    f"MD5: {result.hash_md5}\n"
                    f"SHA256: {result.hash_sha256}\n"
                    f"详情: {result.details}\n"
                    f"检测时间: {result.timestamp}"
                    f"{ai_info}"
                )

                self._show_detail_window(result.file_name, detail_text)
                break

    def _show_detail_window(self, title: str, text: str):
        """显示详情弹窗"""
        win = tk.Toplevel(self.root)
        win.title(f"威胁详情 — {title}")
        win.geometry("550x420")
        win.configure(bg=COLORS["bg_card"])
        win.transient(self.root)
        win.grab_set()

        detail_text = scrolledtext.ScrolledText(
            win, wrap=tk.WORD,
            font=("Consolas", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
        )
        detail_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=14)
        detail_text.insert(1.0, text)
        detail_text.configure(state=tk.DISABLED)

        close_btn = self._create_button(
            win, "关闭", win.destroy, COLORS["accent_blue"],
        )
        close_btn.pack(pady=(0, 14))

    def _copy_selected_path(self):
        """复制选中文件路径"""
        selection = self._result_tree.selection()
        if selection:
            item = self._result_tree.item(selection[0])
            file_path = item["values"][5]
            self.root.clipboard_clear()
            self.root.clipboard_append(file_path)
            self._update_status_bar(f"📋 已复制: {file_path}")

    # ==========================================================
    # 标签切换
    # ==========================================================
    def _switch_tab(self, tab_id: str):
        """切换标签页（左侧侧栏导航）"""
        for tid, frame in self._tab_frames.items():
            frame.pack_forget()

        for tid, pill in self._tab_buttons.items():
            pill.set_active(tid == tab_id)

        self._tab_frames[tab_id].pack(fill=tk.BOTH, expand=True)
        self._active_tab.set(tab_id)

        # 同步顶栏栏目名
        try:
            for sid, _nav, title, sub in self._SECTIONS:
                if sid == tab_id:
                    if hasattr(self, "_section_title") and self._section_title.winfo_exists():
                        self._section_title.configure(text=title)
                    if hasattr(self, "_section_sub") and self._section_sub.winfo_exists():
                        self._section_sub.configure(text=sub)
                    break
        except (tk.TclError, AttributeError):
            pass

    # ==========================================================
    # 状态管理
    # ==========================================================
    def _update_status_bar(self, message: str):
        """更新状态栏（对控件已销毁的情况做容错，避免异常中断后续逻辑，例如隔离时）"""
        try:
            if hasattr(self, "_status_text") and self._status_text.winfo_exists():
                self._status_text.configure(text=message)
        except (tk.TclError, RuntimeError, AttributeError):
            pass

    # ==========================================================
    # 工具方法
    # ==========================================================
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """格式化文件大小"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _set_app_icon(self):
        """设置应用图标"""
        try:
            icon_path = Path(__file__).parent / "xsafe.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass

    # ==========================================================
    # 系统托盘
    # ==========================================================
    def _init_system_tray(self):
        """初始化系统托盘图标"""
        try:
            import pystray
            from PIL import Image

            # 优先使用预生成的图标文件 (xsafe.ico)，回退到运行时绘制
            ico_path = Path(__file__).parent / "xsafe.ico"
            if ico_path.exists():
                img = Image.open(ico_path)
            else:
                from PIL import ImageDraw
                img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
                draw = ImageDraw.Draw(img)
                draw.polygon(
                    [(32, 4), (58, 14), (58, 34), (32, 60), (6, 34), (6, 14)],
                    fill=(13, 17, 23), outline=(46, 160, 67), width=2,
                )
                draw.line([(20, 30), (28, 40), (46, 20)], fill=(46, 160, 67), width=4)

            # ── 托盘菜单回调 ──
            def on_show_window(icon, item):
                self.root.after(0, self._show_window)

            def on_quarantine(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._focus_quarantine_tab()))

            def on_trusted(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._switch_tab("trusted")))

            def on_quick_scan(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._start_quick_scan()))

            def on_cloud_scan(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._start_cloud_scan()))

            def on_advanced_scan(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._start_advanced_scan()))

            def on_custom_scan(icon, item):
                self.root.after(0, lambda: (self._show_window(), self._start_custom_scan()))

            def on_quit(icon, item):
                self.root.after(0, self._tray_quit)

            def on_self_test(icon, item):
                self.root.after(0, self._self_test_defense)

            menu = pystray.Menu(
                pystray.MenuItem("🏠 打开主窗口", on_show_window, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("🔒 打开隔离区", on_quarantine),
                pystray.MenuItem("🛡️ 打开信任区", on_trusted),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("🧪 主动防御自测", on_self_test),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("⚡ 快速扫描", on_quick_scan),
                pystray.MenuItem("☁️ 云查杀", on_cloud_scan),
                pystray.MenuItem("🔥 高级查杀", on_advanced_scan),
                pystray.MenuItem("📁 自定义扫描", on_custom_scan),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("❌ 退出", on_quit),
            )

            self._tray_icon = pystray.Icon(
                "XSafeGuard",
                img,
                "X-Safe安全中心",
                menu,
            )

            # 在独立线程中运行托盘
            self._tray_thread = threading.Thread(
                target=self._tray_icon.run, daemon=True
            )
            self._tray_thread.start()
        except ImportError:
            # 依赖缺失 → 自动安装，不再依赖 bat
            self._auto_install_tray_deps()
        except Exception as e:
            # 其他异常也记录，避免静默
            import traceback
            traceback.print_exc()

    def _auto_install_tray_deps(self):
        """自动安装托盘依赖（pystray + Pillow），装完后重试初始化。
        全程静默 —— 不弹窗，仅在状态栏提示。"""
        def install_and_retry():
            import subprocess
            try:
                pip_cmd = self._resolve_pip()
                use_shell = " " in pip_cmd or '"' in pip_cmd or "-" in pip_cmd[3:8]
                result = subprocess.run(
                    f"{pip_cmd} install pystray Pillow -q",
                    shell=use_shell, capture_output=True, timeout=120,
                )
                if result.returncode == 0:
                    self.root.after(500, self._init_system_tray)
                else:
                    self.root.after(
                        500,
                        lambda: self._update_status_bar(
                            "⚠️ 托盘图标不可用（依赖安装失败）— 程序正常使用不受影响"
                        ),
                    )
            except Exception:
                self.root.after(
                    500,
                    lambda: self._update_status_bar(
                        "ℹ️ 托盘图标不可用 — 程序正常使用不受影响"
                    ),
                )

        threading.Thread(target=install_and_retry, daemon=True).start()

    def _toggle_window(self):
        """切换窗口显示/隐藏"""
        if self.root.state() == "iconic" or not self.root.winfo_viewable():
            self._show_window()
        else:
            self._hide_window()

    def _show_window(self):
        """显示主窗口"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _hide_window(self):
        """隐藏到托盘"""
        self.root.withdraw()

    def _tray_quit(self):
        """从托盘退出（真正销毁应用）"""
        self._destroy_app()

    def _focus_quarantine_tab(self):
        """切换到隔离区标签页（本应用使用自定义标签栏，并非 ttk.Notebook 实例）"""
        self._switch_tab("quarantine")

    def _auto_start_rtp(self):
        """启动时自动开启实时防护（静默，失败不弹窗）"""
        if getattr(self, "_rtp_master_on", False):
            return
        if not self.realtime_monitor.available:
            return

        # 使用新的统一逻辑：设总开关状态 → 根据子模块复选框启动各引擎
        self._rtp_master_on = True
        self._apply_rtp_settings()
        self._update_rtp_ui_state()
        self._log_rtp_event("INFO", "实时防护已自动开启")

    # ----------------------------------------------------------
    # 开机自启动 (Windows Registry Run)
    # ----------------------------------------------------------
    AUTOSTART_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    AUTOSTART_REG_NAME = "X-SafeSecurityCenter"

    def _is_autostart_enabled(self) -> bool:
        """检查注册表里是否有 X-Safe 开机自启动项"""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self.AUTOSTART_REG_KEY, 0, winreg.KEY_READ
            ) as key:
                try:
                    value, _ = winreg.QueryValueEx(key, self.AUTOSTART_REG_NAME)
                    return bool(value and value.strip())
                except FileNotFoundError:
                    return False
        except Exception:
            return False

    def _enable_autostart(self) -> bool:
        """在 HKCU\\...\\Run 下写入 X-Safe 启动项"""
        try:
            import winreg
            # 优先用 pythonw 避免黑框；fallback 到 sys.executable
            if getattr(sys, "frozen", False):
                # PyInstaller 打包：直接用 XSafe.exe
                exe_path = sys.executable
            else:
                # 源码运行：换 pythonw 避免黑框
                exe_path = sys.executable
                if exe_path.lower().endswith("python.exe"):
                    pythonw = exe_path[:-10] + "pythonw.exe"
                    if os.path.exists(pythonw):
                        exe_path = pythonw
                script = os.path.abspath(__file__)
                exe_path = f'"{exe_path}" "{script}"'

            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.AUTOSTART_REG_KEY, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(
                    key, self.AUTOSTART_REG_NAME, 0, winreg.REG_SZ, exe_path
                )
            return True
        except Exception as e:
            try:
                self._update_status_bar(f"❌ 写入自启动失败: {e}")
            except Exception:
                pass
            return False

    def _disable_autostart(self) -> bool:
        """删除 HKCU\\...\\Run 下的 X-Safe 启动项"""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self.AUTOSTART_REG_KEY, 0, winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, self.AUTOSTART_REG_NAME)
                except FileNotFoundError:
                    pass
            return True
        except Exception as e:
            try:
                self._update_status_bar(f"❌ 删除自启动失败: {e}")
            except Exception:
                pass
            return False

    def _toggle_autostart(self):
        """点击自启动开关时切换状态"""
        if self._is_autostart_enabled():
            if self._disable_autostart():
                self._update_status_bar("🚀 开机自启动已关闭")
                try:
                    self._log_rtp_event("INFO", "开机自启动已关闭")
                except Exception:
                    pass
        else:
            if self._enable_autostart():
                self._update_status_bar("🚀 开机自启动已开启 — 下次登录自动启动 X-Safe")
                try:
                    self._log_rtp_event("INFO", "开机自启动已开启")
                except Exception:
                    pass
        # 刷新按钮显示
        self._refresh_autostart_btn()

    def _refresh_autostart_btn(self):
        """根据注册表当前状态刷新自启动按钮文字/颜色"""
        try:
            if self._is_autostart_enabled():
                self._autostart_btn.configure(
                    text="  ✅  已开启  ",
                    bg=COLORS["accent"], fg="#ffffff",
                )
            else:
                self._autostart_btn.configure(
                    text="  ⬜  关 闭  ",
                    bg=COLORS["bg_hover"], fg=COLORS["text_secondary"],
                )
        except Exception:
            pass

    # ----------------------------------------------------------
    # 系统敏感文件防护 (System Guard)
    # ----------------------------------------------------------
    def _start_sensitive_guard(self):
        """启动系统敏感文件防护 — 持续监视 hosts / 启动目录 / 测试目录，
        一旦有程序新建或修改即隔离并弹窗。"""
        # 避免重复启动
        if self.sensitive_monitor and getattr(self.sensitive_monitor, "running", False):
            return
        # 使用类属性（依赖热重载后会更新），而非模块级可能过期的常量
        if not SensitiveFileMonitor.WATCHDOG_AVAILABLE:
            return

        try:
            targets = SensitiveFileMonitor.resolve_targets()
            # 创建可写测试目录（确保自测 bat 可用）
            try:
                os.makedirs(SensitiveFileMonitor.TEST_DIR, exist_ok=True)
            except Exception:
                pass
            # 为 hosts 建立可信备份
            if os.path.exists(SensitiveFileMonitor.HOSTS_FILE):
                self._ensure_hosts_backup()

            self.sensitive_monitor = SensitiveFileMonitor()
            self.sensitive_monitor.start(targets, self._on_sensitive_event)
            try:
                self.root.after(0, lambda: self._update_status_bar(
                    f"🛡️ 系统敏感文件防护已开启 — 监控 {len(targets)} 个敏感目标"))
            except Exception:
                self._update_status_bar(
                    f"🛡️ 系统敏感文件防护已开启 — 监控 {len(targets)} 个敏感目标")
        except Exception as e:
            try:
                self.root.after(0, lambda: self._update_status_bar(
                    f"⚠️ 系统敏感文件防护启动失败: {e}"))
            except Exception:
                self._update_status_bar(f"⚠️ 系统敏感文件防护启动失败: {e}")

    def _ensure_hosts_backup(self):
        """若尚无 hosts 备份则创建一份可信备份"""
        if os.path.exists(self._hosts_backup):
            return
        try:
            shutil.copyfile(SensitiveFileMonitor.HOSTS_FILE, self._hosts_backup)
        except Exception:
            pass

    def _on_sensitive_event(self, filepath: str, event_type: str):
        """watchdog 线程回调 → 切换到主线程处理，避免 Tk 跨线程问题"""
        try:
            self.root.after(0, lambda: self._handle_sensitive_event(filepath, event_type))
        except Exception:
            pass

    def _handle_sensitive_event(self, filepath: str, event_type: str):
        """主线程处理敏感文件事件"""
        try:
            norm = os.path.normcase(os.path.abspath(filepath))
        except Exception:
            return

        # 清理过期项 + 瞬时不告警集合（用户恢复/我们还原后避免事件回环）
        now = time.time()
        self._sensitive_ignore = {k: v for k, v in self._sensitive_ignore.items()
                                  if v > now}
        if norm in self._sensitive_ignore:
            return
        if not os.path.exists(filepath):
            return
        # 受信任文件不告警
        if self.whitelist.is_trusted(filepath):
            return

        # hosts 文件特殊处理（还原 + 告警）
        if norm == os.path.normcase(os.path.abspath(SensitiveFileMonitor.HOSTS_FILE)):
            self._on_hosts_modified()
            return

        # 敏感目录中出现的新程序 → 隔离 + 弹窗
        self._quarantine_sensitive_file(filepath)

    def _on_hosts_modified(self):
        """hosts 文件被篡改 → 从可信备份还原 + 弹窗"""
        hosts = SensitiveFileMonitor.HOSTS_FILE
        norm = os.path.normcase(os.path.abspath(hosts))
        # 加入瞬时不告警，避免还原写入触发回环
        self._sensitive_ignore[norm] = time.time() + 15

        restored = False
        if os.path.exists(self._hosts_backup):
            try:
                shutil.copyfile(self._hosts_backup, hosts)
                restored = True
            except Exception:
                restored = False

        self._show_hosts_toast(restored)

    def _trust_hosts_current(self):
        """将当前 hosts 内容设为可信备份（信任此次修改）"""
        try:
            shutil.copyfile(SensitiveFileMonitor.HOSTS_FILE, self._hosts_backup)
            self._update_status_bar("📌 已将当前 hosts 内容设为可信")
        except Exception as e:
            self._update_status_bar(f"⚠️ 更新 hosts 备份失败: {e}")

    def _quarantine_sensitive_file(self, filepath: str):
        """敏感目录中出现可疑程序 → 立即隔离 + 弹窗(删除/恢复)"""
        try:
            result = self.scanner.scanner.scan_file(filepath)
        except Exception:
            from engine import ScanResult, ThreatLevel
            result = ScanResult(
                file_path=filepath,
                file_name=os.path.basename(filepath),
                file_size=0, timestamp="",
            )
        result.threat_name = "系统敏感位置出现的程序"
        try:
            result.threat_level = ThreatLevel.SUSPICIOUS
        except Exception:
            pass

        qname = self.quarantine.quarantine_file(result)
        if not qname:
            self._update_status_bar(
                f"⚠️ 系统防护隔离失败: {os.path.basename(filepath)}")
            return

        # 加入瞬时不告警（用户恢复后会重新写入敏感位置）
        norm = os.path.normcase(os.path.abspath(filepath))
        self._sensitive_ignore[norm] = time.time() + 15

        self._refresh_quarantine_list()
        self._update_status_bar(
            f"🚨 系统敏感位置出现可疑程序，已隔离: {os.path.basename(filepath)}")
        self._show_sensitive_toast(result, qname)

    def _show_sensitive_toast(self, result, qname):
        """敏感文件告警弹窗（带「删除 / 恢复」操作）"""
        if not self._toast_manager:
            self._fallback_sensitive(result)
            return

        config = ToastConfig(
            title="🚨 系统敏感位置出现可疑程序！",
            subtitle=f"{result.file_name}",
            details=(
                f"📁 位置: {result.file_path}\n"
                f"🛡️ 该文件出现于受保护系统敏感目录，已被自动隔离。\n"
                f"请选择「恢复」放回原处，或「删除」永久移除。"
            ),
            toast_type=ToastType.DANGER,
            auto_dismiss=60,
            block_label="🗑️ 删除",
            quarantine_label="↩️ 恢复",
            ignore_label="稍后处理",
            on_block=lambda: self._sensitive_delete(qname),
            on_quarantine=lambda: self._sensitive_restore(qname, result.file_path),
            on_ignore=lambda: None,
        )
        try:
            self._toast_manager.show_toast(config)
        except Exception:
            self._fallback_sensitive(result)

    def _show_hosts_toast(self, restored: bool):
        """hosts 篡改告警弹窗"""
        if not self._toast_manager:
            self._fallback_toast(
                "🚨 hosts 文件被篡改！",
                SensitiveFileMonitor.HOSTS_FILE,
                "hosts 控制域名解析，常被恶意软件劫持。",
                "danger",
            )
            return
        detail = (
            "系统 hosts 文件被修改"
            + ("，已自动从可信备份还原。" if restored
               else "（还原失败，可能需要管理员权限）。")
            + "\nhosts 文件控制域名解析，常被恶意软件劫持。"
        )
        config = ToastConfig(
            title="🚨 hosts 文件被篡改！",
            subtitle=SensitiveFileMonitor.HOSTS_FILE,
            details=detail,
            toast_type=ToastType.DANGER,
            auto_dismiss=60,
            block_label="📌 信任此次修改",
            quarantine_label="↩️ 再次还原",
            ignore_label="已知悉",
            on_block=lambda: self._trust_hosts_current(),
            on_quarantine=lambda: self._on_hosts_modified(),
            on_ignore=lambda: None,
        )
        try:
            self._toast_manager.show_toast(config)
        except Exception:
            self._fallback_toast(
                "🚨 hosts 文件被篡改！", SensitiveFileMonitor.HOSTS_FILE,
                detail, "danger")

    def _sensitive_restore(self, qname, original_path):
        """从隔离区恢复被系统防护隔离的文件"""
        norm = os.path.normcase(os.path.abspath(original_path))
        # 恢复后文件回到敏感位置，加入瞬时不告警避免回环
        self._sensitive_ignore[norm] = time.time() + 15
        if self.quarantine.restore_file(qname):
            self._refresh_quarantine_list()
            self._update_status_bar(f"↩️ 已恢复: {os.path.basename(original_path)}")
        else:
            self._update_status_bar(f"⚠️ 恢复失败: {os.path.basename(original_path)}")

    def _sensitive_delete(self, qname):
        """永久删除被系统防护隔离的文件"""
        if self.quarantine.delete_quarantined(qname):
            self._refresh_quarantine_list()
            self._update_status_bar("🗑️ 已永久删除该隔离项")
        else:
            self._update_status_bar("⚠️ 删除失败")

    def _fallback_sensitive(self, result):
        """ToastManager 不可用时的兜底弹窗"""
        self._fallback_toast(
            "🚨 系统敏感位置出现可疑程序！",
            getattr(result, "file_name", ""),
            f"位置: {getattr(result, 'file_path', '')}\n已被自动隔离，请在隔离区处理。",
            "danger",
        )

    # ----------------------------------------------------------
    # 主动防御依赖自修复 + 自测
    # ----------------------------------------------------------
    # ----------------------------------------------------------
    # 依赖安装辅助（统一解决 pythonw.exe 下 pip 路径问题）
    # ----------------------------------------------------------
    @staticmethod
    def _resolve_pip() -> str:
        """正确解析 pip 可执行文件路径。
        兼容 python.exe / pythonw.exe / .venv / 管理运行时等场景。"""
        import sys
        exe = sys.executable
        # 场景1: 标准 python.exe → 同目录的 pip.exe
        base = exe.replace("python.exe", "pip.exe")
        if base != exe and os.path.exists(base):
            return base
        # 场景2: pythonw.exe（双击启动 os.execv 后）→ 同目录的 pip.exe
        base = exe.replace("pythonw.exe", "pip.exe")
        if base != exe and os.path.exists(base):
            return base
        # 场景3: 管理运行时（workbuddy）→ Scripts/pip.exe
        venv_scripts = os.path.join(os.path.dirname(exe), "pip.exe")
        if os.path.exists(venv_scripts):
            return venv_scripts
        # 场景4: 用 python -m pip 作为最后兜底
        return f'"{exe}" -m pip'

    def _ensure_and_start_rtp(self):
        """启动实时防护前，先确保主动防御依赖 (watchdog + psutil) 已就绪。
        若依赖缺失则后台静默安装，安装完成后热重载监控模块并启动防护。"""
        self._ensure_active_defense_deps()
        # 立即尝试启动：若依赖已就绪则正常开启；若仍在安装中则稍后由
        # _rebuild_and_start_rtp 在完成回调里再次启动（start() 自带去重）
        self._auto_start_rtp()

    def _ensure_active_defense_deps(self) -> bool:
        """确保主动防御依赖已安装。
        返回 True 表示依赖已就绪（无需安装）；False 表示已触发后台安装。"""
        import importlib.util as _u
        have_wd = _u.find_spec("watchdog") is not None
        have_ps = _u.find_spec("psutil") is not None
        if have_wd and have_ps:
            return True

        missing = []
        if not have_wd:
            missing.append("watchdog")
        if not have_ps:
            missing.append("psutil")

        def _install():
            import subprocess
            try:
                pip_cmd = self._resolve_pip()
                # _resolve_pip 可能返回 "python -m pip" 形式（含空格/引号），需用 shell=True
                use_shell = " " in pip_cmd or '"' in pip_cmd or "-" in pip_cmd[3:8]
                subprocess.run(
                    f"{pip_cmd} install {' '.join(missing)} -q",
                    shell=use_shell, capture_output=True, timeout=180,
                )
            except Exception:
                pass
            # 无论成功与否，回到主线程重建监控器并启动实时防护
            try:
                self.root.after(0, self._rebuild_and_start_rtp)
            except Exception:
                pass

        threading.Thread(target=_install, daemon=True).start()
        self._update_status_bar(
            f"🔧 正在安装主动防御依赖 ({', '.join(missing)})，稍后自动开启实时防护..."
        )
        return False

    def _rebuild_and_start_rtp(self):
        """依赖安装完成后：热重载监控模块并重建监控器，再启动实时防护"""
        try:
            import importlib
            import monitor as _monitor
            import process_monitor as _pm
            importlib.reload(_pm)
            importlib.reload(_monitor)
            g = globals()
            g["RealTimeMonitor"] = _monitor.RealTimeMonitor
            g["ProcessMonitor"] = _pm.ProcessMonitor
            g["ProcessAlert"] = _pm.ProcessAlert
            g["BehaviorLevel"] = _pm.BehaviorLevel
            g["SensitiveFileMonitor"] = _monitor.SensitiveFileMonitor
            g["WATCHDOG_AVAILABLE"] = _monitor.WATCHDOG_AVAILABLE
            self.realtime_monitor = _monitor.RealTimeMonitor(
                self.scanner.scanner, self.quarantine
            )
            self.realtime_monitor.set_alert_callback(self._on_threat_detected)
            self.realtime_monitor.set_proc_alert_callback(self._on_process_alert)
            # 重置敏感文件监控器引用，使其能在依赖就绪后重新启动
            self.sensitive_monitor = None
        except Exception:
            pass
        self._auto_start_rtp()

    def _self_test_defense(self):
        """主动防御自测 — 合成一条可疑进程告警并立即弹窗（不触发任何真实操作）。
        用于零风险验证「可疑程序 → 右下角实时弹窗」是否正常工作。"""
        try:
            from process_monitor import ProcessAlert, BehaviorLevel
            alert = ProcessAlert(
                pid=os.getpid(),
                name="XSafeSelfTest.exe",
                exe_path=str(Path(__file__).parent / "XSafeSelfTest.exe"),
                cmdline="XSafeSelfTest.exe --active-defense-self-test",
                cwd=str(Path.home()),
                username="(自测)",
                level=BehaviorLevel.SUSPICIOUS,
                reason="主动防御自测：模拟可疑程序启动",
                details=(
                    "这是 X-Safe 主动防御功能自测弹窗。\n"
                    "若你看到此窗口，说明「可疑程序 → 右下角实时弹窗」已正常工作。\n"
                    "此自测不会影响你的电脑，也不会对真实进程执行任何操作。"
                ),
                timestamp=datetime.datetime.now().isoformat(),
            )
            self._on_proc_alert_ui(alert)
            self._update_status_bar("🧪 主动防御自测弹窗已触发（模拟可疑程序）")
        except Exception as e:
            self._update_status_bar(f"⚠️ 自测失败: {e}")

    def _minimize_to_tray(self):
        """最小化到托盘"""
        self._hide_window()
        if self._tray_icon:
            try:
                self._tray_icon.notify("X-Safe安全中心正在后台运行", "已最小化到托盘")
            except Exception:
                pass

    # ==========================================================
    # 一键隔离 + 云查杀
    # ==========================================================
    def _quarantine_all(self):
        """一键隔离所有检测到的威胁"""
        if not self._tree_results:
            messagebox.showinfo("提示", "没有需要隔离的威胁文件")
            return

        # 确认对话框
        count = len(self._tree_results)
        if not messagebox.askyesno(
            "一键隔离",
            f"确定要隔离全部 {count} 个威胁文件吗？\n\n"
            f"隔离后文件将被加密移动到隔离区，可通过隔离区恢复。",
        ):
            return

        # 立即反馈 + 禁用控件
        self._update_status_bar(f"🔒 正在隔离 {count} 个文件...")
        self.root.after(0, self._disable_quarantine_controls)

        # 后台执行批量隔离
        def worker():
            success = 0
            failed = 0
            done_ids = []
            for item_id, result in list(self._tree_results.items()):
                try:
                    if self.quarantine.quarantine_file(result):
                        success += 1
                        done_ids.append(item_id)
                    else:
                        failed += 1
                except Exception:
                    failed += 1
            self._scan_queue.put(("quarantine_done", success, failed, done_ids))

        threading.Thread(target=worker, daemon=True).start()

    def _remove_tree_item(self, item_id: str):
        """从结果树与索引字典中彻底移除一行"""
        result = self._tree_results.pop(item_id, None)
        self._checked.pop(item_id, None)
        self._result_tree.delete(item_id)
        if result is not None and result in self._current_results:
            self._current_results.remove(result)

    def _disable_quarantine_controls(self):
        """隔离进行中: 禁用隔离相关控件, 防止重复点击"""
        try:
            if hasattr(self, "_quarantine_sel_btn"):
                self._quarantine_sel_btn.configure(cursor="watch")
        except Exception:
            pass

    def _enable_quarantine_controls(self):
        """隔离结束后: 恢复隔离控件"""
        try:
            if hasattr(self, "_quarantine_sel_btn"):
                self._quarantine_sel_btn.configure(cursor="hand2")
        except Exception:
            pass

    def _on_quarantine_done(self, success: int, failed: int, done_ids=None):
        """批量隔离完成回调"""
        if done_ids is None:
            done_ids = []
        # 从结果树中移除已成功隔离的行
        for item_id in list(done_ids):
            if item_id in self._tree_results:
                self._remove_tree_item(item_id)

        self._refresh_quarantine_list()
        self.root.after(0, self._enable_quarantine_controls)
        self._update_status_bar(
            f"🔒 隔离完成 — 成功 {success} 个, 失败 {failed} 个"
        )
        if failed > 0:
            messagebox.showwarning(
                "隔离完成",
                f"成功隔离 {success} 个文件\n失败 {failed} 个文件\n\n"
                f"失败原因可能是文件被占用或权限不足。",
            )
        else:
            messagebox.showinfo("隔离完成", f"✅ 成功隔离 {success} 个威胁文件")

    def _cloud_scan_selected(self):
        """对选中的文件进行云查杀"""
        selection = self._result_tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先选择一个文件")
            return

        item = self._result_tree.item(selection[0])
        file_path = item["values"][5]

        if not os.path.exists(file_path):
            messagebox.showerror("错误", "文件不存在")
            return

        self._update_status_bar("☁️ 正在云端查杀...")
        self.root.update_idletasks()

        # 异步云查杀
        def on_cloud_done(result: CloudScanResult):
            self._scan_queue.put(("cloud_done", file_path, result))

        self.cloud_scanner.scan_file_cloud_async(file_path, on_cloud_done)

    def _on_cloud_done(self, file_path: str, result: CloudScanResult):
        """云查杀完成回调"""
        self._current_cloud_results[file_path] = result

        if result.error:
            self._update_status_bar(f"❌ 云查杀失败: {result.error}")
            messagebox.showerror("云查杀失败", result.error)
            return

        if result.cached:
            self._update_status_bar(f"☁️ 云查杀完成 (缓存命中)")
        else:
            self._update_status_bar(
                f"☁️ 云查杀完成 — {result.cloud_name}: {result.detection_ratio}"
            )

        # 显示详细结果
        threat_info = "\n".join(result.threat_names[:10]) if result.threat_names else "无"
        detail_text = (
            f"文件: {os.path.basename(file_path)}\n"
            f"云引擎: {result.cloud_name}\n"
            f"检出比: {result.detection_ratio}\n"
            f"是否恶意: {'是' if result.is_malicious else '否'}\n"
            f"置信度: {result.confidence:.0%}\n"
            f"缓存: {'是' if result.cached else '否'}\n"
            f"{'─'*40}\n"
            f"检出详情:\n{threat_info}"
        )

        self._show_detail_window(f"☁️ 云查杀结果 — {os.path.basename(file_path)}", detail_text)

    # ----------------------------------------------------------
    # 高级查杀 — 三引擎联动结果处理
    # ----------------------------------------------------------
    def _on_cloud_result(self, file_path: str, result: CloudScanResult):
        """云端验证结果返回（所有扫描类型通用）— 云引擎为主判定

        判定策略:
          - 云端确认恶意 → 保留并标红（确认威胁）
          - 云端判定干净 + 本地仅为 SUSPICIOUS(非哈希签名确认) → 判定为误报，移除
          - 本地为 HIGH_RISK/MALICIOUS(规则/哈希) → 即便云端无记录也保留（保守）
        """
        self._current_cloud_results[file_path] = result
        if self._cloud_pending > 0:
            self._cloud_pending -= 1
        self._cloud_completed += 1

        # 定位对应的本地扫描结果
        target = next(
            (r for r in self._current_results if r.file_path == file_path), None
        )

        if not result.error:
            cloud_tag = self._cloud_result_tag(result)

            # 更新结果树: 在「检测方式」列追加云端结论
            for item_id in self._result_tree.get_children():
                values = self._result_tree.item(item_id)["values"]
                if values[5] == file_path:
                    old_method = values[4]
                    new_method = old_method if "☁️" in old_method else f"{old_method} | ☁️{cloud_tag}"
                    new_values = list(values)
                    new_values[4] = new_method
                    self._result_tree.item(item_id, values=tuple(new_values))
                    break

            if result.is_malicious:
                # 云端确认恶意 → 保留并标红
                for item_id in self._result_tree.get_children():
                    values = self._result_tree.item(item_id)["values"]
                    if values[5] == file_path:
                        self._result_tree.item(item_id, tags=("malicious",))
                        break
            else:
                # 云端判定为干净
                if (target is not None
                        and target.threat_level == ThreatLevel.SUSPICIOUS
                        and "哈希签名" not in (target.detection_method or "")):
                    # 本地仅为启发式/扩展名黑名单等可疑标记，云端确认干净 → 误报，剔除
                    self._remove_result_from_tree(file_path)
                    self._current_results.remove(target)
                    stats = self.scanner.stats
                    stats.threats_found = max(0, stats.threats_found - 1)
                    stats.suspicious_found = max(0, stats.suspicious_found - 1)
                    self._update_stats_display(stats)
                    self._result_count_label.configure(
                        text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
                    )
                    self._update_status_bar(
                        f"☁️ 云端确认 {os.path.basename(file_path)} 为干净文件 — 已排除误报"
                    )

        # 云端全部返回且本地扫描已结束 → 收尾
        if self._cloud_pending <= 0 and not self._scanning:
            if self._is_advanced_scan:
                self._finish_advanced_scan()
            else:
                self._finalize_scan()
        elif self._cloud_pending > 0:
            # 进度标签显示云端验证进度（所有扫描类型）
            self._progress_label.configure(
                text=f"☁️ 云端验证中... 剩余 {self._cloud_pending} 个文件"
            )

    def _remove_result_from_tree(self, file_path: str):
        """从结果树中移除指定文件行"""
        for item_id in self._result_tree.get_children():
            values = self._result_tree.item(item_id)["values"]
            if len(values) > 5 and values[5] == file_path:
                self._remove_tree_item(item_id)
                break

    def _on_cloud_standalone_done(self, file_path: str, result: CloudScanResult):
        """独立云查杀完成"""
        self._scanning = False
        self._current_cloud_results[file_path] = result

        # 恢复按钮
        self._quick_scan_btn.configure(state=tk.NORMAL)
        self._cloud_scan_btn.configure(state=tk.NORMAL)
        self._advanced_scan_btn.configure(state=tk.NORMAL)
        self._custom_scan_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._progress_bar.stop()
        self._progress_bar.configure(mode="determinate")
        self._progress_var.set(100)

        if result.error:
            self._update_status_bar(f"❌ 云查杀失败: {result.error}")
            self._progress_label.configure(text="云查杀失败")
            messagebox.showerror("云查杀失败", result.error)
            return

        cloud_tag = self._cloud_result_tag(result)
        cache_tag = " (缓存命中)" if result.cached else ""
        self._update_status_bar(
            f"☁️ 云查杀完成{cache_tag} — {result.cloud_name}: {result.detection_ratio}"
        )
        self._progress_label.configure(
            text=f"☁️ 云引擎结果: {cloud_tag} | 检出比 {result.detection_ratio}"
        )

        # 显示详细结果
        threat_info = "\n".join(result.threat_names[:15]) if result.threat_names else "无检出"
        detail_text = (
            f"文件: {os.path.basename(file_path)}\n"
            f"完整路径: {file_path}\n"
            f"文件大小: {self._format_size(os.path.getsize(file_path))}\n"
            f"{'─'*40}\n"
            f"云引擎: {result.cloud_name}\n"
            f"检出比: {result.detection_ratio}\n"
            f"是否恶意: {'⛔ 是' if result.is_malicious else '✅ 否'}\n"
            f"置信度: {result.confidence:.0%}\n"
            f"缓存: {'是' if result.cached else '否'}\n"
            f"{'─'*40}\n"
            f"检出详情:\n{threat_info}"
        )

        self._show_detail_window(f"☁️ 云查杀结果 — {os.path.basename(file_path)}", detail_text)

    def _on_advanced_scan_complete(self, results: list[ScanResult]):
        """高级查杀 — 本地扫描线程完成"""
        self._scanning = False  # 本地扫描完成

        # 用户已取消 — 直接收尾显示「已取消」（不再等待云端验证）
        if self._scan_cancelled:
            self._finish_advanced_scan(cancelled=True)
            return

        # 检查是否还有云端查询在进行
        if self._cloud_pending > 0:
            self._progress_label.configure(
                text=f"本地扫描完成！等待云端验证... 剩余 {self._cloud_pending} 个文件"
            )
            self._update_status_bar(
                f"🔄 本地扫描完成，云端验证中... ({self._cloud_pending} 个待验证)"
            )
            # 不恢复按钮，等待云端全部返回
            return

        # 没有云端查询 → 直接完成
        self._finish_advanced_scan()

    def _finish_advanced_scan(self, cancelled: bool = False):
        """高级查杀全部完成（本地+云端）"""
        stats = self.scanner.stats
        self._is_advanced_scan = False

        # 恢复按钮
        self._quick_scan_btn.configure(state=tk.NORMAL)
        self._cloud_scan_btn.configure(state=tk.NORMAL)
        self._advanced_scan_btn.configure(state=tk.NORMAL)
        self._custom_scan_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._progress_bar.configure(mode="determinate")  # 确保连续模式

        # 统计
        self._update_stats_display(stats)

        cloud_verified = len(self._current_cloud_results)

        # 用户手动取消 — 显示「已取消」而非「完成」
        if cancelled:
            if stats.total_files > 0:
                pct = min(100.0, (stats.scanned_files / stats.total_files) * 100)
                self._progress_var.set(pct)
            self._update_status_bar("⏹ 高级查杀已取消")
            self._progress_label.configure(
                text=f"⏹ 高级查杀已手动停止 — 已扫描 {stats.scanned_files} 个文件"
            )
            self._result_count_label.configure(
                text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
                f" | ☁️ 云验证: {cloud_verified} 个"
            )
            return

        self._progress_var.set(100)

        if stats.threats_found > 0:
            self._update_status_bar(
                f"🔥 高级查杀完成 — "
                f"发现 {stats.threats_found} 个威胁 | "
                f"云端验证 {cloud_verified} 个文件 | "
                f"三引擎联动判定完毕"
            )
            self._progress_label.configure(
                text=f"🔥 三引擎联动完成！发现 {stats.threats_found} 个威胁，"
                     f"已通过云端验证 {cloud_verified} 个文件"
            )
        else:
            self._update_status_bar(
                f"✅ 高级查杀完成 — 共扫描 {stats.scanned_files} 个文件，"
                f"三引擎均未发现威胁"
            )
            self._progress_label.configure(
                text=f"✅ 系统安全！三引擎联动扫描 {stats.scanned_files} 个文件，未发现威胁"
            )

        self._result_count_label.configure(
            text=f"检测结果: {stats.threats_found} 个威胁, {stats.suspicious_found} 个可疑"
            f" | ☁️ 云验证: {cloud_verified} 个"
        )

        self._switch_tab("results")

        # —— 三引擎联动收尾：本地+云完成后，对所有威胁/可疑文件再跑一次 AI 评分 ——
        # scan_directory/quick_scan/full_scan 走的是透传路径，AI 没真正参与；
        # 这里补齐"AI 判定"环节（每个文件走 AIScanner.scan_file，单文件开销可接受）
        if not cancelled:
            try:
                threading.Thread(
                    target=self._ai_rescore_threats_async,
                    args=(results,),
                    daemon=True,
                ).start()
            except Exception:
                pass

    @staticmethod
    def _cloud_result_tag(result: CloudScanResult) -> str:
        """生成云端结果的简短标签"""
        if result.is_malicious:
            return f"云端确认为恶意 ({result.detection_ratio})"
        elif result.detections > 0:
            return f"云端低检出 ({result.detection_ratio})"
        else:
            return "云端未检出"

    def _ai_rescore_threats_async(self, results: list[ScanResult]):
        """三引擎联动收尾：异步对所有 threat/suspicious 文件单独跑 AI 评分。
        AIScanner.scan_file 内部会做特征提取 + 贝叶斯评分 + 自动学习，
        把结果存到 self._current_ai_scores / self._current_features，UI 在收到
        ("ai_score_ready",) 队列消息后刷新对应行。"""
        try:
            # 只重评威胁和可疑文件，跳过安全文件（开销节省 99%）
            targets = [r for r in results
                       if r.threat_level.value in ("malicious", "high_risk", "suspicious")]
            if not targets:
                return
            for r in targets:
                if not os.path.exists(r.file_path):
                    continue
                try:
                    ai_result, ai_score, features = self.scanner.scan_file(r.file_path)
                    self._current_ai_scores[r.file_path] = ai_score
                    self._current_features[r.file_path] = features
                    # 让主线程刷新该行
                    self._scan_queue.put(("ai_score_ready", r.file_path))
                except Exception:
                    continue
        except Exception:
            pass

    # ==========================================================
    # 窗口关闭
    # ==========================================================
    def _on_close(self):
        """点击窗口关闭按钮：托盘运行时最小化到托盘（保留实时防护与窗口状态），
        否则真正退出应用。"""
        if self._tray_icon is not None:
            self._hide_window()
            return
        self._destroy_app()

    def _destroy_app(self):
        """真正退出应用：停止扫描/实时防护/托盘，销毁窗口。"""
        if self._scanning:
            self.scanner.cancel_scan()

        if self.realtime_monitor.running:
            try:
                self.realtime_monitor.stop()
            except Exception:
                pass

        # 停止 UI 轮询与进度心跳
        if self._scan_queue_job is not None:
            try:
                self.root.after_cancel(self._scan_queue_job)
            except Exception:
                pass
        self._stop_progress_ticker()

        # 停止系统托盘
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass

        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        """启动应用"""
        self.root.mainloop()

    def _switch_theme(self):
        """切换浅色/深色主题（保存后重启自身，干净换肤）"""
        if self._scanning:
            messagebox.showinfo("请稍候", "扫描进行中，请扫描完成后再切换主题。")
            return
        new_theme = "dark" if self._theme == "light" else "light"
        _save_theme(new_theme)
        try:
            if self._tray_icon:
                self._tray_icon.stop()
        except Exception:
            pass
        self.root.destroy()
        try:
            if getattr(sys, "frozen", False):
                # 打包后：直接重启自身 exe
                os.execv(sys.executable, [sys.executable] + sys.argv[1:])
            else:
                # 源码运行：用 pythonw 重启，避免 200+ 控件逐体重绘的闪烁
                pythonw = sys.executable.replace("python.exe", "pythonw.exe")
                if not os.path.exists(pythonw):
                    pythonw = sys.executable
                os.execv(pythonw, [pythonw, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception:
            os._exit(0)

    # ----------------------------------------------------------
    # 关于 / 程序介绍
    # ----------------------------------------------------------
    def _show_about_dialog(self):
        """弹出关于 X-Safe安全中心 对话框，显示程序介绍、版本、制作/出品/鸣谢。"""
        try:
            dlg = tk.Toplevel(self.root)
            dlg.title(f"关于 {APP_NAME}")
            dlg.configure(bg=COLORS["bg_secondary"])
            dlg.resizable(False, False)
            dlg.transient(self.root)
            dlg.grab_set()

            w, h = 600, 860
            dlg.geometry(f"{w}x{h}")
            try:
                dlg.update_idletasks()
                px = self.root.winfo_rootx() + (self.root.winfo_width() - w) // 2
                py = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 2
                dlg.geometry(f"+{max(px,0)}+{max(py,0)}")
            except Exception:
                pass

            # ---------- 顶部品牌头 ----------
            header = tk.Frame(dlg, bg=COLORS["bg_secondary"])
            header.pack(fill=tk.X, padx=24, pady=(22, 8))
            tk.Label(header, text="🛡", font=("Segoe UI", 40),
                     bg=COLORS["bg_secondary"], fg=COLORS["accent"]
                     ).pack(side=tk.LEFT, padx=(0, 16))
            info = tk.Frame(header, bg=COLORS["bg_secondary"])
            info.pack(side=tk.LEFT)
            tk.Label(info, text=APP_NAME, font=("Microsoft YaHei UI", 22, "bold"),
                     bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]
                     ).pack(anchor="w")
            tk.Label(info, text=APP_FULL_NAME, font=("Microsoft YaHei UI", 10),
                     bg=COLORS["bg_secondary"], fg=COLORS["text_secondary"]
                     ).pack(anchor="w")
            tk.Label(info, text=f"v{APP_VERSION}  ·  build {APP_BUILD}  ·  {APP_RELEASE_DATE}",
                     font=("Microsoft YaHei UI", 8),
                     bg=COLORS["bg_secondary"], fg=COLORS["text_muted"]
                     ).pack(anchor="w", pady=(2, 0))

            # 分隔线
            tk.Frame(dlg, bg=COLORS["border"], height=1).pack(fill=tk.X, padx=24, pady=(8, 4))

            # ---------- 制作 / 出品 / 鸣谢 ----------
            credit = tk.Frame(dlg, bg=COLORS["bg_secondary"])
            credit.pack(fill=tk.X, padx=24, pady=(4, 6))

            def _credit_row(parent, label, value):
                row = tk.Frame(parent, bg=COLORS["bg_secondary"])
                row.pack(fill=tk.X, pady=1)
                tk.Label(row, text=label, width=8, anchor="w",
                         font=("Microsoft YaHei UI", 9, "bold"),
                         bg=COLORS["bg_secondary"], fg=COLORS["accent"]
                         ).pack(side=tk.LEFT)
                tk.Label(row, text=value, anchor="w",
                         font=("Microsoft YaHei UI", 9),
                         bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]
                         ).pack(side=tk.LEFT, fill=tk.X, expand=True)

            _credit_row(credit, "制  作", APP_PRODUCER)
            _credit_row(credit, "出  品", APP_STUDIO)

            # 鸣谢行
            thanks_row = tk.Frame(credit, bg=COLORS["bg_secondary"])
            thanks_row.pack(fill=tk.X, pady=1)
            tk.Label(thanks_row, text="鸣  谢", width=8, anchor="w",
                     font=("Microsoft YaHei UI", 9, "bold"),
                     bg=COLORS["bg_secondary"], fg=COLORS["accent"]
                     ).pack(side=tk.LEFT)
            thanks_text = "、".join(
                [name + (f"（{role}）" if role else "")
                 for name, role in APP_THANKS]
            ) + "  鼎力支持"
            tk.Label(thanks_row, text=thanks_text, anchor="w", justify=tk.LEFT,
                     font=("Microsoft YaHei UI", 9),
                     bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]
                     ).pack(side=tk.LEFT, fill=tk.X, expand=True)

            # 分隔线
            tk.Frame(dlg, bg=COLORS["border"], height=1).pack(fill=tk.X, padx=24, pady=(6, 4))

            # ---------- 程序介绍（滚动文本） ----------
            # 标点规范：全程使用全角中文标点（，。：；！？「」【】（）／＋——），
            # 技术名词、路径、代码片段保留半角字符，避免视觉割裂。
            intro_text = (
                "X-Safe安全中心是一款面向个人用户与中小团队的轻量化主动防御型安全软件，"
                "由竹影清风独立设计与开发，新启年工作室联合出品。它以「先隔离、再处置」"
                "为核心思路，把传统特征查杀、本地 AI 行为评分、云端联动与系统敏感点"
                "监控整合在同一个简洁的中文控制台中，让普通用户也能拥有接近企业级 EDR"
                "的可见性与响应能力。\n\n"

                "【v1.0 全新升级】\n"
                "· 实时防护独立板块：总开关＋弹窗模式＋六项子能力（注册表 HOOK、引导区、"
                "进程行为、文件监控、卷影副本、自检）独立可调。\n"
                "· 时钟轮询触发器：扫描结果区每 1 秒自动巡检，发现新增威胁立刻弹出"
                "右下角隔离弹窗，不依赖任何回调链。\n"
                "· 批处理摘要弹窗：狂涌场景（≥3 个威胁 / 1.8 秒）自动合并为「批量"
                "检测到 N 个威胁」摘要，避免一秒钟弹几十个窗把界面打爆。\n"
                "· 静默模式：用户主动选择「静默处理中」时，全部弹窗关闭，仅在状态栏"
                "和实时日志区留下处理痕迹，避免游戏 / 演示时被打扰。\n"
                "· 自保护白名单：程序自身的可执行文件与 _internal 运行时目录默认进入"
                "白名单，杜绝「自己杀自己」导致的 PyInstaller 依赖被误删。\n"
                "· 浅、深双主题自适应：分辨率自动识别，工具栏与列表区按 DPI 弹性伸缩，"
                "深色、浅色两套配色通过 os.execv 换肤，全程无控件闪烁。\n\n"

                "【产品定位】\n"
                "· 不与商业杀软正面竞争，而是补齐它们在「行为可见性」与「快速应急」"
                "上的短板。\n"
                "· 面向开发者、运维、安全爱好者，以及希望多一层兜底防护的普通用户。\n"
                "· 完全本地运行，不收集隐私、不上传个人文件，AI 训练样本可由用户"
                "自主反馈。\n\n"

                "【三引擎联动】\n"
                "· 特征引擎：哈希黑名单、模式规则、YARA 风格字符串匹配，"
                "覆盖已知恶意样本与常见 WebShell、远控、挖矿、勒索家族。\n"
                "· AI 引擎：本地熵值、节区特征、API 调用序列综合评分，"
                "结合用户反馈持续学习，越用越准；可解释的置信度而非黑盒判定。\n"
                "· 云引擎：可疑样本哈希上报云端，返回群体判定与最新威胁标签，"
                "本地保留缓存避免重复查询。\n"
                "· 统一 ConfidenceScore：三引擎结果按权重融合，给出最终风险等级。\n\n"

                "【主动防御】\n"
                "· 注册表 HOOK 监控：Run、IFEO、Winlogon Shell、AppInit_DLLs、"
                "Userinit 等关键项，变化即告警。\n"
                "· 引导区保护：MBR、VBR 哈希快照，发现篡改立即告警并提供溯源。\n"
                "· 进程行为：异常父子进程、DLL 注入、批量加密写文件等高危动作，"
                "实时拦截并提示用户处置。\n"
                "· 系统敏感文件：hosts、计划任务、启动项、卷影副本、SAM 等关键"
                "路径的写入监控。\n\n"

                "【自检与恢复】\n"
                "· 自检程序：隔离区完整性、三引擎联动自测、引导区与注册表基线"
                "巡检，一键确认防护体系健康度。\n"
                "· 勒索恢复：WannaCry、EternalBlue 痕迹检测、卷影副本恢复，"
                "对常见家族提供针对性解密线索。\n"
                "· 隔离区：所有处置后的样本落入可恢复的隔离沙箱，误杀可一键还原。\n\n"

                "【设计哲学】\n"
                "· 干净的中文控制台 UI：直角卡片、扁平导航、零弹窗干扰，信息密度"
                "与可读性兼顾。\n"
                "· 不在自己杀自己：X-Safe安全中心 自身可执行文件与 _internal 运行时目录"
                "默认进入自保护白名单，避免 PyInstaller 依赖被误报。\n"
                "· 运行时数据落到 %APPDATA%\\XSafe\\，避免装到只读目录触发 SQLite"
                "「database is locked」错误。\n"
                "· 浅、深双主题：通过 os.execv 重启进程换肤，无逐控件重绘闪烁。\n\n"

                "【开源与协作】\n"
                "本项目由竹影清风主导开发，新启年工作室提供测试、文档与发布支持。"
                "欢迎通过反馈通道提交误报、漏报样本，帮助 AI 引擎持续进化。\n\n"

                "感谢所有为 X-Safe安全中心 提供过建议、测试、翻译与传播的朋友们。"
                "正因为有你们，这个项目才能持续向前。"
            )
            text_frame = tk.Frame(dlg, bg=COLORS["bg_secondary"])
            text_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 6))
            txt = scrolledtext.ScrolledText(
                text_frame, wrap=tk.WORD, height=22,
                font=("Microsoft YaHei UI", 9),
                bg=COLORS["bg_main"], fg=COLORS["text_primary"],
                relief=tk.FLAT, borderwidth=0,
                padx=14, pady=12,
            )
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert("1.0", intro_text)
            txt.configure(state="disabled")

            # ---------- 底部版权 + 关闭按钮 ----------
            footer = tk.Frame(dlg, bg=COLORS["bg_secondary"])
            footer.pack(fill=tk.X, padx=24, pady=(0, 18))
            tk.Label(footer,
                     text=f"{APP_COPYRIGHT}  ·  {APP_STUDIO_SHORT}",
                     font=("Microsoft YaHei UI", 8),
                     bg=COLORS["bg_secondary"], fg=COLORS["text_muted"]
                     ).pack(side=tk.LEFT)

            close_btn = tk.Label(
                footer, text="  关闭  ",
                font=("Microsoft YaHei UI", 9, "bold"),
                bg=COLORS["accent"], fg="#ffffff",
                padx=14, pady=6, cursor="hand2",
            )
            close_btn.pack(side=tk.RIGHT)
            close_btn.bind("<Button-1>", lambda e: dlg.destroy())
            close_btn.bind("<Enter>", lambda e: close_btn.configure(bg=COLORS.get("accent_hover", COLORS["accent"])))
            close_btn.bind("<Leave>", lambda e: close_btn.configure(bg=COLORS["accent"]))

            dlg.bind("<Escape>", lambda e: dlg.destroy())
        except Exception as ex:
            try:
                messagebox.showerror("关于", f"无法显示关于窗口: {ex}")
            except Exception:
                pass


# ============================================================
# 入口
# ============================================================
if __name__ == "__main__":
    # 若以 python.exe（带黑框控制台）运行，则改用 pythonw 重启自身，避免黑色控制台窗口
    if sys.executable.lower().endswith("python.exe"):
        pythonw = sys.executable[:-10] + "pythonw.exe"
        if os.path.exists(pythonw):
            os.execv(pythonw, [pythonw, os.path.abspath(__file__)] + sys.argv[1:])

    # 应用已保存的主题（默认浅色），确保下方 ttk 样式使用正确配色
    _apply_theme(_load_theme())

    # 配置 ttk 样式
    style = ttk.Style()
    style.theme_use("clam")

    # 圆角胶囊进度条改用 RoundedProgress（Canvas 自绘），此处样式保留以兼容旧引用
    style.configure(
        "Custom.Horizontal.TProgressbar",
        background=COLORS["progress_fill"],
        troughcolor=COLORS["progress_bg"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["progress_fill"],
        darkcolor=COLORS["progress_fill"],
        thickness=16,
    )

    style.configure(
        "Treeview",
        background=COLORS["bg_card"],
        foreground=COLORS["text_primary"],
        fieldbackground=COLORS["bg_card"],
        borderwidth=0,
        rowheight=32,
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["bg_secondary"],
        foreground=COLORS["text_secondary"],
        borderwidth=0,
        relief="flat",
        font=("Microsoft YaHei UI", 10, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["bg_hover"])],
        foreground=[("selected", COLORS["accent_blue"])],
    )

    # 启动
    app = AntivirusApp()
    app.run()
