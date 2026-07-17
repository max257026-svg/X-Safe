"""
X-Safe — 杀毒软件主程序
防御恶意软件，保护系统安全
"""

import sys
import os
import json
import queue
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import (
    AntivirusScanner, SignatureDB, QuarantineManager,
    ScanResult, ScanStats, ThreatLevel, ScanCancelled,
)
from monitor import RealTimeMonitor
from ai_engine import AIScanner, AIScorer, LearningDatabase, FeedbackType, ConfidenceScore
from cloud_engine import CloudScanner, CloudScanResult
from toast_notification import ThreatToast, ToastManager, ToastConfig, ToastType
from process_monitor import ProcessAlert, BehaviorLevel

# ============================================================
# 配色方案 — 浅色 / 深色双主题
# ============================================================
THEMES = {
    # 浅色主题（GitHub Light 风格，高对比、护眼）
    "light": {
        "bg_main": "#f6f8fa",
        "bg_secondary": "#ffffff",
        "bg_card": "#ffffff",
        "bg_input": "#ffffff",
        "bg_hover": "#eaeef2",
        "border": "#d0d7de",
        "text_primary": "#1f2328",
        "text_secondary": "#57606a",
        "text_muted": "#8c959f",
        "accent_blue": "#0969da",
        "accent_green": "#1a7f37",
        "accent_red": "#cf222e",
        "accent_orange": "#9a6700",
        "accent_purple": "#8250df",
        "accent_cyan": "#0a7ea4",
        "danger_bg": "#cf222e10",
        "warning_bg": "#9a670010",
        "safe_bg": "#1a7f3710",
        "progress_bg": "#eaeef2",
        "progress_fill": "#1a7f37",
        "scanning_glow": "#0969da",
    },
    # 深色主题（原配色）
    "dark": {
        "bg_main": "#0d1117",
        "bg_secondary": "#161b22",
        "bg_card": "#21262d",
        "bg_input": "#0d1117",
        "bg_hover": "#30363d",
        "border": "#30363d",
        "text_primary": "#e6edf3",
        "text_secondary": "#8b949e",
        "text_muted": "#5c6670",
        "accent_blue": "#58a6ff",
        "accent_green": "#3fb950",
        "accent_red": "#f85149",
        "accent_orange": "#d29922",
        "accent_purple": "#a371f7",
        "accent_cyan": "#39d2c0",
        "danger_bg": "#da363310",
        "warning_bg": "#bb800910",
        "safe_bg": "#23863610",
        "progress_bg": "#21262d",
        "progress_fill": "#3fb950",
        "scanning_glow": "#58a6ff",
    },
}
# 运行期实际使用的配色（会被 _apply_theme 覆盖）
COLORS = dict(THEMES["light"])


def _theme_config_path() -> Path:
    return Path(__file__).parent / "theme_config.json"


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
    """在 Canvas 上绘制圆角矩形（填充）"""
    r = min(float(r), (x2 - x1) / 2.0, (y2 - y1) / 2.0)
    if r < 1:
        r = 1
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
        self._radius = radius
        self._shadow = shadow
        self._canvas = tk.Canvas(self, bg=master.cget("bg"), highlightthickness=0, bd=0)
        self._canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.content = tk.Frame(self, bg=bg, bd=0, highlightthickness=0)
        self.content.pack(fill=tk.BOTH, expand=True, padx=radius, pady=radius)
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def _redraw(self):
        self._canvas.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        r = self._radius
        if self._shadow:
            _round_rect(self._canvas, 3, 5, w - 1, h - 1, r, _shadow_color())
        _round_rect(self._canvas, 0.5, 0.5, w - 0.5, h - 0.5, r, self._border)
        _round_rect(self._canvas, 1.5, 1.5, w - 1.5, h - 1.5, r, self._card_bg)


class RoundedButton(tk.Canvas):
    """圆角胶囊按钮（支持 state 禁用、悬停提亮、点击回调）。"""

    def __init__(self, master, text, command, color, radius=12, fg="#ffffff",
                 font=("Microsoft YaHei UI", 10, "bold"), height=42, width=None, **kw):
        super().__init__(master, bg=master.cget("bg"), highlightthickness=0, bd=0,
                         height=height, width=width, cursor="hand2", takefocus=0, **kw)
        self._text = text
        self._command = command
        self._color = color
        self._fg = fg
        self._font = font
        self._radius = radius
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
        self._radius = radius
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
    """圆角分段标签（支持 set_active 切换选中态）。"""

    def __init__(self, master, text, command, radius=10,
                 font=("Microsoft YaHei UI", 10, "bold"), height=32, **kw):
        super().__init__(master, bg=master.cget("bg"), highlightthickness=0, bd=0,
                         height=height, cursor="hand2", takefocus=0, **kw)
        self._text = text
        self._command = command
        self._radius = radius
        self._font = font
        self._active = False
        est = 0
        for ch in text:
            est += 14 if ord(ch) > 0x2E80 else 8
        self.config(width=est + 36)
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", lambda e: self._command())

    def set_active(self, active: bool):
        self._active = active
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        if self._active:
            _round_rect(self, 0.5, 0.5, w - 0.5, h - 0.5, self._radius, COLORS["border"])
            _round_rect(self, 1.5, 1.5, w - 1.5, h - 1.5, self._radius, COLORS["bg_card"])
            fg = COLORS["accent_blue"]
        else:
            _round_rect(self, 1, 1, w - 1, h - 1, self._radius, COLORS["bg_secondary"])
            fg = COLORS["text_secondary"]
        self.create_text(w / 2, h / 2, text=self._text, fill=fg,
                         font=self._font, anchor="center")


# ============================================================
# 主应用程序
# ============================================================
class AntivirusApp:
    """杀毒软件 GUI 主程序"""

    def __init__(self):
        # 应用已保存的主题（默认浅色）
        self._theme = _load_theme()
        _apply_theme(self._theme)

        # 扫描状态提前初始化，避免未扫描时点击主题按钮等场景访问到未定义属性
        self._scanning = False
        self._scan_cancelled = False
        self._progress_ticker_job = None
        self._scan_queue_job = None

        self.root = tk.Tk()
        self.root.title("🛡️ X-Safe — 智能杀毒软件")
        self.root.geometry("1050x780")
        self.root.minsize(900, 650)
        self.root.configure(bg=COLORS["bg_main"])

        # 设置图标（如果有的话）
        self._set_app_icon()

        # 初始化引擎（失败时在窗口内显示错误，不留下空白窗口）
        sig_path = Path(__file__).parent / "signatures.json"
        quarantine_dir = Path(__file__).parent / "quarantine"

        try:
            self.sig_db = SignatureDB(str(sig_path))
        except Exception as e:
            self._show_fatal_init_error(f"签名库加载失败: {e}")
            return

        try:
            self.scanner = AIScanner(AntivirusScanner(self.sig_db))
        except Exception as e:
            self._show_fatal_init_error(f"引擎初始化失败: {e}")
            return

        self.quarantine = QuarantineManager(str(quarantine_dir))
        self.ai_learning_db = self.scanner.db

        # 云查杀引擎
        try:
            self.cloud_scanner = CloudScanner()
        except Exception:
            self.cloud_scanner = None

        # 实时监控
        try:
            self.realtime_monitor = RealTimeMonitor(self.scanner.scanner, self.quarantine)
            self.realtime_monitor.set_alert_callback(self._on_threat_detected)
            self.realtime_monitor.set_proc_alert_callback(self._on_process_alert)
        except Exception:
            self.realtime_monitor = type('obj', (object,), {'running': False, 'available': False})()

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

        # 高级查杀 — 三引擎联动追踪
        self._is_advanced_scan: bool = False
        self._cloud_pending: int = 0
        self._cloud_completed: int = 0

        # 系统托盘
        self._tray_icon = None
        self._tray_thread = None

        # 构建 UI（核心步骤，失败则显示错误）
        try:
            self._build_ui()
        except Exception as e:
            self._show_fatal_init_error(f"界面构建失败: {e}")
            return

        # 初始化系统托盘（缺失依赖时静默处理）
        self._init_system_tray()

        # 自动开启实时防护（静默启动，先确保依赖就绪）
        self.root.after(500, self._ensure_and_start_rtp)

        # 启动主线程 UI 轮询 (处理跨线程事件)
        self._process_scan_queue()

        # 加载初始状态
        self._refresh_quarantine_list()
        self._update_status_bar("就绪 — 等待扫描指令")

        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_fatal_init_error(self, msg: str):
        """初始化严重失败时在窗口内显示错误，避免留下空白 'tk' 窗口"""
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
        title_bar = tk.Frame(self.root, bg=COLORS["bg_secondary"], height=56)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        # 标题栏底部柔和分隔线
        sep = tk.Frame(self.root, bg=COLORS["border"], height=1)
        sep.pack(fill=tk.X, side=tk.TOP)

        title_frame = tk.Frame(title_bar, bg=COLORS["bg_secondary"])
        title_frame.pack(side=tk.LEFT, padx=20, pady=12)

        shield_label = tk.Label(
            title_frame, text="🛡️", font=("Segoe UI", 22),
            bg=COLORS["bg_secondary"], fg=COLORS["accent_blue"],
        )
        shield_label.pack(side=tk.LEFT)

        title_label = tk.Label(
            title_frame, text=" X-Safe", font=("Microsoft YaHei UI", 18, "bold"),
            bg=COLORS["bg_secondary"], fg=COLORS["text_primary"],
        )
        title_label.pack(side=tk.LEFT, padx=(4, 12))

        subtitle_label = tk.Label(
            title_frame, text="智能杀毒软件", font=("Microsoft YaHei UI", 11),
            bg=COLORS["bg_secondary"], fg=COLORS["text_secondary"],
        )
        subtitle_label.pack(side=tk.LEFT)

        # 右侧：实时防护状态
        status_frame = tk.Frame(title_bar, bg=COLORS["bg_secondary"])
        status_frame.pack(side=tk.RIGHT, padx=20, pady=12)

        # 主题切换按钮（浅色 / 深色）— 圆角胶囊
        self._theme_btn = RoundedButton(
            status_frame,
            text="🌙" if self._theme == "light" else "☀️",
            command=self._switch_theme,
            color=COLORS["bg_hover"], fg=COLORS["text_primary"],
            radius=12, height=32, width=42, font=("Segoe UI", 13),
        )
        self._theme_btn.pack(side=tk.LEFT, padx=(10, 4))

        self._rtp_indicator = tk.Canvas(
            status_frame, width=10, height=10,
            bg=COLORS["bg_secondary"], highlightthickness=0,
        )
        self._rtp_indicator.pack(side=tk.LEFT, padx=(0, 6))
        self._draw_rtp_indicator(False)

        self._rtp_label = tk.Label(
            status_frame, text="实时防护: 已关闭",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_secondary"], fg=COLORS["text_secondary"],
        )
        self._rtp_label.pack(side=tk.LEFT)

        # --- 主内容区域 ---
        main_content = tk.Frame(self.root, bg=COLORS["bg_main"])
        main_content.pack(fill=tk.BOTH, expand=True, padx=16, pady=(12, 8))

        # 左侧面板 — 扫描控制 + 统计
        left_panel = tk.Frame(main_content, bg=COLORS["bg_main"], width=340)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        left_panel.pack_propagate(False)

        self._build_scan_panel(left_panel)
        self._build_stats_panel(left_panel)

        # 右侧面板 — 结果 + 隔离区
        right_panel = tk.Frame(main_content, bg=COLORS["bg_main"])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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

        # 进度信息
        self._progress_label = tk.Label(
            card, text="",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
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

    def _build_notebook(self, parent):
        """标签页面板（圆角分段式）"""
        self._tabs = {}
        self._tab_buttons = {}
        self._tab_frames = {}
        self._active_tab = tk.StringVar(value="results")

        # 圆角分段轨道
        self._tab_bar = RoundedCard(parent, bg=COLORS["bg_secondary"],
                                    border=COLORS["border"], radius=14, shadow=False)
        self._tab_bar.pack(fill=tk.X, pady=(0, 14))

        tabs_config = [
            ("results", "📋 扫描结果"),
            ("quarantine", "🔒 隔离区"),
            ("signatures", "🛡️ 特征库"),
        ]
        for tab_id, tab_text in tabs_config:
            pill = TabPill(self._tab_bar.content, text=tab_text,
                           command=lambda tid=tab_id: self._switch_tab(tid),
                           height=32, radius=10)
            pill.pack(side=tk.LEFT, padx=4, pady=4)
            self._tab_buttons[tab_id] = pill

        # 标签内容区
        self._tab_content = tk.Frame(parent, bg=COLORS["bg_main"])
        self._tab_content.pack(fill=tk.BOTH, expand=True)

        # 结果页
        self._tab_frames["results"] = self._build_results_tab()
        # 隔离区页
        self._tab_frames["quarantine"] = self._build_quarantine_tab()
        # 特征库页
        self._tab_frames["signatures"] = self._build_signatures_tab()

        self._switch_tab("results")

    def _build_results_tab(self) -> tk.Frame:
        """扫描结果标签页"""
        frame = tk.Frame(self._tab_content, bg=COLORS["bg_main"])

        panel = RoundedCard(frame, bg=COLORS["bg_card"], border=COLORS["border"],
                            radius=14, shadow=True)
        panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 工具栏
        toolbar = tk.Frame(panel.content, bg=COLORS["bg_card"])
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 6))

        self._result_count_label = tk.Label(
            toolbar, text="检测结果: 0 个威胁",
            font=("Microsoft YaHei UI", 10),
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
        )
        self._result_count_label.pack(side=tk.LEFT)

        # 隔离选中按钮
        quarantine_sel_btn = tk.Label(
            toolbar, text="🔒 隔离选中",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_red"],
            padx=12, cursor="hand2",
        )
        quarantine_sel_btn.pack(side=tk.RIGHT, padx=4)
        quarantine_sel_btn.bind("<Button-1>", lambda e: self._quarantine_selected())
        self._quarantine_sel_btn = quarantine_sel_btn

        # 全选按钮
        select_all_btn = tk.Label(
            toolbar, text="☑️ 全选/取消",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            padx=12, cursor="hand2",
        )
        select_all_btn.pack(side=tk.RIGHT, padx=4)
        select_all_btn.bind("<Button-1>", lambda e: self._select_all_results())

        export_btn = tk.Label(
            toolbar, text="💾 导出报告",
            font=("Microsoft YaHei UI", 9),
            bg=COLORS["bg_card"], fg=COLORS["accent_blue"],
            padx=12, cursor="hand2",
        )
        export_btn.pack(side=tk.RIGHT, padx=4)
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
        """创建圆角卡片容器，返回 .content 供子控件使用"""
        card = RoundedCard(parent, bg=COLORS["bg_card"], border=COLORS["border"],
                           radius=16, shadow=True)
        card.pack(fill=tk.X, pady=(0, 12))

        # 标题
        title_label = tk.Label(
            card.content, text=title,
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            anchor="w",
        )
        title_label.pack(fill=tk.X, padx=6, pady=(6, 8))

        return card.content

    def _create_button(self, parent, text: str, command, color: str) -> RoundedButton:
        """创建圆角胶囊按钮"""
        return RoundedButton(
            parent, text=text, command=command, color=color,
            radius=12, height=42,
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

        self._update_status_bar("🔄 正在统计文件...")
        self._start_progress_ticker()  # 进度心跳：直接读取扫描器实时统计驱动进度条
        self._progress_label.configure(text="正在统计待扫描文件数...")

        # 重置扫描器
        self.scanner.reset()
        self.scanner.set_progress_callback(self._on_scan_progress)

        # 在线程中执行扫描
        def scan_worker():
            try:
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
            if stats.total_files > 0:
                pct = min(100.0, (stats.scanned_files / stats.total_files) * 100)
                self._progress_var.set(pct)
                text = (
                    f"已扫描: {stats.scanned_files}/{stats.total_files} ({pct:.0f}%) | "
                    f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found}"
                )
            else:
                text = (
                    f"已扫描: {stats.scanned_files} 个文件 | "
                    f"威胁: {stats.threats_found} | 可疑: {stats.suspicious_found}"
                )
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
            self._show_threat_alert(result)
            # 右下角弹窗通知
            self._show_threat_toast(result)
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

    def _update_scan_ui(self, result: ScanResult, stats: ScanStats):
        """在主线程更新扫描进度 UI (进度事件即时到达, 无需等待 AI 二次扫描)"""
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

        # 根据威胁等级着色
        tag = result.threat_level.value
        if tag == "malicious":
            self._result_tree.tag_configure("malicious", background="#da363320")
        elif tag == "high_risk":
            self._result_tree.tag_configure("high_risk", background="#bb800910")
        elif tag == "suspicious":
            self._result_tree.tag_configure("suspicious", background="#bb800908")
        self._result_tree.item(item_id, tags=(tag,))

        # 直接持有该行对应的 ScanResult 引用，隔离时据此隔离
        self._tree_results[item_id] = result
        self._checked[item_id] = False
        self._current_results.append(result)

    def _apply_ai_score(self, file_path: str, ai_result: ScanResult, ai_score: ConfidenceScore):
        """AI 二次扫描完成后, 把评分回填到结果行 (方法列追加 AI 置信度)"""
        # 找到对应行
        target_item = None
        for item_id in self._result_tree.get_children():
            values = self._result_tree.item(item_id)["values"]
            if len(values) > 5 and values[5] == file_path:
                target_item = item_id
                break
        if target_item is None:
            return

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

    def _restore_quarantined(self):
        """恢复隔离文件"""
        selection = self._quarantine_tree.selection()
        if not selection:
            return

        item = self._quarantine_tree.item(selection[0])
        qname = item["values"][0]
        oname = item["values"][1]

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

        item = self._quarantine_tree.item(selection[0])
        qname = item["values"][0]
        oname = item["values"][1]

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
        for item in self._quarantine_tree.get_children():
            self._quarantine_tree.delete(item)

        for entry in self.quarantine.list_quarantined():
            size_str = self._format_size(entry.get("file_size", 0))
            self._quarantine_tree.insert("", tk.END, values=(
                entry["quarantine_name"][:16] + "...",
                entry["original_name"],
                entry["threat_name"],
                entry["original_path"],
                size_str,
                entry["quarantined_at"][:19],
            ))

        self._q_count_label.configure(
            text=f"隔离文件: {self.quarantine.count}"
        )

    # ==========================================================
    # 实时防护
    # ==========================================================
    def _toggle_rtp(self):
        """切换实时防护"""
        if self.realtime_monitor.running:
            self.realtime_monitor.stop()
            self._draw_rtp_indicator(False)
            self._rtp_label.configure(text="实时防护: 已关闭")
            self._rtp_switch_btn.configure(text="🔴 开启实时防护")
            self._update_status_bar("实时防护已关闭")
        else:
            if not self.realtime_monitor.available:
                messagebox.showwarning(
                    "依赖缺失",
                    "实时防护需要 watchdog 库。\n\n"
                    "请运行: pip install watchdog\n\n"
                    "当前仅支持扫描模式。"
                )
                return

            # 监控关键目录
            paths = [
                str(Path.home() / "Downloads"),
                str(Path.home() / "Desktop"),
                str(Path.home() / "Documents"),
            ]
            existing_paths = [p for p in paths if os.path.exists(p)]

            if not existing_paths:
                messagebox.showwarning("无监控目标", "没有找到可监控的目录")
                return

            try:
                self.realtime_monitor.start(existing_paths, enable_proc_monitor=True)
                self._draw_rtp_indicator(True)
                self._rtp_label.configure(text="实时防护: 运行中")
                self._rtp_switch_btn.configure(text="🟢 关闭实时防护")
                self._update_status_bar(
                    f"🛡️ 实时防护已开启 — 监控 {len(existing_paths)} 个目录 + 进程行为分析"
                )
            except Exception as e:
                messagebox.showerror("启动失败", f"无法启动实时防护:\n{e}")

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
    def _show_threat_toast(self, result: ScanResult):
        """对文件威胁显示右下角弹窗"""
        if not self._toast_manager:
            return
        level_to_type = {
            "malicious": ToastType.DANGER,
            "high_risk": ToastType.DANGER,
            "suspicious": ToastType.WARNING,
        }
        toast_type = level_to_type.get(result.threat_level.value, ToastType.WARNING)

        config = ToastConfig(
            title=self._toast_title(result),
            subtitle=f"{result.threat_name} | {result.file_name}",
            details=(
                f"📁 路径: {result.file_path}\n"
                f"🔍 检测方式: {result.detection_method}\n"
                f"⚠️ 威胁等级: {result.threat_level.value}\n"
                f"📏 文件大小: {self._format_size(result.file_size)}\n"
                f"🕐 检测时间: {result.timestamp[:19]}\n\n"
                f"{result.details}"
            ),
            toast_type=toast_type,
            auto_dismiss=30,
            on_block=None,  # 文件威胁用「隔离」代替「阻止」
            on_quarantine=lambda: self._quarantine_single_threat(result),
            on_ignore=lambda: self._update_status_bar(
                f"⚠️ 已忽略威胁: {result.file_name}"
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
            self._toast_title(result),
            f"{result.threat_name} | {result.file_name}",
            result.details or "",
            kind,
        )

    def _show_process_toast(self, alert: ProcessAlert):
        """对进程行为威胁显示右下角弹窗"""
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
        """切换标签页（圆角分段标签）"""
        for tid, frame in self._tab_frames.items():
            frame.pack_forget()

        for tid, pill in self._tab_buttons.items():
            pill.set_active(tid == tab_id)

        self._tab_frames[tab_id].pack(fill=tk.BOTH, expand=True)
        self._active_tab.set(tab_id)

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
            icon_path = Path(__file__).parent / "icon.ico"
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
                "X-Safe 智能杀毒",
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
            import subprocess, sys
            try:
                pip_exe = sys.executable.replace("python.exe", "pip.exe")
                result = subprocess.run(
                    [pip_exe, "install", "pystray", "Pillow", "-q"],
                    capture_output=True, text=True, timeout=120,
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
        if self.realtime_monitor.running:
            return
        if not self.realtime_monitor.available:
            return

        paths = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Documents"),
        ]
        existing_paths = [p for p in paths if os.path.exists(p)]
        if not existing_paths:
            return

        try:
            self.realtime_monitor.start(existing_paths, enable_proc_monitor=True)
            self._draw_rtp_indicator(True)
            self._rtp_label.configure(text="实时防护: 运行中")
            self._rtp_switch_btn.configure(text="🟢 关闭实时防护")
            self._update_status_bar(
                f"🛡️ 实时防护已自动开启 — 监控 {len(existing_paths)} 个目录 + 进程行为分析"
            )
        except Exception as e:
            self._update_status_bar(f"⚠️ 实时防护启动失败: {e}")

    # ----------------------------------------------------------
    # 主动防御依赖自修复 + 自测
    # ----------------------------------------------------------
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
            import subprocess, sys
            try:
                pip_exe = sys.executable.replace("python.exe", "pip.exe")
                if not os.path.exists(pip_exe):
                    pip_exe = sys.executable.replace("pythonw.exe", "pip.exe")
                subprocess.run(
                    [pip_exe, "install", *missing, "-q"],
                    capture_output=True, text=True, timeout=180,
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
            self.realtime_monitor = _monitor.RealTimeMonitor(
                self.scanner.scanner, self.quarantine
            )
            self.realtime_monitor.set_alert_callback(self._on_threat_detected)
            self.realtime_monitor.set_proc_alert_callback(self._on_process_alert)
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
                self._tray_icon.notify("X-Safe正在后台运行", "已最小化到托盘")
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

    @staticmethod
    def _cloud_result_tag(result: CloudScanResult) -> str:
        """生成云端结果的简短标签"""
        if result.is_malicious:
            return f"云端确认为恶意 ({result.detection_ratio})"
        elif result.detections > 0:
            return f"云端低检出 ({result.detection_ratio})"
        else:
            return "云端未检出"

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
        """切换浅色/深色主题（保存后用 pythonw 重启自身，干净换肤）"""
        if self._scanning:
            messagebox.showinfo("请稍候", "扫描进行中，请扫描完成后再切换主题。")
            return
        new_theme = "dark" if self._theme == "light" else "light"
        _save_theme(new_theme)
        # 用 pythonw 重启自身：避免 200+ 控件逐体重绘带来的闪烁与遗漏
        pythonw = sys.executable.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        try:
            if self._tray_icon:
                self._tray_icon.stop()
        except Exception:
            pass
        self.root.destroy()
        try:
            os.execv(pythonw, [pythonw, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception:
            os._exit(0)


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
