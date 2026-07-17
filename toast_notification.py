"""
X-Safe — 右下角弹窗通知组件
Toast Notification: 威胁告警弹窗，支持"立即阻止"和"立即隔离"两个操作按钮
"""

import tkinter as tk
from tkinter import ttk
import threading
from typing import Callable, Optional
from dataclasses import dataclass
from enum import Enum


# ============================================================
# 配色方案 (匹配主程序的深色主题)
# ============================================================
TOAST_COLORS = {
    "bg_main": "#0d1117",
    "bg_card": "#161b22",
    "bg_button": "#21262d",
    "border": "#30363d",
    "text_primary": "#e6edf3",
    "text_secondary": "#8b949e",
    "accent_red": "#f85149",
    "accent_green": "#3fb950",
    "accent_orange": "#d29922",
    "accent_blue": "#58a6ff",
    "danger_bg": "#da363320",
    "danger_border": "#f8514960",
    "warning_bg": "#bb800910",
    "warning_border": "#d2992260",
}


class ToastType(Enum):
    DANGER = "danger"       # 红色 — 高危/恶意
    WARNING = "warning"     # 橙色 — 可疑
    INFO = "info"           # 蓝色 — 信息


@dataclass
class ToastConfig:
    """弹窗配置"""
    title: str
    subtitle: str
    details: str
    toast_type: ToastType = ToastType.DANGER
    auto_dismiss: int = 30  # 自动关闭秒数 (0 = 不自动关闭)
    on_block: Optional[Callable] = None   # "立即阻止" 回调
    on_quarantine: Optional[Callable] = None  # "立即隔离" 回调
    on_dismiss: Optional[Callable] = None     # 关闭回调
    on_ignore: Optional[Callable] = None      # "忽略" 回调


class ThreatToast:
    """威胁告警弹窗 — 右下角弹出，带滑入动画"""

    TOAST_WIDTH = 420
    TOAST_HEIGHT = 320
    MARGIN_RIGHT = 20
    MARGIN_BOTTOM = 20
    SLIDE_STEPS = 12      # 动画帧数
    SLIDE_INTERVAL = 15   # 每帧间隔 (ms)

    def __init__(self, root: tk.Tk, config: ToastConfig):
        self._root = root
        self._config = config
        self._window: Optional[tk.Toplevel] = None
        self._countdown_var: Optional[tk.StringVar] = None
        self._countdown_id: Optional[str] = None
        self._dismissed = False
        self._target_y: int = 0

    # ----------------------------------------------------------
    # 显示弹窗
    # ----------------------------------------------------------
    def show(self):
        """显示弹窗 (主线程调用)"""
        # 布局弹窗
        self._window = tk.Toplevel(self._root)
        self._window.title("")
        self._window.overrideredirect(True)  # 无边框
        self._window.attributes("-topmost", True)  # 始终置顶
        self._window.configure(bg=TOAST_COLORS["bg_main"])

        # 计算屏幕位置
        screen_w = self._window.winfo_screenwidth()
        screen_h = self._window.winfo_screenheight()
        x = screen_w - self.TOAST_WIDTH - self.MARGIN_RIGHT
        target_y = screen_h - self.TOAST_HEIGHT - self.MARGIN_BOTTOM - 40  # 给任务栏留空间
        start_y = screen_h + 50  # 从屏幕底部外开始

        self._target_y = target_y
        self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{start_y}")

        # 构建界面
        self._build_toast_ui()

        # 启动滑入动画
        self._animate_slide_in(x, start_y, target_y, step=0)

        # 如果设置了自动关闭，启动倒计时
        if self._config.auto_dismiss > 0:
            self._start_countdown()

    # ----------------------------------------------------------
    # 构建弹窗 UI
    # ----------------------------------------------------------
    def _build_toast_ui(self):
        """构建弹窗界面"""
        # 颜色配置
        if self._config.toast_type == ToastType.DANGER:
            accent = TOAST_COLORS["accent_red"]
            bg = TOAST_COLORS["danger_bg"]
            border = TOAST_COLORS["danger_border"]
        elif self._config.toast_type == ToastType.WARNING:
            accent = TOAST_COLORS["accent_orange"]
            bg = TOAST_COLORS["warning_bg"]
            border = TOAST_COLORS["warning_border"]
        else:
            accent = TOAST_COLORS["accent_blue"]
            bg = TOAST_COLORS["bg_card"]
            border = TOAST_COLORS["border"]

        # 外边框
        outer = tk.Frame(
            self._window, bg=border,
            highlightbackground=border, highlightthickness=1,
        )
        outer.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # 内层容器
        inner = tk.Frame(outer, bg=TOAST_COLORS["bg_main"])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        # --- 顶部：标题区 ---
        header = tk.Frame(inner, bg=TOAST_COLORS["bg_card"], height=56)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # 图标 + 标题
        icon_text = "🛡️" if self._config.toast_type != ToastType.DANGER else "⚠️"
        icon_label = tk.Label(
            header, text=icon_text,
            font=("Segoe UI", 20),
            bg=TOAST_COLORS["bg_card"], fg=accent,
        )
        icon_label.pack(side=tk.LEFT, padx=(14, 6), pady=10)

        title_frame = tk.Frame(header, bg=TOAST_COLORS["bg_card"])
        title_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)

        title_label = tk.Label(
            title_frame, text=self._config.title,
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_primary"],
            anchor="w",
        )
        title_label.pack(fill=tk.X)

        subtitle_label = tk.Label(
            title_frame, text=self._config.subtitle,
            font=("Microsoft YaHei UI", 9),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_secondary"],
            anchor="w",
        )
        subtitle_label.pack(fill=tk.X)

        # 关闭按钮
        close_btn = tk.Label(
            header, text="✕",
            font=("Segoe UI", 14),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_secondary"],
            padx=12, pady=10, cursor="hand2",
        )
        close_btn.pack(side=tk.RIGHT, padx=(0, 4))
        close_btn.bind("<Button-1>", lambda e: self._on_ignore())
        close_btn.bind("<Enter>", lambda e: close_btn.configure(fg=accent))
        close_btn.bind("<Leave>", lambda e: close_btn.configure(fg=TOAST_COLORS["text_secondary"]))

        # --- 中间：详情区 ---
        detail_frame = tk.Frame(inner, bg=TOAST_COLORS["bg_main"])
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(10, 6))

        # 威胁等级标签
        level_texts = {
            ToastType.DANGER: ("🔴 高危威胁", TOAST_COLORS["accent_red"]),
            ToastType.WARNING: ("🟠 可疑行为", TOAST_COLORS["accent_orange"]),
            ToastType.INFO: ("🔵 安全提示", TOAST_COLORS["accent_blue"]),
        }
        level_text, level_color = level_texts.get(self._config.toast_type,
                                                    ("⚠️ 告警", TOAST_COLORS["accent_orange"]))

        level_label = tk.Label(
            detail_frame, text=level_text,
            font=("Microsoft YaHei UI", 10, "bold"),
            bg=TOAST_COLORS["bg_main"], fg=level_color,
            anchor="w",
        )
        level_label.pack(fill=tk.X, pady=(0, 8))

        # 详情文本
        detail_text = tk.Text(
            detail_frame,
            font=("Consolas", 9),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_secondary"],
            relief=tk.FLAT, borderwidth=0,
            wrap=tk.WORD, height=6,
            padx=10, pady=8,
        )
        detail_text.pack(fill=tk.BOTH, expand=True)
        detail_text.insert("1.0", self._config.details)
        detail_text.configure(state=tk.DISABLED)

        # --- 底部：操作按钮 ---
        btn_frame = tk.Frame(inner, bg=TOAST_COLORS["bg_main"])
        btn_frame.pack(fill=tk.X, padx=14, pady=(6, 12))

        # 倒计时/忽略
        countdown_frame = tk.Frame(btn_frame, bg=TOAST_COLORS["bg_main"])
        countdown_frame.pack(side=tk.LEFT)

        self._countdown_var = tk.StringVar(value="")
        countdown_label = tk.Label(
            countdown_frame, textvariable=self._countdown_var,
            font=("Microsoft YaHei UI", 9),
            bg=TOAST_COLORS["bg_main"], fg=TOAST_COLORS["text_muted"],
        )
        countdown_label.pack(side=tk.LEFT)

        # 右侧按钮
        right_btns = tk.Frame(btn_frame, bg=TOAST_COLORS["bg_main"])
        right_btns.pack(side=tk.RIGHT)

        # "忽略"按钮
        ignore_btn = self._create_toast_button(
            right_btns, "忽略",
            bg=TOAST_COLORS["bg_button"],
            fg=TOAST_COLORS["text_secondary"],
            command=self._on_ignore,
        )
        ignore_btn.pack(side=tk.RIGHT, padx=(6, 0))

        # "立即隔离"按钮
        quarantine_btn = self._create_toast_button(
            right_btns, "🔒 立即隔离",
            bg=TOAST_COLORS["accent_orange"],
            fg="#ffffff",
            command=self._on_quarantine,
        )
        quarantine_btn.pack(side=tk.RIGHT, padx=(6, 0))

        # "立即阻止"按钮 — 最显眼
        block_btn = self._create_toast_button(
            right_btns, "⛔ 立即阻止",
            bg=TOAST_COLORS["accent_red"],
            fg="#ffffff",
            command=self._on_block,
        )
        block_btn.pack(side=tk.RIGHT, padx=(0, 0))

        # 绑定关闭事件
        self._window.protocol("WM_DELETE_WINDOW", self._on_ignore)

    def _create_toast_button(self, parent, text: str, bg: str, fg: str,
                              command) -> tk.Frame:
        """创建弹窗按钮"""
        frame = tk.Frame(parent, bg=TOAST_COLORS["bg_main"])

        btn = tk.Label(
            frame, text=text,
            font=("Microsoft YaHei UI", 9, "bold"),
            bg=bg, fg=fg,
            padx=14, pady=7,
            cursor="hand2",
            relief=tk.FLAT,
        )

        original_bg = bg

        def on_enter(e):
            if btn["state"] != tk.DISABLED:
                # 调亮
                c = bg.lstrip("#")
                r, g, b = int(c[:2], 16), int(c[2:4], 16), int(c[4:6], 16)
                r = min(255, int(r + (255 - r) * 0.2))
                g = min(255, int(g + (255 - g) * 0.2))
                b = min(255, int(b + (255 - b) * 0.2))
                btn.configure(bg=f"#{r:02x}{g:02x}{b:02x}")

        def on_leave(e):
            if btn["state"] != tk.DISABLED:
                btn.configure(bg=original_bg)

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<Button-1>", lambda e: command())

        btn.pack()
        return frame

    # ----------------------------------------------------------
    # 动画
    # ----------------------------------------------------------
    def _animate_slide_in(self, x: int, from_y: int, to_y: int, step: int):
        """滑入动画"""
        if self._dismissed or not self._window:
            return

        if step >= self.SLIDE_STEPS:
            # 动画完成
            self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{to_y}")
            return

        # 缓出曲线 (ease-out)
        progress = step / self.SLIDE_STEPS
        eased = 1 - (1 - progress) ** 3  # cubic ease-out
        current_y = int(from_y + (to_y - from_y) * eased)

        try:
            self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{current_y}")
            self._window.lift()
            self._window.after(
                self.SLIDE_INTERVAL,
                lambda: self._animate_slide_in(x, from_y, to_y, step + 1)
            )
        except tk.TclError:
            pass

    def _animate_slide_out(self, x: int, from_y: int, to_y: int, step: int):
        """滑出动画"""
        if not self._window:
            return

        progress = step / self.SLIDE_STEPS
        eased = progress ** 2  # ease-in
        current_y = int(from_y + (to_y - from_y) * eased)

        try:
            self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{current_y}")

            if step >= self.SLIDE_STEPS:
                self._window.destroy()
                self._window = None
            else:
                self._window.after(
                    self.SLIDE_INTERVAL,
                    lambda: self._animate_slide_out(x, from_y, to_y, step + 1)
                )
        except tk.TclError:
            self._window = None

    # ----------------------------------------------------------
    # 倒计时
    # ----------------------------------------------------------
    def _start_countdown(self):
        """启动自动关闭倒计时"""
        self._remaining = self._config.auto_dismiss
        self._update_countdown()

    def _update_countdown(self):
        """更新倒计时显示"""
        if self._dismissed or not self._window or not self._countdown_var:
            return

        if self._remaining <= 0:
            self._on_ignore()
            return

        self._countdown_var.set(f"{self._remaining} 秒后自动忽略")
        self._remaining -= 1

        self._countdown_id = self._window.after(
            1000, self._update_countdown
        )

    # ----------------------------------------------------------
    # 操作回调
    # ----------------------------------------------------------
    def _on_block(self):
        """点击「立即阻止」"""
        if self._dismissed:
            return
        self._dismissed = True
        self._dismiss_with_animation()
        if self._config.on_block:
            self._config.on_block()

    def _on_quarantine(self):
        """点击「立即隔离」"""
        if self._dismissed:
            return
        self._dismissed = True
        self._dismiss_with_animation()
        if self._config.on_quarantine:
            self._config.on_quarantine()

    def _on_ignore(self):
        """点击「忽略」或关闭"""
        if self._dismissed:
            return
        self._dismissed = True
        self._dismiss_with_animation()
        if self._config.on_ignore:
            self._config.on_ignore()
        if self._config.on_dismiss:
            self._config.on_dismiss()

    def _dismiss_with_animation(self):
        """带动画关闭"""
        if not self._window:
            return

        # 取消倒计时
        if self._countdown_id:
            try:
                self._window.after_cancel(self._countdown_id)
            except Exception:
                pass

        screen_h = self._window.winfo_screenheight()
        try:
            x = self._window.winfo_x()
            y = self._window.winfo_y()
        except tk.TclError:
            return

        to_y = screen_h + 50
        self._animate_slide_out(x, y, to_y, step=0)

    def dismiss(self):
        """外部调用关闭"""
        self._on_ignore()


# ============================================================
# 弹窗管理器 — 管理多个弹窗的显示
# ============================================================
class ToastManager:
    """弹窗管理器 — 避免同时弹出过多窗口"""

    def __init__(self, root: tk.Tk, max_toasts: int = 3):
        self._root = root
        self._max_toasts = max_toasts
        self._active_toasts: list[ThreatToast] = []
        self._pending_configs: list[ToastConfig] = []
        self._lock = threading.Lock()

    def show_toast(self, config: ToastConfig) -> ThreatToast:
        """显示弹窗 (线程安全 — 通过 root.after 调度到主线程)"""
        # 包装 config — 弹窗关闭时自动从活跃列表移除
        original_dismiss = config.on_dismiss

        def on_dismiss_wrapper():
            if original_dismiss:
                original_dismiss()
            self._on_toast_closed()
            # 显示下一个排队的弹窗
            self._show_next_pending()

        config.on_dismiss = on_dismiss_wrapper

        def _show():
            with self._lock:
                if len(self._active_toasts) >= self._max_toasts:
                    # 排队
                    self._pending_configs.append(config)
                    return

                toast = ThreatToast(self._root, config)
                self._active_toasts.append(toast)
                toast.show()

        # 在主线程执行
        if threading.current_thread() is threading.main_thread():
            _show()
        else:
            self._root.after(0, _show)

        # 返回 None 对于跨线程调用 (无法同步返回对象)
        return None

    def _on_toast_closed(self):
        """弹窗关闭时调用"""
        with self._lock:
            # 清理已关闭的弹窗
            self._active_toasts = [t for t in self._active_toasts
                                   if t._window is not None and not t._dismissed]

    def _show_next_pending(self):
        """显示下一个排队的弹窗"""
        with self._lock:
            if self._pending_configs and len(self._active_toasts) < self._max_toasts:
                config = self._pending_configs.pop(0)
                toast = ThreatToast(self._root, config)
                self._active_toasts.append(toast)
                toast.show()

    @property
    def active_count(self) -> int:
        with self._lock:
            return len([t for t in self._active_toasts
                       if t._window is not None and not t._dismissed])
