"""
X-Safe — 右下角弹窗通知组件
Toast Notification: 威胁告警弹窗

设计原则：
- 完全用 tk.Label + tk.Frame（不用 Text/Canvas），避免 DPI 缩放下的渲染黑洞
- Toplevel 锁死尺寸（pack_propagate(False) + resizable(False,False) + 多次 geometry 强制）
- 不依赖任何外部 callback 触发 — 由调用方在主线程调用 show()
"""

import tkinter as tk
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
    "text_muted": "#6e7681",
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
    subtitle: str = ""
    details: str = ""
    toast_type: ToastType = ToastType.DANGER
    auto_dismiss: int = 30  # 自动关闭秒数 (0 = 不自动关闭)
    on_block: Optional[Callable] = None
    on_quarantine: Optional[Callable] = None
    on_dismiss: Optional[Callable] = None
    on_ignore: Optional[Callable] = None
    # 主动防御二期：先隔离后处置
    on_delete: Optional[Callable] = None
    on_restore: Optional[Callable] = None
    on_self_check: Optional[Callable] = None
    pre_isolated: bool = False
    # 自定义按钮文案
    block_label: Optional[str] = None
    quarantine_label: Optional[str] = None
    ignore_label: Optional[str] = None
    delete_label: Optional[str] = None
    restore_label: Optional[str] = None
    self_check_label: Optional[str] = None


class ThreatToast:
    """威胁告警弹窗 — 右下角弹出，纯 Label 实现"""

    TOAST_WIDTH = 420
    TOAST_HEIGHT = 340
    MARGIN_RIGHT = 20
    MARGIN_BOTTOM = 20

    def __init__(self, root: tk.Tk, config: ToastConfig):
        self._root = root
        self._config = config
        self._window: Optional[tk.Toplevel] = None
        self._countdown_var: Optional[tk.StringVar] = None
        self._countdown_id: Optional[str] = None
        self._dismissed = False
        self._remaining = 0

    # ----------------------------------------------------------
    # 显示弹窗
    # ----------------------------------------------------------
    def show(self):
        """显示弹窗（主线程调用）"""
        # 1) 创建 Toplevel
        self._window = tk.Toplevel(self._root)
        self._window.title("")
        self._window.overrideredirect(True)
        self._window.configure(bg=TOAST_COLORS["bg_main"])
        # 锁死尺寸（多种方式叠加）
        self._window.resizable(False, False)
        self._window.minsize(self.TOAST_WIDTH, self.TOAST_HEIGHT)
        self._window.maxsize(self.TOAST_WIDTH, self.TOAST_HEIGHT)

        # 2) 第一次 geometry（指定尺寸+位置，positioning 在右下角）
        screen_w = self._window.winfo_screenwidth()
        screen_h = self._window.winfo_screenheight()
        x = screen_w - self.TOAST_WIDTH - self.MARGIN_RIGHT
        y = screen_h - self.TOAST_HEIGHT - self.MARGIN_BOTTOM - 40
        self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{y}")
        self._window.update_idletasks()
        # 强制一次（防 WM 改动）
        self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{y}")

        # 3) 构建 UI（在 propagate 锁死之后）
        self._build_toast_ui()
        self._window.update_idletasks()
        # 4) 再次强制 geometry
        self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{y}")

        # 5) 延后置顶（在 widget 树稳定后）
        try:
            self._window.attributes("-topmost", True)
        except tk.TclError:
            pass
        self._window.lift()
        self._window.bell()

        # 6) 启动倒计时
        if self._config.auto_dismiss > 0:
            self._start_countdown()

        # 7) 50ms 后再强制一次（防 WM 干预）
        self._window.after(50, lambda: self._force_reposition(x, y))
        # 8) 200ms 后再强制一次
        self._window.after(200, lambda: self._force_reposition(x, y))

    def _force_reposition(self, x: int, y: int):
        """延后强制定位"""
        if not self._window or self._dismissed:
            return
        try:
            self._window.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{y}")
            self._window.lift()
        except tk.TclError:
            pass

    # ----------------------------------------------------------
    # 构建弹窗 UI — 纯 Label/Frame，不用 Text
    # ----------------------------------------------------------
    def _build_toast_ui(self):
        """构建弹窗界面"""
        # 颜色
        if self._config.toast_type == ToastType.DANGER:
            accent = TOAST_COLORS["accent_red"]
            level_text = "🔴 高危威胁"
        elif self._config.toast_type == ToastType.WARNING:
            accent = TOAST_COLORS["accent_orange"]
            level_text = "🟠 可疑行为"
        else:
            accent = TOAST_COLORS["accent_blue"]
            level_text = "🔵 安全提示"

        # 主容器（铺满 Toplevel）
        main = tk.Frame(self._window, bg=TOAST_COLORS["bg_main"])
        main.pack(fill=tk.BOTH, expand=True)

        # === 顶部 header（标题 + 关闭按钮） ===
        header_h = 60
        header = tk.Frame(main, bg=TOAST_COLORS["bg_card"], height=header_h)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # 左边色条
        accent_bar = tk.Frame(header, bg=accent, width=4)
        accent_bar.pack(side=tk.LEFT, fill=tk.Y)

        # 标题 + 副标题
        title_box = tk.Frame(header, bg=TOAST_COLORS["bg_card"])
        title_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 4), pady=8)

        title_lbl = tk.Label(
            title_box, text=self._config.title,
            font=("Microsoft YaHei UI", 12, "bold"),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_primary"],
            anchor="w",
        )
        title_lbl.pack(fill=tk.X)

        sub_text = self._config.subtitle or level_text
        sub_lbl = tk.Label(
            title_box, text=sub_text,
            font=("Microsoft YaHei UI", 9),
            bg=TOAST_COLORS["bg_card"], fg=accent,
            anchor="w",
        )
        sub_lbl.pack(fill=tk.X)

        # 关闭按钮
        close_btn = tk.Label(
            header, text="✕",
            font=("Segoe UI", 14, "bold"),
            bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_secondary"],
            padx=14, pady=4, cursor="hand2",
        )
        close_btn.pack(side=tk.RIGHT)
        close_btn.bind("<Button-1>", lambda e: self._on_ignore())
        close_btn.bind("<Enter>", lambda e: close_btn.configure(fg=accent))
        close_btn.bind("<Leave>",
                        lambda e: close_btn.configure(fg=TOAST_COLORS["text_secondary"]))

        # === 中间详情区（纯 Label，多行手动堆叠） ===
        detail_outer = tk.Frame(main, bg=TOAST_COLORS["bg_main"])
        detail_outer.pack(fill=tk.BOTH, expand=True, padx=14, pady=(10, 6))

        # 详情背景框
        detail_box = tk.Frame(detail_outer, bg=TOAST_COLORS["bg_card"])
        detail_box.pack(fill=tk.BOTH, expand=True)

        # 详情文本（手动换行：每行一个 Label）
        details = self._config.details or "（无详情）"
        # 按 \n 拆分，每段最多 N 字符
        import textwrap
        lines = []
        for raw in details.split("\n"):
            if not raw:
                lines.append("")
                continue
            wrapped = textwrap.wrap(raw, width=44, break_long_words=True, replace_whitespace=False)
            lines.extend(wrapped if wrapped else [""])
        # 最多显示 6 行
        lines = lines[:6]
        for line in lines:
            tk.Label(
                detail_box, text=line,
                font=("Microsoft YaHei UI", 9),
                bg=TOAST_COLORS["bg_card"], fg=TOAST_COLORS["text_secondary"],
                anchor="w", justify="left",
            ).pack(fill=tk.X, padx=10, pady=1, anchor="w")

        # === 底部按钮区 ===
        btn_h = 56
        btn_frame = tk.Frame(main, bg=TOAST_COLORS["bg_main"], height=btn_h)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=14, pady=(0, 12))
        btn_frame.pack_propagate(False)

        # 倒计时
        self._countdown_var = tk.StringVar(value="")
        countdown_lbl = tk.Label(
            btn_frame, textvariable=self._countdown_var,
            font=("Microsoft YaHei UI", 8),
            bg=TOAST_COLORS["bg_main"], fg=TOAST_COLORS["text_muted"],
        )
        countdown_lbl.pack(side=tk.LEFT)

        # 右侧按钮（按需）
        right_btns = tk.Frame(btn_frame, bg=TOAST_COLORS["bg_main"])
        right_btns.pack(side=tk.RIGHT)

        if self._config.pre_isolated:
            # 新版：忽略 / 自检 / 恢复 / 删除
            self._mk_btn(right_btns, self._config.ignore_label or "忽略",
                          TOAST_COLORS["bg_button"], TOAST_COLORS["text_secondary"],
                          self._on_ignore).pack(side=tk.RIGHT, padx=(6, 0))
            if self._config.on_self_check:
                self._mk_btn(right_btns, self._config.self_check_label or "🔍 自检",
                              TOAST_COLORS["bg_button"], TOAST_COLORS["text_primary"],
                              self._on_self_check).pack(side=tk.RIGHT, padx=(6, 0))
            if self._config.on_restore:
                self._mk_btn(right_btns, self._config.restore_label or "↩ 恢复",
                              TOAST_COLORS["accent_blue"], "#ffffff",
                              self._on_restore).pack(side=tk.RIGHT, padx=(6, 0))
            self._mk_btn(right_btns, self._config.delete_label or "🗑 删除",
                          TOAST_COLORS["accent_red"], "#ffffff",
                          self._on_delete).pack(side=tk.RIGHT)
        else:
            # 旧版：忽略 / 隔离 / 阻止
            self._mk_btn(right_btns, self._config.ignore_label or "忽略",
                          TOAST_COLORS["bg_button"], TOAST_COLORS["text_secondary"],
                          self._on_ignore).pack(side=tk.RIGHT, padx=(6, 0))
            self._mk_btn(right_btns, self._config.quarantine_label or "🔒 隔离",
                          TOAST_COLORS["accent_orange"], "#ffffff",
                          self._on_quarantine).pack(side=tk.RIGHT, padx=(6, 0))
            self._mk_btn(right_btns, self._config.block_label or "⛔ 阻止",
                          TOAST_COLORS["accent_red"], "#ffffff",
                          self._on_block).pack(side=tk.RIGHT)

        # 关闭事件
        self._window.protocol("WM_DELETE_WINDOW", self._on_ignore)

    def _mk_btn(self, parent, text: str, bg: str, fg: str, command) -> tk.Label:
        """创建按钮（直接返回 tk.Label）"""
        original_bg = bg
        btn = tk.Label(
            parent, text=text,
            font=("Microsoft YaHei UI", 9, "bold"),
            bg=bg, fg=fg,
            padx=12, pady=6, cursor="hand2",
        )

        def on_enter(e):
            try:
                c = original_bg.lstrip("#")
                r, g, b = int(c[:2], 16), int(c[2:4], 16), int(c[4:6], 16)
                r = min(255, int(r + (255 - r) * 0.2))
                g = min(255, int(g + (255 - g) * 0.2))
                b = min(255, int(b + (255 - b) * 0.2))
                btn.configure(bg=f"#{r:02x}{g:02x}{b:02x}")
            except Exception:
                pass

        def on_leave(e):
            try:
                btn.configure(bg=original_bg)
            except Exception:
                pass

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<Button-1>", lambda e: command())
        return btn

    # ----------------------------------------------------------
    # 倒计时
    # ----------------------------------------------------------
    def _start_countdown(self):
        self._remaining = self._config.auto_dismiss
        self._update_countdown()

    def _update_countdown(self):
        if self._dismissed or not self._window or not self._countdown_var:
            return
        if self._remaining <= 0:
            self._on_ignore()
            return
        self._countdown_var.set(f"{self._remaining}s 后自动忽略")
        self._remaining -= 1
        self._countdown_id = self._window.after(1000, self._update_countdown)

    # ----------------------------------------------------------
    # 操作回调
    # ----------------------------------------------------------
    def _on_block(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_block:
            try:
                self._config.on_block()
            except Exception:
                pass

    def _on_quarantine(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_quarantine:
            try:
                self._config.on_quarantine()
            except Exception:
                pass

    def _on_ignore(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_ignore:
            try:
                self._config.on_ignore()
            except Exception:
                pass

    def _on_delete(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_delete:
            try:
                self._config.on_delete()
            except Exception:
                pass

    def _on_restore(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_restore:
            try:
                self._config.on_restore()
            except Exception:
                pass

    def _on_self_check(self):
        if self._dismissed:
            return
        self._dismissed = True
        self._cleanup()
        if self._config.on_self_check:
            try:
                self._config.on_self_check()
            except Exception:
                pass

    def _cleanup(self):
        """清理：取消倒计时、销毁窗口"""
        if self._countdown_id:
            try:
                self._window.after_cancel(self._countdown_id)
            except Exception:
                pass
        if self._window:
            try:
                self._window.destroy()
            except tk.TclError:
                pass
            self._window = None


class ToastManager:
    """弹窗管理器 — 单例，限制同时显示的弹窗数"""

    MAX_VISIBLE = 3
    _instance: Optional["ToastManager"] = None

    def __init__(self, root: tk.Tk, max_toasts: int = 8):
        # v28: 保持 max_toasts=8 — v28 引入累积摘要弹窗，
        # 手动扫描时先 clear_all() 再创建 1 个 toast，不会再狂涌
        # max_toasts=8 仍能容纳实时模式多个并发告警
        self._root = root
        self._max_toasts = max_toasts
        self._toasts: list[ThreatToast] = []

    @classmethod
    def get(cls, root: tk.Tk) -> "ToastManager":
        if cls._instance is None:
            cls._instance = cls(root)
        return cls._instance

    def show_toast(self, config: ToastConfig):
        """显示一个弹窗，自动管理队列"""
        if not self._root.winfo_exists():
            return
        if len(self._toasts) >= self._max_toasts:
            old = self._toasts.pop(0)
            try:
                old._cleanup()
            except Exception:
                pass
        toast = ThreatToast(self._root, config)
        self._toasts.append(toast)
        try:
            toast.show()
        except Exception as e:
            print(f"[ToastManager] show failed: {e}")
            import traceback
            traceback.print_exc()

    def clear_all(self):
        """关闭所有弹窗"""
        for t in self._toasts:
            try:
                t._cleanup()
            except Exception:
                pass
        self._toasts.clear()
