# X-Safe 安全中心 — 架构设计

> 本文面向开发者，解释 X-Safe 的核心模块设计、关键流程和性能考量。

---

## 📐 模块依赖图

```
                            ┌─────────────────┐
                            │    main.py      │  (tkinter GUI 主程序)
                            │  (5000+ 行)     │
                            └────────┬────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
            ▼                        ▼                        ▼
   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │   src/engine.py │    │  src/ai_engine.py│    │ src/cloud_engine │
   │  扫描引擎核心   │    │  AI 评分引擎     │    │  云端查杀        │
   │  + ScanResult   │    │  + AIScorer      │    │  + VirusTotal    │
   │  + 隔离区       │    │  + 学习数据库     │    │  + 360 云         │
   └────────┬────────┘    └─────────────────┘    └─────────────────┘
            │
            │ (主动防御子系统)
            ├────────────────────────┐
            │                        │
            ▼                        ▼
   ┌─────────────────┐    ┌─────────────────┐
   │ src/monitor.py  │    │ src/registry_   │
   │ 文件系统监控    │    │   monitor.py    │
   │ (watchdog)      │    │ 注册表监控      │
   └─────────────────┘    └─────────────────┘
            │
            ▼
   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │ src/process_    │    │ src/boot_guard.py│    │ src/whitelist.py │
   │   monitor.py    │    │ 引导区保护       │    │ 白名单 + 自保护 │
   │ 进程行为监控    │    │ (MBR/VBR 哈希)   │    │                 │
   └─────────────────┘    └─────────────────┘    └─────────────────┘

   ┌─────────────────┐    ┌─────────────────┐
   │ src/recovery.py │    │ src/self_check  │
   │ 勒索恢复        │    │ 自检程序         │
   │ WannaCry/EtB    │    │ (三引擎联动)    │
   └─────────────────┘    └─────────────────┘

   ┌─────────────────────────────────────────┐
   │ src/toast_notification.py               │
   │ ThreatToast 弹窗系统 (主弹窗组件)       │
   └─────────────────────────────────────────┘
```

---

## 🔄 关键流程

### 1. 快速扫描流程

```
用户点击「快速扫描」按钮
  ↓
_start_quick_scan()  (main.py)
  ↓
_start_scan_thread(scan_fn)  ── 启动后台线程
  ↓
scanner.quick_scan()  (engine.py)  ── 逐文件扫描
  ↓
self._on_scan_progress(result, stats)  ── 每次发现可疑
  ↓
self._scan_queue.put(("progress", result, stats))  ── 跨线程安全
  ↓
主线程 _process_scan_queue()  ── 30ms 轮询
  ↓
_dispatch_scan_event("progress")
  ↓
_update_scan_ui(result, stats)
  ↓
if result.is_threat:  _add_result_to_tree(result)
  ↓
if result.is_threat:  _show_threat_toast(result, source="manual_scan")
  ↓
_show_scan_summary_toast(result)  ── 累积摘要弹窗（1.5s 节流）
  ↓
ThreatToast 弹窗（屏幕右下方）
```

### 2. 实时防护触发流程

```
watchdog 监控器检测到文件创建/修改/移动
  ↓
FileMonitor._on_modified(event)  (monitor.py, 子线程)
  ↓
判断路径是否值得关注
  ↓
scanner.scan_file(file_path)  ── 同步扫描单个文件
  ↓
result = ScanResult(...)  ── 包含 is_threat / threat_level
  ↓
OnThreatDetectedCallback(result)  (main.py)
  ↓
self._on_threat_detected(result)
  ↓
self._scan_queue.put(("threat", result))  ── 跨线程
  ↓
主线程 _process_scan_queue() 处理
  ↓
_show_threat_alert(result) → _add_result_to_tree(result)
  ↓
_show_threat_toast(result, source="realtime")
  ↓
ThreatToast 弹窗（每个威胁一个）
```

### 3. ThreatToast 弹窗系统

**累积摘要弹窗**（手动扫描时使用）：

```python
def _show_scan_summary_toast(self, result):
    """手动扫描 = 累积摘要弹窗（避免 516 个被 max_toasts 顶掉）"""
    # 1) 累积本批威胁
    self._scan_acc_count += 1
    self._scan_acc_samples.append(result)

    # 2) 节流：1.5s 内只弹 1 次
    if now - self._last_scan_summary_toast_ts < 1500:
        return  # 仅累积，不弹

    # 3) 弹窗前先清空现有 toast 队列
    self._toast_manager.clear_all()

    # 4) 创建摘要弹窗
    config = ToastConfig(
        title=f"🚨 扫描发现 {count} 个威胁",
        details="前几个样本...",
        auto_dismiss=0,  # 不自动消失
    )
    self._toast_manager.show_toast(config)
```

**单条带按钮弹窗**（实时监控时使用）：

```python
def _show_threat_toast(self, result, source="realtime"):
    """实时 = 每个威胁一个弹窗"""
    config = ToastConfig(
        title="🚨 检测到恶意文件！",
        details=...,
        auto_dismiss=0,  # 不自动消失
        on_delete=...,   # 按钮回调
        on_self_check=...,
        on_ignore=...,
    )
    self._toast_manager.show_toast(config)
```

### 4. 数据流向

```
exe 启动
  ↓
_get_data_dir()  ── %TEMP%\XSafe\  (Windows)
                    ./.userdata/  (源码)
  ↓
_ensure_seeded_files()  ── 首次启动把 bundled 数据拷过去
  ↓
self.ai_learning_db, self.quarantine, ...
  ↓
运行时读写
```

---

## 🧵 线程模型

| 线程 | 职责 | 创建位置 |
|------|------|---------|
| **主线程 (Tk)** | UI 渲染 + 30ms 轮询 `_process_scan_queue` | tkinter |
| **扫描线程** | 快速/高级/自定义扫描，逐文件调 `_on_scan_progress` | `_start_scan_thread` |
| **文件系统监控线程** | watchdog 监听（每个路径一个 Observer） | `monitor.py:FileMonitor.start` |
| **注册表监控线程** | 轮询关键项变化 | `registry_monitor.py:RegistryMonitor.start` |
| **进程监控线程** | 轮询进程启动/退出 | `process_monitor.py:ProcessMonitor.start` |
| **UI 轮询线程** (after) | 1000ms 检查 result_tree 新增行 | `self.root.after(1000, ...)` |

### 跨线程通信
- **扫描线程 → 主线程**：`_scan_queue: queue.Queue` (先进先出)
- **监控线程 → 主线程**：通过 `_scan_queue` 推 `("threat", result)` 事件
- **主线程 → 子线程**：无（子线程不接收主线程指令，扫描取消通过 `threading.Event`）

### 关键原则
- **任何 UI 操作必须在主线程**：widget.configure / .insert / .delete
- **任何 tkinter 变量读取必须在主线程**：BooleanVar.get() / StringVar.get()
- **后台线程绝不能调 tkinter API**：会导致 `main thread is not in main loop`

---

## 🎯 关键设计决策

### 1. 累积摘要弹窗（手动扫描）
**问题**：快速扫描发现 500+ 威胁时，30ms 内创建 500+ ThreatToast，被 max_toasts=8 顶替后用户什么都看不到。

**方案**：手动扫描时只弹 1 个累积摘要（每 1.5s 更新一次），弹窗前 `clear_all()` 清空队列。

### 2. 不自动隔离
**问题**：用户希望对威胁有最终决定权，自动隔离是过度保护。

**方案**：检测到威胁 → 弹 ThreatToast → 用户选「删除/隔离/自检/忽略」。

### 3. 自保护白名单
**问题**：PyInstaller 打包的 _internal 目录被扫描器误报，导致程序无法运行。

**方案**：`WhitelistEngine.is_self_protected(path)` 检查 `sys.executable` 和 `_internal` 目录，默认豁免。

### 4. 数据目录在 %TEMP%
**问题**：%APPDATA% 在某些用户环境（公司/家庭策略）下被静默重定向到 exe 同目录。

**方案**：用 %TEMP% 替代 %APPDATA%，跨用户稳定可写，不受策略限制。

### 5. after 链不断裂
**问题**：`self.root.after(1000, self.method)` 传 bound method，Tk 注册成临时 command，GC 后失效。

**方案**：用 `_poll_tick_wrapper()` 包装函数 + `lambda: self._poll_tick_wrapper()` 保引用。

---

## 📊 性能指标

| 操作 | 时间 | 备注 |
|------|------|------|
| 快速扫描（500 文件） | 1-2 秒 | 取决于磁盘 I/O |
| AI 评分（单文件） | 5-10 ms | 纯 Python，无外部依赖 |
| 云查杀（单文件） | 200-500 ms | 受网络影响 |
| ThreatToast 弹窗延迟 | < 50 ms | tkinter 创建 Toplevel |
| 累积摘要弹窗节流 | 1.5 s | 避免狂涌时弹窗叠加 |
| 实时监控事件处理 | < 100 ms | watchdog + 队列 |

---

## 🐛 调试工具

| 工具 | 路径 | 用途 |
|------|------|------|
| init_debug.log | exe 同目录 / 源码根 | 启动流程的 6 个关键步骤打点 |
| poll_debug.log | `%TEMP%\XSafe\` | 轮询器心跳 + 弹窗触发记录 |
| XSAFE_DEBUG_TOAST=1 | 环境变量 | 启动 5s 后自动触发一个 ThreatToast |
| XSAFE_AUTO_SCAN=1 | 环境变量 | 启动 3s 后自动触发快速扫描 |

---

## 📚 进一步阅读

- [build.md](build.md) — PyInstaller 打包注意事项
- [README.md](../README.md) — 用户使用指南
- [CHANGELOG.md](../CHANGELOG.md) — 版本历史
