"""X-Safe 安全中心 — 核心模块包

包含所有核心安全模块：
- engine: 扫描引擎 + ScanResult + 隔离区
- ai_engine: AI 自学习引擎
- cloud_engine: 云端查杀
- monitor: 文件系统监控
- registry_monitor: 注册表监控
- process_monitor: 进程行为监控
- whitelist: 白名单引擎
- recovery: 勒索恢复
- self_check: 主动防御自检
- boot_guard: 引导区保护
- toast_notification: ThreatToast 弹窗系统
"""

__version__ = "1.0.0"
__author__ = "竹影清风 (ZYWind-S)"
__studio__ = "新启年工作室 (NewEra Studio)"
__license__ = "MIT"
