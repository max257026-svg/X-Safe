# X-Safe 安全中心

> 一款面向个人用户与中小团队的轻量化主动防御型安全软件
> 由 **竹影清风** 独立设计开发，**新启年工作室**（NewEra Studio）联合出品

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#)
[![Version 1.0](https://img.shields.io/badge/version-1.0-green.svg)](#)

---

## 📖 项目简介

**X-Safe 安全中心** 是面向个人用户与中小团队的轻量化主动防御型安全软件，以「先弹窗、再处置」为核心思路，把**特征查杀、AI 行为评分、云端联动、系统敏感点监控**整合在同一个简洁的中文控制台中，让普通用户也能拥有接近企业级 EDR 的可见性与响应能力。

### ✨ 核心特性

- 🔍 **三引擎联动**：特征引擎 + AI 自学习 + 云端查杀，按权重融合给出最终风险等级
- 🛡️ **主动防御**：解压/下载/注册表/引导区/进程行为实时监控
- 🔁 **系统自检**：隔离区完整性 + 引导区 + 注册表基线巡检，一键确认防护体系健康度
- 💀 **勒索恢复**：WannaCry / EternalBlue 痕迹检测 + 卷影副本恢复
- 🪟 **屏幕右下方 ThreatToast 弹窗**：累积摘要弹窗（狂涌 500+ 威胁也只弹 1 个）+ 单条带「删除 / 隔离 / 自检 / 忽略」按钮
- 🎯 **自保护白名单**：程序自身 + _internal 目录默认豁免，避免 PyInstaller 依赖被误报
- 🌓 **浅 / 深双主题**：一键切换，通过 os.execv 重启进程换肤
- 📂 **数据本地化**：所有用户数据落到 `%TEMP%\XSafe\`，跨会话存活

---

## 🚀 快速开始

### 方式一：直接下载预编译 exe（推荐）

从 [Releases](https://github.com/max257026-svg/X-Safe/releases) 页面下载最新版本：
- 解压 `XSafe_v*.zip`
- 双击 `XSafe.exe` 即可运行
- 数据目录：`%TEMP%\XSafe\`

### 方式二：从源码运行

```bash
# 克隆项目
git clone https://github.com/max257026-svg/X-Safe.git
cd X-Safe

# 创建虚拟环境
python -m venv .venv
.venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 运行
python main.py
```

### 方式三：从源码打包成 exe

```bash
# 安装 PyInstaller
pip install pyinstaller

# 一键打包（生成 dist\XSafe\XSafe.exe）
pyinstaller main.spec --noconfirm --clean
```

> ⚠️ **PyInstaller 缓存陷阱**：每次改完代码后必须 `rm -rf build/ dist/`，否则可能用旧代码打包。

---

## 📂 项目结构

```
X-Safe/
├── main.py                  # GUI 主程序（tkinter）
├── main.spec                # PyInstaller 打包配置
├── requirements.txt         # 依赖清单
├── xsafe.ico                # 应用图标
├── LICENSE                  # MIT 许可证
├── README.md                # 本文件
├── .gitignore               # Git 忽略规则
│
├── src/                     # 核心模块
│   ├── engine.py            # 扫描引擎 + ScanResult + 隔离区
│   ├── ai_engine.py         # AI 自学习引擎
│   ├── cloud_engine.py      # 云端查杀（360云 + VirusTotal）
│   ├── monitor.py           # 文件系统实时监控
│   ├── registry_monitor.py  # 注册表 HOOK 监控
│   ├── process_monitor.py   # 进程行为监控
│   ├── whitelist.py         # 白名单引擎 + 自保护
│   ├── recovery.py          # 勒索恢复 + 永恒之蓝检测
│   ├── self_check.py        # 主动防御自检
│   ├── boot_guard.py        # 引导区（MBR/VBR）保护
│   └── toast_notification.py# ThreatToast 弹窗系统
│
├── data/                    # 数据/资源文件
│   ├── signatures.json      # 病毒签名数据库
│   ├── theme_config.json    # 主题配置
│   ├── cloud_config.json    # 云查杀配置
│   ├── cloud_cache.json     # 云查杀缓存
│   ├── ai_learning.db       # AI 学习数据库种子
│   ├── hosts_backup.txt     # hosts 文件备份
│   └── quarantine/          # 隔离区（空目录）
│
├── docs/                    # 项目文档
│   ├── architecture.md      # 架构设计
│   ├── build.md             # 打包说明
│   └── screenshots/         # 截图
│
├── tests/                   # 单元测试
│   └── test_engine.py
│
└── .github/
    └── workflows/
        └── build.yml        # CI: 自动打包 Windows exe
```

---

## 🏗️ 技术架构

### 三引擎联动

```
                   ┌──────────────┐
                   │  特征引擎     │  哈希签名 + 模式匹配 + YARA 风格
                   └──────┬───────┘
                          │ ConfidenceScore
                          ▼
┌──────────┐      ┌──────────────┐      ┌──────────┐
│ 扫描器    │ ───▶ │  AI 引擎     │ ───▶ │  融合评分  │ ──▶ 最终判定
└──────────┘      └──────────────┘      └──────────┘
                          │                      ▲
                          │                      │
                   ┌──────┴───────┐              │
                   │  云端引擎     │ ─────────────┘
                   │  (可选)      │  360云 + VirusTotal
                   └──────────────┘
```

### 主动防御体系

- **文件系统监控**：watchdog（实时）+ PollingObserver（系统目录兜底）
- **注册表监控**：Run / IFEO / Winlogon Shell / AppInit_DLLs / Userinit 关键项
- **引导区保护**：MBR / VBR 哈希快照，发现篡改立即告警
- **进程行为**：异常父子进程、DLL 注入、批量加密写文件实时拦截
- **系统敏感文件**：hosts、计划任务、启动项、卷影副本、SAM

### ThreatToast 弹窗系统

- 屏幕右下方 420x340 Toplevel 弹窗（无边框，overrideredirect）
- **累积摘要弹窗**（手动扫描）：狂涌 500+ 威胁时每 1.5s 弹 1 个「🚨 扫描发现 N 个威胁」
- **单条带按钮**（实时监控）：「🗑 删除 / 🔍 自检 / ✕ 忽略」

详见 [docs/architecture.md](docs/architecture.md)

---

## 🎮 使用指南

### 1. 快速扫描
点击「⚡ 快速扫描」按钮，自动扫描关键目录（下载/桌面/文档/临时文件）。

### 2. 高级查杀（三引擎联动）
点击「🔥 高级查杀」按钮，对全盘进行深度扫描，调用本地+AI+云端三个引擎。

### 3. 自定义扫描
点击「📁 自定义扫描」按钮，选择任意文件夹进行扫描。

### 4. 实时防护
实时防护页面有 6 个子模块复选框：
- ✅ 标准实时监控
- ✅ 解压/下载监控
- ✅ 注册表监控
- ✅ 引导区监控
- ✅ 系统敏感文件监控
- ✅ 应用异常行为监控

建议全部开启以获得最佳防护效果。

### 5. 自检
点击「自检」按钮，一键确认防护体系健康度：
- 隔离区完整性
- 引导区基线对比
- 注册表关键项巡检
- 三引擎联动测试

### 6. 勒索恢复
在「逆向恢复」页面，针对常见勒索软件家族（WannaCry / EternalBlue）提供针对性恢复工具。

---

## 🛠️ 开发说明

### 数据目录（运行时自动创建）

| 平台 | 路径 |
|------|------|
| Windows (exe 模式) | `%TEMP%\XSafe\` （默认 `C:\Users\<user>\AppData\Local\Temp\XSafe\`）|
| Windows (源码模式) | `<项目根>\.userdata\` |

数据迁移：第一次启动时自动从 `%APPDATA%\XSafe\`（旧版本）迁移到 `%TEMP%\XSafe\`。

### 添加新病毒签名

编辑 `data/signatures.json`：

```json
{
  "hash_signatures": [
    {
      "md5": "你的病毒MD5",
      "sha256": "你的病毒SHA256",
      "name": "病毒名",
      "severity": "high",
      "type": "trojan",
      "description": "描述"
    }
  ],
  "pattern_signatures": [
    {
      "name": "WebShell 检测",
      "pattern": "eval\\s*\\(\\s*\\$_",
      "type": "regex",
      "severity": "critical",
      "description": "PHP 一句话木马"
    }
  ]
}
```

---

## 🧪 测试

```bash
# 单元测试
pytest tests/

# 主动防御自测（启动后 3 秒自动触发）
set XSAFE_AUTO_SCAN=1 && start "" "dist\XSafe\XSafe.exe"
```

---

## 🤝 贡献

欢迎通过以下方式贡献：
- 🐛 提交 Issue 报告 Bug
- 💡 提交 Pull Request 改进代码
- 📋 完善特征库
- 🌐 多语言支持
- 📖 改进文档

---

## 📜 许可证

本项目采用 **MIT 许可证** — 详见 [LICENSE](LICENSE)

---

## 🙏 鸣谢

| 角色 | 姓名 |
|------|------|
| 制作 | 竹影清风（ZYWind-S） |
| 出品 | 新启年工作室（NewEra Studio） |
| 鸣谢 | WinDF（室长） / 老干白 / 小青墨 / 不言而喻 |

---

## 📞 联系方式

- GitHub Issues: https://github.com/max257026-svg/X-Safe/issues
- 项目主页: https://github.com/max257026-svg/X-Safe

---

**X-Safe 安全中心** — 让每一台电脑都拥有企业级主动防御
