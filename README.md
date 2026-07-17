# X-Safe

> 非常高级的杀毒软件 🛡️

X-Safe 是一款基于 Python 的轻量级主动防御杀毒软件，集**签名查杀、启发式分析、AI 自学习、云查杀、实时防护、进程行为监控、隔离区**于一体，并带有系统托盘与深浅双主题图形界面。

---

## ✨ 功能特性

- **多引擎扫描**
  - 签名查杀（`signatures.json` 特征库）
  - 启发式规则 + 熵（entropy）分析，识别加壳 / 混淆的可疑文件
  - 按威胁等级分级：`SAFE` / `SUSPICIOUS` / `HIGH_RISK` / `MALICIOUS`
- **AI 自学习引擎**（`ai_engine.py`）
  - 贝叶斯置信度评分，对未知文件给出风险概率
  - 用户每次「确认威胁 / 标记误报 / 标记安全」的反馈都会**训练本地模型**，误报率持续下降
  - 上下文感知：文件位置、来源影响最终判定
- **云查杀**（`cloud_engine.py`）
  - 本地特征库 + 云端缓存（`cloud_cache.json` / `cloud_config.json`）协同判定
- **实时防护**（`monitor.py`，基于 `watchdog`）
  - 监控指定目录的新增 / 修改文件，命中即触发右下角弹窗告警
- **进程行为监控**（`process_monitor.py`）
  - 检测从可疑目录启动的程序、危险命令行参数与高危行为（`psutil` 可选增强）
- **隔离区（Quarantine）**
  - 命中威胁的文件可移入隔离区，避免误删重要文件
- **系统托盘 + 弹窗通知**（`toast_notification.py`，基于 `pystray`）
  - 轻量、非侵入的威胁提示
- **深浅双主题 GUI**（`main.py`，基于 `tkinter`）
  - GitHub Light 风格浅色主题 + 原配深色主题，可一键切换

---

## 📂 目录结构

```
X-Safe/
├── main.py                    # 主程序 / GUI 入口（深浅双主题）
├── engine.py                  # 核心扫描引擎（签名 + 启发式 + 熵分析）
├── ai_engine.py               # AI 自学习引擎（贝叶斯置信度 + 反馈学习）
├── cloud_engine.py            # 云查杀引擎
├── monitor.py                 # 实时文件监控（watchdog）
├── process_monitor.py         # 进程行为监控
├── toast_notification.py      # 系统托盘 / 弹窗通知
├── signatures.json            # 本地特征库
├── cloud_config.json          # 云查杀配置
├── cloud_cache.json           # 云查杀结果缓存
├── theme_config.json          # 主题偏好
├── xsafe.ico                  # 程序图标
├── quarantine/                # 隔离区（运行时生成）
├── requirements.txt           # 依赖
├── XSafe_ActiveDefense_Test.bat  # 主动防御自测脚本（无害）
└── test_webshell.php          # WebShell 测试样本
```

> 注：`.venv/`、`.idea/`、`__pycache__/` 与运行时数据库、隔离区内容已通过 `.gitignore` 排除，不会进入版本库。

---

## 🚀 安装

要求 **Python 3.8+**，推荐在 **Windows** 上运行（托盘与弹窗依赖 Windows 环境）。

```bash
# 1. 克隆仓库
git clone https://github.com/max257026-svg/X-Safe.git
cd X-Safe

# 2. 创建并激活虚拟环境（可选但推荐）
python -m venv .venv
.venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt
```

`requirements.txt`：

| 依赖 | 作用 |
| --- | --- |
| `watchdog` | 实时文件监控 |
| `pystray` | 系统托盘图标 |
| `pillow` | 图标 / 图像处理 |
| `psutil`（可选） | 增强进程行为监控 |
| `pywin32`（可选） | Windows 系统级 API，增强检测能力 |

---

## 🖥️ 使用

```bash
python main.py
```

- 在图形界面中选择目录 / 文件进行扫描
- 最小化后常驻系统托盘，实时防护在后台运行
- 右键托盘图标可进行「主动防御自测」等操作
- 主题可在界面内切换浅色 / 深色

### 主动防御自测

双击 `XSafe_ActiveDefense_Test.bat`（**完全无害**），或将它复制到 `Downloads` 目录，X-Safe 实时防护会扫描并弹出右下角告警，用于验证主动防御是否生效。

---

## 🧪 测试样本

仓库附带几个用于验证检测能力的样本：

- `test_webshell.php` —— WebShell 测试样本
- `XSafe_ActiveDefense_Test.bat` —— 主动防御自测脚本（含触发标记串）

> ⚠️ 原压缩包中的 `eicar_test.txt`（EICAR 标准杀软测试串）**未纳入本仓库**：其字面内容会被 Windows Defender 等杀软在写入 / 检出时直接隔离，会导致 Windows 用户克隆后文件丢失。如需本地测试，请自行从 [EICAR 官网](https://www.eicar.org/download-anti-malware-testfile/) 下载。

---

## ⚙️ 配置文件

| 文件 | 说明 |
| --- | --- |
| `signatures.json` | 本地恶意特征库，可手动扩充 |
| `cloud_config.json` | 云查杀开关 / 地址等配置 |
| `cloud_cache.json` | 云查杀结果本地缓存 |
| `theme_config.json` | 界面主题偏好（light / dark） |

---

## ⚠️ 免责声明

X-Safe 为学习与演示用途的轻量级防护工具，**不能替代专业商业杀软**。请勿将其用于生产环境的关键安全防护。
