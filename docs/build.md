# X-Safe 安全中心 — 打包指南

> 本文面向维护者，解释如何从源码打包成 Windows exe。

---

## 🏗️ 快速打包

```bash
# 1. 清理旧 build（必须！PyInstaller --clean 不会清 build/ 目录）
rm -rf build/ dist/

# 2. 打包
pyinstaller main.spec --noconfirm --clean

# 3. 输出位置
# dist/XSafe/XSafe.exe        — 主程序
# dist/XSafe/_internal/        — 依赖库
# dist/XSafe/signatures.json   — 病毒签名
# dist/XSafe/xsafe.ico         — 图标
# ... 等等
```

---

## ⚠️ PyInstaller 缓存陷阱

**关键问题**：`--clean` 不会清空 `build/` 目录！如果只跑 `pyinstaller --clean`，可能用旧代码打包！

```bash
# ❌ 错误做法（用了 build 缓存）
pyinstaller main.spec --noconfirm --clean

# ✅ 正确做法（强制全量重建）
rm -rf build/ dist/  # ← 必须！
pyinstaller main.spec --noconfirm --clean
```

### 验证新代码是否进了 exe
打包后**必须**验证关键代码字符串是否真的进了 exe：

```bash
# 检查 PYZ 缓存文件
grep "累积摘要" build/main/PYZ-00.pyz
# 如果没找到，说明 build 缓存里有旧版本

# 检查 _internal 目录下的 PYZ
grep -r "_tree_results\[item_id\] = result" dist/XSafe/_internal/
# 如果没找到，说明 exe 里没包含最新代码
```

---

## 📦 main.spec 配置说明

`main.spec` 是 PyInstaller 的打包配置：

```python
datas = [
    ('signatures.json', '.'),    # 病毒签名
    ('ai_learning.db', '.'),     # AI 学习数据库种子
    ('theme_config.json', '.'),  # 主题配置
    ('cloud_cache.json', '.'),   # 云查杀缓存
    ('cloud_config.json', '.'),  # 云查杀配置
    ('hosts_backup.txt', '.'),   # hosts 备份
    ('xsafe.ico', '.'),          # 应用图标
    ('quarantine', 'quarantine'),# 隔离区
]

hiddenimports = [
    'watchdog',                  # 文件监控
    'pystray',                   # 系统托盘
    'PIL',                       # 图像
    'self_check', 'boot_guard',  # 自检 + 引导区保护
    'registry_monitor', 'winreg',# 注册表监控
    # ... 等
]
```

---

## 🐛 常见问题

### Q1: 打包后 exe 启动报 "ModuleNotFoundError: No module named 'xyz'"
**原因**：模块没在 `hiddenimports` 列表中。

**解决**：把模块名加到 `main.spec` 的 `hiddenimports`，重新打包。

### Q2: 启动后报 "database is locked"
**原因**：exe 模式的数据目录是 `_internal/.userdata` 而不是 `%TEMP%\XSafe`。

**解决**：
- 确认 `_get_data_dir()` 用了 `sys.frozen`（不是 `sys._frozen`）
- 确认打包时带了 `ai_learning.db` 数据文件

### Q3: ThreatToast 弹窗不显示
**原因**：
1. PyInstaller 用了 build 缓存（最常见）
2. max_toasts 被狂涌覆盖（手动扫描 500+ 威胁时）
3. toast_manager 没初始化

**解决**：
- `rm -rf build/ dist/` 重新打包
- 手动扫描走累积摘要弹窗（v28 修复）
- 检查 `%TEMP%\XSafe\poll_debug.log` 里的弹窗触发记录

### Q4: 实时监控失效
**原因**：watchdog 子线程 join 卡 UI 线程。

**解决**：后台 daemon 线程 + PollingObserver 兜底 + try/except 隔离失败路径。

---

## 🚀 自动化发布

项目配了 GitHub Actions CI（`.github/workflows/build.yml`），推送 tag 自动打包：

```bash
git tag v1.0.0
git push origin v1.0.0
# 自动构建 → 自动创建 Release
```

CI 在 `windows-latest` runner 上跑，输出 `XSafe_v1.0.0.zip`。

---

## 📋 发布前检查清单

- [ ] `rm -rf build/ dist/` 后重新打包
- [ ] 验证 PYZ 缓存里有新代码（grep 关键字）
- [ ] 启动 exe，跑快速扫描，确认 ThreatToast 弹窗
- [ ] 检查 `%TEMP%\XSafe\poll_debug.log` 有心跳
- [ ] 启动实时防护，确认子模块复选框不崩
- [ ] 关于页显示正确（制作/出品/鸣谢）
- [ ] 主题切换正常工作
- [ ] 病毒扫描结果正常显示
- [ ] 隔离/恢复/删除功能正常
- [ ] 引导区基线建立正常
- [ ] 自检程序正常
- [ ] 勒索恢复工具正常

---

## 🔧 调试模式

```cmd
# 启动 5 秒后自动弹 ThreatToast（验证弹窗链路）
set XSAFE_DEBUG_TOAST=1
start "" "dist\XSafe\XSafe.exe"

# 启动 3 秒后自动跑快速扫描
set XSAFE_AUTO_SCAN=1
start "" "dist\XSafe\XSafe.exe"
```

---

## 📚 进一步阅读

- [architecture.md](architecture.md) — 架构设计
- [README.md](../README.md) — 用户使用指南
- [PyInstaller 官方文档](https://pyinstaller.org/en/stable/)
