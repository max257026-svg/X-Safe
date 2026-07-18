# -*- mode: python ; coding: utf-8 -*-
"""X-Safe PyInstaller 打包配置（onedir，便于运行时写 ai_learning.db / trusted.json / quarantine 等）。"""

block_cipher = None

# 运行时所需数据文件：(源, 目标目录)
datas = [
    ('signatures.json', '.'),
    ('ai_learning.db', '.'),
    ('theme_config.json', '.'),
    ('cloud_cache.json', '.'),
    ('cloud_config.json', '.'),
    ('hosts_backup.txt', '.'),
    ('xsafe.ico', '.'),
    ('quarantine', 'quarantine'),
]

binaries = []

# 显式声明可能被动态加载的模块
hiddenimports = [
    'watchdog',
    'watchdog.observers',
    'watchdog.observers.polling',
    'watchdog.events',
    'pystray',
    'pystray._win32',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    # 新增模块（main.py 直接 import，这里显式声明以防静态分析遗漏）
    'self_check',
    'boot_guard',
    'registry_monitor',
    'winreg',
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='XSafe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # 无控制台黑框
    disable_windowed_traceback=False,
    icon='xsafe.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='XSafe',
)
