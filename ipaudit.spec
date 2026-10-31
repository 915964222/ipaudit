# -*- mode: python ; coding: utf-8 -*-
# ipaudit 打包配置：python -m PyInstaller --noconfirm ipaudit.spec
# 产物 dist/ipaudit.exe（单文件），挂进「我的工具大全」library 后可一键运行。
# 入口必须用 launch.py（顶层绝对导入）；ipaudit/__main__.py 的相对导入
# 在单文件模式下没有父包，会 ImportError。console=True 保留终端报告输出。

a = Analysis(
    ['launch.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'ipaudit', 'ipaudit.cli', 'ipaudit.dnsbl', 'ipaudit.collector',
        'ipaudit.judge', 'ipaudit.report', 'ipaudit.store', 'ipaudit.server',
        'ipaudit.probe_page', 'ipaudit.asn_data', 'ipaudit.models',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'PIL', 'unittest'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ipaudit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
