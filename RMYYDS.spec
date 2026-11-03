# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['d:\\test\\logcat\\logcat_viewer.py'],
    pathex=[],
    binaries=[],
    datas=[('d:\\test\\logcat\\app_icon.ico', '.'), ('d:\\test\\logcat\\app_icon.png', '.'), ('d:\\test\\logcat\\splash_logo.jpg', '.'), ('d:\\test\\logcat\\windivert', 'windivert'), ('d:\\test\\logcat\\scrcpy', 'scrcpy')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='RMYYDS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['d:\\test\\logcat\\app_icon.ico'],
)
