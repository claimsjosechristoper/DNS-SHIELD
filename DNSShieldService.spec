# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['windows_service.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['win32timezone', 'win32service', 'win32serviceutil', 'win32event', 'win32file', 'win32pipe', 'win32security', 'cryptography', 'hosted_management.policy_verifier', 'wfp_manager', 'network_manager'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'matplotlib', 'scipy'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DNSShieldService',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DNSShieldService',
)
