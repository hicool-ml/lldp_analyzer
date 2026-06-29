# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LLDP Helper CLI.
Used by GUI for privileged operations on macOS.
"""

import sys

block_cipher = None

a = Analysis(
    ['lldp_helper.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'network.backends.macos.adapter',
        'network.backends.posix.adapter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'psutil',
        'tkinter',
    ],
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
    name='LLDP_Helper',
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
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='LLDP_Helper',
)