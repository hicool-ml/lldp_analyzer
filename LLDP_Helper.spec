# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LLDP Helper CLI.
Used by GUI for privileged operations on macOS.
FIXED: Added pathex to ensure network modules are found during build.
"""

import sys
import os

block_cipher = None

spec_dir = os.path.dirname(os.path.abspath(__file__))

a = Analysis(
    ['lldp_helper.py'],
    pathex=[spec_dir],
    binaries=[],
    datas=[],
    hiddenimports=[
        'network',
        'network.__init__',
        'network.backend',
        'network.engine',
        'network.platform',
        'network.elevated_op',
        'network.backends',
        'network.backends.__init__',
        'network.backends.macos',
        'network.backends.macos.adapter',
        'network.backends.posix',
        'network.backends.posix.adapter',
        'network.core',
        'network.core.interfaces',
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
