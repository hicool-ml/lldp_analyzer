# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LLDP Analyzer CLI.
"""

import sys
import os

block_cipher = None

a = Analysis(
    ['lldp.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('i18n/locales/', 'i18n/locales/'),
    ],
    hiddenimports=[
        'utils.adapter_scanner',
        'utils.capture_engine',
        'utils.elevator',
        'utils.hexdump',
        'utils.interface_finder',
        'utils.link_monitor',
        'utils.lldp_sender',
        'utils.packet_capture',
        'utils.platform_utils',
        'utils.protocol_parser',
        'network.backends.windows.adapter',
        'network.backends.macos.adapter',
        'network.backends.posix.adapter',
        'decoders.cisco_decoder',
        'decoders.h3c_decoder',
        'decoders.huawei_decoder',
        'decoders.juniper_decoder',
        'decoders.ruijie_decoder',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'psutil',
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
    name='LLDP_CLI',
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
    name='LLDP_CLI',
)
