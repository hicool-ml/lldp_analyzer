# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LLDP Analyzer GUI.
"""

import sys
import os

block_cipher = None

target_arch = os.environ.get('PYINSTALLER_TARGET_ARCH', None)

a = Analysis(
    ['lldp_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('i18n/locales/', 'i18n/locales/'),
        ('lldp_icon.png', '.'),
        ('lldp_icon.ico', '.'),
        ('lldp_icon.icns', '.'),
        ('lldp.png', '.'),
    ],
    hiddenimports=[
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
    name='LLDP_GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=target_arch,
    codesign_identity=None,
    entitlements_file=None,
    icon='lldp_icon.ico' if sys.platform == 'win32' else 'lldp_icon.png',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='LLDP_GUI',
)

if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='LLDP_GUI.app',
        icon='lldp_icon.icns',
        bundle_identifier='com.lldp.analyzer',
        info_plist={
            'NSHighResolutionCapable': 'True',
            'LSRequiresCarbon': 'True',
            'NSAppTransportSecurity': {
                'NSAllowsArbitraryLoads': True,
            },
        },
        codesign_identity=None,
        entitlements_file='entitlements.plist',
    )
