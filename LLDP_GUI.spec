# -*- mode: python ; coding: utf-8 -*-
import sys, os

block_cipher = None
spec_dir = os.path.abspath(os.path.curdir)

a = Analysis(
    ['lldp_gui.py'],
    pathex=[spec_dir],
    binaries=[],
    datas=[
        ('i18n/locales/', 'i18n/locales/'),
        ('lldp_icon.png', '.'), ('lldp_icon.ico', '.'),
        ('lldp_icon.icns', '.'), ('lldp.png', '.'),
        ('runtime/', 'runtime/'),
        ('utils/', 'utils/'),
        ('decoders/', 'decoders/'),
        ('network/', 'network/'),
        ('ui/', 'ui/'),
        ('engine/', 'engine/'),
        ('db/', 'db/'),
        ('vendor_dispatcher.py', '.'),
    ],
    hiddenimports=[
        'utils.adapter_scanner', 'utils.capture_backend', 'utils.capture_engine',
        'runtime', 'runtime.checker', 'runtime.models', 'runtime.macos', 'runtime.linux', 'runtime.windows', 'utils.elevator',
        'utils.hexdump', 'utils.interface_finder', 'utils.link_monitor',
        'utils.lldp_sender', 'utils.packet_capture', 'utils.platform_utils',
        'utils.protocol_parser',
        'decoders.cisco_decoder', 'decoders.h3c_decoder', 'decoders.huawei_decoder',
        'decoders.juniper_decoder', 'decoders.ruijie_decoder',
        'network.backends.macos.adapter', 'network.backends.posix.adapter',
        'network.backends.windows.adapter', 'network.core.interfaces',
        'engine.decision_engine', 'engine.port_profile', 'engine.api',
        'db.database',
        'ui.main_window', 'ui.capture_page', 'ui.history_page',
        'ui.network_page', 'ui.widgets', 'ui.styles',
        'i18n.config', 'i18n.translations',
        'scapy',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['_import_all.py'],
    excludes=['psutil'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True, name='LLDP_GUI',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=True,
    console=False, disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None,
    icon='lldp_icon.ico' if sys.platform == 'win32' else 'lldp_icon.png',
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=True, upx_exclude=[], name='LLDP_GUI',
)

if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='LLDP_GUI.app',
        icon='lldp_icon.icns',
        bundle_identifier='com.lldp.analyzer',
        info_plist={
            'NSHighResolutionCapable': True,
            'CFBundleDisplayName': 'LLDP Analyzer',
            'CFBundleName': 'LLDP_GUI',
            'CFBundleExecutable': 'LLDP_GUI',
            'CFBundleShortVersionString': '2.0.0',
            'CFBundleVersion': '2.0.0',
            'CFBundlePackageType': 'APPL',
            'CFBundleInfoDictionaryVersion': '6.0',
            'NSHumanReadableCopyright': 'Copyright 2024 LLDP Analyzer',
            'LSMinimumSystemVersion': '10.13',
            'NSAppTransportSecurity': {'NSAllowsArbitraryLoads': True},
            'NSRequiresAquaSystemAppearance': False,
        },
        codesign_identity='-',
        entitlements_file='entitlements.plist',
    )
