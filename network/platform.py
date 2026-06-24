#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Platform detection and backend factory.
"""

import sys
from typing import Type
from network.backend import NetworkBackend


def is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == "win32"


def is_darwin() -> bool:
    """Check if running on macOS."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """Check if running on Linux."""
    return sys.platform.startswith("linux")


def get_backend() -> NetworkBackend:
    """Get the appropriate NetworkBackend for the current platform.
    
    Returns:
        NetworkBackend instance for the current platform.
    """
    if is_windows():
        from network.backends.windows.adapter import WindowsNetworkBackend
        return WindowsNetworkBackend()
    elif is_darwin():
        from network.backends.macos.adapter import MacOSNetworkBackend
        return MacOSNetworkBackend()
    elif is_linux():
        from network.backends.linux.adapter import LinuxNetworkBackend
        return LinuxNetworkBackend()
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")


def get_backend_class() -> Type[NetworkBackend]:
    """Get the NetworkBackend class for the current platform.
    
    Returns:
        NetworkBackend class for the current platform.
    """
    if is_windows():
        from network.backends.windows.adapter import WindowsNetworkBackend
        return WindowsNetworkBackend
    elif is_darwin():
        from network.backends.macos.adapter import MacOSNetworkBackend
        return MacOSNetworkBackend
    elif is_linux():
        from network.backends.linux.adapter import LinuxNetworkBackend
        return LinuxNetworkBackend
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")