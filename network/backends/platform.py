#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-platform detection and abstraction module.

Provides:
- Platform detection (windows, linux, darwin)
- Common abstractions for platform-specific operations
- Privilege escalation helpers
"""

import os
import ctypes
import sys
import subprocess
from enum import Enum
from typing import Optional, Callable, Any

# --- Scapy imports are done lazily to avoid ipconfig_get_packet errors on macOS ---
_scapy_imported = False
get_windows_if_list = None
get_working_iface = None
get_if_list = None
get_if_hwaddr = None


def _import_scapy():
    """Lazy import of Scapy modules to avoid errors on macOS at startup."""
    global _scapy_imported, get_windows_if_list, get_working_iface, get_if_list, get_if_hwaddr
    if _scapy_imported:
        return
    _scapy_imported = True
    try:
        from scapy.arch.windows import get_windows_if_list as _gwil
        from scapy.arch.common import get_working_iface as _gwi
        from scapy.all import get_if_list as _gil, get_if_hwaddr as _gih
        get_windows_if_list = _gwil
        get_working_iface = _gwi
        get_if_list = _gil
        get_if_hwaddr = _gih
    except ImportError:
        pass


class Platform(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    DARWIN = "darwin"
    UNKNOWN = "unknown"


def get_platform() -> Platform:
    """Detect the current platform."""
    if sys.platform == "win32":
        return Platform.WINDOWS
    elif sys.platform == "darwin":
        return Platform.DARWIN
    elif sys.platform.startswith("linux"):
        return Platform.LINUX
    else:
        return Platform.UNKNOWN


_current_platform = get_platform()


def is_windows() -> bool:
    return _current_platform == Platform.WINDOWS


def is_linux() -> bool:
    return _current_platform == Platform.LINUX


def is_darwin() -> bool:
    return _current_platform == Platform.DARWIN


def is_posix() -> bool:
    return _current_platform in (Platform.LINUX, Platform.DARWIN)


def _run_cmd(cmd: list, timeout: int = 10, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, platform-agnostic."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", "Command timed out")
    except Exception as e:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", str(e))





def show_message_box(title: str, message: str, kind: str = "info") -> None:
    """Show a platform-appropriate message box.

    kind: 'info', 'warning', 'error'
    """
    if is_windows():
        flags = {"info": 0x40, "warn": 0x30, "error": 0x10}.get(kind, 0x40)
        ctypes.windll.user32.MessageBoxW(0, message, title, flags)
    elif is_darwin():
        icon_map = {"info": "note", "warn": "caution", "error": "stop"}
        icon = icon_map.get(kind, "note")
        script = f'display dialog "{message}" with title "{title}" with icon {icon}'
        subprocess.run(["osascript", "-e", script], capture_output=True)
    else:
        # Linux: use zenity or fallback to print
        try:
            icon_map = {"info": "info", "warn": "warning", "error": "error"}
            icon = icon_map.get(kind, "info")
            subprocess.run(
                ["zenity", f"--{kind}", f"--title={title}", f"--text={message}"],
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"{title}: {message}")


# scapy arch import helper
def get_scapy_if_list():
    """Get network interfaces using Scapy, platform-aware."""
    _import_scapy()
    if is_windows():
        if get_windows_if_list is None:
            return []
        return get_windows_if_list()
    else:
        if get_if_list is None:
            return []
        # For POSIX, we use get_if_list but need to enrich with more info
        ifaces = []
        for name in get_if_list():
            try:
                if get_if_hwaddr is not None:
                    mac = get_if_hwaddr(name)
                else:
                    mac = ""
                ifaces.append({
                    "name": name,
                    "mac": mac,
                    "description": name,
                    "guid": name,
                })
            except Exception:
                ifaces.append({
                    "name": name,
                    "mac": "",
                    "description": name,
                    "guid": name,
                })
        return ifaces


def get_scapy_hwaddr(iface_name: str) -> str:
    """Get hardware address for an interface using Scapy."""
    _import_scapy()
    if get_if_hwaddr is None:
        return ""
    return get_if_hwaddr(iface_name)


# Network utility commands (platform-specific)
def get_network_commands() -> dict:
    """Return platform-specific network utility commands."""
    if is_windows():
        return {
            "ifconfig": "netsh",
            "ip": "netsh",
            "restart_interface": None,  # Uses cfgmgr32
        }
    elif is_darwin():
        return {
            "ifconfig": "ifconfig",
            "ip": "ifconfig",
            "restart_interface": "ifconfig",
        }
    else:  # Linux
        return {
            "ifconfig": "ifconfig",
            "ip": "ip",
            "restart_interface": "ip",
        }


def get_pcap_library() -> Optional[str]:
    """Detect available pcap library."""
    if is_windows():
        # Check for Npcap
        try:
            import winreg
            for key_path in [r"SOFTWARE\Npcap", r"SOFTWARE\Wow6432Node\Npcap"]:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    return "npcap"
                except FileNotFoundError:
                    pass
            # Check for WinPcap
            for key_path in [r"SOFTWARE\WinPcap", r"SOFTWARE\Wow6432Node\WinPcap"]:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    return "winpcap"
                except FileNotFoundError:
                    pass
        except Exception:
            pass
        return None
    else:
        # On POSIX, we assume libpcap is available
        return "libpcap"
