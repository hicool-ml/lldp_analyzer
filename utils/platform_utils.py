#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-platform utilities for Windows, macOS, and Linux."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional


# =========================================================================
# Platform Detection
# =========================================================================

def is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == "win32"


def is_macos() -> bool:
    """Check if running on macOS."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """Check if running on Linux."""
    return sys.platform.startswith("linux")


def get_platform_name() -> str:
    """Return human-readable platform name."""
    if is_windows():
        return "Windows"
    elif is_macos():
        return "macOS"
    elif is_linux():
        return "Linux"
    else:
        return f"Unknown ({sys.platform})"


def get_user_data_dir() -> str:
    """Get the platform-specific user data directory for the application.
    
    Creates the directory if it doesn't exist.
    
    Returns:
        Path to the user data directory.
    """
    if is_windows():
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        data_dir = os.path.join(base, "LLDP Analyzer")
    elif is_macos():
        base = os.path.expanduser("~/Library/Application Support")
        data_dir = os.path.join(base, "LLDP Analyzer")
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        data_dir = os.path.join(base, "lldp-analyzer")
    
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


# =========================================================================
# Packet Capture Support Detection
# =========================================================================

def check_runtime_environment() -> dict:
    """Check all runtime dependencies for LLDP/CDP capture.

    Returns a dict with keys:
        scapy_installed : bool
        scapy_version   : str (empty if not installed)
        capture_ready   : bool
        issues          : list[str]   (human-readable problems)
        fix_hints       : list[str]   (platform-specific install commands)
    """
    issues: list[str] = []
    fix_hints: list[str] = []

    # --- Scapy ---
    scapy_installed = False
    scapy_version = ""
    try:
        import scapy
        scapy_installed = True
        scapy_version = getattr(scapy, "__version__", "")
    except ImportError:
        issues.append("scapy is not installed")
        if is_macos():
            fix_hints.append("Install scapy:  pip3 install scapy")
        elif is_linux():
            fix_hints.append("Install scapy:  sudo pip3 install scapy")
        else:
            fix_hints.append("Install scapy:  pip install scapy")

    # --- Platform-specific capture checks ---
    if is_macos():
        # BPF device must exist and be readable
        bpf_found = any(os.path.exists(f"/dev/bpf{i}") for i in range(16))
        if not bpf_found:
            issues.append("No /dev/bpf* devices found")
            fix_hints.append("This should not happen on macOS. "
                             "Try: sudo chmod o+r /dev/bpf*")

        # Root check — capture requires root unless ChmodBPF is set up
        if os.geteuid() != 0:
            # Check if any bpf device is readable without root
            bpf_readable = False
            for i in range(16):
                try:
                    fd = os.open(f"/dev/bpf{i}", os.O_RDONLY)
                    os.close(fd)
                    bpf_readable = True
                    break
                except OSError:
                    continue
            if not bpf_readable:
                issues.append("BPF devices require root access")
                fix_hints.append("Run with sudo, or install ChmodBPF:  "
                                 "brew install --cask chmodbpf")

    elif is_linux():
        # libpcap / tcpdump
        try:
            r = subprocess.run(["which", "tcpdump"],
                               capture_output=True, timeout=5)
            if r.returncode != 0:
                issues.append("tcpdump/libpcap not found")
                fix_hints.append("Install libpcap:  "
                                 "sudo apt install tcpdump  (Debian/Ubuntu)\n"
                                 "                sudo yum install tcpdump  (RHEL/CentOS)")
        except Exception:
            issues.append("Cannot check for tcpdump")
        # Root or capture group
        if os.geteuid() != 0:
            try:
                import grp
                groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
                if not any(g in groups for g in ("wireshark", "pcap", "packet")):
                    issues.append("Not root and not in a capture group")
                    fix_hints.append("Run with sudo, or add user to capture group:  "
                                     "sudo usermod -a -G wireshark $USER")
            except Exception:
                pass

    elif is_windows():
        cap_ok, msg = _check_windows_packet_capture()
        if not cap_ok:
            issues.append(msg)
            fix_hints.append("Install Npcap:  https://npcap.com/dist/  "
                             "(enable 'WinPcap API-compatible Mode')")

    capture_ready = len(issues) == 0
    return {
        "scapy_installed": scapy_installed,
        "scapy_version": scapy_version,
        "capture_ready": capture_ready,
        "issues": issues,
        "fix_hints": fix_hints,
    }


def print_environment_check() -> bool:
    """Print a human-readable environment check and return True if ready."""
    env = check_runtime_environment()
    if env["capture_ready"]:
        scapy_ver = f" {env['scapy_version']}" if env["scapy_version"] else ""
        print(f"[OK] Environment ready (scapy{scapy_ver})")
        return True

    print("[!] Environment check found issues:")
    for issue in env["issues"]:
        print(f"    - {issue}")
    if env["fix_hints"]:
        print()
        print("    To fix:")
        for hint in env["fix_hints"]:
            print(f"      {hint}")
        print()
    return False


# =========================================================================

def check_packet_capture_support() -> tuple[bool, str]:
    """Check if packet capture is available on this platform.
    
    Returns
    -------
    tuple[bool, str]
        (is_supported, message)
    """
    if is_windows():
        return _check_windows_packet_capture()
    elif is_macos():
        return _check_macos_packet_capture()
    elif is_linux():
        return _check_linux_packet_capture()
    else:
        return False, f"Unknown platform: {sys.platform}"


def _check_windows_packet_capture() -> tuple[bool, str]:
    """Check for Npcap or WinPcap on Windows."""
    try:
        import winreg
    except ImportError:
        return False, "Cannot import winreg on this system"

    # Check Npcap
    for hive_path in [
        r"SOFTWARE\Npcap",
        r"SOFTWARE\Wow6432Node\Npcap",
    ]:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive_path)
            return True, "Npcap is installed"
        except FileNotFoundError:
            continue

    # Check WinPcap
    for hive_path in [
        r"SOFTWARE\WinPcap",
        r"SOFTWARE\Wow6432Node\WinPcap",
    ]:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive_path)
            return True, "WinPcap is installed"
        except FileNotFoundError:
            continue

    return False, "Neither Npcap nor WinPcap is installed"


def _check_macos_packet_capture() -> tuple[bool, str]:
    """Check for ChmodBPF or system libpcap on macOS."""
    # Check ChmodBPF (macOS Npcap equivalent)
    for i in range(16):
        bpf_device = f"/dev/bpf{i}"
        if os.path.exists(bpf_device):
            try:
                # Check if we can read the device
                with open(bpf_device, "rb") as f:
                    return True, "ChmodBPF is installed and accessible"
            except (OSError, PermissionError):
                return False, f"ChmodBPF found but not accessible (permission denied)"

    # Check system libpcap availability
    try:
        result = subprocess.run(
            ["which", "tcpdump"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return (
                True,
                "System libpcap is available (tcpdump found)\n"
                "Note: You may need to install ChmodBPF for non-root packet capture"
            )
    except Exception:
        pass

    return (
        False,
        "ChmodBPF not found and tcpdump not available.\n"
        "Install ChmodBPF: https://github.com/Homebrew/homebrew-cask/blob/master/Casks/chmodbpf.rb"
    )


def _check_linux_packet_capture() -> tuple[bool, str]:
    """Check for libpcap and packet capture permissions on Linux."""
    # Check if tcpdump is available
    try:
        result = subprocess.run(
            ["which", "tcpdump"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            return False, "tcpdump not found. Install libpcap-dev or tcpdump package"
    except Exception as e:
        return False, f"Cannot check for tcpdump: {e}"

    # Check if we can run tcpdump (permission check)
    try:
        result = subprocess.run(
            ["sudo", "-n", "tcpdump", "-V"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return True, "libpcap is available with sudo access"
    except Exception:
        pass

    # Check if user is in packet group (Debian/Ubuntu)
    try:
        import pwd
        import grp

        current_uid = os.getuid()
        user_info = pwd.getpwuid(current_uid)
        user_groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]

        if "wireshark" in user_groups or "packet" in user_groups:
            return True, f"libpcap available (user in {user_groups} group)"
    except Exception:
        pass

    return (
        True,
        "libpcap is available but requires elevated privileges.\n"
        "Run with: sudo python3 lldp.py\n"
        "Or add user to packet group: sudo usermod -a -G wireshark $USER"
    )


# =========================================================================
# Interface Management (Platform-Specific)
# =========================================================================

def trigger_link_renegotiation(interface_name: str) -> bool:
    """Trigger link down/up on the specified interface.
    
    Parameters
    ----------
    interface_name : str
        Name of the network interface
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    if is_windows():
        return _trigger_link_renegotiation_windows(interface_name)
    elif is_macos():
        return _trigger_link_renegotiation_macos(interface_name)
    elif is_linux():
        return _trigger_link_renegotiation_linux(interface_name)
    else:
        return False


def _trigger_link_renegotiation_windows(interface_name: str) -> bool:
    """Windows: use netsh to toggle interface."""
    try:
        from utils.interface_finder import _run_netsh
        
        print(f"[1/2] Disabling interface: {interface_name}")
        r = _run_netsh(["interface", "set", "interface", interface_name, "admin=disable"])
        if r.returncode != 0:
            print(f"[ERROR] Failed to disable interface")
            return False

        import time
        time.sleep(1.0)

        print(f"[2/2] Re-enabling interface: {interface_name}")
        r = _run_netsh(["interface", "set", "interface", interface_name, "admin=enable"])
        if r.returncode != 0:
            print(f"[ERROR] Failed to enable interface")
            return False

        return True
    except Exception as e:
        print(f"[ERROR] Windows renegotiation failed: {e}")
        return False


def _trigger_link_renegotiation_macos(interface_name: str) -> bool:
    """macOS: use networksetup to toggle interface."""
    try:
        print(f"[1/2] Disabling interface: {interface_name}")
        result = subprocess.run(
            ["networksetup", "-setairportpower", interface_name, "off"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            # Try alternative method for non-airport interfaces
            result = subprocess.run(
                ["sudo", "ifconfig", interface_name, "down"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                print(f"[ERROR] Failed to disable interface")
                return False

        import time
        time.sleep(1.0)

        print(f"[2/2] Re-enabling interface: {interface_name}")
        result = subprocess.run(
            ["networksetup", "-setairportpower", interface_name, "on"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            # Try alternative method
            result = subprocess.run(
                ["sudo", "ifconfig", interface_name, "up"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                print(f"[ERROR] Failed to re-enable interface")
                return False

        return True
    except Exception as e:
        print(f"[ERROR] macOS renegotiation failed: {e}")
        return False


def _trigger_link_renegotiation_linux(interface_name: str) -> bool:
    """Linux: use ethtool or ip to toggle interface."""
    try:
        print(f"[1/2] Disabling interface: {interface_name}")
        result = subprocess.run(
            ["sudo", "ip", "link", "set", interface_name, "down"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[ERROR] Failed to disable interface: {result.stderr.decode()}")
            return False

        import time
        time.sleep(1.0)

        print(f"[2/2] Re-enabling interface: {interface_name}")
        result = subprocess.run(
            ["sudo", "ip", "link", "set", interface_name, "up"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[ERROR] Failed to re-enable interface: {result.stderr.decode()}")
            return False

        return True
    except Exception as e:
        print(f"[ERROR] Linux renegotiation failed: {e}")
        return False


# =========================================================================
# UI/Theme Utilities
# =========================================================================

def get_recommended_tkinter_theme() -> str:
    """Get the best tkinter theme for the current platform.
    
    Returns
    -------
    str
        Theme name (e.g., "aqua", "clam", "alt", "default")
    """
    try:
        import tkinter as tk
        from tkinter import ttk

        style = ttk.Style()
        available = style.theme_names()

        if is_macos():
            # macOS: prefer native aqua theme
            if "aqua" in available:
                return "aqua"
        elif is_linux():
            # Linux: prefer clam or default
            if "clam" in available:
                return "clam"
        elif is_windows():
            # Windows: prefer clam or default
            if "clam" in available:
                return "clam"

        # Fallback to default
        if "default" in available:
            return "default"

        # Last resort: use first available
        return available[0] if available else "default"
    except Exception:
        return "default"


def apply_platform_theme(root_widget) -> None:
    """Apply platform-appropriate theme to tkinter root widget.
    
    Parameters
    ----------
    root_widget : tk.Tk
        The root tkinter widget
    """
    try:
        from tkinter import ttk

        style = ttk.Style(root_widget)
        theme = get_recommended_tkinter_theme()

        if theme in style.theme_names():
            style.theme_use(theme)

        # Additional platform-specific styling
        if is_macos():
            # macOS-specific adjustments
            style.configure("TButton", padx=10, pady=5)
        elif is_linux():
            # Linux-specific adjustments
            style.configure("TButton", padx=8, pady=4)
    except Exception:
        pass


# =========================================================================
# Resource Path Utilities
# =========================================================================

def get_resource_path(relative_path: str) -> str:
    """Resolve a resource path for both source runs and PyInstaller bundles.
    
    Parameters
    ----------
    relative_path : str
        Relative path to the resource (e.g., "lldp_icon.ico")
    
    Returns
    -------
    str
        Full path to the resource
    """
    if is_macos() and hasattr(sys, "_MEIPASS"):
        # macOS app bundle (PyInstaller)
        # Resources are typically in Contents/Resources/
        base = sys._MEIPASS
    elif is_macos():
        # macOS app bundle (source)
        try:
            import Foundation
            bundle = Foundation.NSBundle.mainBundle()
            base = bundle.resourcePath()
        except Exception:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    else:
        # Windows and Linux
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    return os.path.join(base, relative_path)


# =========================================================================
# Elevation/Privilege Utilities
# =========================================================================

def request_elevation_reason() -> Optional[str]:
    """Get a human-readable reason why elevation is needed.
    
    Returns
    -------
    str or None
        Reason string, or None if already elevated
    """
    if is_windows():
        # Windows: always needs admin for interface operations
        return "Administrator privileges required for network interface operations"
    elif is_linux():
        return "Root privileges required for packet capture. Use: sudo python3 lldp.py"
    elif is_macos():
        return "Administrative privileges required for packet capture. Use: sudo python3 lldp.py"
    return None


def get_elevation_command() -> list[str]:
    """Get the appropriate elevation command for the current platform.
    
    Returns
    -------
    list[str]
        Command prefix (e.g., ["sudo", "-n"] or ["powershell", "-c", "Start-Process"])
    """
    if is_windows():
        # Windows: requires re-launch via UAC (handled separately in lldp.py)
        return []
    elif is_linux():
        # Linux: try non-interactive sudo first
        return ["sudo", "-n"]
    elif is_macos():
        # macOS: try non-interactive sudo first
        return ["sudo", "-n"]
    return []
