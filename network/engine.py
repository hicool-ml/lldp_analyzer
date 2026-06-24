#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Management Engine API.

Provides unified API for network adapter operations:
- Get interface list
- Get interface info
- Set MAC address
- Restore MAC address
- Set static IP
- Enable DHCP
- Restart adapter

Handles privilege escalation internally using platform-specific methods.
"""

import os
import sys
import ctypes
from typing import List, Dict, Any, Optional, Tuple

from utils.elevator import run_elevated
from utils.elevator import is_admin
from network.backends.platform import (
    is_windows, is_linux, is_darwin
)


def _get_backend():
    """Get the appropriate backend based on platform."""
    if is_windows():
        from network.backends.windows.adapter import WindowsNetworkBackend
        return WindowsNetworkBackend()
    else:
        from network.backends.posix.adapter import PosixNetworkBackend
        return PosixNetworkBackend()


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def get_interfaces() -> List[Any]:
    """Get list of network interfaces with full info."""
    be = _get_backend()
    return be.get_interfaces()


def get_interface_info(name: str) -> Optional[Any]:
    """Get detailed info for a specific interface."""
    be = _get_backend()
    return be.get_interface_info(name)


def set_mac_address(iface_name: str, mac: str) -> Tuple[bool, str]:
    """Set MAC address on an interface.
    
    Returns: (success, error_message)
    """
    if not is_admin():
        exit_code = run_elevated(["--elevated-op", "modify-mac", iface_name, mac], wait=True)
        return (exit_code == 0, "" if exit_code == 0 else "Operation failed")
    
    be = _get_backend()
    success = be.set_mac_address(iface_name, mac)
    return (success, be.last_error if not success else "")


def restore_mac(iface_name: str) -> Tuple[bool, str]:
    """Restore default MAC address on an interface.
    
    Returns: (success, error_message)
    """
    if not is_admin():
        exit_code = run_elevated(["--elevated-op", "restore-mac", iface_name], wait=True)
        return (exit_code == 0, "" if exit_code == 0 else "Operation failed")
    
    be = _get_backend()
    success = be.restore_mac(iface_name)
    return (success, be.last_error if not success else "")


def set_static_ip(iface_name: str, ip: str, mask: str, 
                  gateway: str = "", dns: List[str] = None) -> Tuple[bool, str]:
    """Set static IP configuration on an interface.
    
    Returns: (success, error_message)
    """
    if not is_admin():
        args = ["--elevated-op", "set-static", iface_name, ip, mask]
        if gateway:
            args.append(gateway)
        if dns:
            args.extend(dns)
        exit_code = run_elevated(args, wait=True)
        return (exit_code == 0, "" if exit_code == 0 else "Operation failed")
    
    be = _get_backend()
    success = be.set_static_ip(iface_name, ip, mask, gateway, dns)
    return (success, be.last_error if not success else "")


def set_dhcp(iface_name: str) -> Tuple[bool, str]:
    """Enable DHCP on an interface.
    
    Returns: (success, error_message)
    """
    if not is_admin():
        exit_code = run_elevated(["--elevated-op", "set-dhcp", iface_name], wait=True)
        return (exit_code == 0, "" if exit_code == 0 else "Operation failed")
    
    be = _get_backend()
    success = be.set_dhcp(iface_name)
    return (success, be.last_error if not success else "")


def restart_interface(iface_name: str) -> Tuple[bool, str]:
    """Restart an interface.
    
    Returns: (success, error_message)
    """
    if not is_admin():
        exit_code = run_elevated(["--elevated-op", "restart-adapter", iface_name], wait=True)
        return (exit_code == 0, "" if exit_code == 0 else "Operation failed")
    
    be = _get_backend()
    success = be.restart_interface(iface_name)
    return (success, be.last_error if not success else "")


# -----------------------------------------------------------------------------
# Command-line handler for elevated operations
# -----------------------------------------------------------------------------

def handle_elevated_op(args: List[str]) -> int:
    """Handle elevated operations when launched with --elevated-op flag."""
    if not args:
        print("Error: No operation specified", file=sys.stderr)
        return 1
    
    # Determine project root based on whether we're running as compiled EXE or source
    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        # In compiled EXE, use the directory containing the EXE
        project_root = os.path.dirname(sys.executable)
        meipass = getattr(sys, '_MEIPASS', '')
    else:
        # In source mode, use the project directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        meipass = ''
    
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    if meipass and meipass not in sys.path:
        sys.path.insert(0, meipass)
    
    be = _get_backend()
    op = args[0]
    
    try:
        if op == "modify-mac":
            if len(args) < 3:
                print("Error: Usage: modify-mac <iface_name> <mac>", file=sys.stderr)
                return 1
            iface_name, mac = args[1], args[2]
            ok = be.set_mac_address(iface_name, mac)
            return 0 if ok else 1
        
        elif op == "restore-mac":
            if len(args) < 2:
                print("Error: Usage: restore-mac <iface_name>", file=sys.stderr)
                return 1
            iface_name = args[1]
            ok = be.restore_mac(iface_name)
            return 0 if ok else 1
        
        elif op == "restart-adapter":
            if len(args) < 2:
                print("Error: Usage: restart-adapter <iface_name>", file=sys.stderr)
                return 1
            iface_name = args[1]
            ok = be.restart_interface(iface_name)
            return 0 if ok else 1
        
        elif op == "set-static":
            if len(args) < 4:
                print("Error: Usage: set-static <name> <ip> <mask> [gateway] [dns...]", file=sys.stderr)
                return 1
            name, ip, mask = args[1], args[2], args[3]
            gw = args[4] if len(args) > 4 else ""
            dns = args[5:] if len(args) > 5 else []
            ok = be.set_static_ip(name, ip, mask, gw, dns if dns else None)
            return 0 if ok else 1
        
        elif op == "set-dhcp":
            if len(args) < 2:
                print("Error: Usage: set-dhcp <name>", file=sys.stderr)
                return 1
            name = args[1]
            ok = be.set_dhcp(name)
            return 0 if ok else 1
        
        else:
            print(f"Error: Unknown operation: {op}", file=sys.stderr)
            return 1
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


# For backwards compatibility with subprocess calls
import subprocess