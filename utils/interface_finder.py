#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Physical Ethernet interface discovery and link renegotiation."""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Any

from utils.elevator import is_admin
from utils.adapter_scanner import scan_ethernet_adapters, pick_best_adapter
from utils.platform_utils import is_windows, is_macos, is_linux


def _run_netsh(args: list[str]) -> subprocess.CompletedProcess:
    """Windows only: run netsh command."""
    if not is_windows():
        raise NotImplementedError("netsh is not available on this platform")
    
    cmd = ["netsh"] + args
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="ansi",
        errors="ignore",
        timeout=10,
        creationflags=0x08000000,  # CREATE_NO_WINDOW
    )
    print(f"    returncode={r.returncode}  stdout={r.stdout.strip()!r}  stderr={r.stderr.strip()!r}")
    return r


def get_physical_ethernet_interface() -> dict[str, Any] | None:
    """Return a Scapy-friendly physical Ethernet interface record."""
    print("[1] Scanning physical Ethernet interfaces...")
    adapters = scan_ethernet_adapters()
    if not adapters:
        print("[ERROR] No suitable physical Ethernet interface was found.")
        return None

    best = pick_best_adapter(adapters)
    if best:
        sn = best.get("scapy_name", "") or "(empty)"
        print(f"[OK] Interface: {best['name']} ({best['mac']})  [scapy: {sn}]")
    return best


def trigger_link_renegotiation(interface_name: str) -> None:
    """Force a down/up cycle so the switch emits fresh LLDP/CDP frames.

    The key timing considerations:
    - The switch sends LLDP/CDP frames within milliseconds of link-up
    - Too long a delay between down and up reduces responsiveness
    - Too short a delay may not allow the interface to fully disable
    
    Supports Windows (netsh), macOS (networksetup), and Linux (ip command).
    """
    _ts = lambda: time.strftime('%H:%M:%S')
    print(f"\n[{_ts()}] [2] Triggering link renegotiation: down > up")
    print(f"    Target interface: {interface_name}")
    
    try:
        if is_windows():
            _trigger_link_renegotiation_windows(interface_name, _ts)
        elif is_macos():
            _trigger_link_renegotiation_macos(interface_name, _ts)
        elif is_linux():
            _trigger_link_renegotiation_linux(interface_name, _ts)
        else:
            print(f"[{_ts()}] [WARN] Link renegotiation not supported on this platform")
    except Exception as exc:
        print(f"[{_ts()}] [WARNING] Renegotiation failed: {exc}")


def _trigger_link_renegotiation_windows(interface_name: str, _ts) -> None:
    """Windows: use netsh to toggle interface."""
    if not is_admin():
        print(f"    [{_ts()}] [WARN] Not admin, skipping down/up.")
        return

    # Phase 1: admin=disable
    print(f"    [{_ts()}] [1/2] admin=disable ...")
    r = _run_netsh(["interface", "set", "interface", interface_name, "admin=disable"])
    if r.returncode != 0:
        print(f"    [{_ts()}] [ERROR] admin=disable failed (rc={r.returncode})")
        return

    # Reduced from 2s to 1s - modern NICs disable quickly
    time.sleep(1.0)

    # Phase 2: admin=enable
    print(f"    [{_ts()}] [2/2] admin=enable ...")
    r = _run_netsh(["interface", "set", "interface", interface_name, "admin=enable"])
    if r.returncode != 0:
        print(f"    [{_ts()}] [ERROR] admin=enable failed (rc={r.returncode}).")
        return

    print(f"[{_ts()}] [OK] Link renegotiation completed.")


def _trigger_link_renegotiation_macos(interface_name: str, _ts) -> None:
    """macOS: use ifconfig to toggle Ethernet interface, or networksetup for Wi-Fi."""
    # Determine interface type from networksetup
    is_wifi = False
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == f"Device: {interface_name}":
                if i > 0 and "Hardware Port: Wi-Fi" in lines[i - 1]:
                    is_wifi = True
                break
    except Exception:
        pass

    if is_wifi:
        # Wi-Fi interface - use networksetup
        print(f"    [{_ts()}] [1/2] Wi-Fi: disabling...")
        result = subprocess.run(
            ["networksetup", "-setairportpower", interface_name, "off"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"    [{_ts()}] [WARN] Wi-Fi disable failed, trying ifconfig...")
            subprocess.run(["ifconfig", interface_name, "down"], capture_output=True, timeout=5)

        time.sleep(1.0)

        print(f"    [{_ts()}] [2/2] Wi-Fi: re-enabling...")
        result = subprocess.run(
            ["networksetup", "-setairportpower", interface_name, "on"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            subprocess.run(["ifconfig", interface_name, "up"], capture_output=True, timeout=5)
    else:
        # Ethernet interface - use ifconfig directly (already elevated)
        print(f"    [{_ts()}] [1/2] Ethernet: ifconfig {interface_name} down...")
        result = subprocess.run(
            ["ifconfig", interface_name, "down"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"    [{_ts()}] [ERROR] Failed to disable interface")
            return

        time.sleep(1.0)

        print(f"    [{_ts()}] [2/2] Ethernet: ifconfig {interface_name} up...")
        result = subprocess.run(
            ["ifconfig", interface_name, "up"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"    [{_ts()}] [ERROR] Failed to re-enable interface")
            return

    print(f"[{_ts()}] [OK] Link renegotiation completed.")


def _trigger_link_renegotiation_linux(interface_name: str, _ts) -> None:
    """Linux: use ip command to toggle interface."""
    print(f"    [{_ts()}] [1/2] Disabling interface with 'ip link set down'...")
    
    result = subprocess.run(
        ["sudo", "ip", "link", "set", interface_name, "down"],
        capture_output=True,
        timeout=10,
    )
    
    if result.returncode != 0:
        stderr = result.stderr.decode() if result.stderr else "unknown error"
        print(f"    [{_ts()}] [ERROR] Failed to disable interface: {stderr}")
        return

    time.sleep(1.0)

    print(f"    [{_ts()}] [2/2] Re-enabling interface with 'ip link set up'...")
    
    result = subprocess.run(
        ["sudo", "ip", "link", "set", interface_name, "up"],
        capture_output=True,
        timeout=10,
    )
    
    if result.returncode != 0:
        stderr = result.stderr.decode() if result.stderr else "unknown error"
        print(f"    [{_ts()}] [ERROR] Failed to re-enable interface: {stderr}")
        return

    print(f"[{_ts()}] [OK] Link renegotiation completed.")
