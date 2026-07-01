#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows runtime capability checks."""

from __future__ import annotations

import ctypes
import os
import sys

from runtime.models import CheckResult, FixAction

NPCAP_URL = "https://npcap.com/dist/"
WPCAP_URL = "https://www.winpcap.org/install/default.htm"


def check_scapy() -> CheckResult:
    try:
        import scapy
        ver = getattr(scapy, "__version__", "unknown")
        return CheckResult(name="scapy", label="Scapy", passed=True, detail=f"v{ver}")
    except ImportError:
        return CheckResult(
            name="scapy", label="Scapy", passed=False,
            detail="not installed",
            fix=FixAction(
                label="Install scapy",
                command="pip install scapy",
                description="Scapy is required for packet capture.",
            ),
        )


def _check_npcap_registry() -> tuple[bool, bool, str]:
    """Return (npcap_found, winpcap_found, version_str)."""
    npcap = False
    winpcap = False
    version = ""
    try:
        import winreg
        for hive in (r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive) as k:
                    npcap = True
                    try:
                        version, _ = winreg.QueryValueEx(k, "Version")
                    except OSError:
                        pass
                break
            except FileNotFoundError:
                continue
        for hive in (r"SOFTWARE\WinPcap", r"SOFTWARE\WOW6432Node\WinPcap"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive) as k:
                    winpcap = True
                    if not version:
                        try:
                            version, _ = winreg.QueryValueEx(k, "Version")
                        except OSError:
                            pass
                break
            except FileNotFoundError:
                continue
    except ImportError:
        pass
    return npcap, winpcap, version


def check_pcap() -> CheckResult:
    npcap, winpcap, version = _check_npcap_registry()
    if npcap:
        return CheckResult(
            name="pcap", label="Npcap", passed=True,
            detail=f"Npcap {version}" if version else "Npcap",
        )
    if winpcap:
        return CheckResult(
            name="pcap", label="WinPcap", passed=True,
            detail=f"WinPcap {version}" if version else "WinPcap (deprecated)",
        )
    return CheckResult(
        name="pcap", label="Packet capture driver", passed=False,
        detail="neither Npcap nor WinPcap found",
        fix=FixAction(
            label="Download Npcap",
            url=NPCAP_URL,
            description="Npcap is the modern packet capture driver for Windows.\n"
                        "During install, enable 'WinPcap API-compatible Mode'.",
        ),
    )


def check_admin() -> CheckResult:
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return CheckResult(name="admin", label="Administrator", passed=True, detail="elevated")
    except Exception:
        pass
    return CheckResult(
        name="admin", label="Administrator", passed=False,
        detail="not elevated",
        fix=FixAction(
            label="Run as Administrator",
            command="Right-click LLDP_CLI.exe > Run as administrator",
            description="Administrator privileges are needed for link renegotiation and raw capture.",
        ),
    )


def check_all() -> list[CheckResult]:
    return [check_scapy(), check_pcap(), check_admin()]
