#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux runtime capability checks."""

from __future__ import annotations

import ctypes.util
import grp
import os
import shutil
import subprocess

from runtime.models import CheckResult, FixAction


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
                command="sudo pip3 install scapy",
                description="Scapy is required for packet capture.",
            ),
        )


def check_libpcap() -> CheckResult:
    found = ctypes.util.find_library("pcap")
    if found:
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail=found)
    if shutil.which("tcpdump"):
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail="via tcpdump")
    return CheckResult(
        name="libpcap", label="libpcap", passed=False,
        detail="not found",
        fix=FixAction(
            label="Install libpcap",
            command="sudo apt install libpcap-dev  # Debian/Ubuntu\n"
                    "sudo yum install libpcap-devel  # RHEL/CentOS",
            description="libpcap development headers are needed for scapy.",
        ),
    )


def check_root() -> CheckResult:
    if os.geteuid() == 0:
        return CheckResult(name="root", label="Root", passed=True, detail="root")
    # Check capture group membership
    groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
    capture_groups = {"wireshark", "pcap", "packet"}
    matched = capture_groups & set(groups)
    if matched:
        return CheckResult(
            name="root", label="Capture permission", passed=True,
            detail=f"user in group(s): {', '.join(sorted(matched))}",
        )
    return CheckResult(
        name="root", label="Capture permission", passed=False,
        detail="not root and not in a capture group",
        fix=FixAction(
            label="Add to capture group",
            command="sudo usermod -a -G wireshark $USER  # then re-login",
            description="Non-root users need to be in a capture group for raw socket access.",
        ),
    )


def check_tools() -> CheckResult:
    """Check for ip and ethtool (used for link renegotiation)."""
    missing = []
    for tool in ("ip", "ethtool"):
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        return CheckResult(
            name="tools", label="Network tools", passed=False,
            detail=f"missing: {', '.join(missing)}",
            fix=FixAction(
                label="Install network tools",
                command="sudo apt install iproute2 ethtool  # Debian/Ubuntu\n"
                        "sudo yum install iproute ethtool    # RHEL/CentOS",
                description="ip and ethtool are used for interface management.",
            ),
        )
    return CheckResult(name="tools", label="Network tools", passed=True, detail="ip, ethtool")


def check_all() -> list[CheckResult]:
    return [check_scapy(), check_libpcap(), check_root(), check_tools()]
