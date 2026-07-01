#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""macOS runtime capability checks."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

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
                command="pip3 install scapy",
                description="Scapy is the packet manipulation library used for capture.",
            ),
        )


def check_libpcap() -> CheckResult:
    found = ctypes.util.find_library("pcap")
    if found:
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail=found)
    # tcpdump implies libpcap
    import shutil
    if shutil.which("tcpdump"):
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail="via tcpdump")
    return CheckResult(
        name="libpcap", label="libpcap", passed=False,
        detail="not found",
        fix=FixAction(
            label="Install libpcap",
            command="brew install libpcap",
            description="libpcap is the system packet capture library.",
        ),
    )


def check_bpf() -> CheckResult:
    for i in range(16):
        dev = f"/dev/bpf{i}"
        if os.path.exists(dev):
            try:
                fd = os.open(dev, os.O_RDONLY)
                os.close(fd)
                return CheckResult(name="bpf", label="BPF device", passed=True, detail=dev)
            except OSError:
                return CheckResult(
                    name="bpf", label="BPF device", passed=False,
                    detail=f"{dev} exists but not readable",
                    fix=FixAction(
                        label="Fix BPF permissions",
                        command="sudo chmod o+r /dev/bpf*  # or run with sudo",
                        description="BPF devices require root or ChmodBPF.",
                    ),
                )
    return CheckResult(
        name="bpf", label="BPF device", passed=False,
        detail="no /dev/bpf* found",
        fix=FixAction(
            label="Run with sudo",
            command="sudo python3 lldp.py",
            description="BPF devices are created on demand and need root access.",
        ),
    )


def check_root() -> CheckResult:
    if os.geteuid() == 0:
        return CheckResult(name="root", label="Administrator", passed=True, detail="root")
    return CheckResult(
        name="root", label="Administrator", passed=False,
        detail=f"uid={os.geteuid()} (not root)",
        fix=FixAction(
            label="Run with sudo",
            command="sudo python3 lldp.py",
            description="Packet capture on macOS requires root privileges.",
        ),
    )


def check_all() -> list[CheckResult]:
    return [check_scapy(), check_libpcap(), check_bpf(), check_root()]
