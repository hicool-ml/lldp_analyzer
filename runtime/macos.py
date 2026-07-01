#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""macOS runtime capability checks.

These checks run inside both the source tree and the PyInstaller-built
``.app`` bundle, so remediation guidance must never reference ``lldp.py``
(which does not exist in the distributed binary). Instead, fixes tell the
user how to run the application they actually have, or how to install the
missing system dependency.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import sys

from runtime.models import CheckResult, FixAction


def _is_frozen() -> bool:
    """True when running inside a PyInstaller-built app/binary."""
    return bool(getattr(sys, "frozen", False))


def _run_hint() -> str:
    """How to relaunch this program with privileges on macOS.

    For a frozen ``.app`` bundle we point at the executable inside
    ``Contents/MacOS/``; for source runs we fall back to the entry script.
    """
    if _is_frozen():
        exe = sys.executable
        # If launched via the .app bundle, sys.executable is already the
        # MacOS/<binary> inside Contents/, which is what sudo can run.
        return f"sudo \"{exe}\""
    # Source-tree run: python3 -m lldp_gui / lldp.py
    main = getattr(sys.modules.get("__main__"), "__file__", "lldp.py")
    return f"sudo python3 \"{main}\""


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
                label="Copy install command",
                command="pip3 install scapy",
                description="Scapy is the packet manipulation library used for capture. Install it with pip, then restart this app.",
            ),
        )


def check_libpcap() -> CheckResult:
    found = ctypes.util.find_library("pcap")
    if found:
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail=found)
    # tcpdump implies libpcap
    if shutil.which("tcpdump"):
        return CheckResult(name="libpcap", label="libpcap", passed=True, detail="via tcpdump")
    return CheckResult(
        name="libpcap", label="libpcap", passed=False,
        detail="not found",
        fix=FixAction(
            label="Open Homebrew",
            url="https://brew.sh",
            description="libpcap is the system packet capture library. Install Homebrew from brew.sh, then run:  brew install libpcap",
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
                        label="Copy fix command",
                        command="sudo chmod o+r /dev/bpf*",
                        description="BPF devices need read permission. Run the command once (or install ChmodBPF from the libpcap installer), then restart this app.",
                    ),
                )
    return CheckResult(
        name="bpf", label="BPF device", passed=False,
        detail="no /dev/bpf* found",
        fix=FixAction(
            label="Copy relaunch command",
            command=_run_hint(),
            description="BPF devices are created on demand and require root. Quit this app and relaunch it with sudo using the copied command.",
        ),
    )


def check_root() -> CheckResult:
    if os.geteuid() == 0:
        return CheckResult(name="root", label="Administrator", passed=True, detail="root")
    return CheckResult(
        name="root", label="Administrator", passed=False,
        detail=f"uid={os.geteuid()} (not root)",
        fix=FixAction(
            label="Copy relaunch command",
            command=_run_hint(),
            description="Packet capture on macOS requires root privileges. Quit this app and relaunch it with sudo using the copied command.",
        ),
    )


def check_all() -> list[CheckResult]:
    return [check_scapy(), check_libpcap(), check_bpf(), check_root()]
