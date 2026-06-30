#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified capture backend detection.

Provides a single :class:`CaptureBackend` dataclass that describes the
packet-capture backend (Npcap, WinPcap, or native BPF/libpcap) and its
capabilities.  CLI and GUI code should depend on the capability flags,
never on the product name.

Example
-------
    >>> be = detect_backend()
    >>> be.provider
    'Npcap'
    >>> be.can_capture
    True
    >>> if not be.supports_kernel_bpf:
    ...     # use software filtering
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CaptureBackend:
    """Describes the active packet-capture backend and its capabilities.

    Upper-layer code (CLI, GUI, capture engine) should branch on the
    capability flags (``can_capture``, ``supports_kernel_bpf``, ...)
    rather than on ``provider``.  This keeps the code forward-compatible
    with future backends.
    """

    provider: str = "Unknown"
    """Human-readable backend name: ``"Npcap"``, ``"WinPcap"``, ``"BPF"``, ``"libpcap"``."""

    version: str = ""
    """Backend version string (e.g. ``"1.82"``).  Empty if unknown."""

    can_capture: bool = False
    """Can capture packets at all."""

    can_send_l2: bool = False
    """Can send raw Layer-2 frames (needed for active LLDP/CDP injection)."""

    can_loopback: bool = False
    """Has a loopback capture adapter (Npcap's ``\\Device\\NPF_Loopback``)."""

    supports_kernel_bpf: bool = False
    """Kernel-side BPF filter is reliable (use it for efficiency).
    
    WinPcap's BPF compiler silently accepts some filters but then captures
    zero packets, so this is ``False`` for WinPcap.
    """

    supports_monitor: bool = False
    """Supports monitor / promiscuous mode on wireless adapters."""

    survives_link_toggle: bool = False
    """Capture socket survives interface down/up without dying.
    
    WinPcap sockets die on ``netsh admin=disable`` and do NOT recover on
    ``admin=enable``, so this is ``False`` for WinPcap.  Npcap, macOS BPF,
    and Linux libpcap all survive.
    """

    is_windows: bool = field(default_factory=lambda: sys.platform == "win32")

    # Convenience aliases used in older code paths.
    @property
    def is_winpcap(self) -> bool:
        """True if the backend is legacy WinPcap (not Npcap)."""
        return self.provider == "WinPcap"

    @property
    def is_npcap(self) -> bool:
        return self.provider == "Npcap"

    @property
    def ready(self) -> bool:
        """Shorthand for 'can we capture right now?'."""
        return self.can_capture


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_cached: CaptureBackend | None = None


def detect_backend() -> CaptureBackend:
    """Detect the capture backend once and cache the result."""
    global _cached
    if _cached is not None:
        return _cached
    if sys.platform == "win32":
        _cached = _detect_windows()
    elif sys.platform == "darwin":
        _cached = _detect_macos()
    else:
        _cached = _detect_linux()
    return _cached


# ---------------------------------------------------------------------------
# Windows: Npcap vs WinPcap
# ---------------------------------------------------------------------------

def _detect_windows() -> CaptureBackend:
    """Detect Npcap or WinPcap on Windows.

    Key gotcha: Npcap installs ``npcap.dll`` in
    ``C:\\Windows\\System32\\Npcap\\`` which is NOT in the DLL search path,
    so ``ctypes.CDLL('npcap.dll')`` fails even when Npcap is installed.
    Meanwhile Npcap provides a compatible ``wpcap.dll`` in ``System32``, so
    loading ``wpcap.dll`` succeeds under BOTH WinPcap and Npcap.
    Detection must therefore rely on the install directory / registry, not
    on DLL loading.
    """
    npcap_dir = None
    for d in (r"C:\Windows\System32\Npcap", r"C:\Windows\SysWOW64\Npcap"):
        if os.path.isdir(d):
            npcap_dir = d
            break

    npcap_registry = False
    npcap_version = ""
    winpcap_registry = False
    winpcap_version = ""
    try:
        import winreg
        for hive in (r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive) as k:
                    npcap_registry = True
                    try:
                        npcap_version, _ = winreg.QueryValueEx(k, "Version")
                    except OSError:
                        pass
                break
            except FileNotFoundError:
                continue
        for hive in (r"SOFTWARE\WinPcap", r"SOFTWARE\WOW6432Node\WinPcap"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive) as k:
                    winpcap_registry = True
                    try:
                        winpcap_version, _ = winreg.QueryValueEx(k, "Version")
                    except OSError:
                        pass
                break
            except FileNotFoundError:
                continue
    except ImportError:
        pass

    npcap_present = npcap_dir is not None or npcap_registry

    # Load the pcap DLL for diagnostic messaging (does not affect detection).
    dll_loaded = None
    for name in ("npcap.dll", "wpcap.dll"):
        try:
            ctypes.CDLL(name)
            dll_loaded = name
            break
        except OSError:
            continue

    if npcap_present:
        return CaptureBackend(
            provider="Npcap",
            version=npcap_version,
            can_capture=True,
            can_send_l2=True,
            can_loopback=True,
            supports_kernel_bpf=True,
            supports_monitor=False,
            survives_link_toggle=True,
        )

    if winpcap_registry:
        return CaptureBackend(
            provider="WinPcap",
            version=winpcap_version,
            can_capture=True,
            can_send_l2=True,
            can_loopback=False,
            supports_kernel_bpf=False,
            supports_monitor=False,
            survives_link_toggle=False,
        )

    # Neither found.
    return CaptureBackend(
        provider="None",
        can_capture=False,
    )


# ---------------------------------------------------------------------------
# macOS: BPF
# ---------------------------------------------------------------------------

def _detect_macos() -> CaptureBackend:
    has_bpf = any(os.path.exists(f"/dev/bpf{i}") for i in range(16))
    return CaptureBackend(
        provider="BPF",
        can_capture=has_bpf,
        can_send_l2=True,
        can_loopback=True,
        supports_kernel_bpf=True,
        supports_monitor=False,
        survives_link_toggle=True,
    )


# ---------------------------------------------------------------------------
# Linux: libpcap
# ---------------------------------------------------------------------------

def _detect_linux() -> CaptureBackend:
    has_libpcap = False
    try:
        result = subprocess.run(["which", "tcpdump"], capture_output=True, timeout=5)
        has_libpcap = result.returncode == 0
    except Exception:
        pass
    return CaptureBackend(
        provider="libpcap",
        can_capture=has_libpcap,
        can_send_l2=True,
        can_loopback=True,
        supports_kernel_bpf=True,
        supports_monitor=True,
        survives_link_toggle=True,
    )


# ---------------------------------------------------------------------------
# Pretty-printing for CLI / GUI
# ---------------------------------------------------------------------------

def format_backend_info(be: CaptureBackend) -> str:
    """Return a multi-line human-readable summary for the CLI."""
    ok = "\u2714"
    no = "\u2718"
    lines = [f"Backend: {be.provider}"]
    if be.version:
        lines[0] += f" {be.version}"
    lines.append("Capabilities:")
    lines.append(f"  {ok if be.can_capture else no} Capture")
    lines.append(f"  {ok if be.can_send_l2 else no} Send L2")
    lines.append(f"  {ok if be.can_loopback else no} Loopback")
    lines.append(f"  {ok if be.supports_kernel_bpf else no} Kernel BPF")
    lines.append(f"  {ok if be.supports_monitor else no} Monitor Mode")
    return "\n".join(lines)
