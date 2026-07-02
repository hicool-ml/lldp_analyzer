#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified privilege elevation for Windows, macOS and Linux.

Two modes:

    wait=False   Fire-and-forget via ShellExecuteW("runas").
                 Current process exits after launch.  Used when the
                 caller wants to restart itself elevated.

    wait=True    Blocking via ShellExecuteExW("runas") + WaitForSingleObject.
                 Returns the elevated child's exit code.  Used when the
                 caller needs to know whether a single privileged
                 operation succeeded.

Cross-platform: on macOS uses osascript, on Linux uses pkexec.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Optional


def is_admin() -> bool:
    """Check whether the current process has administrator / root privileges."""
    if sys.platform == "win32":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_elevated(
    args: list[str],
    *,
    executable: str | None = None,
    wait: bool = False,
    show_window: bool = False,
    timeout_ms: int | None = None,
    cwd: str | None = None,
) -> Optional[int]:
    """Re-launch the current executable with elevated privileges.

    Parameters
    ----------
    args : list[str]
        Command-line arguments to pass to the elevated child.
    executable : str | None
        Path to the executable.  Defaults to sys.executable (current process).
        Use this to launch a different script (e.g. elevated_op.py).
    wait : bool
        If True, block until the child exits and return its exit code.
        If False, return None immediately (fire-and-forget).
    show_window : bool
        If False the elevated process window is hidden (SW_HIDE).
    timeout_ms : int | None
        Maximum wait time in milliseconds.  None means no timeout.
    cwd : str | None
        Working directory for the elevated child.  Defaults to the parent's cwd.
        On macOS osascript this is applied via ``cd`` in the shell script.
    """
    exe = executable or sys.executable

    if sys.platform == "win32":
        # Windows: keep the historical 120s default (user confirmed working).
        effective_timeout = timeout_ms if timeout_ms is not None else 120_000
        return _elevate_windows(exe, args, wait, show_window, effective_timeout)
    elif sys.platform == "darwin":
        return _elevate_darwin(exe, args, wait, timeout_ms, cwd)
    else:
        return _elevate_linux(exe, args, wait, timeout_ms, cwd)


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _elevate_windows(
    exe: str,
    args: list[str],
    wait: bool,
    show_window: bool,
    timeout_ms: int | None,
) -> Optional[int]:
    n_show = 1 if show_window else 0  # SW_SHOWNORMAL : SW_HIDE

    if wait:
        return _elevate_windows_wait(exe, args, n_show, timeout_ms)
    else:
        return _elevate_windows_fire(exe, args, n_show)


def _elevate_windows_fire(exe: str, args: list[str], n_show: int) -> None:
    """Fire-and-forget via ShellExecuteW."""
    params = subprocess.list2cmdline(args)
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, None, n_show,
    )
    if result <= 32:
        raise OSError(f"ShellExecuteW failed (rc={result})")


def _elevate_windows_wait(
    exe: str,
    args: list[str],
    n_show: int,
    timeout_ms: int | None,
) -> int:
    """Blocking elevation via ShellExecuteExW + WaitForSingleObject."""
    params = subprocess.list2cmdline(args)

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hKeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.lpDirectory = None
    sei.nShow = n_show

    ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    if not ok:
        raise OSError("ShellExecuteExW failed")

    if sei.hProcess:
        # INFINITE = 0xFFFFFFFF for Windows; otherwise use the supplied ms.
        wait_ms = timeout_ms if timeout_ms is not None else 0xFFFFFFFF
        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, wait_ms)
        exit_code = ctypes.c_uint32(0)
        ctypes.windll.kernel32.GetExitCodeProcess(
            sei.hProcess, ctypes.byref(exit_code),
        )
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        return exit_code.value
    return 0


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def _elevate_darwin(
    exe: str,
    args: list[str],
    wait: bool,
    timeout_ms: int | None,
    cwd: str | None = None,
) -> Optional[int]:
    """Elevate on macOS.

    When running in a terminal (TTY available), uses sudo -E.
    When running as GUI app (no TTY), uses osascript to show macOS auth dialog.

    Unlike osascript+administrator-privileges, sudo -E does NOT inherit
    macOS 14+ Hardened Runtime / TCC provenance restrictions, so the
    elevated process can read project files even when they have the
    kernel-enforced com.apple.provenance xattr.

    CRITICAL: sudo(8) on macOS defaults to env_reset, which strips
    PYTHONPATH even with -E.  We work around this by prepending
    sudo env PYTHONPATH=... so the variable is set via env(1)
    *after* sudo resets the environment.
    """
    import subprocess
    import shlex

    full_cmd = [exe] + args
    cmd_str = " ".join(shlex.quote(arg) for arg in full_cmd)

    ppath = os.environ.get("PYTHONPATH", "")
    if ppath:
        cmd_str = f"PYTHONPATH={shlex.quote(ppath)} {cmd_str}"

    if sys.stdout.isatty():
        if ppath:
            sudo_cmd = ["sudo", "env", f"PYTHONPATH={ppath}"] + full_cmd
        else:
            sudo_cmd = ["sudo", "-E"] + full_cmd

        if wait:
            timeout_s = timeout_ms / 1000 if timeout_ms is not None else None
            try:
                result = subprocess.run(sudo_cmd, timeout=timeout_s)
                return result.returncode
            except subprocess.TimeoutExpired:
                return 1
        else:
            subprocess.Popen(sudo_cmd)
            return None
    else:
        import tempfile

        env_vars = []
        for key in ["HOME", "PATH", "TMPDIR", "USER"]:
            val = os.environ.get(key)
            if val:
                env_vars.append(f"{key}={shlex.quote(val)}")

        # osascript's `do shell script` runs with a minimal environment.
        # Ensure PATH includes sbin so ifconfig/networksetup/system_profiler
        # are found by scapy and our own interface enumeration code.
        path_val = os.environ.get("PATH", "/usr/bin:/bin")
        for extra in ["/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin"]:
            if extra not in path_val:
                path_val = path_val + ":" + extra
        env_vars.append(f"PATH={shlex.quote(path_val)}")

        if env_vars:
            cmd_str = " ".join(env_vars) + " " + cmd_str

        # Run in the requested working directory (defaults to osascript's /).
        if cwd:
            cmd_str = f"cd {shlex.quote(cwd)} && {cmd_str}"

        # Capture stderr to a temp file so GUI callers can read the real
        # error when the elevated child fails (osascript swallows stdout/stderr).
        err_log = os.path.join(tempfile.gettempdir(), "lldp_elevate_err.log")
        cmd_str = f"{cmd_str} 2>{shlex.quote(err_log)}"

        escaped_cmd = cmd_str.replace('"', '\\"')
        osascript_cmd = [
            "osascript",
            "-e",
            f'do shell script "{escaped_cmd}" with administrator privileges',
        ]

        if wait:
            timeout_s = timeout_ms / 1000 if timeout_ms is not None else None
            try:
                result = subprocess.run(osascript_cmd, timeout=timeout_s,
                                         capture_output=True, text=True)
                # osascript returns non-zero if the shell command failed;
                # surface a hint in stderr so callers can debug.
                if result.returncode != 0 and result.stderr:
                    try:
                        with open(err_log, "a") as f:
                            f.write("\n[osascript] " + result.stderr)
                    except OSError:
                        pass
                return result.returncode
            except subprocess.TimeoutExpired:
                return 1
        else:
            subprocess.Popen(osascript_cmd)
            return None


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _elevate_linux(
    exe: str,
    args: list[str],
    wait: bool,
    timeout_ms: int | None,
    cwd: str | None = None,
) -> Optional[int]:
    """Elevate on Linux using sudo in the current terminal."""
    import subprocess

    full_cmd = [exe] + args
    sudo_cmd = ["sudo", "-E", "--"] + full_cmd

    if wait:
        timeout_s = timeout_ms / 1000 if timeout_ms is not None else None
        result = subprocess.run(
            sudo_cmd,
            timeout=timeout_s,
            cwd=cwd,
        )
        return result.returncode
    else:
        subprocess.Popen(sudo_cmd)
        return None
