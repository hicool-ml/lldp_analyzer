#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified runtime checker — entry point for all platforms."""

from __future__ import annotations

import platform
import sys

from runtime.models import RuntimeStatus, CheckResult

OK = "\u2714"    # heavy check mark
FAIL = "\u2718"  # heavy ballot X


def check_runtime() -> RuntimeStatus:
    """Run all platform-appropriate checks and return a RuntimeStatus."""
    status = RuntimeStatus()
    if sys.platform == "darwin":
        from runtime import macos
        status.results = macos.check_all()
    elif sys.platform == "win32":
        from runtime import windows
        status.results = windows.check_all()
    elif sys.platform.startswith("linux"):
        from runtime import linux
        status.results = linux.check_all()
    else:
        status.warnings.append(f"Unsupported platform: {sys.platform}")
    return status


def format_cli(status: RuntimeStatus) -> str:
    """Format the status for CLI output (PASS/FAIL lines)."""
    lines = ["Checking Runtime..."]
    for r in status.results:
        mark = OK if r.passed else FAIL
        lines.append(f"  {mark} {r.label}" + (f" ({r.detail})" if r.detail else ""))
    if status.warnings:
        for w in status.warnings:
            lines.append(f"  ! {w}")
    return "\n".join(lines)


def format_diagnostics(status: RuntimeStatus | None = None) -> str:
    """Generate a full diagnostics report string for export / Issue reports."""
    if status is None:
        status = check_runtime()
    lines = [
        "=" * 60,
        "LLDP Analyzer - Diagnostics Report",
        "=" * 60,
        f"Platform      : {platform.system()} {platform.release()}",
        f"Architecture  : {platform.machine()}",
        f"Python        : {sys.version.split()[0]}",
        f"Frozen        : {getattr(sys, 'frozen', False)}",
        "-" * 60,
        "Runtime Checks:",
    ]
    for r in status.results:
        mark = "PASS" if r.passed else "FAIL"
        lines.append(f"  [{mark}] {r.label}: {r.detail}")
    if status.warnings:
        lines.append("-" * 60)
        lines.append("Warnings:")
        for w in status.warnings:
            lines.append(f"  {w}")
    if status.errors:
        lines.append("-" * 60)
        lines.append("Suggested Fixes:")
        for r in status.errors:
            if r.fix:
                lines.append(f"  {r.label}:")
                if r.fix.command:
                    lines.append(f"    Command: {r.fix.command}")
                if r.fix.url:
                    lines.append(f"    URL: {r.fix.url}")
    lines.append("=" * 60)
    return "\n".join(lines)


def save_diagnostics(filepath: str, status: RuntimeStatus | None = None) -> str:
    """Save diagnostics report to a file. Returns the path."""
    report = format_diagnostics(status)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)
    return filepath
