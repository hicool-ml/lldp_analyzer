#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Data models for runtime environment checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FixAction:
    """A single remediation step the user can take.

    Attributes
    ----------
    label : str
        Short label for the button / menu item, e.g. ``"Install scapy"``.
    command : str
        The shell command to display or copy, e.g. ``"pip3 install scapy"``.
        May be empty if ``url`` is used instead.
    url : str
        A web page to open, e.g. the Npcap download page.
        May be empty if ``command`` is used instead.
    description : str
        Longer explanation shown in the dialog body.
    """

    label: str = ""
    command: str = ""
    url: str = ""
    description: str = ""


@dataclass
class CheckResult:
    """Outcome of a single capability check.

    Attributes
    ----------
    name : str
        Machine-readable check name, e.g. ``"scapy"``, ``"libpcap"``.
    label : str
        Human-readable label, e.g. ``"Scapy"``, ``"libpcap"``.
    passed : bool
    detail : str
        Extra info (version string, path found, error message).
    fix : Optional[FixAction]
        If ``passed`` is False, the suggested remediation.
    """

    name: str = ""
    label: str = ""
    passed: bool = False
    detail: str = ""
    fix: Optional[FixAction] = None


@dataclass
class RuntimeStatus:
    """Aggregated result of all runtime checks.

    Attributes
    ----------
    ok : bool
        True if every *required* check passed.
    results : list[CheckResult]
    warnings : list[str]
    """

    results: list[CheckResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def errors(self) -> list[CheckResult]:
        """Only the failed checks."""
        return [r for r in self.results if not r.passed]

    @property
    def fixes(self) -> list[FixAction]:
        """All FixActions from failed checks."""
        return [r.fix for r in self.errors if r.fix]

    def get(self, name: str) -> Optional[CheckResult]:
        """Look up a check by its machine name."""
        for r in self.results:
            if r.name == name:
                return r
        return None
