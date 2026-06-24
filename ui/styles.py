"""Centralized styles for LLDP_CLI GUI — macOS and cross-platform."""

import os
import sys

from tkinter import ttk
from typing import Callable, List

_is_dark = False
_theme_callbacks: List[Callable[[], None]] = []


def _detect_dark_mode() -> bool:
    """Detect if macOS is in dark mode."""
    if sys.platform == "darwin":
        try:
            import subprocess
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=2,
            )
            if result.returncode == 0:
                return result.stdout.strip().lower() == "dark"
        except Exception:
            pass
    # Check env var (Linux/other)
    if os.environ.get("DARK_MODE", "").lower() in ("1", "true", "dark"):
        return True
    return False


def force_detect_dark_mode() -> bool:
    """Re-detect dark mode and update COLORS if changed.
    Returns True if the theme actually changed.
    """
    global _is_dark
    old_dark = _is_dark
    new_dark = _detect_dark_mode()
    if new_dark != old_dark:
        _is_dark = new_dark
        COLORS.clear()
        COLORS.update(_DARK if _is_dark else _LIGHT)
        return True
    return False


def register_theme_callback(cb: Callable[[], None]) -> None:
    """Register a callback to be called after theme is refreshed.
    Use for re-configuring widget tags, re-styling custom widgets, etc.
    """
    _theme_callbacks.append(cb)


def refresh_all_themes() -> None:
    """Re-apply theme colors and trigger all callbacks."""
    apply_styles()
    for cb in _theme_callbacks:
        try:
            cb()
        except Exception:
            pass


# --- Light theme ---
_LIGHT = {
    "bg": "#f0f0f0",
    "surface": "#ffffff",
    "surface2": "#e2e8f0",
    "border": "#cccccc",
    "text": "#1e293b",
    "text2": "#64748b",
    "primary": "#2563eb",
    "success": "#16a34a",
    "warning": "#d97706",
    "info": "#0891b2",
}

# --- Dark theme ---
_DARK = {
    "bg": "#2d2d2d",
    "surface": "#3c3c3c",
    "surface2": "#4a4a4a",
    "border": "#555555",
    "text": "#e0e0e0",
    "text2": "#a0a0a0",
    "primary": "#5a9cf6",
    "success": "#34d399",
    "warning": "#fbbf24",
    "info": "#22d3ee",
}


def _init_colors():
    global _is_dark
    _is_dark = _detect_dark_mode()
    COLORS.clear()
    COLORS.update(_DARK if _is_dark else _LIGHT)


COLORS = {}
_init_colors()


def apply_styles():
    """Configure ttk styles for native look with dark mode support."""
    s = ttk.Style()
    # Use native macOS aqua theme - no custom styling
    if sys.platform == "darwin":
        if s.theme_use() != "aqua":
            try:
                s.theme_use("aqua")
            except Exception:
                pass
    # Keep default theme on other platforms
    if _is_dark:
        s.configure(".", background=COLORS["bg"], foreground=COLORS["text"])
        s.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        s.configure("Treeview", rowheight=24,
                    background=COLORS["surface"], foreground=COLORS["text"],
                    fieldbackground=COLORS["surface"])
        s.map("Treeview",
              background=[("selected", COLORS["primary"])],
              foreground=[("selected", COLORS["surface"])])
        s.configure("TFrame", background=COLORS["bg"])
        s.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])
    else:
        s.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        s.configure("TFrame", background=COLORS["bg"])


def is_dark_mode() -> bool:
    """Return whether dark mode is active."""
    return _is_dark


def toggle_theme():
    """Manually toggle between light and dark themes. Call apply_styles() after."""
    global _is_dark
    _is_dark = not _is_dark
    COLORS.clear()
    COLORS.update(_DARK if _is_dark else _LIGHT)


def refresh_widget_colors(widget):
    """Recursively update widget colors after a theme change.
    Handles tk.Text, tk.Entry, tk.Label, tk.Frame, tk.LabelFrame, and generic widgets.
    For Text widgets, also re-applies the "log" tag for proper log message coloring.
    """
    import tkinter as tk
    try:
        if not hasattr(widget, 'config'):
            return
        wtype = type(widget).__name__
        if wtype == 'Text':
            widget.config(bg=COLORS.get("surface", "#3c3c3c"),
                          fg=COLORS.get("text", "#e0e0e0"),
                          insertbackground=COLORS.get("text", "#e0e0e0"))
            # Re-apply the "log" tag if it exists
            try:
                widget.tag_configure("log",
                    background=COLORS.get("surface", "#3c3c3c"),
                    foreground=COLORS.get("text", "#e0e0e0"))
            except Exception:
                pass
        elif wtype == 'Entry':
            widget.config(bg=COLORS.get("surface", "#3c3c3c"),
                          fg=COLORS.get("text", "#e0e0e0"),
                          insertbackground=COLORS.get("text", "#e0e0e0"))
        elif wtype == 'Label':
            try:
                target_fg = COLORS.get("text", "#e0e0e0")
                parent = widget.master
                is_info_card = False
                while parent:
                    try:
                        pbg = parent.cget('bg')
                        if pbg == COLORS.get('surface', '#3c3c3c'):
                            is_info_card = True
                            break
                    except Exception:
                        pass
                    if hasattr(parent, 'master'):
                        parent = parent.master
                    else:
                        break
                if is_info_card:
                    widget.config(bg=COLORS.get("surface", "#3c3c3c"), fg=target_fg)
                else:
                    widget.config(bg=COLORS.get("bg", "#2d2d2d"), fg=target_fg)
            except Exception:
                widget.config(bg=COLORS.get("bg", "#2d2d2d"))
        elif wtype == 'Frame':
            try:
                current_bg = widget.cget("bg")
                if current_bg and current_bg not in ('systemWindowBody', ''):
                    # Don't overwrite surface-colored Frames (used by InfoCards)
                    surface = COLORS.get("surface", "#3c3c3c")
                    if current_bg != surface:
                        widget.config(bg=COLORS.get("bg", "#2d2d2d"))
            except Exception:
                pass
        elif wtype == 'LabelFrame':
            try:
                widget.config(bg=COLORS.get("surface", "#3c3c3c"),
                              fg=COLORS.get("text", "#e0e0e0"),
                              font=("Segoe UI", 11, "bold"))
            except Exception:
                widget.config(bg=COLORS.get("surface", "#3c3c3c"))
            # Update child frames inside LabelFrame
            for child in widget.winfo_children():
                refresh_widget_colors(child)
            return  # already recursed
        elif wtype == 'Combobox':
            pass  # ttk Combobox managed by native theme
        elif wtype == 'Toplevel':
            try:
                widget.configure(bg=COLORS.get("bg", "#2d2d2d"))
            except Exception:
                pass
        else:
            # Generic tk widget
            try:
                if hasattr(widget, 'cget'):
                    bg = widget.cget('bg')
                    if bg and bg not in ('systemWindowBody', ''):
                        widget.config(bg=COLORS.get("bg", "#2d2d2d"))
            except Exception:
                pass
    except Exception:
        pass
    # Recurse into children
    for child in widget.winfo_children():
        refresh_widget_colors(child)
