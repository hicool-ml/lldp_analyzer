#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLDP/CDP Protocol Analyzer Main Window - tkinter notebook with three pages."""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.styles import COLORS, apply_styles
from ui.capture_page import CapturePage
from ui.network_page import NetworkPage
from ui.history_page import HistoryPage
from i18n.translations import get_translator, _
from i18n.config import LanguageConfig


class LLDPMainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.configure(bg=COLORS["bg"])
        apply_styles()

        self.translator = get_translator()

        # ---- Toolbar ----
        toolbar = tk.Frame(root, bg=COLORS["bg"])
        toolbar.pack(fill=tk.X, padx=6, pady=(0, 4))

        # Language selector
        lang_frame = tk.Frame(toolbar, bg=COLORS["bg"])
        lang_frame.pack(side=tk.RIGHT)
        
        ttk.Label(lang_frame, text=_("language"), background=COLORS["bg"],
                  foreground=COLORS["text2"]).pack(side=tk.LEFT, padx=(0, 4))
        
        self.lang_var = tk.StringVar()
        self.lang_combo = ttk.Combobox(lang_frame, textvariable=self.lang_var,
                                       width=12, state="readonly")
        self.lang_combo.pack(side=tk.LEFT)
        
        self._update_lang_options()
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        # ---- Notebook ----
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.capture_page = CapturePage(self.notebook, self)
        self.history_page = HistoryPage(self.notebook, self)
        self.network_page = NetworkPage(self.notebook, self)

        # Add tabs with translated text
        self.notebook.add(self.capture_page.frame, text=f"  {_('title_capture')}  ")
        self.notebook.add(self.history_page.frame, text=f"  {_('title_history')}  ")
        self.notebook.add(self.network_page.frame, text=f"  {_('title_network')}  ")

        # Start periodic system theme monitoring
        self.root.after(2000, self._periodic_theme_check)

    def _update_lang_options(self):
        """Update language combo box options."""
        langs = self.translator.get_available_languages()
        lang_names = [(lang, self.translator.get_language_name(lang)) for lang in langs]
        self.lang_combo["values"] = [name for _, name in lang_names]
        current_lang = self.translator.get_language()
        for idx, (code, name) in enumerate(lang_names):
            if code == current_lang:
                self.lang_combo.current(idx)
                break

    def _on_lang_change(self, event):
        """Handle language change."""
        langs = self.translator.get_available_languages()
        idx = self.lang_combo.current()
        if 0 <= idx < len(langs):
            new_lang = langs[idx]
            if new_lang != self.translator.get_language():
                config = LanguageConfig()
                config.set_language(new_lang)
                messagebox.showinfo(
                    _("settings"),
                    _("language") + ": " + self.translator.get_language_name(new_lang) + "\n\n" +
                    "Language changed. Please restart the application for changes to take effect.",
                    parent=self.root
                )

    def load_offline_file(self, filepath: str):
        self.notebook.select(0)
        self.capture_page.load_file(filepath)

    def refresh_history(self):
        try:
            self.history_page.refresh()
        except Exception:
            pass

    def _periodic_theme_check(self):
        """Periodically check if system dark/light theme changed."""
        from ui.styles import force_detect_dark_mode, refresh_all_themes, refresh_widget_colors, COLORS
        try:
            if force_detect_dark_mode():
                refresh_all_themes()
                refresh_widget_colors(self.root)
                # Re-apply InfoCard themes and page refreshes
                for page in (self.capture_page, self.history_page, self.network_page):
                    try:
                        if hasattr(page, '_refresh_log_theme'):
                            page._refresh_log_theme()
                        if hasattr(page, '_refresh_theme'):
                            page._refresh_theme()
                    except Exception:
                        pass
        except Exception:
            pass
        # Check every 3 seconds for snappier response
        self.root.after(3000, self._periodic_theme_check)
