#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
History Page — SQLite capture history with query, detail view, statistics.


Features:
  - Query filters: device name, date range, port role
  - Results table with semantic analysis column
  - Double-click row → packet detail dialog (hex dump)
  - Statistics panel (total captures, unique devices, model/role distribution)
  - Export filtered results to CSV
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from ui.styles import COLORS
from ui.widgets import InfoCard
from utils.hexdump import hexdump
from db.database import LLDPHistoryDatabase
from i18n.translations import _


class HistoryPage:
    def __init__(self, notebook: ttk.Notebook, main_window):
        self.main = main_window
        self.db = LLDPHistoryDatabase()
        self.frame = tk.Frame(notebook, bg=COLORS["bg"])
        self._build_ui()
        from ui.styles import register_theme_callback
        register_theme_callback(self._refresh_theme)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ---- Query bar ----
        query = tk.Frame(self.frame, bg=COLORS["surface"], bd=1, relief=tk.GROOVE)
        query.pack(fill=tk.X, padx=10, pady=(6, 2))

        inner = tk.Frame(query, bg=COLORS["surface"])
        inner.pack(fill=tk.X, padx=8, pady=6)

        # Device name
        tk.Label(inner, text=_("label_device"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9)).grid(row=0, column=0, padx=(0, 4))
        self.inp_name = tk.Entry(inner, width=16, font=("Segoe UI", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_name.grid(row=0, column=1, padx=2)

        # Date range
        tk.Label(inner, text=_("label_from"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9)).grid(row=0, column=2, padx=(8, 4))
        self.inp_start = tk.Entry(inner, width=10, font=("Segoe UI", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_start.grid(row=0, column=3, padx=2)
        self.inp_start.insert(0, (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"))

        tk.Label(inner, text=_("label_to"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9)).grid(row=0, column=4, padx=(4, 4))
        self.inp_end = tk.Entry(inner, width=10, font=("Segoe UI", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_end.grid(row=0, column=5, padx=2)
        self.inp_end.insert(0, datetime.now().strftime("%Y-%m-%d"))

        # Port role
        tk.Label(inner, text=_("label_role"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9)).grid(row=0, column=6, padx=(8, 4))
        self.role_var = tk.StringVar(value="All")
        self.role_combo = ttk.Combobox(inner, textvariable=self.role_var,
                                        width=14, state="readonly",
                                        values=["All", "Trunk (Native)", "Trunk (No Native)",
                                                "Uplink (LAG)", "Uplink (Single)",
                                                "Access Terminal", "Core/Distribution",
                                                "Access Voice", "Access Wireless",
                                                "Storage Network", "Infrastructure", "Unknown"])
        self.role_combo.grid(row=0, column=7, padx=2)

        # Buttons
        ttk.Button(inner, text=_("button_query"),
                   command=self._execute_query).grid(row=0, column=8, padx=(8, 2))
        ttk.Button(inner, text=_("button_export_csv"),
                   command=self._export_csv).grid(row=0, column=9, padx=2)

        self.count_var = tk.StringVar(value="0 records")
        tk.Label(inner, textvariable=self.count_var, bg=COLORS["surface"],
                 fg=COLORS["text2"], font=("Segoe UI", 9)).grid(row=0, column=10, padx=8)

        # ---- Results table ----
        cols = ("time", "protocol", "device", "model", "mac", "port", "role",
                "vlan", "speed", "type", "conf", "analysis")
        self.tree = ttk.Treeview(self.frame, columns=cols, show="headings", height=14)
        widths = (120, 50, 140, 110, 120, 90, 100, 45, 65, 75, 35, 180)
        self._col_labels = {
            "time": _("column_time"),
            "protocol": _("column_proto"),
            "device": _("column_device"),
            "model": _("column_model"),
            "mac": _("column_mac"),
            "port": _("column_port"),
            "role": _("column_port_role"),
            "vlan": _("column_vlan"),
            "speed": _("column_speed"),
            "type": _("column_dev_type"),
            "conf": _("column_confidence"),
            "analysis": _("column_analysis")
        }
        for c, w in zip(cols, widths):
            label = self._col_labels.get(c, c.capitalize())
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, minwidth=30)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        # Double-click → detail dialog
        self.tree.bind("<Double-1>", self._on_double_click)

        # ---- Bottom: Statistics + Log ----
        bottom = tk.Frame(self.frame, bg=COLORS["bg"])
        bottom.pack(fill=tk.X, padx=10, pady=(0, 6))

        self.stats_card = InfoCard(bottom, _("stats_title"))
        self.stats_card.pack(fill=tk.X)
        self.lbl_total = self.stats_card.add_row(_("stats_total"))
        self.lbl_unique = self.stats_card.add_row(_("stats_unique"))
        self.lbl_avg = self.stats_card.add_row(_("stats_avg_day"))
        self.lbl_models = self.stats_card.add_row(_("stats_top_models"))
        self.lbl_roles = self.stats_card.add_row(_("stats_role_dist"))

        # Initial load
        self._execute_query()

    def _refresh_theme(self):
        """Update widget colors to match current theme."""
        try:
            self.frame.config(bg=COLORS["bg"])
            self.stats_card.refresh_theme()
            query_frame = self.frame.winfo_children()[0]
            if query_frame:
                for child in query_frame.winfo_children():
                    try:
                        child.config(bg=COLORS.get("surface", "#3c3c3c"))
                    except Exception:
                        pass
                    for grandchild in child.winfo_children():
                        try:
                            if grandchild.winfo_class() not in ("TButton", "TCombobox", "TLabel"):
                                grandchild.config(bg=COLORS.get("surface", "#3c3c3c"))
                        except Exception:
                            pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def _execute_query(self):
        self.tree.delete(*self.tree.get_children())
        try:
            kwargs: Dict[str, Any] = {"limit": 500}

            # Parse date range
            start_str = self.inp_start.get().strip()
            end_str = self.inp_end.get().strip()
            if start_str:
                try:
                    kwargs["start_time"] = datetime.strptime(start_str, "%Y-%m-%d")
                except ValueError:
                    pass
            if end_str:
                try:
                    kwargs["end_time"] = datetime.strptime(end_str, "%Y-%m-%d").replace(
                        hour=23, minute=59, second=59)
                except ValueError:
                    pass

            # Device name
            name = self.inp_name.get().strip()
            if name:
                kwargs["device_name"] = name

            # Port role
            role = self.role_var.get()
            if role != "All":
                kwargs["port_role"] = role

            rows = self.db.query_devices(**kwargs)
            if rows is None:
                rows = []

            for r in rows:
                port_desc = r.get("port_description", "") or r.get("port_id", "") or ""
                # If port_id looks like MAC, don't show it as port name
                if port_desc and ":" in port_desc and len(port_desc) == 17:
                    port_desc = r.get("port_description", "") or ""
                analysis = self._semantic_analysis(r)
                vals = (
                    str(r.get("timestamp", ""))[:19],
                    str(r.get("protocol", "")),
                    str(r.get("device_name", "")),
                    str(r.get("device_model", "")),
                    str(r.get("mac_address", "")),
                    port_desc,
                    str(r.get("port_role", "")),
                    str(r.get("port_vlan", "") or ""),
                    str(r.get("link_speed", "")),
                    str(r.get("device_type", "")),
                    str(r.get("confidence", "") or ""),
                    analysis,
                )
                self.tree.insert("", tk.END, values=vals, tags=(str(r.get("id", "")),))

            self.count_var.set(f"{len(rows)} records")
            self._update_statistics()
        except Exception as exc:
            import traceback
            error_msg = f"Error: {exc}"
            self.count_var.set(error_msg)
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def _update_statistics(self):
        """Update statistics display - must run in main thread."""
        def _do_update():
            try:
                stats = self.db.get_statistics(days=30)
                
                self.lbl_total.config(text=str(stats.get("total_captures", 0)))
                self.lbl_unique.config(text=str(stats.get("unique_devices", 0)))
                days = stats.get("period_days", 30)
                total = stats.get("total_captures", 0)
                avg = f"{total / days:.1f}" if days > 0 else "0"
                self.lbl_avg.config(text=avg)

                models = stats.get("device_models", [])
                models_str = ", ".join(f"{m['device_model']} ({m['count']})" for m in models[:5])
                self.lbl_models.config(text=models_str or "\u2014")

                roles = stats.get("port_roles", [])
                roles_str = ", ".join(f"{r['port_role']} ({r['count']})" for r in roles[:5])
                self.lbl_roles.config(text=roles_str or "\u2014")
                
                self.frame.update_idletasks()
            except Exception as e:
                import traceback
                traceback.print_exc()
        
        # Ensure GUI updates run in main thread
        self.frame.after(0, _do_update)

    # ------------------------------------------------------------------
    # Detail dialog (double-click row)
    # ------------------------------------------------------------------

    def _on_double_click(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tree.item(item, "values")
        # Find matching DB row by timestamp + device name
        ts = values[0]
        dev = values[2]
        try:
            rows = self.db.query_devices(limit=500)
            match = None
            for r in rows:
                if str(r.get("timestamp", ""))[:19] == ts and r.get("device_name", "") == dev:
                    match = r
                    break
            if match:
                self._show_detail_dialog(match)
        except Exception:
            pass

    def _show_detail_dialog(self, rec: dict):
        """Show a Toplevel window with full record details + hex dump."""
        win = tk.Toplevel(self.frame.winfo_toplevel())
        name = rec.get("device_name", "Unknown")
        win.title(f"Packet Detail — {name}")
        win.geometry("720x560")
        win.configure(bg=COLORS["bg"])

        # Info card
        card = InfoCard(win, "Device Information")
        card.pack(fill=tk.X, padx=10, pady=(10, 4))

        for key, label in (
            ("timestamp", "Time"), ("protocol", "Protocol"),
            ("device_name", "Device Name"), ("device_model", "Model"),
            ("mac_address", "MAC Address"), ("port_description", "Port"),
            ("port_id", "Port ID"), ("ip_address", "IP Address"),
            ("port_vlan", "VLAN"), ("link_speed", "Speed"),
            ("port_role", "Port Role"), ("device_type", "Device Type"),
            ("confidence", "Confidence"), ("system_description", "Description"),
        ):
            val = rec.get(key, "")
            if val is not None and val != "":
                card.add_row(label, str(val))

        # Raw packet hex dump
        raw = (rec.get("raw_packet") or "").strip()
        if raw:
            hex_frame = tk.LabelFrame(win, text="  Raw Packet Hex  ",
                                      bg=COLORS["bg"], fg=COLORS["text2"],
                                      font=("Segoe UI", 9, "bold"))
            hex_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

            hex_text = tk.Text(hex_frame, wrap=tk.NONE, bg="#1e293b", fg="#22d3ee",
                               font=("Consolas", 9), relief=tk.FLAT, padx=6, pady=6)
            hex_scroll = ttk.Scrollbar(hex_frame, command=hex_text.yview, orient=tk.VERTICAL)
            hex_text.configure(yscrollcommand=hex_scroll.set)
            hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hex_scroll.pack(side=tk.RIGHT, fill=tk.Y)

            try:
                from utils.protocol_parser import clean_hex_text
                clean = clean_hex_text(raw)
                if len(clean) % 2 != 0:
                    clean += "0"
                data = bytes.fromhex(clean)
                hex_text.insert(tk.END, hexdump(data))
            except Exception:
                # Old records may have stored a path; try resolving it.
                from pathlib import Path
                resolved = False
                for candidate in (Path(raw),):
                    if candidate.is_file():
                        try:
                            clean = clean_hex_text(candidate.read_text(encoding="utf-8", errors="ignore"))
                            if len(clean) % 2 != 0:
                                clean += "0"
                            data = bytes.fromhex(clean)
                            hex_text.insert(tk.END, hexdump(data))
                            resolved = True
                            break
                        except Exception:
                            pass
                if not resolved:
                    import traceback
                    traceback.print_exc()
                    hex_text.insert(tk.END, str(raw))
            hex_text.config(state=tk.DISABLED)
        else:
            tk.Label(win, text="No raw packet data available for this record.",
                     bg=COLORS["bg"], fg=COLORS["text2"],
                     font=("Segoe UI", 9, "italic")).pack(pady=(0, 10))

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 10))



    # ------------------------------------------------------------------
    # Semantic analysis (ported from old _generate_semantic_analysis)
    # ------------------------------------------------------------------

    @staticmethod
    def _semantic_analysis(rec: dict) -> str:
        role = rec.get("port_role", "") or ""
        dtype = rec.get("device_type", "") or ""
        model = str(rec.get("device_model", "") or "").lower()
        name = str(rec.get("device_name", "") or "").lower()
        vlan = rec.get("port_vlan")

        # Model-based inference
        combined = model + name
        if any(k in combined for k in ("router", "7608", "core", "qfx100")):
            return "Core Router" if "Trunk" in role else "Core Router (Access)"
        if any(k in combined for k in ("switch", "s2910", "s5130", "s5120", "rgos")):
            if "Trunk" in role or "Uplink" in role:
                return "Switch Trunk/Uplink"
            return "Switch Access"
        if any(k in combined for k in ("ap", "wireless", "wifi")):
            return "Wireless AP (PoE)"
        if any(k in combined for k in ("phone", "voice")):
            return "IP Phone (Voice)"

        # Role-based
        if "Trunk" in role:
            return "Trunk Port (Multi-VLAN)"
        if "Uplink" in role:
            return "Uplink Port"
        if "Access" in role:
            return "Access Port (Single VLAN)"
        if "Core" in role:
            return "Core/Distribution"

        # VLAN-based
        if vlan and vlan != 1:
            return f"VLAN {vlan} Device"
        return "Network Device"

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_csv(self):
        default_name = f"lldp_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile=default_name,
            filetypes=[("CSV files", "*.csv")], title="Export History")
        if path:
            try:
                n = self.db.export_csv(path)
                messagebox.showinfo("Export", f"Exported {n} records to:\n{path}")
            except Exception as exc:
                messagebox.showerror("Export Error", str(exc))

    # ------------------------------------------------------------------
    # Called by main window after a capture is saved
    # ------------------------------------------------------------------

    def refresh(self):
        self._execute_query()

    def update_texts(self):
        pass

