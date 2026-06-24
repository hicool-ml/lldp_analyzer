#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Page — local Ethernet adapter status and configuration.


Features:
  - Adapter list with full info (IP, MAC, link speed, MTU, DNS, DHCP)
  - MAC address: modify / restore / random generate
  - IP configuration: static IP / DHCP / clear
  - Restart adapter
  - UAC elevation for privileged operations via network/elevated_op.py
"""

import ctypes
import os
import random
import re
import subprocess
import sys
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any, Optional

from ui.styles import COLORS, register_theme_callback
from ui.widgets import InfoCard
from utils.elevator import run_elevated
from network.backends.platform import is_windows, is_darwin
if is_windows():
    from network.backends.windows.adapter import WindowsNetworkBackend as _Backend
elif is_darwin():
    from network.backends.macos.adapter import MacOSNetworkBackend as _Backend
else:
    from network.backends.posix.adapter import PosixNetworkBackend as _Backend
from i18n.translations import _

def _is_admin() -> bool:
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


class NetworkPage:
    def __init__(self, notebook: ttk.Notebook, main_window):
        self.main = main_window
        self.backend = _Backend()
        self.frame = tk.Frame(notebook, bg=COLORS["bg"])
        self._interfaces: List[Any] = []
        self._current: Optional[Any] = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ---- Toolbar ----
        toolbar = tk.Frame(self.frame, bg=COLORS["bg"])
        toolbar.pack(fill=tk.X, padx=10, pady=(6, 2))

        tk.Label(toolbar, text=_("network_adapter"), bg=COLORS["bg"],
                 fg=COLORS["text2"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(toolbar, textvariable=self.iface_var,
                                        width=40, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=4)
        self.iface_combo.bind("<<ComboboxSelected>>", self._on_combo_select)

        ttk.Button(toolbar, text=_("action_refresh"),
                   command=self._refresh).pack(side=tk.LEFT, padx=4)

        self.iface_count_var = tk.StringVar(value="0 adapters")
        tk.Label(toolbar, textvariable=self.iface_count_var,
                 bg=COLORS["bg"], fg=COLORS["text2"],
                 font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=8)

        # ---- Info Cards row ----
        cards = tk.Frame(self.frame, bg=COLORS["bg"])
        cards.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        # Left: Network Status
        self.card_status = InfoCard(cards, _("network_status"), width=340)
        self.card_status.pack_propagate(False)
        self.card_status.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))
        self.lbl_mac = self.card_status.add_row(_("network_mac"))
        self.lbl_mac_st = self.card_status.add_row(_("network_mac_status"))
        self.lbl_ip = self.card_status.add_row(_("network_ip"))
        self.lbl_mask = self.card_status.add_row(_("network_mask"))
        self.lbl_gw = self.card_status.add_row(_("network_gateway"))
        self.lbl_dns = self.card_status.add_row(_("network_dns"))
        self.lbl_dhcp = self.card_status.add_row(_("network_dhcp"))
        self.lbl_dhcp_srv = self.card_status.add_row(_("network_dhcp_server"))
        self.lbl_speed = self.card_status.add_row(_("network_speed"))
        self.lbl_mtu = self.card_status.add_row(_("network_mtu"))
        self.lbl_status = self.card_status.add_row(_("network_status_label"))
        self.lbl_guid = self.card_status.add_row(_("network_guid"))
        self.lbl_scapy = self.card_status.add_row(_("network_scapy"))

        # Right: Configuration
        right_col = tk.Frame(cards, bg=COLORS["bg"])
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))

        # -- IP Config card --
        self.card_ip = InfoCard(right_col, _("ip_config"))
        self.card_ip.pack(fill=tk.X, pady=(0, 4))

        ip_frame = tk.Frame(self.card_ip, bg=COLORS["surface"])
        ip_frame.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(ip_frame, text="IP:", bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=0, column=0)
        self.inp_ip = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_ip.grid(row=0, column=1, padx=2, pady=1)
        self.inp_ip.insert(0, "192.168.1.100")

        tk.Label(ip_frame, text=_("network_mask"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=1, column=0)
        self.inp_mask = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_mask.grid(row=1, column=1, padx=2, pady=1)
        self.inp_mask.insert(0, "255.255.255.0")

        tk.Label(ip_frame, text=_("network_gateway"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=2, column=0)
        self.inp_gw = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_gw.grid(row=2, column=1, padx=2, pady=1)
        self.inp_gw.insert(0, "192.168.1.1")

        tk.Label(ip_frame, text="DNS1:", bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=3, column=0)
        self.inp_dns1 = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_dns1.grid(row=3, column=1, padx=2, pady=1)

        tk.Label(ip_frame, text="DNS2:", bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=4, column=0)
        self.inp_dns2 = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_dns2.grid(row=4, column=1, padx=2, pady=1)

        tk.Label(ip_frame, text=_("network_dhcp_server"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).grid(row=5, column=0)
        self.inp_dhcp_srv = tk.Entry(ip_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_dhcp_srv.grid(row=5, column=1, padx=2, pady=1)
        self.inp_dhcp_srv.config(state="readonly")

        # IP buttons
        ip_btns = tk.Frame(self.card_ip, bg=COLORS["surface"])
        ip_btns.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(ip_btns, text=_("btn_set_static"),
                   command=self._on_set_static).pack(side=tk.LEFT, padx=2)
        ttk.Button(ip_btns, text=_("btn_set_dhcp"),
                   command=self._on_set_dhcp).pack(side=tk.LEFT, padx=2)
        ttk.Button(ip_btns, text=_("btn_clear_ip"),
                   command=self._on_clear_ip).pack(side=tk.LEFT, padx=2)

        # -- MAC Config card --
        self.card_mac = InfoCard(right_col, _("mac_config"))
        self.card_mac.pack(fill=tk.X, pady=(0, 4))

        mac_frame = tk.Frame(self.card_mac, bg=COLORS["surface"])
        mac_frame.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(mac_frame, text=_("label_new_mac"), bg=COLORS["surface"], fg=COLORS["text2"],
                 font=("Segoe UI", 9), width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.inp_mac = tk.Entry(mac_frame, width=18, font=("Consolas", 9), bg=COLORS["surface"], fg=COLORS["text"])
        self.inp_mac.pack(side=tk.LEFT, padx=2)

        mac_btns = tk.Frame(self.card_mac, bg=COLORS["surface"])
        mac_btns.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(mac_btns, text=_("btn_modify_mac"),
                   command=self._on_modify_mac).pack(side=tk.LEFT, padx=2)
        ttk.Button(mac_btns, text=_("btn_restore_mac"),
                   command=self._on_restore_mac).pack(side=tk.LEFT, padx=2)
        ttk.Button(mac_btns, text=_("btn_random_mac"),
                   command=self._on_random_mac).pack(side=tk.LEFT, padx=2)
        ttk.Button(mac_btns, text=_("btn_restart_adapter"),
                   command=self._on_restart).pack(side=tk.LEFT, padx=2)

        # Warnings
        tk.Label(self.card_mac,
                 text=_("note_mac_ip"),
                 bg=COLORS["surface"], fg="#f59e0b",
                 font=("Segoe UI", 8, "italic")).pack(anchor=tk.W, padx=6, pady=(0, 1))
        tk.Label(self.card_mac,
                 text=_("note_mac_spoof"),
                 bg=COLORS["surface"], fg="#f59e0b",
                 font=("Segoe UI", 8, "italic")).pack(anchor=tk.W, padx=6, pady=(0, 2))

        # ---- Log panel ----
        log_frame = tk.LabelFrame(self.frame, text="  Log  ",
                                  bg=COLORS["bg"], fg=COLORS["text"],
                                  font=("Segoe UI", 9, "bold"))
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 6))
        self.log_text = tk.Text(log_frame, height=4, wrap=tk.WORD,
                               bg=COLORS["surface"], fg=COLORS["text"],
                               font=("Consolas", 9), relief=tk.SUNKEN, bd=1)
        self.log_text.tag_configure("log", background=COLORS["surface"], foreground=COLORS["text"])
        self.log_text.configure(insertbackground=COLORS["text"])
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Initial refresh
        self._refresh()
        register_theme_callback(self._refresh_log_theme)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _refresh_log_theme(self):
        """Re-apply log text widget colors after theme change."""
        try:
            from ui.styles import COLORS as _C
            bg = _C.get("surface", "#3c3c3c")
            fg = _C.get("text", "#e0e0e0")
            self.log_text.config(bg=bg, fg=fg, insertbackground=fg)
            self.log_text.tag_configure("log", background=bg, foreground=fg)
            parent = self.log_text.master
            if parent and hasattr(parent, 'config'):
                try:
                    parent.config(bg=bg,
                                  fg=fg)
                except Exception:
                    pass
            # Refresh InfoCard themes
            for card in (self.card_status, self.card_ip, self.card_mac):
                try:
                    card.refresh_theme()
                except Exception:
                    pass
        except Exception:
            pass

    def log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n", "log")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _append_log(self, msg: str):
        self.log_text.insert(tk.END, msg, "log")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _show_progress(self, total_ms: int):
        import time as _t
        start = _t.time()

        def _tick():
            elapsed = (_t.time() - start) * 1000
            if elapsed >= total_ms:
                self._append_log("\n")
                self._refresh()
                return
            self._append_log(".")
            self.frame.after(150, _tick)

        _tick()

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def _refresh(self):
        self.log("Scanning adapters...")
        try:
            self._interfaces = self.backend.get_interfaces()
        except Exception as exc:
            self.log(f"Scan error: {exc}")
            self._interfaces = []

        iface_labels = [f"{i.name} ({i.description})" for i in self._interfaces]
        self.iface_combo["values"] = iface_labels
        self.iface_count_var.set(f"{len(self._interfaces)} adapter(s)")

        if self._interfaces:
            # Find best selection: keep current if still present, else pick first CONNECTED
            current_name = self._current.name if self._current else ""
            best_idx = 0
            found_current = False
            for idx, iface in enumerate(self._interfaces):
                if iface.name == current_name:
                    best_idx = idx
                    found_current = True
                    break
            if not found_current:
                # Pick first connected adapter
                for idx, iface in enumerate(self._interfaces):
                    if iface.is_connected:
                        best_idx = idx
                        break
            self.iface_combo.current(best_idx)
            self._show_interface(self._interfaces[best_idx])
        else:
            self._clear_display()
            self._current = None
        self.log(f"Found {len(self._interfaces)} adapter(s)")

    def _on_combo_select(self, _event=None):
        idx = self.iface_combo.current()
        if 0 <= idx < len(self._interfaces):
            self._show_interface(self._interfaces[idx])

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _show_interface(self, iface):
        self._current = iface
        dash = "\u2014"

        self.lbl_mac.config(text=iface.mac_address or dash)
        if iface.is_mac_modified:
            self.lbl_mac_st.config(text="Modified")
        else:
            self.lbl_mac_st.config(text="Original")

        self.lbl_ip.config(text=iface.ipv4_address or dash)
        self.lbl_mask.config(text=iface.ipv4_mask or dash)
        self.lbl_gw.config(text=iface.ipv4_gateway or dash)
        dns_str = ", ".join(iface.dns_servers) if iface.dns_servers else dash
        self.lbl_dns.config(text=dns_str)
        self.lbl_dhcp.config(text="Enabled" if iface.dhcp_enabled else "Disabled")
        self.lbl_dhcp_srv.config(text=iface.dhcp_server or dash)
        self.lbl_speed.config(text=iface.link_speed or dash)
        self.lbl_mtu.config(text=str(iface.mtu) if iface.mtu else dash)
        self.lbl_status.config(text="Connected" if iface.is_connected else "Disconnected")
        self.lbl_guid.config(text=iface.guid or dash)
        self.lbl_scapy.config(text=iface.scapy_name or dash)

        self.inp_ip.delete(0, tk.END)
        self.inp_ip.insert(0, iface.ipv4_address or "")
        self.inp_mask.delete(0, tk.END)
        self.inp_mask.insert(0, iface.ipv4_mask or "")
        self.inp_gw.delete(0, tk.END)
        self.inp_gw.insert(0, iface.ipv4_gateway or "")
        self.inp_dns1.delete(0, tk.END)
        if iface.dns_servers:
            self.inp_dns1.insert(0, iface.dns_servers[0] if len(iface.dns_servers) > 0 else "")
            self.inp_dns2.delete(0, tk.END)
            self.inp_dns2.insert(0, iface.dns_servers[1] if len(iface.dns_servers) > 1 else "")
        else:
            self.inp_dns2.delete(0, tk.END)
        self.inp_mac.delete(0, tk.END)
        self.inp_mac.insert(0, iface.mac_address or "")
        self.inp_dhcp_srv.config(state="normal")
        self.inp_dhcp_srv.delete(0, tk.END)
        self.inp_dhcp_srv.insert(0, iface.dhcp_server or "")
        self.inp_dhcp_srv.config(state="readonly")

    def _clear_display(self):
        dash = "\u2014"
        for lbl in (self.lbl_mac, self.lbl_mac_st, self.lbl_ip, self.lbl_mask,
                    self.lbl_gw, self.lbl_dns, self.lbl_dhcp, self.lbl_dhcp_srv, self.lbl_speed,
                    self.lbl_mtu, self.lbl_status, self.lbl_guid, self.lbl_scapy):
            lbl.config(text=dash)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_iface(self) -> Optional[Any]:
        if not self._current:
            self.log("No adapter selected")
            return None
        return self._current

    def _run_elevated(self, op: str, *args) -> bool:
        """Run elevated operation and wait for completion."""
        try:
            if getattr(sys, 'frozen', False):
                rc = run_elevated(["--elevated-op", op] + [str(a) for a in args],
                                  wait=True, show_window=True)
            else:
                helper = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "network", "elevated_op.py",
                )
                rc = run_elevated([helper, op] + [str(a) for a in args],
                                  wait=True, show_window=True)
            if rc == 0:
                self.log(f"Operation '{op}' succeeded")
            else:
                self.log(f"Operation '{op}' failed (exit code {rc})")
            return rc == 0
        except Exception as e:
            self.log(f"Elevation error: {e}")
            return False

    def _do_op(self, op_name: str, in_process_fn, *args, refresh_after_ms: int = 5000):
        """Run an admin-only op either in-process (if admin) or via elevated helper."""
        if _is_admin():
            ok = in_process_fn(*args)
            if ok:
                self.log(f"{op_name} succeeded")
                if refresh_after_ms:
                    self.frame.after(refresh_after_ms, self._refresh)
            else:
                err = getattr(self.backend, "last_error", "") or "unknown"
                self.log(f"{op_name} failed: {err}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            if self._run_elevated(*args):
                self.log("Elevated helper launched — wait for it to finish, then click Refresh.")
                if refresh_after_ms:
                    self.frame.after(refresh_after_ms, self._refresh)
            else:
                self.log("Operation cancelled")

    # ------------------------------------------------------------------
    # Actions — IP
    # ------------------------------------------------------------------

    def _on_set_static(self):
        iface = self._require_iface()
        if not iface:
            return
        ip = self.inp_ip.get().strip()
        mask = self.inp_mask.get().strip()
        gw = self.inp_gw.get().strip()
        dns = [d for d in (self.inp_dns1.get().strip(), self.inp_dns2.get().strip()) if d]
        if not ip or not mask:
            self.log("IP and mask are required")
            return
        self.log(f"Setting static IP {ip}/{mask} on {iface.name}...")
        if _is_admin():
            ok = self.backend.set_static_ip(iface.name, ip, mask, gw, dns)
            if ok:
                self.log("Static IP set")
                self._show_progress(3000)
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            args = ["set-static", iface.name, ip, mask]
            if gw:
                args.append(gw)
            if dns:
                args.append("--dns")
                args.extend(dns)
            self._run_elevated(*args)
            self._show_progress(5000)

    def _on_set_dhcp(self):
        iface = self._require_iface()
        if not iface:
            return
        self.log(f"Enabling DHCP on {iface.name}...")
        if _is_admin():
            ok = self.backend.set_dhcp(iface.name)
            if ok:
                self.log("DHCP enabled")
                self._show_progress(3000)
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            self._run_elevated("set-dhcp", iface.name)
            self._show_progress(5000)

    def _on_clear_ip(self):
        """Clear IP configuration on the adapter and reset the input fields."""
        iface = self._require_iface()
        if not iface:
            # Even without an adapter, clear the input fields
            self.inp_ip.delete(0, tk.END)
            self.inp_mask.delete(0, tk.END)
            self.inp_gw.delete(0, tk.END)
            self.inp_dns1.delete(0, tk.END)
            self.inp_dns2.delete(0, tk.END)
            self.log("IP fields cleared")
            return
        
        # Clear the adapter's IP using the backend
        self.log(f"Clearing IP on {iface.name}...")
        if _is_admin():
            ok = self.backend.clear_ip(iface.name)
            if ok:
                self.log("IP cleared on adapter")
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights ...")
            self._run_elevated("clear-ip", iface.name)
        
        # Also clear IP input fields
        self.inp_ip.delete(0, tk.END)
        self.inp_mask.delete(0, tk.END)
        self.inp_gw.delete(0, tk.END)
        self.inp_dns1.delete(0, tk.END)
        self.inp_dns2.delete(0, tk.END)
        self._show_progress(3000)

    # ------------------------------------------------------------------
    # Actions — MAC
    # ------------------------------------------------------------------

    def _on_modify_mac(self):
        iface = self._require_iface()
        if not iface:
            return
        new_mac = self.inp_mac.get().strip()
        clean = new_mac.replace(":", "").replace("-", "")
        if not re.match(r"^[0-9A-Fa-f]{12}$", clean):
            self.log("Invalid MAC format (use XX:XX:XX:XX:XX:XX)")
            return
        self.log(f"Setting MAC to {new_mac} on {iface.name}...")
        if _is_admin():
            ok = self.backend.set_mac_address(iface.name, new_mac)
            if ok:
                self.log("MAC modified (adapter will restart)")
                self._show_progress(5000)
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            self._run_elevated("modify-mac", iface.guid, new_mac)
            self._show_progress(8000)

    def _on_restore_mac(self):
        iface = self._require_iface()
        if not iface:
            return
        self.log(f"Restoring default MAC on {iface.name}...")
        if _is_admin():
            ok = self.backend.restore_mac(iface.name)
            if ok:
                self.log("MAC restored (adapter will restart)")
                self._show_progress(5000)
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            self._run_elevated("restore-mac", iface.guid)
            self._show_progress(8000)

    def _on_random_mac(self):
        # Locally-administered, unicast: first byte has bits 0x02 set, bit 0x01 cleared
        first = random.randint(0, 254) | 0x02
        first &= 0xFE  # clear multicast bit
        mac_bytes = [first] + [random.randint(0, 255) for _ in range(5)]
        mac = ":".join(f"{b:02X}" for b in mac_bytes)
        self.inp_mac.delete(0, tk.END)
        self.inp_mac.insert(0, mac)
        self.log(f"Generated random MAC: {mac}")

    def _on_restart(self):
        iface = self._require_iface()
        if not iface:
            return
        self.log(f"Restarting {iface.name}...")
        if _is_admin():
            ok = self.backend.restart_interface(iface.name)
            if ok:
                self.log("Adapter restarted")
                self._show_progress(5000)
            else:
                self.log(f"Failed: {getattr(self.backend, 'last_error', '')}")
        else:
            self.log("Requesting admin rights (click Yes on the UAC prompt)...")
            self._run_elevated("restart-adapter", iface.guid)
            self._show_progress(8000)

    def update_texts(self):
        pass
