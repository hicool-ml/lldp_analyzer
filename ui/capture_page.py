from typing import Optional, Dict, Any
import tkinter as tk
from tkinter import ttk

from utils.adapter_scanner import scan_ethernet_adapters
from db.database import LLDPHistoryDatabase
from ui.widgets import InfoCard
from i18n.translations import _
from ui.styles import COLORS, register_theme_callback
from engine.decision_engine import DecisionEngine


class CapturePage:
    def __init__(self, notebook: ttk.Notebook, main_window):
        self.main = main_window
        self.db = LLDPHistoryDatabase()
        self.frame = tk.Frame(notebook, bg=COLORS["bg"])
        self._current_result: Optional[Dict[str, Any]] = None

        # Persistent capture engine for always-on monitoring
        self._capture_engine = None
        self._is_monitoring = False

        self._build_ui()
        self._start_monitoring()
        register_theme_callback(self._refresh_log_theme)

    def _start_monitoring(self):
        """Start persistent monitoring when page is loaded."""
        from network.backends.platform import is_darwin

        if is_darwin():
            # macOS: Show waiting for cable message, but let user click capture to start
            self.log(_("msg_waiting_cable"))
            self.status_var.set(_("status_waiting_link"))
        else:
            # Windows/Linux: traditional click-to-capture
            self.log(_("status_idle"))

    def _refresh_log_theme(self):
        """Re-apply log text widget colors after theme change."""
        try:
            from ui.styles import COLORS as _C
            bg = _C.get("surface", "#3c3c3c")
            fg = _C.get("text", "#e0e0e0")
            self.log_text.config(bg=bg, fg=fg, insertbackground=fg)
            self.log_text.tag_configure("log", background=bg, foreground=fg)
            # Also refresh the parent LabelFrame if it exists
            parent = self.log_text.master
            if parent and hasattr(parent, 'config'):
                try:
                    parent.config(bg=bg,
                                  fg=fg)
                except Exception:
                    pass
            # Refresh InfoCard themes
            for card in (self.card_device, self.card_semantic, self.card_port):
                try:
                    card.refresh_theme()
                except Exception:
                    pass
        except Exception:
            pass

    def _process_capture_results(self, packets):
        """Process captured LLDP/CDP packets and update UI."""
        try:
            if packets:
                self._current_result = packets[0]
                self._run_semantic_analysis(packets[0])
                self._display_result(packets[0])
                self._save_to_db(packets[0])
                self.log(f"Capture finished — {len(packets)} neighbors found.")
                self.status_var.set(_("status_idle"))
        except Exception as e:
            self.log(f"Error processing results: {e}")

    def _build_ui(self):
        ctrl = tk.Frame(self.frame, bg=COLORS["bg"])
        ctrl.pack(fill=tk.X, padx=10, pady=(6, 4))

        tk.Label(ctrl, text=_("network_adapter"), bg=COLORS["bg"],
                 fg=COLORS["text2"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(ctrl, textvariable=self.iface_var,
                                        width=30, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=4)

        ttk.Button(ctrl, text=_("action_refresh"),
                   command=self._refresh_interfaces).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text=_("btn_start_capture"),
                   command=self._on_capture).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text=_("btn_load_file"),
                   command=self._on_open_file).pack(side=tk.LEFT, padx=4)

        self.thorough_var = tk.BooleanVar(value=False)
        self.thorough_checkbox = ttk.Checkbutton(
            ctrl,
            text="Wait for both LLDP and CDP",
            variable=self.thorough_var,
        )
        self.thorough_checkbox.pack(side=tk.LEFT, padx=8)

        self.status_var = tk.StringVar(value=_("status_idle"))
        tk.Label(ctrl, textvariable=self.status_var, bg=COLORS["bg"],
                 fg=COLORS["info"], font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=8)

        cards_frame = tk.Frame(self.frame, bg=COLORS["bg"])
        cards_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        self.card_device = InfoCard(cards_frame, _("network_status"), width=340)
        self.card_device.pack_propagate(False)
        self.card_device.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))
        self.d_protocol = self.card_device.add_row(_("protocol"))
        self.d_vendor = self.card_device.add_row(_("vendor"))
        self.d_name = self.card_device.add_row(_("system_name"))
        self.d_model = self.card_device.add_row(_("platform"))
        self.d_serial = self.card_device.add_row(_("serial"))
        self.d_mac = self.card_device.add_row(_("chassis_mac"))
        self.d_ip = self.card_device.add_row(_("mgmt_address"))
        self.d_sw = self.card_device.add_row(_("software"))
        self.d_desc = self.card_device.add_row(_("description"))

        right_container = tk.Frame(cards_frame, bg=COLORS["bg"])
        right_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))

        self.card_semantic = InfoCard(right_container, _("semantic_analysis"))
        self.card_semantic.pack(fill=tk.X, pady=(0, 4))
        self.s_role = self.card_semantic.add_row(_("port_role"))
        self.s_dtype = self.card_semantic.add_row(_("device_type"))
        self.s_conf = self.card_semantic.add_row(_("confidence"))
        self.s_intent = self.card_semantic.add_row(_("intent"))
        self.s_evidence = self.card_semantic.add_row(_("evidence"))

        self.card_port = InfoCard(right_container, _("connection_port"))
        self.card_port.pack(fill=tk.BOTH)
        self.p_portid = self.card_port.add_row(_("port_id"))
        self.p_pdesc = self.card_port.add_row(_("port_desc"))
        self.p_vlan = self.card_port.add_row(_("native_vlan"))
        self.p_speed = self.card_port.add_row(_("speed_duplex"))
        self.p_agg = self.card_port.add_row(_("link_aggr"))
        self.p_mtu = self.card_port.add_row(_("mtu"))
        self.p_poe = self.card_port.add_row(_("poe"))
        self.p_caps = self.card_port.add_row(_("capabilities"))

        prog_frame = tk.Frame(self.frame, bg=COLORS["bg"])
        prog_frame.pack(fill=tk.X, padx=10, pady=(2, 4))
        self.progress = ttk.Progressbar(prog_frame, mode="determinate", maximum=100)
        self.progress.pack(fill=tk.X)

        log_frame = tk.LabelFrame(self.frame, text="  Log  ",
                                  bg=COLORS["bg"],
                                  fg=COLORS["text"],
                                  font=("Segoe UI", 9, "bold"))
        log_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 6))

        self.log_text = tk.Text(log_frame, height=6, wrap=tk.WORD,
                                bg=COLORS["surface"], fg=COLORS["text"],
                                font=("Consolas", 9), relief=tk.SUNKEN, bd=1)
        # Configure default tag for proper theme coloring
        self.log_text.tag_configure("log", background=COLORS["surface"], foreground=COLORS["text"])
        self.log_text.configure(insertbackground=COLORS["text"])
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._refresh_interfaces()

    def update_texts(self):
        pass

    def log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n", "log")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _append_log(self, msg: str):
        self.log_text.insert(tk.END, msg, "log")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def load_file(self, filepath: str) -> None:
        """Load an offline capture hex file into the capture page."""
        self.status_var.set(_("status_analyzing"))
        self.log(f"Loading file: {filepath}")
        try:
            from utils.protocol_parser import parse_offline_file
            result = parse_offline_file(filepath)
            if result and result.get("success"):
                self._current_result = result
                self._run_semantic_analysis(result)
                self._display_result(result)
                self._save_to_db(result)
                self.log("Loaded 1 packet(s)")
            else:
                self.log(_("msg_no_packets_found"))
            self.status_var.set(_("status_idle"))
        except Exception as e:
            self.log(f"Error loading file: {e}")
            self.status_var.set(_("status_idle"))

    def _refresh_interfaces(self):
        self.iface_combo["values"] = []
        self._adapters = []
        self._iface_data = []
        try:
            for a in scan_ethernet_adapters():
                display = f"{a['name']} ({a['description']})" if a.get('description') else a['name']
                self._iface_data.append(display)
                self._adapters.append(a)
            if self._iface_data:
                self.iface_combo["values"] = self._iface_data
                self.iface_combo.current(0)
                self.log(f"Found {len(self._iface_data)} Ethernet adapter(s)")
            else:
                self.log(_("msg_no_adapters"))
        except Exception as exc:
            self.log(f"Adapter scan error: {exc}")

    def _on_capture(self):
        """Start capture."""
        import os
        import sys
        import tempfile
        from network.backends.platform import is_darwin

        iface_idx = self.iface_combo.current()
        iface_name = ""
        if 0 <= iface_idx < len(self._adapters):
            iface_name = self._adapters[iface_idx].get("scapy_name") or self._adapters[iface_idx].get("name", "")

        fd, json_path = tempfile.mkstemp(suffix=".json", prefix="lldp_cap_")
        os.close(fd)
        os.unlink(json_path)

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        is_frozen = getattr(sys, 'frozen', False)

        if is_frozen:
            exe = sys.executable
            cmd_args = ["--json-out", json_path]
            if iface_name:
                cmd_args.extend(["--interface", iface_name])
            if is_darwin():
                cmd_args.append("--wait-for-link")
            if self.thorough_var.get():
                cmd_args.append("--thorough")
            cwd = os.path.dirname(exe)
        else:
            # Non-frozen: use lldp_gui.py itself with --json-out (it has a
            # headless capture mode). This avoids path issues when lldp.py
            # is not in the same directory.
            exe = sys.executable
            gui_script = os.path.abspath(sys.argv[0])
            cmd_args = [gui_script, "--json-out", json_path]
            if iface_name:
                cmd_args.extend(["--interface", iface_name])
            if is_darwin():
                cmd_args.append("--wait-for-link")
            if self.thorough_var.get():
                cmd_args.append("--thorough")
            cwd = project_root

        from utils.elevator import is_admin
        self.frame.after(0, lambda: self.log("Launching elevated capture..."))

        def _on_capture_complete(rc):
            self.progress.stop()
            self.progress.config(mode="determinate")

            # Preserve the full capture log (written by the headless child
            # to json_path + ".log") on the Desktop so the user can find it.
            import shutil as _shutil
            cap_log_src = json_path + ".log"
            desktop_dir = os.path.expanduser("~/Desktop")
            cap_log_dst = os.path.join(desktop_dir, "lldp_capture.log")
            try:
                if os.path.exists(cap_log_src):
                    _shutil.copy2(cap_log_src, cap_log_dst)
            except Exception:
                cap_log_dst = ""

            if rc == 0:
                if os.path.exists(json_path):
                    try:
                        import json
                        with open(json_path, "r", encoding="utf-8") as f:
                            results = json.load(f)
                        os.unlink(json_path)
                        if results:
                            # Wrap each step independently so failures don't block DB save
                            try:
                                self._run_semantic_analysis(results[0])
                            except Exception as e:
                                self.log(f"Semantic analysis error: {e}")
                            try:
                                self._display_result(results[0])
                            except Exception as e:
                                self.log(f"Display error: {e}")
                            try:
                                self._save_to_db(results[0])
                            except Exception as e:
                                self.log(f"Database save error: {e}")
                            self.log(f"Capture finished — {len(results)} neighbors found.")
                        else:
                            self.log("Capture finished — 0 neighbors found.")
                            if cap_log_dst:
                                self.log("Full capture log: " + cap_log_dst)
                    except Exception as e:
                        self.log(f"Error reading results: {e}")
                else:
                    self.log("Capture finished — 0 neighbors found.")
            else:
                # Show the capture log so failures are diagnosable.
                if cap_log_dst and os.path.exists(cap_log_dst):
                    try:
                        with open(cap_log_dst, "r") as lf:
                            tail = lf.read().strip()[-800:]
                    except Exception:
                        tail = ""
                    self.log("Capture failed (exit %d). Log: %s" % (rc, cap_log_dst))
                    if tail:
                        self.log(tail)
                else:
                    self.log("Capture failed with exit code %d" % rc)

            self.status_var.set(_("status_idle"))

        self.status_var.set(_("status_capturing"))
        self.progress.config(mode="indeterminate")
        self.progress.start(15)
        self.log(_("msg_capture_start"))

        if is_admin():
            import subprocess
            import threading

            # On macOS, set PYTHONPATH so the system Python can find scapy
            # in the venv site-packages (the venv Python is not used by
            # the elevated process to avoid TCC pyvenv.cfg blocking).
            extra_env = None
            if is_darwin() and not is_frozen:
                venv_site = os.path.join(project_root, 'venv', 'lib', 'python3.11', 'site-packages')
                if os.path.isdir(venv_site):
                    extra_env = os.environ.copy()
                    pp = extra_env.get("PYTHONPATH", "")
                    parts = [project_root, venv_site]
                    if pp:
                        parts.insert(0, pp)
                    extra_env["PYTHONPATH"] = ":".join(parts)

            def _run_capture():
                try:
                    result = subprocess.run(
                        [exe] + cmd_args,
                        capture_output=True, text=True,
                        stdin=subprocess.DEVNULL,
                        env=extra_env,
                        timeout=120,
                        cwd=cwd,
                    )
                    _rc = result.returncode
                except subprocess.TimeoutExpired:
                    _rc = 1
                    self.log("Capture timed out")
                self.frame.after(0, lambda: _on_capture_complete(_rc))

            t = threading.Thread(target=_run_capture, daemon=True)
            t.start()
        else:
            from utils.elevator import run_elevated
            import threading

            def _run_elevated():
                rc = run_elevated(cmd_args, executable=exe, wait=True, show_window=True, cwd=cwd)
                self.frame.after(0, lambda: _on_capture_complete(rc if rc is not None else 0))

            t = threading.Thread(target=_run_elevated, daemon=True)
            t.start()

    def _display_result(self, result):
        """Display captured LLDP/CDP result in UI."""
        if result is None:
            return
        try:

            def _fmt(val):
                if val is None or val == "":
                    return ""
                if isinstance(val, bool):
                    return "Supported" if val else "Not supported"
                if isinstance(val, dict):
                    # Capabilities TLV
                    if "enabled" in val:
                        enabled = val.get("enabled", [])
                        if enabled:
                            return ", ".join(str(v) for v in enabled)
                        supported = val.get("supported", [])
                        if supported:
                            return ", ".join(str(v) for v in supported)
                    # Capabilities dict with "capabilities" key
                    if "capabilities" in val:
                        caps = val["capabilities"]
                        if isinstance(caps, list) and caps:
                            return ", ".join(str(v) for v in caps)
                    # Try decoded sub-dict for vendor fields
                    if "decoded" in val:
                        return _fmt(val["decoded"])
                    # Generic dict: just show readable values
                    parts = []
                    for k, v in val.items():
                        if isinstance(v, (list, tuple)):
                            parts.append(f"{k}: {', '.join(str(x) for x in v)}")
                        elif isinstance(v, (str, int, float)):
                            parts.append(str(v))
                    return ", ".join(parts) if parts else str(val)
                if isinstance(val, (list, tuple)):
                    return ", ".join(str(v) for v in val)
                return str(val)

            fields = result.get("fields", {})

            self.d_protocol.config(text=result.get("protocol", ""))
            self.d_vendor.config(text=result.get("vendor", ""))
            self.d_name.config(text=fields.get("system_name", ""))
            self.d_model.config(text=fields.get("platform", ""))
            self.d_serial.config(text=fields.get("serial", ""))
            self.d_mac.config(text=fields.get("chassis_id", ""))
            self.d_ip.config(text=_fmt(fields.get("management_addresses", "")))
            self.d_sw.config(text=fields.get("software_version", ""))
            self.d_desc.config(text=fields.get("system_description", ""))

            self.s_role.config(text=fields.get("port_role", ""))
            self.s_dtype.config(text=fields.get("device_type", ""))
            self.s_conf.config(text=fields.get("confidence", ""))
            self.s_intent.config(text=fields.get("intent", ""))
            self.s_evidence.config(text=fields.get("evidence", ""))

            self.p_portid.config(text=fields.get("port_id", ""))
            self.p_pdesc.config(text=fields.get("port_description", ""))
            self.p_vlan.config(text=_fmt(fields.get("native_vlan", "")))
            self.p_speed.config(text=_fmt(fields.get("mac_phy", "")))
            self.p_agg.config(text=_fmt(fields.get("aggregation", "")))
            self.p_mtu.config(text=_fmt(fields.get("mtu", "")))
            self.p_poe.config(text=_fmt(fields.get("poe_supported", "")))
            self.p_caps.config(text=_fmt(fields.get("capabilities", "")))
        except Exception as e:
            self.log(f"Display error: {e}")

    def _save_to_db(self, result):
        """Save capture result to history database."""
        try:
            fields = result.get("fields", {})
            mgmt = fields.get("management_addresses", [])
            ip_address = ", ".join(str(a) for a in mgmt) if mgmt else ""
            self.db.save_capture(
                protocol=result.get("protocol", ""),
                device_name=fields.get("system_name", ""),
                chassis_id=fields.get("chassis_id", ""),
                port_id=fields.get("port_id", ""),
                port_description=fields.get("port_description", ""),
                mac_address=fields.get("chassis_id", ""),
                ip_address=ip_address,
                system_description=fields.get("system_description", ""),
                device_model=fields.get("platform", ""),
                serial_number=fields.get("serial", ""),
                software_version=fields.get("software_version", ""),
                port_vlan=fields.get("native_vlan") or fields.get("pvid"),
                link_speed=fields.get("link_speed") or fields.get("mac_phy", ""),
                duplex_mode=str(fields.get("duplex", "")),
                port_role=fields.get("port_role"),
                device_type=fields.get("device_type"),
                confidence=fields.get("confidence"),
                raw_packet=result.get("raw_hex", ""),
            )
        except Exception as e:
            self.log(f"Database save error: {e}")

    def _run_semantic_analysis(self, result):
        """Run decision engine and update semantic analysis GUI fields."""
        try:
            engine = DecisionEngine()
            engine.feed_from_result(result)
            profile = engine.resolve()
            if profile:
                role = profile.role.value if profile.role else ""
                dtype = profile.device_type.value if profile.device_type else ""
                intent = profile.intent.value if profile.intent else ""
                evidence_parts = []
                if profile.tlv_evidence:
                    evidence_parts.extend(profile.tlv_evidence)
                if profile.semantic_reasons:
                    evidence_parts.extend(r.description for r in profile.semantic_reasons)
                if profile.operational_insight:
                    evidence_parts.append(profile.operational_insight)
                evidence = "; ".join(evidence_parts) if evidence_parts else ""
                # Store semantic fields into result so _display_result and
                # _save_to_db can access them.
                fields = result.get("fields", {})
                if role:
                    fields["port_role"] = role
                if dtype:
                    fields["device_type"] = dtype
                if profile.confidence:
                    fields["confidence"] = profile.confidence
                if intent:
                    fields["intent"] = intent
                if evidence:
                    fields["evidence"] = evidence
        except Exception as e:
            self.log(f"Semantic analysis error: {e}")

    def _on_open_file(self):
        """Open file dialog to load offline capture file."""
        from tkinter import filedialog

        file_path = filedialog.askopenfilename(
            title=_("select_capture_file"),
            filetypes=[
                ("Capture files", "*.txt *.hex *.pcap *.pcapng"),
                ("Hex text files", "*.txt"),
                ("PCAP files", "*.pcap"),
                ("PCAPNG files", "*.pcapng"),
                ("All files", "*.*"),
            ]
        )

        if file_path:
            self.status_var.set(_("status_analyzing"))
            self.log(f"Loading file: {file_path}")
            try:
                from utils.protocol_parser import parse_offline_file
                result = parse_offline_file(file_path)
                if result and result.get("success"):
                    self._current_result = result
                    self._run_semantic_analysis(result)
                    self._display_result(result)
                    self._save_to_db(result)
                    self.log("Loaded 1 packet(s)")
                else:
                    self.log(_("msg_no_packets_found"))
                self.status_var.set(_("status_idle"))
            except Exception as e:
                self.log(f"Error loading file: {e}")
                self.status_var.set(_("status_idle"))


def _find_system_python() -> str:
    """Find a system Python binary for elevated capture on macOS.

    We need a Python that:
      1. Can run the project code (Python 3.10+ for | syntax in type hints).
      2. Does NOT trigger macOS 14+ TCC restrictions when run via sudo -E
         (the venv Python does trigger this because of pyvenv.cfg).
      3. Can find scapy via PYTHONPATH pointing to venv site-packages.

    Strategy: prefer Homebrew Python 3.11, fall back to system Python.
    """
    import sys, os
    # 1. Homebrew Python 3.11 (preferred: syntax-compatible, no TCC issue)
    for candidate in ("/opt/homebrew/bin/python3.11",
                       "/opt/homebrew/opt/python@3.11/bin/python3.11"):
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    # 2. Inside a venv: sys.base_prefix has the base Python path.
    #    The real binary is at <base_prefix>/bin/python3.11 or similar.
    if getattr(sys, "prefix", None) and getattr(sys, "base_prefix", None):
        if sys.prefix != sys.base_prefix:
            bp = sys.base_prefix
            for candidate in (os.path.join(bp, "bin", "python3.11"),
                               os.path.join(bp, "..", "bin", "python3.11"),
                               os.path.join(bp, "bin", "python3")):
                c = os.path.normpath(os.path.abspath(candidate))
                if os.path.isfile(c):
                    return c
    # 3. Common Homebrew / macOS system Python locations
    for candidate in ("/opt/homebrew/bin/python3",
                       "/usr/local/bin/python3",
                       "/usr/bin/python3"):
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    # 4. Ultimate fallback — same as caller
    return sys.executable
