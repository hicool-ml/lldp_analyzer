import _import_all  # noqa: F401 - MUST be first import for PyInstaller
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLDP/CDP Protocol Analyzer GUI entry point.

Usage:
    python lldp_gui.py              # Launch GUI
    python lldp_gui.py <file>       # Launch GUI with offline file loaded

When invoked with --json-out <path> the GUI is skipped and the CLI
capture engine runs directly (used for elevated captures launched by
the GUI itself via ShellExecuteW('runas')).

When invoked with --elevated-op <op> <args...> the GUI is skipped and
a single privileged network operation runs (used by the Network page).
"""

import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Platform-specific imports and initialization
_is_windows = sys.platform == "win32"
_is_macos = sys.platform == "darwin"
_is_admin = False
try:
    _is_admin = os.geteuid() == 0
except Exception:
    pass

if _is_windows:
    import ctypes
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "com.lldp.analyzer.app")
    except Exception:
        pass

    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDpiAwareness(2)
        except Exception:
            pass


def _resource_path(relative):
    """Resolve a resource path for both source runs and PyInstaller bundles."""
    from utils.platform_utils import get_resource_path
    return get_resource_path(relative)


# Initialize internationalization
from i18n.translations import init_translations, get_translator, _
from i18n.config import LanguageConfig


init_translations()

# Load saved language preference or use system default
config = LanguageConfig()
saved_lang = config.get_language()
if saved_lang:
    get_translator().set_language(saved_lang)


def _run_cli_capture(json_out_path: str) -> int:
    """Headless capture path: run the CLI engine and write JSON, no GUI."""
    import json, time as _time, io
    log_path = json_out_path + ".log"
    _log_file = open(log_path, "w", encoding="utf-8")

    def _log(msg):
        try:
            _log_file.write(f"{_time.strftime('%H:%M:%S')} {msg}\n")
            _log_file.flush()
        except Exception:
            pass

    _orig_stdout = sys.stdout
    sys.stdout = _log_file
    try:
        _log(f"START admin={_is_admin()} frozen={getattr(sys, 'frozen', False)}")
        _log(f"argv: {sys.argv}")
        
        interface = None
        wait_for_link = False
        wait_for_both = False
        
        if "--interface" in sys.argv:
            idx = sys.argv.index("--interface")
            if idx + 1 < len(sys.argv):
                interface = sys.argv[idx + 1]
        
        if "--wait-for-link" in sys.argv:
            wait_for_link = True
        
        if "--thorough" in sys.argv:
            wait_for_both = True
        
        _log(f"Parsed args: interface={interface}, wait_for_link={wait_for_link}, wait_for_both={wait_for_both}")
        
        from utils.packet_capture import run_online_capture
        _log("--- run_online_capture starting ---")
        results = run_online_capture(
            timeout=30, 
            renegotiate=True,
            interface=interface,
            wait_for_link=wait_for_link,
            wait_for_both=wait_for_both
        )
        _log(f"--- capture done, {len(results or [])} results ---")
        with open(json_out_path, "w", encoding="utf-8") as f:
            json.dump(results or [], f, default=str, ensure_ascii=False)
        _log("JSON written")
        return 0
    except Exception as exc:
        import traceback
        _log(f"ERROR {exc}")
        _log(f"TRACEBACK: {traceback.format_exc()}")
        return 1
    finally:
        sys.stdout = _orig_stdout
        _log_file.close()


def _run_elevated_network_op(args: list) -> int:
    """Headless elevated network operation — reuses elevated_op logic."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    meipass = getattr(sys, '_MEIPASS', '')
    if meipass and meipass not in sys.path:
        sys.path.insert(0, meipass)

    saved_argv = sys.argv
    sys.argv = ['elevated_op'] + args
    try:
        from network.elevated_op import main as _elev_main
        return _elev_main() or 0
    except Exception as exc:
        print(f"[ERROR] Elevated op failed: {exc}")
        return 1
    finally:
        sys.argv = saved_argv


def _is_admin() -> bool:
    from utils.elevator import is_admin
    return is_admin()


def _find_system_python() -> str:
    """Find a system Python binary for elevated execution.

    The venv Python (sys.executable) triggers macOS 14+ TCC kernel
    enforcement when read via sudo because of pyvenv.cfg provenance.
    A system Python (Homebrew or Xcode) has no pyvenv.cfg and thus
    avoids the block.

    Strategy:
        1. Homebrew Python 3.11 (preferred — matches the venv Python version).
        2. Homebrew Python 3 (generic).
        3. macOS / Xcode /usr/bin/python3.
        4. Ultimate fallback — the caller's own executable.
    """
    _candidates = [
        "/opt/homebrew/bin/python3.11",
        "/opt/homebrew/opt/python@3.11/bin/python3.11",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ]
    for _p in _candidates:
        if os.path.isfile(_p):
            return os.path.abspath(_p)
    return sys.executable


def _check_packet_capture_support() -> tuple[bool, str]:
    """Check if packet capture support is available on this platform."""
    from utils.platform_utils import check_packet_capture_support
    return check_packet_capture_support()


def main():
    if "--json-out" in sys.argv:
        idx = sys.argv.index("--json-out")
        if idx + 1 < len(sys.argv):
            sys.exit(_run_cli_capture(sys.argv[idx + 1]))

    if "--elevated-op" in sys.argv:
        idx = sys.argv.index("--elevated-op")
        op_args = sys.argv[idx + 1:]
        if op_args:
            sys.exit(_run_elevated_network_op(op_args))
        sys.exit(1)

    # --- macOS startup elevation ---
    # CRITICAL: Use the SYSTEM Python (not the venv Python) to avoid macOS 14+
    # TCC kernel-level enforcement that blocks pyvenv.cfg reads even with sudo.
    # + Set PYTHONPATH so the system Python can find the project + venv packages.
    # NOTE: Skip startup elevation in frozen mode (PyInstaller) because sudo
    # requires a terminal, which isn't available when double-clicking from Finder.
    # Instead, elevation happens per-operation via osascript GUI authentication.
    if sys.platform == 'darwin' and not _is_admin() and '--skip-elevate' not in sys.argv and not getattr(sys, 'frozen', False):
        project_root = os.path.dirname(os.path.abspath(__file__))
        system_python = _find_system_python()

        pythonpath_parts = [project_root]
        venv_site = os.path.join(project_root, 'venv', 'lib', 'python3.11', 'site-packages')
        if os.path.isdir(venv_site):
            pythonpath_parts.append(venv_site)
        ppath = ":".join(pythonpath_parts)

        import subprocess
        # Detect dark mode in the CURRENT (user) context before sudo clears HOME
        try:
            dark_check = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=2,
            )
            dark_mode_flag = "1" if (dark_check.returncode == 0 and dark_check.stdout.strip().lower() == "dark") else "0"
        except Exception:
            dark_mode_flag = "0"

        cmd = [system_python] + sys.argv + ['--skip-elevate']
        env_cmd = ['sudo', 'env', f'PYTHONPATH={ppath}', f'DARK_MODE={dark_mode_flag}'] + cmd
        try:
            subprocess.run(env_cmd)
        except Exception:
            pass
        sys.exit(0)

    # --- Check packet capture support ---
    supported, message = _check_packet_capture_support()
    
    if not supported:
        import subprocess
        import tempfile
        import tkinter as tk
        from tkinter import ttk
        from tkinter import messagebox as _mb
        
        _continue_without_support = False
        
        def _install_support():
            """Guide user to install packet capture support."""
            if _is_windows:
                import webbrowser
                _mb.showinfo(
                    "Install Packet Capture Driver",
                    "LLDP Analyzer requires a packet capture driver on Windows.\n\n"
                    "Recommended: Npcap (modern, maintained)\n"
                    "  https://npcap.com/dist/npcap-1.88.exe\n\n"
                    "Alternative: WinPcap (legacy)\n"
                    "  https://www.winpcap.org/install/bin/WpdPack_4_1_2.exe\n\n"
                    "If you already have WinPcap installed:\n"
                    "  1. Install Npcap with 'WinPcap API-compatible mode'\n"
                    "  2. Or enable Npcap compatibility in WinPcap settings"
                )
            elif _is_macos:
                import webbrowser
                webbrowser.open("https://github.com/Homebrew/homebrew-cask/blob/master/Casks/chmodbpf.rb")
            else:  # Linux
                _mb.showinfo(
                    "Install libpcap",
                    "Please install libpcap:\n\n"
                    "Ubuntu/Debian: sudo apt install libpcap-dev tcpdump\n"
                    "Fedora: sudo dnf install libpcap-devel tcpdump\n"
                    "macOS: brew install homebrew/cask/chmodbpf"
                )
        
        def _check_and_continue():
            nonlocal _continue_without_support
            supported_now, _ = _check_packet_capture_support()
            if supported_now:
                _continue_without_support = True
                _root.destroy()
            else:
                _mb.showwarning("Packet Capture Not Available", "Packet capture not available.\n\nPlease install the required support.")
        
        def _on_close():
            _root.destroy()
            sys.exit(0)
        
        _root = tk.Tk()
        _root.title("Packet Capture Support")
        _root.geometry("420x240")
        _root.resizable(False, False)
        try:
            _root.iconbitmap(_resource_path("lldp_icon.ico"))
        except Exception:
            pass
        
        _frame = ttk.Frame(_root, padding="20")
        _frame.pack(fill="both", expand=True)
        
        _label = ttk.Label(
            _frame,
            text="LLDP Analyzer requires packet capture support to function:\n\n" + message,
            wraplength=380,
            justify="center"
        )
        _label.pack(pady=(0, 15))
        
        _install_button = ttk.Button(_frame, text="Install / Learn More", command=_install_support)
        _install_button.pack(pady=(0, 15))
        
        _button = ttk.Button(_frame, text="Check Again", command=_check_and_continue)
        _button.pack(pady=(0, 10))
        
        _exit_button = ttk.Button(_frame, text="Exit", command=_on_close)
        _exit_button.pack()
        
        _root.protocol("WM_DELETE_WINDOW", _on_close)
        _root.mainloop()
        
        if not _continue_without_support:
            sys.exit(0)
    
    # --- Normal GUI mode ---
    import traceback
    def _excepthook(exc_type, exc_value, exc_tb):
        msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            from tkinter import messagebox as _mb
            _mb.showerror('Error', msg[-500:])
        except Exception:
            print(msg)
    sys.excepthook = _excepthook
    import tkinter as tk
    from tkinter import ttk
    from ui.main_window import LLDPMainWindow
    from utils.platform_utils import apply_platform_theme

    root = tk.Tk()
    root.title(_("app_title"))
    root.geometry("1100x750")
    root.minsize(900, 600)

    _ico_path = _resource_path("lldp_icon.ico")
    
    # Set window icon (cross-platform)
    icon_set = False
    
    if _is_windows:
        try:
            root.iconbitmap(_ico_path)
            icon_set = True
        except Exception:
            pass
    elif _is_macos:
        # macOS: icon is typically handled by .app bundle
        try:
            root.iconbitmap(_ico_path)
        except Exception:
            pass
    else:
        # Linux
        try:
            if os.path.isfile(_ico_path):
                root.iconbitmap(_ico_path)
        except Exception:
            pass

    # Apply platform-appropriate theme
    apply_platform_theme(root)

    app = LLDPMainWindow(root)

    # Force-refresh theme after all widgets are created and callbacks registered
    from ui.styles import refresh_all_themes, force_detect_dark_mode, refresh_widget_colors
    force_detect_dark_mode()
    refresh_all_themes()
    # Extra refresh after window is mapped (ensures log text colors, LabelFrame colors, etc.)
    root.after(50, refresh_all_themes)
    root.after(500, refresh_all_themes)
    # Force-refresh widget colors to ensure dark theme is properly applied
    root.after(100, lambda: refresh_widget_colors(root))
    root.after(700, lambda: refresh_widget_colors(root))

    # If a file was passed on the command line, load it
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if os.path.isfile(filepath):
            root.after(100, lambda: app.load_offline_file(filepath))

    root.mainloop()


if __name__ == "__main__":
    main()
