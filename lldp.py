#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLDP/CDP 3.0 command line entry."""

from __future__ import annotations

import argparse
import io
import os
import sys

from utils.elevator import is_admin
from utils.elevator import run_elevated
from utils.packet_capture import run_online_capture
from runtime import check_runtime, format_cli, format_diagnostics
from utils.protocol_parser import parse_offline_file



class _TeeStream(io.TextIOBase):
    """Tee: writes to both the log file and the original stdout."""

    def __init__(self, log_file, orig_stdout):
        self._log = log_file
        self._orig = orig_stdout

    def write(self, s):
        self._log.write(s)
        self._log.flush()
        self._orig.write(s)
        self._orig.flush()
        return len(s)

    def flush(self):
        self._log.flush()
        self._orig.flush()



def _interactive_menu(args: argparse.Namespace) -> int:
    """Show a simple menu when the exe is double-clicked (no arguments)."""
    print()
    print("  1. Online capture (scan for LLDP/CDP neighbors)")
    print("  2. Parse offline hex file")
    print("  3. Exit")
    print()
    try:
        choice = input("Select [1-3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return 0

    if choice == "1":
        # Online capture — needs admin, elevate now.
        if not is_admin():
            script_path = os.path.abspath(sys.argv[0])
            rc = run_elevated(
                [script_path, "--capture"],
                executable=sys.executable,
                wait=True,
                show_window=True,
            )
            return rc or 0
        results = run_online_capture(
            timeout=args.timeout,
            renegotiate=not args.no_renegotiate,
            wait_for_link=args.wait_for_link,
            wait_for_both=args.thorough,
        )
        wait_for_q_to_exit()
        return 0

    if choice == "2":
        try:
            filepath = input("Enter hex file path: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            return 0
        if filepath and os.path.isfile(filepath):
            output_mode = "debug" if args.debug else ("verbose" if args.verbose else "normal")
            parse_offline_file(filepath, output_mode=output_mode)
        else:
            print(f"[ERROR] File not found: {filepath}")
        wait_for_q_to_exit()
        return 0

    return 0


def main() -> int:
    if sys.platform == "win32":
        os.system("chcp 65001 > nul")

    # Runtime capability check: verify capture dependencies before doing anything.
    try:
        _status = check_runtime()
        print(format_cli(_status))
        if not _status.ok:
            print()
            for r in _status.errors:
                if r.fix:
                    print(f"  [FIX] {r.fix.label}")
                    if r.fix.command:
                        print(f"        {r.fix.command}")
                    if r.fix.url:
                        print(f"        {r.fix.url}")
                    print(f"        {r.fix.description}")
                    print()
    except Exception:
        pass  # don't block execution if the check itself fails

    parser = argparse.ArgumentParser(description="LLDP/CDP 3.0 analyzer")
    parser.add_argument("file", nargs="?", help="Offline hex packet text file.")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose TLV parse output: include Type, Len, Subtype and decoded fields.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Debug TLV parse output: include offset, raw hex and TLV header bitfield.",
    )
    parser.add_argument(
        "-l",
        "--log-raw",
        action="store_true",
        help="Capture LLDP/CDP packets and print raw payload hex plus readable hexdump.",
    )
    parser.add_argument(
        "-t",
        "--thorough",
        action="store_true",
        help="Wait for BOTH LLDP and CDP before stopping (default: stop on first protocol).",
    )
    parser.add_argument("--timeout", type=int, default=35, help="Online capture timeout in seconds.")
    parser.add_argument("--no-renegotiate", action="store_true", help="Skip interface down/up before capture.")
    parser.add_argument("--wait-for-link", action="store_true", help="Wait for link up before starting capture.")
    parser.add_argument("--json-out", dest="json_out", default=None,
                        help="Write online capture results as JSON to this path (for GUI automation).")
    parser.add_argument("--interface", default=None,
                        help="Use this interface name (skip auto-detection).")
    parser.add_argument("--capture", action="store_true",
                        help="Skip interactive menu and start online capture directly.")
    args = parser.parse_args()

    # PyInstaller on Windows sometimes duplicates the exe path in argv,
    # causing argparse to treat it as the positional "file" argument.
    # If args.file matches our own exe path, ignore it.
    if args.file:
        exe_path = os.path.abspath(sys.argv[0]).lower()
        file_path = os.path.abspath(args.file).lower()
        if file_path == exe_path:
            args.file = None

    # Elevate BEFORE printing any banner — the elevated child will print it
    # exactly once.  If we are already root (e.g. `sudo python lldp.py`), skip.
    if _needs_admin(args) and not is_admin():
        script_path = os.path.abspath(sys.argv[0])
        # Filter out any argv entries that are just the exe path itself
        # (PyInstaller sometimes duplicates it in the elevated child).
        child_args = [a for a in sys.argv[1:]
                      if os.path.abspath(a).lower() != script_path.lower()]
        rc = run_elevated(
            [script_path] + child_args,
            executable=sys.executable,
            wait=True,
            show_window=True
        )
        return rc or 0

    # From this point on we are either already root, or doing offline work.
    show_banner()

    # Interactive mode: if launched by double-click (no arguments, no
    # --json-out), offer a simple menu instead of silently failing.
    if not args.file and not args.json_out and not args.interface and not args.capture:
        return _interactive_menu(args)

    # --json-out: redirect stdout to a .log file so the GUI can show
    # the same console output the CLI would produce, for debugging.
    _log_file = None
    _orig_stdout = None
    try:
        if args.json_out:
            _log_file = open(args.json_out + ".log", "w", encoding="utf-8")
            _orig_stdout = sys.stdout
            sys.stdout = _TeeStream(_log_file, _orig_stdout)

        exit_code = 0
        try:
            output_mode = "debug" if args.debug else ("verbose" if args.verbose else "normal")

            if args.file:
                if not os.path.isfile(args.file):
                    print(f"[ERROR] File not found: {args.file}")
                    return 1
                parse_offline_file(args.file, output_mode=output_mode)
                return exit_code

            results = run_online_capture(
                raw_log_mode=args.log_raw,
                output_mode=output_mode,
                timeout=args.timeout,
                renegotiate=not args.no_renegotiate,
                interface=args.interface,
                wait_for_link=args.wait_for_link,
                wait_for_both=args.thorough,
            )
            if args.json_out and results is not None:
                import json
                with open(args.json_out, "w", encoding="utf-8") as _f:
                    json.dump(results, _f, default=str, ensure_ascii=False)
                return exit_code
        except KeyboardInterrupt:
            print("\nInterrupted.")
            exit_code = 130
        except Exception as exc:
            print(f"[ERROR] {exc}", flush=True)
            import traceback
            traceback.print_exc(file=sys.stderr)
            exit_code = 1
        finally:
            # In --json-out mode the subprocess has no interactive terminal,
            # so skip the "press q to exit" prompt to avoid hanging forever.
            if args.json_out:
                return exit_code
            wait_for_q_to_exit()
        return exit_code
    finally:
        if _log_file is not None:
            _log_file.close()
            if _orig_stdout is not None:
                sys.stdout = _orig_stdout


def show_banner() -> None:
    print("=" * 72)
    print("LLDP_CLI")
    print("=" * 72)
    print("python lldp.py              Online capture and neighbor summary")
    print("python lldp.py -v           Verbose parsed TLV output")
    print("python lldp.py -d           Debug parsed TLV output")
    print("python lldp.py -l -t        Online raw packet hex/hexdump + thorough mode")
    print("python lldp.py cisco.txt    Offline hex file parsing")
    print("=" * 72)


def _needs_admin(args: argparse.Namespace) -> bool:
    # Online capture (including the GUI-driven --json-out path) needs admin:
    # - On Windows: needs admin for netsh interface toggle, and for Npcap
    # - On macOS/Linux: needs root for raw packet capture via Scapy
    # If --no-renegotiate is set, we skip interface toggle but still need
    # privileges for packet capture on non-Windows platforms.
    if args.file:
        return False
    if sys.platform == "win32":
        return not args.no_renegotiate
    # macOS/Linux: packet capture always requires root
    return True


def wait_for_q_to_exit() -> None:
    print()
    if sys.platform == "win32" and sys.stdin is not None and sys.stdin.isatty():
        print("Press q to exit: ", end="", flush=True)
        try:
            import msvcrt

            while True:
                key = msvcrt.getwch().lower()
                if key == "q":
                    print("q")
                    return
        except KeyboardInterrupt:
            print()
            return

    while True:
        try:
            choice = input("Press q then Enter to exit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "q":
            return


if __name__ == "__main__":
    raise SystemExit(main())
