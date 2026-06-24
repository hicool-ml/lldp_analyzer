#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLDP/CDP Capture Engine API.

提供跨平台的LLDP/CDP报文捕获接口。
支持Windows/Linux/macOS，自动处理提权需求检测。
"""

from __future__ import annotations

import os
import sys
import time
import json
from typing import Any

from utils.elevator import is_admin, run_elevated

from utils.interface_finder import get_physical_ethernet_interface, trigger_link_renegotiation
from utils.protocol_parser import analyze_packet, detect_protocol


def needs_elevation() -> bool:
    """Check if capture operation requires elevation."""
    return not is_admin()


def request_elevation() -> bool:
    """Request administrator privileges via UAC/sudo.

    Re-launches the current process elevated.
    Returns True if elevation was granted, False if cancelled or failed.
    """
    try:
        from utils.elevator import run_elevated
        run_elevated(sys.argv[1:], wait=False, show_window=True)
        return True
    except Exception:
        return False


def capture(
    interface_name: str | None = None,
    timeout: int = 30,
    renegotiate: bool = True,
    verbose: bool = False,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """
    Execute LLDP/CDP capture on the specified interface.

    Args:
        interface_name: Network interface name (e.g., "以太网", "eth0").
                       If None, auto-detects the primary Ethernet interface.
        timeout: Capture timeout in seconds.
        renegotiate: If True, trigger link down/up before capture to force
                    fresh LLDP/CDP frames from the switch.
        verbose: If True, include detailed TLV parse output.
        debug: If True, include raw hex and TLV header details.

    Returns:
        List of discovered neighbor dictionaries. Each dictionary contains:
        - protocol: "LLDP" or "CDP"
        - chassis_id: MAC address of neighbor
        - port_id: Port identifier
        - system_name: Switch hostname
        - platform: Switch model
        - And other TLV fields...

    Example:
        >>> results = capture(timeout=30, renegotiate=True)
        >>> for neighbor in results:
        ...     print(neighbor["system_name"], neighbor["platform"])
    """
    from utils.packet_capture import run_online_capture as _run_capture

    output_mode = "debug" if debug else ("verbose" if verbose else "normal")

    return _run_capture(
        raw_log_mode=False,
        output_mode=output_mode,
        timeout=timeout,
        renegotiate=renegotiate,
    )


def capture_to_json(
    json_path: str,
    interface_name: str | None = None,
    timeout: int = 30,
    renegotiate: bool = True,
) -> bool:
    """
    Execute capture and write results to JSON file.

    Args:
        json_path: Path to write JSON results.
        interface_name: Network interface name. If None, auto-detects.
        timeout: Capture timeout in seconds.
        renegotiate: If True, trigger link renegotiation before capture.

    Returns:
        True if capture succeeded and JSON was written,
        False otherwise.
    """
    try:
        results = capture(
            interface_name=interface_name,
            timeout=timeout,
            renegotiate=renegotiate,
        )

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results or [], f, default=str, ensure_ascii=False)

        return True

    except Exception:
        return False


# Convenience function for CLI use
def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="LLDP/CDP Capture Engine")
    parser.add_argument("--json-out", help="Write results to JSON file")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--no-renegotiate", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()

    results = capture(
        interface_name=None,
        timeout=args.timeout,
        renegotiate=not args.no_renegotiate,
        verbose=args.verbose,
        debug=args.debug,
    )

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results or [], f, default=str, ensure_ascii=False)
        print(f"Capture finished — {len(results)} packet(s)")
    else:
        for r in results:
            print(f"{r.get('protocol', '?')} from {r.get('system_name', '?')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
