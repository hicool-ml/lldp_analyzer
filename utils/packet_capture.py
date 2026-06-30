#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Online LLDP/CDP capture engine."""

from __future__ import annotations

import time
import sys
import os
import datetime
from pathlib import Path
from typing import Any

from utils.adapter_scanner import scan_ethernet_adapters
from utils.hexdump import hexdump, strip_ethernet_header
from utils.interface_finder import get_physical_ethernet_interface, trigger_link_renegotiation
from utils.protocol_parser import analyze_packet, detect_protocol, print_tlv_pipeline


def build_lldp_cdp_filter(exclude_mac: str = "") -> str:
    """Build a BPF capture filter for LLDP (0x88cc) and CDP (01:00:0c:cc:cc:cc).

    When *exclude_mac* is non-empty, frames from that MAC are filtered out
    so the capture only shows neighbor traffic.
    """
    base = "(ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc)"
    if exclude_mac:
        return f"{base} and not ether src {exclude_mac}"
    return base



def _scapy_suppress() -> None:
    """Suppress scapy's macOS ipconfig_get_packet stderr on first import.
    
    scapy's get_if_list() runs ipconfig getpacket on all en* interfaces,
    which prints 'not found' errors to stderr for non-DHCP interfaces.
    This function redirects stderr during the first scapy import so those
    messages don't clutter the user's terminal or log.
    """
    if sys.platform != 'darwin':
        return
    old_fd = -1
    try:
        old_fd = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        os.close(devnull)
        import scapy.all  # noqa: F401 - forces scapy init with suppressed stderr
        if old_fd >= 0:
            os.dup2(old_fd, 2)
            os.close(old_fd)
    except Exception:
        try:
            if old_fd >= 0:
                os.dup2(old_fd, 2)
                os.close(old_fd)
        except Exception:
            pass


def run_online_capture(
    raw_log_mode: bool = False,
    output_mode: str = "normal",
    timeout: int = 35,
    renegotiate: bool = True,
    interface: str | None = None,
    wait_for_link: bool = True,
    wait_for_both: bool = False,
) -> list[dict[str, Any]]:
    """
    Run online LLDP/CDP capture.
    
    Args:
        raw_log_mode: If True, capture raw packets for debugging
        output_mode: "normal", "verbose", or "debug"
        timeout: Capture timeout in seconds
        renegotiate: If True, trigger link renegotiation
        interface: Interface name to use (auto-detect if None)
        wait_for_link: If True, wait for link up before starting capture
        wait_for_both: If True, wait for BOTH LLDP and CDP before stopping.
                       If False (default), stop as soon as one complete
                       LLDP or CDP frame has been captured.  Matches
                       Fluke LinkRunner-style "fast capture" behaviour.
    
    Returns:
        List of captured and analyzed packets
    """
    _scapy_suppress()

    # Detect capture backend (Npcap / WinPcap / BPF / libpcap).
    # Upper-layer code branches on capability flags, not product names.
    from utils.capture_backend import detect_backend
    _backend = detect_backend()
    print(f"[DEBUG] {_backend.provider}"
          + (f" {_backend.version}" if _backend.version else "")
          + f" — kernel BPF: {_backend.supports_kernel_bpf}, "
          f"survives link toggle: {_backend.survives_link_toggle}")
    
    if interface:
        from scapy.all import get_if_hwaddr
        adapters = scan_ethernet_adapters()
        matched = None
        for a in adapters:
            if a.get("scapy_name") == interface or a.get("name") == interface:
                matched = a
                break
        if matched:
            iface = matched
            print(f"[OK] Using supplied interface: {iface['name']} ({iface['mac']})")
        else:
            try:
                mac = get_if_hwaddr(interface)
            except Exception:
                mac = ""
            if not mac or mac == "00:00:00:00:00:00":
                print(f"[ERROR] Cannot get MAC for interface: {interface}")
                return []
            iface = {"name": interface, "scapy_name": interface, "mac": mac.upper(),
                     "description": interface, "guid": ""}
            print(f"[OK] Using supplied interface: {interface} ({mac.upper()})")
    else:
        iface = get_physical_ethernet_interface()
        if not iface:
            return []

    try:
        from scapy.all import AsyncSniffer, sniff
    except Exception as exc:
        print(f"[ERROR] Scapy import failed: {exc}")
        return []

    own_mac = iface.get("mac", "").upper()
    packets: list[tuple[str, bytes]] = []
    debug_protocols_printed: set[str] = set()
    seen_protocols: set[str] = set()

    # Use kernel-side BPF filtering on all platforms.  The capture always runs
    # as root (elevated via osascript / UAC / sudo), so BPF device access is
    # guaranteed.  BPF is far more efficient than software filtering, especially
    # on busy interfaces where Python cannot keep up with the packet rate.
    bpf_filter = build_lldp_cdp_filter(own_mac)

    _ts = lambda: time.strftime('%H:%M:%S')
    print(f"\n[{_ts()}] [3] Starting capture on {iface['name']} ({own_mac})")
    print(f"    Filter mode: {'BPF kernel' if bpf_filter else 'software'}")
    print(f"    Timeout: {timeout}s; post-packet quiet: 5s")

    # Check initial link state
    initial_link_up = False
    try:
        import subprocess
        import platform
        result = subprocess.check_output(
            ["ifconfig", iface['name']], text=True, timeout=5
        ) if platform.system() == "Darwin" else ""
        initial_link_up = "status: active" in result or "RUNNING" in result
    except Exception:
        pass

    link_was_down = not initial_link_up and wait_for_link

    # If link was DOWN→UP detected, the switch will send LLDP/CDP on link-up.
    # We still do renegotiation (interface down/up) because it guarantees a
    # fresh burst of discovery frames regardless of switch timers.
    # The sniffer MUST be started BEFORE any link-state change so we don't
    # miss packets (the old project did exactly this).

    def on_packet(packet: Any) -> None:
        raw = bytes(packet)
        proto = detect_protocol(raw)
        if proto not in {"LLDP", "CDP"}:
            return
        src = _src_mac(raw)
        if own_mac and src == own_mac:
            return

        # Track arrival time for the polling loop (used for both modes;
        # raw_log_mode does NOT append to packets[], so we must track here).
        nonlocal _last_capture_time, _first_capture_time
        _last_capture_time = time.time()
        if _first_capture_time is None:
            _first_capture_time = _last_capture_time

        if raw_log_mode:
            if proto in debug_protocols_printed:
                print(f" [{_ts()}] [SKIPPED] duplicate {proto} from {src} ({len(raw)} bytes)")
                return
            debug_protocols_printed.add(proto)
            print_debug_packet(raw, proto, src, _ts())
            return

        # Normal mode: capture every frame, but only log ONCE per protocol
        # type.  The analyzer below summarizes what was actually captured.
        packets.append((proto, raw))
        if proto not in seen_protocols:
            seen_protocols.add(proto)
            print(f" [{_ts()}] [CAPTURED] {proto} from {src}")

    _first_capture_time: float | None = None
    _last_capture_time: float | None = None
    _sniff_error: str | None = None
    _last_packet_count: int = 0

    # --- Start the sniffer BEFORE any link-state changes ---
    # This is the critical fix that matches the old project: start capturing
    # first, then wait for link / trigger renegotiation.  Otherwise the
    # switch's link-up LLDP burst happens before we are listening.
    #
    # On Windows the Scapy interface identifier (scapy_name) MUST be a real
    # pcap device path that Scapy's get_if_list() actually knows about.
    # WinPcap and Npcap enumerate devices slightly differently, so we verify
    # the chosen name and, if it is not recognized, try the friendly name and
    # the canonical \Device\NPF_{GUID} form before giving up.
    scapy_iface = iface["scapy_name"]
    if sys.platform == "win32" and scapy_iface:
        try:
            from scapy.all import get_if_list as _get_if_list
            known_ifaces = set(_get_if_list())
        except Exception:
            known_ifaces = set()
        if known_ifaces and scapy_iface not in known_ifaces:
            print(f"[{_ts()}] [WARN] Interface '{scapy_iface}' not in Scapy device list; "
                  f"attempting fallback resolution")
            guid = iface.get("guid", "")
            tried = [scapy_iface, iface.get("name", "")]
            if guid:
                g = guid.strip().strip("{}")
                tried.extend([rf"\Device\NPF_{{{g}}}", rf"\Device\NPF_{g}"])
            resolved = ""
            for cand in tried:
                if cand and cand in known_ifaces:
                    resolved = cand
                    break
            if resolved:
                scapy_iface = resolved
                iface["scapy_name"] = resolved
                print(f"[{_ts()}] [OK] Resolved interface to: {resolved}")
            else:
                print(f"[{_ts()}] [WARN] Could not match interface to a known Scapy device. "
                      f"Capture may fail. Known devices: {len(known_ifaces)}")

    print(f"[{_ts()}] Starting persistent capture socket on '{scapy_iface}'...")

    def _start_sniffer(use_filter: bool):
        return AsyncSniffer(
            iface=scapy_iface,
            filter=bpf_filter if use_filter else "",
            prn=on_packet,
            store=False,
        )

    # --- Capture start order differs between pcap backends ---
    #
    # Npcap (Windows), macOS, Linux: start the sniffer BEFORE the link toggle
    #   so we don't miss the switch's link-up LLDP/CDP burst.
    #
    # WinPcap (Windows): the capture socket DIES when the interface is
    #   disabled via netsh and does NOT recover on re-enable.  So we must
    #   renegotiate FIRST, wait for link-up, and only then start the sniffer.
    #   This means we may miss the initial link-up burst, but most switches
    #   re-send LLDP within the default 30s interval, so we still capture it.

    def _do_start_sniffer():
        nonlocal sniffer, _sniff_error
        try:
            sniffer = _start_sniffer(use_filter=_use_bpf)
            sniffer.start()
            if _use_bpf:
                print(f"[{_ts()}] Capture socket ready (filter={bpf_filter!r})")
            else:
                print(f"[{_ts()}] Capture socket ready (software filter — WinPcap mode)")
        except Exception as exc:
            print(f"[{_ts()}] [WARN] Capture start failed ({exc}); "
                  f"retrying without kernel filter")
            try:
                if sniffer is not None:
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                sniffer = _start_sniffer(use_filter=False)
                sniffer.start()
                print(f"[{_ts()}] Capture socket ready (software filter fallback)")
            except Exception as exc2:
                _sniff_error = str(exc2)
                print(f"[{_ts()}] [ERROR] Failed to start capture: {exc2}")

    sniffer = None
    _use_bpf = _backend.supports_kernel_bpf

    if not _backend.survives_link_toggle:
        # Backend kills capture socket on link down/up (WinPcap).
        if renegotiate:
            trigger_link_renegotiation(iface["name"])
            print(f"[{_ts()}] Link renegotiation triggered (WinPcap: pre-capture)")
        if wait_for_link:
            print(f"[{_ts()}] Waiting for link up...")
            if not _wait_for_link_up(iface['name'], timeout=30):
                print(f"[{_ts()}] [WARN] Link did not come up within 30s, continuing anyway")
            else:
                print(f"[{_ts()}] Link is UP")
        _do_start_sniffer()
        if _sniff_error:
            return []
        # WinPcap: verify the sniffer thread is actually alive.  WinPcap's
        # AsyncSniffer.start() can return without error even when the pcap
        # adapter is dead (e.g. adapter handle from a previous run not yet
        # released, or link not fully up). The error only surfaces on stop().
        time.sleep(0.5)
        if hasattr(sniffer, "thread") and sniffer.thread is not None:
            if not sniffer.thread.is_alive():
                print(f"[{_ts()}] [WARN] Sniffer thread died immediately; "
                      f"adapter may be busy or link not ready. Retrying...")
                time.sleep(1)
                _do_start_sniffer()
                if _sniff_error:
                    return []
        print(f"[{_ts()}] Listening for LLDP/CDP frames")
    else:
        # Npcap / macOS / Linux: sniff first, then renegotiate.
        _do_start_sniffer()
        if _sniff_error:
            return []
        if wait_for_link:
            print(f"[{_ts()}] Waiting for link up...")
            if not _wait_for_link_up(iface['name'], timeout=30):
                print(f"[{_ts()}] [WARN] Link did not come up within 30s, continuing anyway")
            else:
                print(f"[{_ts()}] Link is UP")
        if renegotiate:
            trigger_link_renegotiation(iface["name"])
            print(f"[{_ts()}] Link renegotiation triggered — listening for LLDP/CDP frames")

    # --- Poll for captured packets with a deadline ---
    # Stop rules — two modes:
    #
    #   FAST (default, wait_for_both=False):
    #     Stop as soon as one complete LLDP or CDP frame has been captured.
    #     This matches Fluke LinkRunner behaviour and gives a ~3 second
    #     capture on most networks regardless of vendor.
    #
    #   THOROUGH (wait_for_both=True, e.g. `python lldp.py /t`):
    #     1. Overall timeout (default 35s) — hard upper bound.
    #     2. LLDP-only (no CDP seen) + 5s quiet → stop.
    #     3. Both LLDP+CDP seen + 5s quiet → stop.
    #     4. CDP seen but NO LLDP yet → keep listening until timeout.
    #        Cisco SG300 does NOT reset its LLDP timer on ifconfig down/up;
    #        the LLDP frame arrives 5..30s after the CDP burst ends.
    deadline = time.time() + timeout
    quiet_grace_seconds = 5
    while time.time() < deadline:
        current_count = len(packets)

        # Refresh the "last seen" timer whenever a new packet arrives.
        if current_count > _last_packet_count:
            _last_packet_count = current_count
            _last_capture_time = time.time()
            if _first_capture_time is None:
                _first_capture_time = time.time()

        # Choose the correct protocol-tracking variable.
        # raw_log_mode -> debug_protocols_printed is updated in on_packet.
        # normal mode  -> seen_protocols is updated in on_packet.
        protocols_seen = debug_protocols_printed if raw_log_mode else seen_protocols
        have_cdp = "CDP" in protocols_seen
        have_lldp = "LLDP" in protocols_seen
        have_both = have_cdp and have_lldp
        have_any = have_cdp or have_lldp

        # --- Apply stop rules ---
        if not wait_for_both:
            # FAST mode: stop as soon as we have captured at least one
            # complete frame of either protocol.  Fluke-style behaviour.
            if have_any:
                break
        else:
            # THOROUGH mode: wait for BOTH protocols before accepting stop.
            if _last_capture_time is not None:
                elapsed_since_last = time.time() - _last_capture_time
                if have_both and elapsed_since_last >= quiet_grace_seconds:
                    # Got both, 5s quiet — done.
                    break
                if have_lldp and not have_cdp and elapsed_since_last >= quiet_grace_seconds:
                    # LLDP-only device — no CDP will come.  Stop.
                    break
                # CDP seen but not LLDP yet (Cisco SG300) → keep listening.
        time.sleep(0.05)

    try:
        sniffer.stop()
    except Exception as stop_exc:
        print(f"[{_ts()}] [WARN] sniffer.stop() error (ignored): {stop_exc}")
    print(f"[{_ts()}] Capture finished")

    if _sniff_error:
        return []

    if raw_log_mode:
        if not debug_protocols_printed:
            print("\n[WARNING] No LLDP/CDP packet captured.")
        else:
            print(f"\n[Done] Raw debug captured protocol(s): {', '.join(sorted(debug_protocols_printed))}")
        return []

    return analyze_captured_packets(packets, output_mode=output_mode)


def _wait_for_link_up(iface_name: str, timeout: int = 30) -> bool:
    """
    Wait for network interface link to come up.
    
    Args:
        iface_name: Interface name to monitor
        timeout: Maximum wait time in seconds
    
    Returns:
        True if link came up, False on timeout
    """
    import platform
    system = platform.system()
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            if system == "Darwin":
                import subprocess
                result = subprocess.check_output(["ifconfig", iface_name], text=True, timeout=5)
                if "status: active" in result:
                    return True
            elif system == "Windows":
                import subprocess
                result = subprocess.check_output(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f"Get-NetAdapter -Name '{iface_name}' | Select-Object -ExpandProperty Status"],
                    text=True, timeout=5, creationflags=0x08000000
                )
                if result.strip().lower() == "up":
                    return True
            else:
                try:
                    with open(f"/sys/class/net/{iface_name}/operstate", "r") as f:
                        state = f.read().strip().lower()
                        if state in ("up", "unknown"):
                            return True
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.5)

    return False


def analyze_captured_packets(packets: list[tuple[str, bytes]], output_mode: str = "normal") -> list[dict[str, Any]]:
    print(f"\n[4] Analyzing {len(packets)} captured packets...")
    raw_results = [analyze_packet(raw, proto) for proto, raw in packets]

    # Attach raw frame hex so the GUI can store it in history.
    for result, (_proto, raw) in zip(raw_results, packets):
        if result.get("success"):
            result["raw_hex"] = raw.hex()

    # De-duplicate by (chassis_id, port_id, protocol)
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in raw_results:
        if not result.get("success"):
            continue
        proto = result.get("protocol") or "UNKNOWN"
        key = (result.get("chassis_id") or "UNKNOWN",
               result.get("port_id") or "UNKNOWN",
               proto)
        cur = deduped.get(key)
        if cur is None:
            deduped[key] = result
        else:
            _merge_fields(cur.setdefault("fields", {}), result.get("fields", {}))
            if len(result.get("tlvs", [])) > len(cur.get("tlvs", [])):
                cur["tlvs"] = result.get("tlvs", [])

    results = list(deduped.values())

    print("\n" + "=" * 90)
    print("Neighbor discovery summary")
    print("=" * 90)
    print(f"Packets captured: {len(packets)}")
    print(f"Unique entries  : {len(results)}")
    for idx, result in enumerate(results, 1):
        fields = result.get("fields", {})
        chassis = result.get("chassis_id") or "UNKNOWN"
        port = result.get("port_id") or "UNKNOWN"
        proto = result.get("protocol") or "UNKNOWN"
        print("-" * 90)
        print(f"Device #{idx}: {fields.get('system_name') or chassis}")
        print(f"  Protocol   : {proto}")
        print(f"  Vendor     : {result.get('vendor')}")
        print(f"  Chassis ID : {chassis}")
        print(f"  Port ID    : {port}")
        if fields.get("management_addresses"):
            print(f"  Mgmt Addr  : {', '.join(fields['management_addresses'])}")
        if fields.get("platform"):
            print(f"  Platform   : {fields['platform']}")
        if fields.get("serial"):
            print(f"  Serial     : {fields['serial']}")
        if fields.get("software_version"):
            print(f"  Version    : {str(fields['software_version'])[:120]}")
        if fields.get("link_speed") or fields.get("duplex"):
            link = " ".join(str(v) for v in [fields.get('link_speed'), fields.get('duplex')] if v)
            print(f"  Link       : {link}")
        if fields.get("native_vlan"):
            print(f"  VLAN       : {fields['native_vlan']}")
        if result.get("tlvs"):
            print(f"  TLVs       : {len(result['tlvs'])}")
            print_tlv_pipeline(result["tlvs"], output_mode=output_mode, protocol=proto)
    print("=" * 90)
    return results


def print_debug_packet(raw: bytes, protocol: str, src_mac: str, ts: str = "") -> None:
    payload = strip_ethernet_header(raw)
    prefix = f" [{ts}] " if ts else ""
    print(f"{prefix}" + "=" * 70)
    print(f"{prefix}{protocol} raw capture from {src_mac} ({len(raw)} bytes)")
    print(f"{prefix}" + "=" * 70)
    print(f"{prefix}frame_bytes  : {len(raw)}")
    print(f"{prefix}payload_bytes: {len(payload)}")
    print(f"{prefix}\npayload_hex (without Ethernet header):")
    print(f"{prefix}{payload.hex()}")
    print(f"{prefix}\nhexdump (full Ethernet frame):")
    print(f"{prefix}{hexdump(raw)}")
    save_capture_file(raw, protocol, src_mac, ts)
    print()


def save_capture_file(raw: bytes, protocol: str, src_mac: str, ts: str = "") -> None:
    """Save full Ethernet frame hex to a file for offline parsing."""
    from utils.platform_utils import get_user_data_dir
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if ts:
        timestamp = ts.replace(":", "")
    captures_dir = Path(get_user_data_dir()) / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    safe_mac = src_mac.replace(":", "-")
    filename = captures_dir / f"{protocol}_{safe_mac}_{timestamp}.txt"
    hex_data = raw.hex()
    filename.write_text(hex_data, encoding="utf-8")
    print(f"    Saved offline file: {filename}")


def _src_mac(raw: bytes) -> str:
    if len(raw) < 12:
        return "UNKNOWN"
    return ":".join(f"{b:02X}" for b in raw[6:12])


def _merge_fields(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, value in src.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            dst.setdefault(key, [])
            for item in value:
                if item not in dst[key]:
                    dst[key].append(item)
        elif _is_richer(value, dst.get(key)):
            dst[key] = value


def _is_richer(new_val: Any, old_val: Any) -> bool:
    if old_val in (None, "", [], {}):
        return True
    if isinstance(new_val, str) and isinstance(old_val, str) and len(new_val) > len(old_val):
        return True
    if isinstance(new_val, dict) and isinstance(old_val, dict) and len(new_val) > len(old_val):
        return True
    return False
