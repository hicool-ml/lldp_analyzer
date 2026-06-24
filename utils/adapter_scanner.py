#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified physical Ethernet adapter scanner.

Single source of truth for discovering and filtering network interfaces.
Used by the CLI capture engine, the GUI Capture page, the Network page
backend, and anywhere else that needs a list of available interfaces.

Design informed by Wireshark's capture-pcap-util.c get_interface_list /
get_windows_iftype pipeline: prefer the OS-reported IfType over keyword
matching whenever possible.
"""

from __future__ import annotations

import locale
import json
import subprocess
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Canonical filter keywords -- fallback when OS-level IfType is unavailable.
# ---------------------------------------------------------------------------

# Words that DISQUALIFY a candidate interface.
EXCLUDE_KEYWORDS = [
    "wi-fi", "wifi", "wireless", "802.11", "wlan",
    "bluetooth", "蓝牙",
    "vmware", "virtualbox", "vbox",
    "hyper-v", "docker", "bridge", "tunnel",
    "pseudo", "veth", "virbr",
    "vpn", "tap", "tun", "ppp",
    "wan miniport", "miniport", "network monitor", "ndis",
    "npcap", "wfp", "qos packet", "lightweight filter",
    "kernel debug",
]

INCLUDE_KEYWORDS = [
    "ethernet",
    "realtek", "intel", "broadcom", "qualcomm", "marvell",
    "killer", "controller",
]

# ---------------------------------------------------------------------------
# Interface type constants (mirrors Wireshark's if_type enum).
# ---------------------------------------------------------------------------

IF_WIRED = "wired"
IF_WIRELESS = "wireless"
IF_LOOPBACK = "loopback"
IF_VIRTUAL = "virtual"
IF_DIALUP = "dialup"
IF_TUNNEL = "tunnel"
IF_UNKNOWN = "unknown"


_DARWIN_PORT_CACHE: dict = {}
_DARWIN_PORT_INITIALIZED = False


def _init_darwin_port_cache() -> None:
    """Cache macOS hardware port mappings via networksetup."""
    global _DARWIN_PORT_CACHE, _DARWIN_PORT_INITIALIZED
    if _DARWIN_PORT_INITIALIZED:
        return
    _DARWIN_PORT_INITIALIZED = True

    try:
        import subprocess
        r = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return

        current_device = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_device = None
                continue
            if line.startswith("Device:"):
                current_device = line.split("Device:", 1)[1].strip()
            if current_device and line.startswith("Ethernet Address:"):
                addr = line.split("Ethernet Address:", 1)[1].strip().replace(":", "").upper()
                _DARWIN_PORT_CACHE[current_device.upper()] = addr
    except Exception:
        pass


def is_ethernet_adapter(name: str, description: str = "") -> bool:
    """Return True if *name* + *description* describe a physical Ethernet adapter.

    This is the keyword-based fallback.  Prefer scan_ethernet_adapters() which
    uses OS-level IfType when available.
    """
    import sys
    label = f"{name} {description}".lower()
    for kw in EXCLUDE_KEYWORDS:
        if kw in label:
            return False
    # On macOS, use networksetup to identify port type
    if sys.platform == "darwin" and name.startswith("en"):
        _init_darwin_port_cache()
        desc_lower = description.lower()
        if "wi-fi" in desc_lower or "airport" in desc_lower or "wifi" in desc_lower:
            return False
        return True
    if not INCLUDE_KEYWORDS:
        return True
    for kw in INCLUDE_KEYWORDS:
        if kw in label:
            return True
    return False


def is_darwin_physical_ethernet(name: str) -> bool:
    """Return True if name is a physical Ethernet port on macOS.

    Uses networksetup -listallhardwareports to determine the port type.
    Returns False for non-macOS or if determination cannot be made.

    Filter rules:
    - Keep: status == active AND Hardware Port in ("Ethernet", "USB Ethernet", "Thunderbolt Ethernet")
    - Filter out: Wi-Fi, Thunderbolt Bridge, inactive interfaces, utun*, awdl*, llw*, bridge100, vmenet*
    """
    import sys
    if sys.platform != "darwin":
        return True

    # Quick filter for known virtual interfaces
    if name.startswith("utun") or name.startswith("awdl") or name.startswith("llw"):
        return False
    if name == "bridge100" or name.startswith("vmenet"):
        return False

    # Get interface status
    try:
        import subprocess
        r = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False
        if "UP," not in r.stdout:
            return False
    except Exception:
        pass

    # Scan networksetup output for matching device
    try:
        import subprocess
        r = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return True  # Fallback: assume it's physical

        current_port = None
        current_dev = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split("Hardware Port:", 1)[1].strip()
            elif line.startswith("Device:"):
                current_dev = line.split("Device:", 1)[1].strip()
            elif line.startswith("Ethernet Address:") and current_dev == name:
                # Found our device, check port type
                allowed_ports = {"Ethernet", "USB Ethernet", "Thunderbolt Ethernet"}
                return current_port in allowed_ports
        return True  # Device not in networksetup, assume physical
    except Exception:
        return True  # Fallback


def _scan_darwin_adapters(
    skip_loopback: bool = True,
    filter_virtual_adapters: bool = False,
    require_ethernet: bool = True,
) -> list[dict[str, Any]]:
    """Scan adapters on macOS using system commands (no root required).

    Uses networksetup and ifconfig instead of Scapy to avoid
    ipconfig_get_packet errors that require elevated privileges.
    """
    results: list[dict[str, Any]] = []

    try:
        # Get hardware ports from networksetup
        r = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return results

        current_port = None
        current_dev = None
        current_mac = None

        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                # Save previous device if valid
                if current_dev and current_mac:
                    _add_darwin_adapter(
                        results, current_dev, current_port, current_mac,
                        skip_loopback, filter_virtual_adapters, require_ethernet,
                    )
                current_port = line.split("Hardware Port:", 1)[1].strip()
                current_dev = None
                current_mac = None
            elif line.startswith("Device:"):
                current_dev = line.split("Device:", 1)[1].strip()
            elif line.startswith("Ethernet Address:"):
                current_mac = line.split("Ethernet Address:", 1)[1].strip().replace(":", "").upper()

        # Don't forget the last device
        if current_dev and current_mac:
            _add_darwin_adapter(
                results, current_dev, current_port, current_mac,
                skip_loopback, filter_virtual_adapters, require_ethernet,
            )
    except Exception:
        pass

    return results


def _add_darwin_adapter(
    results: list[dict[str, Any]],
    name: str,
    port_type: str,
    mac_raw: str,
    skip_loopback: bool,
    filter_virtual_adapters: bool,
    require_ethernet: bool,
) -> None:
    """Add a macOS adapter to results if it passes filters."""
    # Skip virtual interfaces
    if any(name.startswith(p) for p in ["lo", "utun", "awdl", "llw", "bridge", "vmenet"]):
        return

    # Format MAC address
    mac = ":".join([mac_raw[i:i+2] for i in range(0, 12, 2)])
    if not mac or mac == "00:00:00:00:00:00":
        return

    # Determine if_type based on port_type
    port_lower = port_type.lower() if port_type else ""
    if "wi-fi" in port_lower or "airport" in port_lower or "wireless" in port_lower:
        if_type = IF_WIRELESS
    elif "ethernet" in port_lower or "lan" in port_lower or "usb" in port_lower:
        if_type = IF_WIRED
    elif "thunderbolt bridge" in port_lower:
        if_type = IF_VIRTUAL
    elif name.startswith("en") and "wi-fi" not in port_lower and "airport" not in port_lower:
        # macOS physical Ethernet interfaces are named en0, en1, etc.
        # If the port type doesn't contain Wi-Fi/Airport keywords, it is likely wired.
        if_type = IF_WIRED
    elif "thunderbolt" in port_lower and "bridge" not in port_lower:
        if_type = IF_WIRED
    else:
        if_type = IF_UNKNOWN

    # Apply filters
    if skip_loopback and if_type == IF_LOOPBACK:
        return
    if require_ethernet and if_type != IF_WIRED:
        return
    if filter_virtual_adapters and if_type == IF_VIRTUAL:
        return

    # Get interface status from ifconfig
    up = False
    running = False
    try:
        r = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            up = "UP," in r.stdout or "flags=" in r.stdout
            running = "status: active" in r.stdout or "link status: active" in r.stdout
    except Exception:
        pass

    results.append({
        "name": name,
        "description": port_type or name,
        "guid": "",
        "mac": mac,
        "scapy_name": name,
        "loopback": if_type == IF_LOOPBACK,
        "up": up,
        "running": running,
        "type": if_type,
        "speed": "",
        "mtu": 0,
    })


# ---------------------------------------------------------------------------
# Windows: Get-NetAdapter -- single source of truth for interface metadata.
# ---------------------------------------------------------------------------

def _query_net_adapters_windows() -> list[dict[str, Any]]:
    """Use PowerShell Get-NetAdapter for accurate IfType / MediaType discovery.

    Returns a list of raw adapter dicts with keys:
    name, description, guid, mac, speed, mtu, status, media_type, if_type.
    """
    if sys.platform != "win32":
        return []

    cmd = (
        "Get-NetAdapter | "
        "Select-Object Name, InterfaceDescription, InterfaceGuid, "
        "MacAddress, LinkSpeed, MtuSize, Status, MediaType, "
        "InterfaceType | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15,
            encoding=locale.getpreferredencoding(False), errors="replace",
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        out = r.stdout or ""
    except Exception:
        return []

    if not out.strip():
        return []

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        data = [data]

    results: list[dict[str, Any]] = []
    for d in data:
        mac = (d.get("MacAddress") or "").replace("-", ":").upper()
        guid = d.get("InterfaceGuid") or ""
        speed = str(d.get("LinkSpeed") or "").strip()
        mtu = d.get("MtuSize") or 0
        try:
            mtu = int(mtu)
        except (ValueError, TypeError):
            mtu = 0
        results.append({
            "name": d.get("Name", ""),
            "description": d.get("InterfaceDescription", ""),
            "guid": guid,
            "mac": mac,
            "speed": speed,
            "mtu": mtu,
            "status": d.get("Status", ""),
            "media_type": d.get("MediaType", ""),
            "if_type": d.get("InterfaceType", 0),
        })
    return results


def _infer_if_type(ad: dict[str, Any]) -> str:
    """Determine the Wireshark-style interface type from adapter metadata.

    Priority:
    1. Windows MediaType -- most reliable (Get-NetAdapter)
    2. Windows InterfaceType -- fallback numeric IfType
    3. Keyword matching on name + description
    """
    media = str(ad.get("media_type", "")).lower()
    if_type = ad.get("if_type", 0)
    name = str(ad.get("name", ""))
    desc = str(ad.get("description", ""))
    label = f"{name} {desc}".lower()

    # --- MediaType (most reliable on Windows) ---
    if "802.3" in media:
        return IF_WIRED
    if "native 802.11" in media or "wireless" in media:
        return IF_WIRELESS
    if "tunnel" in media:
        return IF_TUNNEL

    # --- InterfaceType numeric fallback ---
    # IF_TYPE_ETHERNET_CSMACD = 6
    # IF_TYPE_SOFTWARE_LOOPBACK = 24
    # IF_TYPE_IEEE80211 = 71
    # IF_TYPE_TUNNEL = 131
    # IF_TYPE_PPP = 23
    if if_type:
        if if_type == 6:
            return IF_WIRED
        if if_type == 24:
            return IF_LOOPBACK
        if if_type == 71:
            return IF_WIRELESS
        if if_type == 131:
            return IF_TUNNEL
        if if_type == 23:
            return IF_DIALUP

    # --- Keyword fallback ---
    if "loopback" in label or "loopback" in name.lower():
        return IF_LOOPBACK
    for kw in ("wi-fi", "wifi", "wireless", "802.11", "wlan"):
        if kw in label:
            return IF_WIRELESS
    for kw in ("tunnel", "vpn", "tap", "tun"):
        if kw in label:
            return IF_TUNNEL
    for kw in ("vmware", "virtualbox", "hyper-v", "virtual", "docker",
               "bridge", "pseudo", "veth", "virbr", "miniport"):
        if kw in label:
            return IF_VIRTUAL
    for kw in ("ppp", "dial", "dialup"):
        if kw in label:
            return IF_DIALUP

    # Positive match: if is_ethernet_adapter() says it looks like a wired
    # Ethernet adapter, classify it as wired.  This handles the Scapy
    # fallback path where MediaType / InterfaceType are unavailable.
    if is_ethernet_adapter(name, desc):
        return IF_WIRED

    return IF_UNKNOWN


def _is_up(status: str) -> bool:
    return status.lower() == "up"


def _is_running(status: str) -> bool:
    """'Running' in Wireshark terms: interface is up AND has link."""
    return status.lower() == "up"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_ethernet_adapters(
    skip_loopback: bool = True,
    filter_virtual_adapters: bool = False,
    require_ethernet: bool = True,
) -> list[dict[str, Any]]:
    """Return every network adapter on this machine with rich metadata.

    Parameters
    ----------
    skip_loopback : bool
        Auto-skip loopback adapters (default True).
    filter_virtual_adapters : bool
        Also filter out virtual adapters (VMware, Hyper-V, Docker, etc.).
        Default False.
    require_ethernet : bool
        Only return wired (IF_WIRED) adapters.  Default True.

    Returns
    -------
    list[dict]
        Each record has these keys:
        name        -- friendly name
        description -- driver description
        guid        -- Windows GUID (empty on non-Windows)
        mac         -- MAC address, uppercase XX:XX:XX:XX:XX:XX
        scapy_name  -- Scapy-compatible interface name
        loopback     -- bool, is this a loopback interface?
        up           -- bool, is the interface administratively up?
        running      -- bool, is the interface up with link?
        type        -- "wired"|"wireless"|"loopback"|"virtual"|"dialup"|"tunnel"|"unknown"
        speed       -- link speed string (e.g. "1 Gbps"), may be empty
        mtu         -- int, MTU size, may be 0
    """
    results: list[dict[str, Any]] = []

    # --- macOS: Use system commands first (no root required) ---
    if sys.platform == "darwin":
        return _scan_darwin_adapters(
            skip_loopback=skip_loopback,
            filter_virtual_adapters=filter_virtual_adapters,
            require_ethernet=require_ethernet,
        )

    # --- Primary: PowerShell Get-NetAdapter (Windows only) ---
    net_adapters = _query_net_adapters_windows()
    if net_adapters:
        # Build scapy lookup for GUID -> scapy_name resolution
        scapy_lookup: dict[str, str] = {}
        try:
            from scapy.arch.windows import get_windows_if_list
            from scapy.all import get_if_hwaddr as _hwaddr
            for s in get_windows_if_list():
                g = s.get("guid", "")
                if g:
                    scapy_lookup[g] = s
        except Exception:
            pass

        for ad in net_adapters:
            name = ad.get("name", "")
            guid = ad.get("guid", "")
            mac = ad.get("mac", "")

            if not mac or mac == "00:00:00:00:00:00":
                continue

            if_type = _infer_if_type(ad)
            loopback = (if_type == IF_LOOPBACK)

            if skip_loopback and loopback:
                continue
            if require_ethernet and if_type != IF_WIRED:
                continue
            if filter_virtual_adapters and if_type == IF_VIRTUAL:
                continue

            # Resolve scapy name
            scapy_name = ""
            if guid:
                for candidate in (rf"\Device\NPF_{guid}", name):
                    try:
                        s_info = scapy_lookup.get(guid)
                        if s_info:
                            scapy_name = candidate
                            break
                        test_mac = _hwaddr(candidate)
                        if test_mac and test_mac != "00:00:00:00:00:00":
                            scapy_name = candidate
                            break
                    except Exception:
                        continue

            if not scapy_name and guid:
                scapy_name = rf"\Device\NPF_{guid}"

            status = ad.get("status", "")
            results.append({
                "name": name,
                "description": ad.get("description", ""),
                "guid": guid,
                "mac": mac,
                "scapy_name": scapy_name,
                "loopback": loopback,
                "up": _is_up(status),
                "running": _is_running(status),
                "type": if_type,
                "speed": ad.get("speed", ""),
                "mtu": ad.get("mtu", 0),
            })
        return results

    # --- Fallback: Scapy-only (non-Windows or PowerShell unavailable) ---
    try:
        from scapy.all import get_if_list, get_if_hwaddr as _hwaddr
    except Exception:
        return results

    # Try the richer Windows Scapy list first (only on Windows)
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            name = str(iface.get("name", ""))
            desc = str(iface.get("description", ""))
            guid = iface.get("guid", "")
            mac = str(iface.get("mac", "")).upper()

            if not mac or mac == "00:00:00:00:00:00":
                continue

            if_type = _infer_if_type({"name": name, "description": desc})
            loopback = (if_type == IF_LOOPBACK)

            if skip_loopback and loopback:
                continue
            if require_ethernet and if_type != IF_WIRED:
                continue
            if filter_virtual_adapters and if_type == IF_VIRTUAL:
                continue
            # On macOS, filter out Wi-Fi/Thunderbolt/USB virtual adapters
            if require_ethernet and sys.platform == "darwin":
                if not is_darwin_physical_ethernet(name):
                    continue

            scapy_name = ""
            for candidate in (rf"\Device\NPF_{guid}", name):
                try:
                    test_mac = _hwaddr(candidate)
                except Exception:
                    continue
                if test_mac and test_mac != "00:00:00:00:00:00":
                    scapy_name = candidate
                    break

            results.append({
                "name": name,
                "description": desc,
                "guid": guid,
                "mac": mac,
                "scapy_name": scapy_name,
                "loopback": loopback,
                "up": True,
                "running": True,
                "type": if_type,
                "speed": "",
                "mtu": 0,
            })
    except Exception:
        pass

    # Simpler fallback for non-Windows or if above produced nothing
    if not results:
        try:
            for iface_name in get_if_list():
                if not is_ethernet_adapter(iface_name):
                    continue
                try:
                    mac = _hwaddr(iface_name)
                except Exception:
                    continue
                if not mac or mac == "00:00:00:00:00:00":
                    continue
                if_type = _infer_if_type({"name": iface_name, "description": ""})
                loopback = (if_type == IF_LOOPBACK)
                if skip_loopback and loopback:
                    continue
                if require_ethernet and if_type != IF_WIRED:
                    continue
                # On macOS, filter out Wi-Fi/Thunderbolt/USB virtual adapters
                if require_ethernet and sys.platform == "darwin":
                    if not is_darwin_physical_ethernet(iface_name):
                        continue
                results.append({
                    "name": iface_name,
                    "description": iface_name,
                    "guid": "",
                    "mac": mac.upper(),
                    "scapy_name": iface_name,
                    "loopback": loopback,
                    "up": True,
                    "running": True,
                    "type": if_type,
                    "speed": "",
                    "mtu": 0,
                })
        except Exception:
            pass

    return results


def pick_best_adapter(
    adapters: list[dict[str, Any]],
    interactive: bool = True,
) -> dict[str, Any] | None:
    """Return the single best adapter for LLDP/CDP capture.

    Selection heuristic (mirrors Wireshark's approach):
    1. Prefer 'up' + 'running' wired adapters
    2. Among those, prefer the one with a non-empty scapy_name
    3. If only one adapter remains, return it directly
    4. Otherwise prompt the user interactively (unless interactive=False)

    When *interactive* is False and multiple candidates remain, the
    first wired/running adapter is returned.
    """
    if not adapters:
        return None

    # If stdin is None or not a TTY (elevated hidden process, pipe, redirect,
    # or GUI mode with console=False), force non-interactive mode.
    if interactive and (sys.stdin is None or not sys.stdin.isatty()):
        interactive = False

    def _score(a: dict[str, Any]) -> int:
        s = 0
        if a.get("type") == IF_WIRED:
            s += 100
        if a.get("up"):
            s += 50
        if a.get("running"):
            s += 50
        if a.get("scapy_name"):
            s += 10
        if a.get("speed"):
            s += 5
        return s

    scored = sorted(adapters, key=_score, reverse=True)

    if len(scored) == 1:
        return scored[0]

    if not interactive:
        return scored[0]

    # Interactive selection
    print("[SELECT] Multiple candidate interfaces:")
    for idx, a in enumerate(scored, 1):
        up_flag = "UP" if a.get("up") else "DOWN"
        run_flag = "link" if a.get("running") else "no-link"
        print(f"  {idx}. {a['name']} ({a['mac']}) [{a.get('type','?')}] {up_flag}/{run_flag}")
    try:
        choice = int(input(f"Select interface [1-{len(scored)}]: ")) - 1
        if 0 <= choice < len(scored):
            return scored[choice]
    except Exception:
        pass
    return None


def get_recommended_interface(
    skip_loopback: bool = True,
    filter_virtual_adapters: bool = False,
) -> str:
    """Return the name of the recommended physical Ethernet interface.

    Convenience wrapper that scans and picks the best adapter
    non-interactively.  Returns an empty string when no suitable
    adapter is found.
    """
    adapters = scan_ethernet_adapters(
        skip_loopback=skip_loopback,
        filter_virtual_adapters=filter_virtual_adapters,
    )
    best = pick_best_adapter(adapters, interactive=False)
    return best["name"] if best else ""
