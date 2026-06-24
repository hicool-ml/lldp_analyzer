#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POSIX (Linux/macOS) network adapter backend.

Uses standard POSIX commands:
  - ip / ifconfig — interface listing, IP configuration
  - ethtool — link speed, status (if available)
  - ip link set — MAC address modification (Linux)
  - ifconfig — MAC modification (macOS)

Data sources:
  - psutil — primary interface enumeration
  - subprocess calls to ip/ifconfig — supplementary info
  - ethtool — link speed/duplex when available
"""

import os
import re
import subprocess
import time
from typing import List, Optional, Dict, Any

from network.core.interfaces import NetworkInterface, NetworkAdapterBackend
from network.backends.platform import is_linux, is_darwin


# Filter: only real Ethernet adapters
_VIRTUAL_KW = [
    "virtual", "vmware", "virtualbox", "vbox", "tunnel", "hyper-v",
    "docker", "bridge", "loopback", "pseudo", "veth", "virbr",
    "wi-fi", "wifi", "wireless", "802.11", "wlan",
    "bluetooth", "vpn", "tap", "tun", "ppp",
    "docker", "container", "host-only",
]

_PHYSCIAL_KW = [
    "ethernet", "eth", "en", "em", "eno", "ens", "enp", "enx",
    "realtek", "intel", "broadcom", "qualcomm", "marvell", "killer",
]


def _is_ethernet(name: str, desc: str) -> bool:
    label = f"{name} {desc}".lower()
    for kw in _VIRTUAL_KW:
        if kw in label:
            return False
    # On macOS, use networksetup to verify it's a physical Ethernet port
    if is_darwin() and name.startswith("en"):
        desc_lower = desc.lower()
        if "wi-fi" in desc_lower or "airport" in desc_lower or "wifi" in desc_lower:
            return False
        if is_darwin_physical_ethernet(name):
            return True
        return False
    # Standard Linux naming: eth* (ethernet), en* (embedded), etc.
    if name.startswith("eth") or name.startswith("eno") or name.startswith("ens") or name.startswith("enp") or name.startswith("enx"):
        return True
    # If it contains ethernet-related keywords in description (not name), it's likely physical
    for kw in ["ethernet", "realtek", "intel", "broadcom", "qualcomm", "marvell", "killer"]:
        if kw in desc.lower():
            return True
    return False


def is_darwin_physical_ethernet(name: str) -> bool:
    """Return True if name is a physical Ethernet port on macOS.

    Uses networksetup -listallhardwareports to determine the port type.
    Returns True for non-macOS or if determination cannot be made.

    Filter rules:
    - Keep: status == active AND Hardware Port in ("Ethernet", "USB Ethernet", "Thunderbolt Ethernet")
    - Filter out: Wi-Fi, Thunderbolt Bridge, inactive interfaces, utun*, awdl*, llw*, bridge100, vmenet*
    """
    import subprocess
    if not is_darwin():
        return True

    # Quick filter for known virtual interfaces
    if name.startswith("utun") or name.startswith("awdl") or name.startswith("llw"):
        return False
    if name == "bridge100" or name.startswith("vmenet"):
        return False

    # Get interface status
    try:
        r = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False
        if "UP," not in r.stdout:
            return False
    except Exception:
        pass

    # Scan networksetup output for matching device
    try:
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


def _run_cmd(cmd: list, timeout: int = 10, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, return CompletedProcess."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", "Command timed out")
    except Exception as e:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


class PosixNetworkBackend(NetworkAdapterBackend):
    """POSIX-compliant network backend for Linux and macOS."""

    last_error: str = ""

    def __init__(self):
        self._pcap_lib = "libpcap"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_interfaces(self) -> List[NetworkInterface]:
        return self._enumerate()

    def get_interface_info(self, name: str) -> Optional[NetworkInterface]:
        for iface in self._enumerate():
            if iface.name == name:
                return iface
        return None

    def restart_interface(self, name: str) -> bool:
        self.last_error = ""
        try:
            if is_linux():
                r = _run_cmd(["ip", "link", "set", name, "down"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to bring interface down: {r.stderr}"
                    return False
                time.sleep(1)
                r = _run_cmd(["ip", "link", "set", name, "up"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to bring interface up: {r.stderr}"
                    return False
                return True
            elif is_darwin():
                r = _run_cmd(["ifconfig", name, "down"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to bring interface down: {r.stderr}"
                    return False
                time.sleep(1)
                r = _run_cmd(["ifconfig", name, "up"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to bring interface up: {r.stderr}"
                    return False
                return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def set_mac_address(self, name: str, mac: str) -> bool:
        self.last_error = ""
        clean = mac.replace(":", "").replace("-", "").upper()
        if len(clean) != 12:
            self.last_error = "Invalid MAC format"
            return False

        try:
            if is_linux():
                _run_cmd(["ip", "link", "set", name, "down"], timeout=5)
                time.sleep(0.5)
                r = _run_cmd(["ip", "link", "set", name, "address", mac], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to set MAC: {r.stderr}"
                    _run_cmd(["ip", "link", "set", name, "up"], timeout=5)
                    return False
                time.sleep(0.5)
                r = _run_cmd(["ip", "link", "set", name, "up"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"MAC set but failed to bring interface up: {r.stderr}"
                    return False
                return True

            elif is_darwin():
                _run_cmd(["ifconfig", name, "down"], timeout=5)
                time.sleep(0.5)
                r = _run_cmd(["ifconfig", name, "ether", mac], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to set MAC: {r.stderr}"
                    _run_cmd(["ifconfig", name, "up"], timeout=5)
                    return False
                time.sleep(0.5)
                r = _run_cmd(["ifconfig", name, "up"], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"MAC set but failed to bring interface up: {r.stderr}"
                    return False
                return True

        except Exception as e:
            self.last_error = str(e)
            return False

        self.last_error = "Unsupported platform for MAC modification"
        return False

    def restore_mac(self, name: str) -> bool:
        self.last_error = ""
        try:
            if is_linux():
                sysfs_path = f"/sys/class/net/{name}/address"
                if os.path.exists(sysfs_path):
                    with open(sysfs_path) as f:
                        permanent_mac = f.read().strip()
                    return self.set_mac_address(name, permanent_mac)
                else:
                    self.last_error = "Cannot determine permanent MAC address"
                    return False
            elif is_darwin():
                self.last_error = "Cannot determine permanent MAC address on macOS"
                return False
        except Exception as e:
            self.last_error = str(e)
            return False

        return False

    def set_static_ip(self, name: str, ip: str, mask: str,
                      gateway: str = "", dns: List[str] = None) -> bool:
        self.last_error = ""
        try:
            if is_linux():
                from ipaddress import IPv4Network
                try:
                    prefix = IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
                except Exception:
                    self.last_error = f"Invalid mask: {mask}"
                    return False

                _run_cmd(["ip", "addr", "flush", "dev", name], timeout=5)
                r = _run_cmd(["ip", "addr", "add", f"{ip}/{prefix}", "dev", name], timeout=5)
                if r.returncode != 0:
                    self.last_error = f"Failed to set IP: {r.stderr}"
                    return False

                if gateway:
                    _run_cmd(["ip", "route", "del", "default"], timeout=5)
                    r = _run_cmd(
                        ["ip", "route", "add", "default", "via", gateway, "dev", name],
                        timeout=5
                    )
                    if r.returncode != 0:
                        self.last_error = f"Failed to set gateway: {r.stderr}"
                        return False

                if dns:
                    self._set_dns_linux(dns)

                return True

            elif is_darwin():
                r = _run_cmd(
                    ["ifconfig", name, ip, "netmask", mask],
                    timeout=10
                )
                if r.returncode != 0:
                    self.last_error = f"Failed to set IP: {r.stderr}"
                    return False

                if gateway:
                    _run_cmd(["route", "-n", "add", "default", gateway], timeout=10)

                if dns:
                    self._set_dns_macos(name, dns)

                return True

        except Exception as e:
            self.last_error = str(e)
            return False

        self.last_error = "Unsupported platform for static IP"
        return False

    def set_dhcp(self, name: str) -> bool:
        self.last_error = ""
        try:
            if is_linux():
                _run_cmd(["ip", "addr", "flush", "dev", name], timeout=5)
                r = _run_cmd(["dhclient", "-r", name], timeout=10)
                r = _run_cmd(["dhclient", name], timeout=30)
                if r.returncode != 0:
                    self.last_error = f"DHCP request failed: {r.stderr}"
                    return False
                return True

            elif is_darwin():
                r = _run_cmd(
                    ["ifconfig", name, "dhcp"],
                    timeout=15
                )
                if r.returncode != 0:
                    self.last_error = f"Failed to enable DHCP: {r.stderr}"
                    return False
                return True

        except Exception as e:
            self.last_error = str(e)
            return False

        self.last_error = "Unsupported platform for DHCP"
        return False

    # ------------------------------------------------------------------
    # Internal: enumerate adapters using psutil
    # ------------------------------------------------------------------

    def _enumerate(self) -> List[NetworkInterface]:
        """Build interface list using psutil (primary source)."""
        result: List[NetworkInterface] = []

        try:
            import psutil
            import socket
            for if_name, addrs in psutil.net_if_addrs().items():
                if not _is_ethernet(if_name, ""):
                    continue

                mac = ""
                ipv4 = ""
                ipv4_mask = ""
                ipv6_list = []

                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        mac = addr.address.upper() if addr.address else ""
                    elif addr.family == socket.AF_INET:
                        ipv4 = addr.address
                        ipv4_mask = addr.netmask if addr.netmask else ""
                    elif addr.family == socket.AF_INET6:
                        if not addr.address.startswith("fe80"):
                            ipv6_list.append(addr.address)

                if not mac or mac == "00:00:00:00:00:00":
                    continue

                status = psutil.net_if_stats().get(if_name)
                is_connected = status.isup if status else False
                mtu = status.mtu if status else 0

                speed_info = self._get_link_speed(if_name)
                link_speed = speed_info.get("speed", "")

                gateway = self._get_gateway()
                dns = self._get_dns()
                dhcp_enabled = self._is_dhcp_enabled(if_name)
                original_mac = self._get_permanent_mac(if_name)
                is_modified = original_mac != "" and original_mac.upper() != mac.upper()

                result.append(NetworkInterface(
                    name=if_name,
                    description=if_name,
                    mac_address=mac,
                    original_mac=original_mac,
                    is_mac_modified=is_modified,
                    ipv4_address=ipv4,
                    ipv4_mask=ipv4_mask,
                    ipv4_gateway=gateway,
                    ipv6_addresses=ipv6_list,
                    dns_servers=dns,
                    dhcp_enabled=dhcp_enabled,
                    dhcp_server="",
                    is_connected=is_connected,
                    link_speed=link_speed,
                    mtu=mtu,
                    guid=if_name,
                    pnp_instance_id=if_name,
                    scapy_name=if_name,
                ))

        except Exception as e:
            self.last_error = f"Failed to enumerate interfaces: {e}"

        return result

    def _get_link_speed(self, if_name: str) -> dict:
        """Get link speed using ethtool on Linux."""
        result = {"speed": "", "duplex": ""}

        if is_linux():
            r = _run_cmd(["ethtool", if_name], timeout=5)
            if r.returncode == 0:
                match = re.search(r'Speed:\s+(\d+)\s*(Mb/s|Gb/s)', r.stdout)
                if match:
                    num = match.group(1)
                    unit = match.group(2)
                    result["speed"] = f"{num}{unit}"

        return result

    def _get_gateway(self) -> str:
        """Get default gateway."""
        if is_linux():
            r = _run_cmd(["ip", "route", "show", "default"], timeout=5)
            if r.returncode == 0:
                match = re.search(r'default via\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                if match:
                    return match.group(1)
        elif is_darwin():
            r = _run_cmd(["route", "-n", "get", "default"], timeout=5)
            if r.returncode == 0:
                match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                if match:
                    return match.group(1)
        return ""

    def _get_dns(self) -> List[str]:
        """Get DNS servers."""
        dns_list = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            dns_list.append(parts[1])
        except Exception:
            pass
        return dns_list

    def _is_dhcp_enabled(self, if_name: str) -> bool:
        """Check if DHCP is enabled."""
        if is_linux():
            lease_paths = [
                f"/var/lib/dhcp/dhclient-{if_name}.leases",
                f"/var/lib/dhcp-client/dhclient-{if_name}.leases",
            ]
            for path in lease_paths:
                if os.path.exists(path):
                    return True
        return False

    def _get_permanent_mac(self, if_name: str) -> str:
        """Get permanent (hardware) MAC address."""
        if is_linux():
            sysfs_path = f"/sys/class/net/{if_name}/address"
            if os.path.exists(sysfs_path):
                try:
                    with open(sysfs_path) as f:
                        return f.read().strip()
                except Exception:
                    pass
        return ""

    def _set_dns_linux(self, dns_list: List[str]) -> None:
        try:
            with open("/etc/resolv.conf", "w") as f:
                for dns in dns_list:
                    f.write(f"nameserver {dns}\n")
        except Exception:
            pass

    def _set_dns_macos(self, if_name: str, dns_list: List[str]) -> None:
        try:
            if dns_list:
                _run_cmd(["networksetup", "-setdnsservers", if_name] + dns_list, timeout=10)
        except Exception:
            pass
