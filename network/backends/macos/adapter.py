#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
macOS Network Backend implementation.

Uses lldp_helper for privileged operations and system commands.
No scapy or psutil dependencies in this module.
"""

import json
import os
import subprocess
import sys
from typing import List, Optional

from network.core.interfaces import NetworkInterface, NetworkAdapterBackend
from network.backend import LLDPPacket


class MacOSNetworkBackend(NetworkAdapterBackend):
    """macOS network operations backend."""

    def __init__(self):
        self.last_error = ""
        is_frozen = getattr(sys, 'frozen', False)
        if is_frozen:
            meipass = getattr(sys, '_MEIPASS', '')
            self._helper_path = os.path.join(meipass, "lldp_helper.py")
        else:
            backend_dir = os.path.dirname(os.path.abspath(__file__))
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(backend_dir)))
            self._helper_path = os.path.join(root_dir, "lldp_helper.py")

    def _find_system_python(self) -> str:
        """Find system Python for running helper script."""
        candidates = [
            "/opt/homebrew/bin/python3.11",
            "/opt/homebrew/opt/python@3.11/bin/python3.11",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return sys.executable

    def _run_helper(self, command: str, *args) -> dict:
        """Run lldp_helper with the specified command."""
        is_frozen = getattr(sys, 'frozen', False)
        if is_frozen:
            python_exe = self._find_system_python()
        else:
            python_exe = sys.executable

        cmd_args = [python_exe, self._helper_path, command] + list(args)

        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=60
            )
            # The helper always prints JSON to stdout (never stderr),
            # so we always try stdout first regardless of returncode.
            stdout_json = None
            try:
                stdout_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass

            # Capture stderr for debug logging
            debug_stderr = (result.stderr or "").strip()

            if result.returncode == 0:
                if stdout_json is not None:
                    # If helper wrote debug to stderr, merge it into error field
                    # so the GUI can show it (only if the operation failed)
                    if debug_stderr and not stdout_json.get("success", True):
                        debug_msg = stdout_json.get("error", "")
                        if debug_msg:
                            stdout_json["error"] = debug_msg + " | " + debug_stderr
                    return stdout_json
                else:
                    return {"success": True, "output": result.stdout}
            else:
                # Non-zero exit: helper prints JSON to stdout.
                if stdout_json is not None:
                    return stdout_json
                try:
                    return json.loads(result.stderr)
                except json.JSONDecodeError:
                    err = result.stderr or result.stdout
                    if debug_stderr:
                        err = (err or "") + " | " + debug_stderr
                    return {"success": False, "error": err}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_interfaces(self) -> List[NetworkInterface]:
        """Get list of network interfaces with full information."""
        return self._enumerate_interfaces()

    def list_interfaces(self) -> List[NetworkInterface]:
        """List network interfaces (alias for get_interfaces)."""
        return self._enumerate_interfaces()

    def _enumerate_interfaces(self) -> List[NetworkInterface]:
        """Enumerate interfaces with full macOS-specific info."""
        result = self._run_helper("list-ifaces")

        if not isinstance(result, list):
            return self._list_interfaces_fallback()

        # If the helper returned an empty list (e.g. all interfaces inactive),
        # fall back to the direct system-command path which shows all adapters.
        if not result:
            return self._list_interfaces_fallback()

        interfaces = []
        for iface_data in result:
            name = iface_data.get("name", "")
            mac = iface_data.get("mac", "")
            port_type = iface_data.get("port_type", "Ethernet")
            status = iface_data.get("status", "unknown")

            # Get additional info via ifconfig
            ip_info = self._get_ifconfig_info(name)

            # Get DHCP info
            dhcp_info = self._get_dhcp_info(name)

            # Detect runtime MAC (ifconfig) vs hardware MAC (networksetup) for spoofing
            runtime_mac = self._get_runtime_mac(name)
            if runtime_mac and runtime_mac.upper().replace("-", ":") != mac.upper().replace("-", ":"):
                display_mac = runtime_mac
                is_modified = True
            else:
                display_mac = mac
                is_modified = False

            interfaces.append(NetworkInterface(
                name=name,
                description=port_type,
                mac_address=display_mac,
                original_mac=mac,
                is_mac_modified=is_modified,
                ipv4_address=ip_info.get("ipv4", ""),
                ipv4_mask=ip_info.get("mask", ""),
                ipv4_gateway=ip_info.get("gateway", ""),
                ipv6_addresses=ip_info.get("ipv6", []),
                dns_servers=ip_info.get("dns", []),
                dhcp_enabled=dhcp_info.get("enabled", False),
                dhcp_server=dhcp_info.get("server", ""),
                is_connected=(status == "active"),
                link_speed=ip_info.get("speed", ""),
                mtu=ip_info.get("mtu", 1500),
                guid=name,  # On macOS, interface name is the GUID
                pnp_instance_id="",
                scapy_name=name,
            ))
        return interfaces

    def _get_ifconfig_info(self, iface_name: str) -> dict:
        """Get detailed interface info using ifconfig."""
        info = {"ipv4": "", "mask": "", "gateway": "", "ipv6": [], "dns": [], "speed": "", "mtu": 1500, "connected": False}
        try:
            out = subprocess.check_output(["ifconfig", iface_name], text=True, timeout=10)
            lines = out.splitlines()

            for line in lines:
                line = line.strip()
                # Combined inet + netmask line: "inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255"
                if line.startswith("inet "):
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "inet" and i + 1 < len(parts):
                            info["ipv4"] = parts[i + 1]
                        elif part == "netmask" and i + 1 < len(parts):
                            hex_mask = parts[i + 1]
                            info["mask"] = self._hex_to_netmask(hex_mask)
                # MTU on separate line: "mtu 1500"
                elif line.startswith("mtu "):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            info["mtu"] = int(parts[1])
                        except ValueError:
                            pass
                # Status: "status: active"
                elif "status: active" in line:
                    info["connected"] = True
                # Link speed from "media:" line, e.g.: "media: autoselect (1000baseT <full-duplex>)"
                elif line.startswith("media:"):
                    # Extract speed like "1000baseT" from media line
                    import re as _re
                    m = _re.search(r'(\d+)\s*base', line, _re.IGNORECASE)
                    if m:
                        speed_val = m.group(1)
                        if "1000" in speed_val:
                            info["speed"] = "1 Gbps"
                        elif "2500" in speed_val:
                            info["speed"] = "2.5 Gbps"
                        elif "5000" in speed_val:
                            info["speed"] = "5 Gbps"
                        elif "10000" in speed_val:
                            info["speed"] = "10 Gbps"
                        else:
                            info["speed"] = f"{speed_val} Mbps"
                # IPv6 on separate line or same
                elif line.startswith("inet6 "):
                    parts = line.split()
                    if len(parts) >= 2 and "%" not in parts[1]:
                        info["ipv6"].append(parts[1])
        except Exception:
            pass

        # Get interface-specific gateway via netstat -rn
        try:
            out = subprocess.check_output(["netstat", "-rn"], text=True, timeout=10)
            for line in out.splitlines():
                parts = line.split()
                # Look for "default" route on our interface
                if len(parts) >= 4 and parts[0] == "default":
                    gw_iface = parts[-1]  # Last column is interface name on macOS
                    if gw_iface == iface_name:
                        info["gateway"] = parts[1]
                        break
        except Exception:
            pass
        # Fallback: use route -n get default (system-wide)
        if not info["gateway"]:
            try:
                out = subprocess.check_output(["route", "-n", "get", "default"], text=True, timeout=10)
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("gateway:"):
                        info["gateway"] = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass

        # Get DNS servers via networksetup (requires SERVICE name)
        try:
            service = self._device_name_to_service(iface_name)
            out = subprocess.check_output(["networksetup", "-getdnsservers", service], text=True, timeout=10)
            dns_lines = [l.strip() for l in out.splitlines() if l.strip()]
            if dns_lines and not any("aren't any DNS" in l for l in dns_lines):
                info["dns"] = dns_lines
        except Exception:
            pass
        # Fallback: read /etc/resolv.conf for DNS
        if not info["dns"]:
            try:
                with open("/etc/resolv.conf", "r") as _f:
                    for _line in _f:
                        if _line.startswith("nameserver"):
                            info["dns"].append(_line.split()[1])
            except Exception:
                pass

        return info

    def _hex_to_netmask(self, hex_mask: str) -> str:
        """Convert hex netmask (e.g. 0xffffff00) to dotted decimal."""
        try:
            if hex_mask.startswith("0x"):
                mask_int = int(hex_mask, 16)
            else:
                mask_int = int(hex_mask, 16)
            octets = [(mask_int >> 24) & 0xFF, (mask_int >> 16) & 0xFF,
                        (mask_int >> 8) & 0xFF, mask_int & 0xFF]
            return ".".join(str(o) for o in octets)
        except Exception:
            return ""

    # Cached device-name to service-name mapping for networksetup
    _DEVICE_TO_SERVICE_CACHE = None

    def _build_device_to_service_map(self):
        if MacOSNetworkBackend._DEVICE_TO_SERVICE_CACHE is not None:
            return MacOSNetworkBackend._DEVICE_TO_SERVICE_CACHE
        mapping = {}
        try:
            out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True, timeout=5)
            current_port = None
            current_dev = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Hardware Port:"):
                    current_port = line.split("Hardware Port:", 1)[1].strip()
                elif line.startswith("Device:"):
                    current_dev = line.split("Device:", 1)[1].strip()
                    if current_port and current_dev:
                        mapping[current_dev] = current_port
        except Exception:
            pass
        MacOSNetworkBackend._DEVICE_TO_SERVICE_CACHE = mapping
        return mapping

    def _device_name_to_service(self, device_name: str) -> str:
        mapping = self._build_device_to_service_map()
        return mapping.get(device_name, device_name)

    def _get_runtime_mac(self, iface_name: str) -> str:
        try:
            out = subprocess.check_output(["ifconfig", iface_name], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("ether "):
                    return line.split("ether ", 1)[1].strip()
                if "lladdr " in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "lladdr" and i + 1 < len(parts):
                            return parts[i + 1]
        except Exception:
            pass
        return ""

    def _get_dhcp_info(self, iface_name: str) -> dict:
        """Detect DHCP status using networksetup -getinfo (works for all interface types).
        Falls back to ipconfig getpacket for more reliable DHCP server detection."""
        info = {"enabled": False, "server": ""}

        try:
            # networksetup -getinfo requires the SERVICE name, not device name
            service = self._device_name_to_service(iface_name)
            out = subprocess.check_output(
                ["networksetup", "-getinfo", service],
                text=True, timeout=5, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                line = line.strip()
                if "DHCP" in line and "Configuration" in line:
                    info["enabled"] = True
                if line.startswith("DHCP Server"):
                    parts = line.split(":", 1)
                    if len(parts) >= 2:
                        sid = parts[1].strip()
                        if sid and sid not in ("0.0.0.0", "255.255.255.255"):
                            info["server"] = sid
        except Exception:
            pass

        # Fallback: use ipconfig getpacket to read DHCP server info directly
        if not info["server"]:
            try:
                out = subprocess.check_output(
                    ["ipconfig", "getpacket", iface_name],
                    text=True, timeout=5, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    line = line.strip()
                    if "server_identifier" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) >= 2:
                            sid = parts[1].strip()
                            if sid and sid not in ("0.0.0.0", "255.255.255.255"):
                                info["server"] = sid
                                info["enabled"] = True
                                break
            except Exception:
                pass

        # Also try scutil --dns as a hint
        if not info["enabled"]:
            try:
                out = subprocess.check_output(
                    ["scutil", "--dns"],
                    text=True, timeout=5, stderr=subprocess.DEVNULL
                )
                if iface_name in out:
                    info["enabled"] = True
            except Exception:
                pass

        return info

    def _list_interfaces_fallback(self) -> List[NetworkInterface]:
        """Fallback interface listing using direct system commands."""
        interfaces = []
        try:
            out = subprocess.check_output(["networksetup", "-listallhardwareports"]).decode()
            current_port = None
            current_dev = None
            current_mac = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Hardware Port:"):
                    if current_dev and current_mac:
                        interfaces.append(NetworkInterface(
                            name=current_dev, description=current_port,
                            mac_address=current_mac, original_mac=current_mac,
                        ))
                    current_port = line.split("Hardware Port:", 1)[1].strip()
                    current_dev = None
                    current_mac = None
                elif line.startswith("Device:"):
                    current_dev = line.split("Device:", 1)[1].strip()
                elif line.startswith("Ethernet Address:"):
                    current_mac = line.split("Ethernet Address:", 1)[1].strip()
            if current_dev and current_mac:
                interfaces.append(NetworkInterface(
                    name=current_dev, description=current_port,
                    mac_address=current_mac, original_mac=current_mac,
                ))
            SKIP_PREFIXES = ["lo", "utun", "awdl", "llw", "ap", "gif", "stf", "anpi", "bridge"]
            filtered = []
            for iface in interfaces:
                if any(iface.name.startswith(p) for p in SKIP_PREFIXES):
                    continue
                runtime_mac = self._get_runtime_mac(iface.name)
                if runtime_mac and runtime_mac.upper().replace("-", ":") != iface.mac_address.upper().replace("-", ":"):
                    iface.mac_address = runtime_mac
                    iface.is_mac_modified = True
                    iface.original_mac = iface.mac_address
                ip_info = self._get_ifconfig_info(iface.name)
                iface.ipv4_address = ip_info.get("ipv4", "")
                iface.ipv4_mask = ip_info.get("mask", "")
                iface.ipv4_gateway = ip_info.get("gateway", "")
                iface.ipv6_addresses = ip_info.get("ipv6", [])
                iface.dns_servers = ip_info.get("dns", [])
                iface.is_connected = ip_info.get("connected", False)
                iface.mtu = ip_info.get("mtu", 1500)
                iface.link_speed = ip_info.get("speed", "")
                iface.guid = iface.name
                iface.scapy_name = iface.name
                dhcp_info = self._get_dhcp_info(iface.name)
                iface.dhcp_enabled = dhcp_info.get("enabled", False)
                iface.dhcp_server = dhcp_info.get("server", "")
                filtered.append(iface)
        except Exception as e:
            self.last_error = str(e)
            return self._list_interfaces_ifconfig_fallback()
        # networksetup exits code 0 even on failure (e.g., "AuthorizationCreate() failed")
        if not filtered:
            return self._list_interfaces_ifconfig_fallback()
        return filtered
    def _list_interfaces_ifconfig_fallback(self) -> list:
        """Tertiary fallback: enumerate using only ifconfig."""
        interfaces = []
        try:
            out = subprocess.check_output(["ifconfig", "-a"], text=True, timeout=10)
            current_iface = None
            current_mac = ""
            current_status = False
            for line in out.splitlines():
                if line and not line.startswith("\t") and ":" in line and "flags" in line:
                    if current_iface and current_mac:
                        interfaces.append(NetworkInterface(
                            name=current_iface, description="Ethernet",
                            mac_address=current_mac, original_mac=current_mac,
                            is_connected=current_status, guid=current_iface,
                            scapy_name=current_iface,
                        ))
                    current_iface = line.split(":", 1)[0].strip()
                    current_mac = ""
                    current_status = False
                elif current_iface:
                    sline = line.strip()
                    if sline.startswith("ether "):
                        current_mac = sline.split("ether ", 1)[1].strip()
                    elif "status: active" in sline:
                        current_status = True
            if current_iface and current_mac:
                interfaces.append(NetworkInterface(
                    name=current_iface, description="Ethernet",
                    mac_address=current_mac, original_mac=current_mac,
                    is_connected=current_status, guid=current_iface,
                    scapy_name=current_iface,
                ))
            SKIP_PREFIXES = ["lo", "utun", "awdl", "llw", "ap", "gif", "stf", "anpi", "bridge"]
            filtered = []
            for iface in interfaces:
                if any(iface.name.startswith(p) for p in SKIP_PREFIXES):
                    continue
                ip_info = self._get_ifconfig_info(iface.name)
                iface.ipv4_address = ip_info.get("ipv4", "")
                iface.ipv4_mask = ip_info.get("mask", "")
                iface.ipv4_gateway = ip_info.get("gateway", "")
                iface.ipv6_addresses = ip_info.get("ipv6", [])
                iface.dns_servers = ip_info.get("dns", [])
                iface.mtu = ip_info.get("mtu", 1500)
                iface.link_speed = ip_info.get("speed", "")
                dhcp_info = self._get_dhcp_info(iface.name)
                iface.dhcp_enabled = dhcp_info.get("enabled", False)
                iface.dhcp_server = dhcp_info.get("server", "")
                filtered.append(iface)
            return filtered
        except Exception:
            return []
    def get_interface_info(self, interface_id: str) -> Optional[NetworkInterface]:
        """Get interface information."""
        for iface in self.list_interfaces():
            if iface.name == interface_id:
                return iface
        return None
    def capture_lldp(self, interface_name: str, timeout: int = 10) -> Optional[LLDPPacket]:
        """Capture LLDP packet using tcpdump via lldp_helper."""
        result = self._run_helper("capture", interface_name)
        if not result.get("success"):
            self.last_error = result.get("error", "Capture failed")
            return None
        output = result.get("output", "")
        return self._parse_tcpdump_output(output)
    def _parse_tcpdump_output(self, output: str) -> Optional[LLDPPacket]:
        """Parse tcpdump output into LLDPPacket."""
        try:
            lines = output.splitlines()
            source_mac = ""
            dest_mac = ""
            chassis_id = ""
            port_id = ""
            for line in lines:
                if "LLDP" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        source_mac = parts[2]
                        dest_mac = parts[0]
                elif "Chassis ID" in line:
                    chassis_id = line.split("Chassis ID:", 1)[1].strip()
                elif "Port ID" in line:
                    port_id = line.split("Port ID:", 1)[1].strip()
            if source_mac and dest_mac:
                return LLDPPacket(
                    source_mac=source_mac,
                    destination_mac=dest_mac,
                    chassis_id=chassis_id,
                    port_id=port_id
                )
            return None
        except Exception as e:
            self.last_error = str(e)
            return None
    def restart_interface(self, interface_id: str) -> bool:
        """Restart interface using lldp_helper."""
        result = self._run_helper("restart", interface_id)
        success = result.get("success", False)
        if not success:
            self.last_error = result.get("error", "Restart failed")
        return success
    def _verify_mac_change(self, interface_id: str, expected_mac: str) -> tuple[bool, str]:
        """Check if the MAC actually changed. Some adapters (Apple Silicon built-in)
        silently accept the command but don't actually change the MAC."""
        import subprocess
        try:
            r = subprocess.run(["ifconfig", interface_id], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("ether "):
                    actual = line.split("ether ", 1)[1].strip().upper()
                    expected = expected_mac.replace("-", ":").upper()
                    if actual != expected:
                        return False, f"MAC unchanged (still {actual}). This adapter may not support MAC spoofing."
                    return True, ""
                if "lladdr " in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "lladdr" and i + 1 < len(parts):
                            actual = parts[i+1].strip().upper()
                            expected = expected_mac.replace("-", ":").upper()
                            if actual != expected:
                                return False, f"MAC unchanged (still {actual}). This adapter may not support MAC spoofing."
                            return True, ""
            return False, "Could not read MAC from ifconfig output (no ether/lladdr line found)"
        except Exception as e:
            return False, f"Could not verify MAC: {e}"
    def set_mac_address(self, interface_id: str, mac_address: str) -> bool:
        """Set MAC address on macOS. Tries ether then lladdr while UP
        (works on USB adapters and most modern drivers), then falls back
        to down/up bounce only if needed.
        Verifies the MAC actually changed after each step."""
        import subprocess, time

        def _set_and_verify(cmd: str, bounce: bool = False) -> bool:
            if bounce:
                subprocess.run(["ifconfig", interface_id, "down"],
                               capture_output=True, text=True, timeout=10)
                time.sleep(0.3)
            r = subprocess.run(["ifconfig", interface_id, cmd, mac_address],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                if bounce:
                    subprocess.run(["ifconfig", interface_id, "up"],
                                   capture_output=True, text=True, timeout=10)
                return False
            if bounce:
                time.sleep(0.5)
                subprocess.run(["ifconfig", interface_id, "up"],
                               capture_output=True, text=True, timeout=10)
            time.sleep(1.0)
            actual = ""
            r2 = subprocess.run(["ifconfig", interface_id],
                                capture_output=True, text=True, timeout=5)
            for line in r2.stdout.splitlines():
                s = line.strip()
                if s.startswith("ether "):
                    actual = s.split("ether ", 1)[1].strip().upper()
                    expected = mac_address.replace("-", ":").upper()
                    if actual == expected:
                        return True
                    break
                if "lladdr " in s:
                    parts = s.split()
                    for i, p in enumerate(parts):
                        if p == "lladdr" and i + 1 < len(parts):
                            actual = parts[i+1].strip().upper()
                            expected = mac_address.replace("-", ":").upper()
                            if actual == expected:
                                return True
                    break
            self.last_error = f"MAC unchanged (still {actual if actual else 'unknown'}). This adapter may not support MAC spoofing."
            return False

        # Strategy 1: try ether while UP (works on USB and most adapters)
        if _set_and_verify("ether", bounce=False):
            return True
        # Strategy 2: try lladdr while UP (macOS 14+ sometimes prefers this)
        if _set_and_verify("lladdr", bounce=False):
            return True
        # Strategy 3: last resort - down→ether→up
        if _set_and_verify("ether", bounce=True):
            return True
        # Strategy 4: down→lladdr→up
        if _set_and_verify("lladdr", bounce=True):
            return True
        if not self.last_error:
            self.last_error = "All strategies to set MAC failed. This adapter may not support MAC spoofing."
        return False
    def restore_mac(self, interface_id: str) -> bool:
        """Restore original MAC address on macOS."""
        try:
            import subprocess
            r = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=10,
            )
            current_dev = None
            current_mac = None
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("Device:"):
                    current_dev = line.split("Device:", 1)[1].strip()
                elif line.startswith("Ethernet Address:") and current_dev == interface_id:
                    current_mac = line.split("Ethernet Address:", 1)[1].strip()
                    break
            if not current_mac:
                self.last_error = "Could not find original MAC for " + interface_id
                return False
            mac = current_mac.replace("-", ":").upper()
            return self.set_mac_address(interface_id, mac)
        except Exception as e:
            self.last_error = str(e)
            return False
    def set_static_ip(self, interface_id: str, ip_address: str, subnet_mask: str,
                      gateway: str = "", dns_servers: List[str] = None) -> bool:
        """Set static IP using lldp_helper."""
        args = [interface_id, ip_address, subnet_mask]
        if gateway:
            args.append(gateway)
        if dns_servers:
            args.append("--dns")
            args.extend(dns_servers)
        result = self._run_helper("set-static", *args)
        success = result.get("success", False)
        if not success:
            self.last_error = result.get("error", "Failed to set static IP")
        return success
    def set_dhcp(self, interface_id: str) -> bool:
        """Enable DHCP using lldp_helper."""
        result = self._run_helper("set-dhcp", interface_id)
        success = result.get("success", False)
        if not success:
            self.last_error = result.get("error", "Failed to enable DHCP")
        return success
    def clear_ip(self, interface_id: str) -> bool:
        """Clear IP address using lldp_helper."""
        result = self._run_helper("clear-ip", interface_id)
        success = result.get("success", False)
        if not success:
            self.last_error = result.get("error", "Failed to clear IP")
        return success
