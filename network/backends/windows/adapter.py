#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows network adapter backend.

Data sources:
  - Scapy get_windows_if_list — name, GUID, MAC, IPs, description
  - psutil net_if_addrs / net_if_stats — subnet mask, link speed, MTU, status
  - winreg — MAC address read/write, original MAC detection
  - cfgmgr32 — adapter disable/enable (restart)
  - netsh — static IP / DHCP configuration (no WMI dependency)
"""

import ctypes
import locale
import ctypes.wintypes as wintypes
import os
import re
import subprocess
import sys
from typing import List, Optional, Dict, Any

from network.core.interfaces import NetworkInterface, NetworkAdapterBackend


from utils.adapter_scanner import is_ethernet_adapter


# ---------------------------------------------------------------------------
# Windows backend
# ---------------------------------------------------------------------------

class WindowsNetworkBackend(NetworkAdapterBackend):

    # Populated by set_mac_address / restore_mac with the error reason
    last_error: str = ""

    def __init__(self):
        self._cfgmgr32 = ctypes.WinDLL("cfgmgr32")
        self._CM_Locate_DevNode = self._cfgmgr32.CM_Locate_DevNodeW
        self._CM_Locate_DevNode.restype = wintypes.DWORD
        self._CM_Locate_DevNode.argtypes = [
            ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR, wintypes.ULONG,
        ]
        self._CM_Disable_DevNode = self._cfgmgr32.CM_Disable_DevNode
        self._CM_Disable_DevNode.restype = wintypes.DWORD
        self._CM_Disable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]
        self._CM_Enable_DevNode = self._cfgmgr32.CM_Enable_DevNode
        self._CM_Enable_DevNode.restype = wintypes.DWORD
        self._CM_Enable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_interfaces(self) -> List[NetworkInterface]:
        return self._enumerate()

    def get_interface_info(self, name_or_guid: str) -> Optional[NetworkInterface]:
        for iface in self._enumerate():
            if iface.name == name_or_guid or iface.guid == name_or_guid:
                return iface
        return None

    def restart_interface(self, name_or_guid: str) -> bool:
        self.last_error = ""
        iface = self.get_interface_info(name_or_guid)
        if not iface:
            self.last_error = "Adapter not found"
            return False
        dev_inst = self._locate_dev_node(iface.pnp_instance_id)
        if dev_inst is None:
            self.last_error = "Cannot locate PnP device node (need admin or PnP ID missing)"
            return False
        rc1 = self._CM_Disable_DevNode(dev_inst, 0)
        if rc1 != 0:
            self.last_error = f"CM_Disable_DevNode failed (rc=0x{rc1:X}, need admin)"
            return False
        import time; time.sleep(1.5)
        rc2 = self._CM_Enable_DevNode(dev_inst, 0)
        if rc2 != 0:
            self.last_error = f"CM_Enable_DevNode failed (rc=0x{rc2:X})"
            return False
        return True

    def set_mac_address(self, name_or_guid: str, mac: str) -> bool:
        self.last_error = ""
        iface = self.get_interface_info(name_or_guid)
        if not iface:
            self.last_error = "Adapter not found"
            return False
        clean = mac.replace(":", "").replace("-", "").upper()
        if len(clean) != 12:
            self.last_error = "Invalid MAC format"
            return False
        err = self._write_registry_mac(iface, clean)
        if err:
            self.last_error = err
            return False
        if not self.restart_interface(name_or_guid):
            # restart_interface sets its own last_error
            return False
        return True

    def restore_mac(self, name_or_guid: str) -> bool:
        self.last_error = ""
        iface = self.get_interface_info(name_or_guid)
        if not iface:
            self.last_error = "Adapter not found"
            return False
        err = self._delete_registry_mac(iface)
        if err:
            self.last_error = err
            return False
        if not self.restart_interface(name_or_guid):
            return False
        return True

    def set_static_ip(self, name_or_guid: str, ip: str, mask: str,
                      gateway: str = "", dns: List[str] = None) -> bool:
        self.last_error = ""
        iface = self.get_interface_info(name_or_guid)
        if not iface:
            self.last_error = "Adapter not found"
            return False
        name = iface.name
        try:
            cmd = ["netsh", "interface", "ipv4", "set", "address",
                   f"name={name}", "static", ip, mask]
            if gateway:
                cmd.append(gateway)
            r = subprocess.run(cmd, capture_output=True, timeout=15,
                                creationflags=0x08000000)  # CREATE_NO_WINDOW
            if r.returncode != 0:
                err = (r.stdout or b"").decode('utf-8', 'replace').strip()
                if not err:
                    err = (r.stderr or b"").decode('utf-8', 'replace').strip()
                self.last_error = f"netsh: {err}"
                return False
            if dns:
                for idx, d in enumerate(dns):
                    if not d:
                        continue
                    if idx == 0:
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "set", "dns",
                             f"name={name}", "static", d],
                            capture_output=True, timeout=15,
                            creationflags=0x08000000,
                        )
                    else:
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "add", "dns",
                             f"name={name}", d, f"index={idx + 1}"],
                            capture_output=True, timeout=15,
                            creationflags=0x08000000,
                        )
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def set_dhcp(self, name_or_guid: str) -> bool:
        self.last_error = ""
        iface = self.get_interface_info(name_or_guid)
        if not iface:
            self.last_error = "Adapter not found"
            return False
        name = iface.name
        try:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "address", f"name={name}", "dhcp"],
                capture_output=True, timeout=15,
                            creationflags=0x08000000,  # CREATE_NO_WINDOW
                        )
            if r.returncode != 0:
                err = (r.stdout or b"").decode('utf-8', 'replace').strip()
                if not err:
                    err = (r.stderr or b"").decode('utf-8', 'replace').strip()
                self.last_error = f"netsh: {err}"
                return False
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dns", f"name={name}", "dhcp"],
                capture_output=True, timeout=15,
                            creationflags=0x08000000,  # CREATE_NO_WINDOW
                        )
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    # ------------------------------------------------------------------
    # Internal: enumerate adapters
    # ------------------------------------------------------------------

    def _enumerate(self) -> List[NetworkInterface]:
        """Build interface list. PowerShell Get-NetAdapter is the single source
        of truth for link speed, MTU, and status; everything else comes from
        Get-NetIPAddress / Get-DnsClientServerAddress / registry."""
        result: List[NetworkInterface] = []

        adapters = self._query_net_adapters()
        if not adapters:
            # Fallback: try Scapy-only if PowerShell is unavailable
            return self._enumerate_scapy_fallback()

        # Build a quick lookup of {description -> scapy_iface} for GUID/scapy_name
        scapy_lookup: Dict[str, Dict[str, Any]] = {}
        try:
            from scapy.arch.windows import get_windows_if_list
            for s in get_windows_if_list():
                d = str(s.get("description", ""))
                if d:
                    scapy_lookup.setdefault(d, s)
        except Exception:
            pass

        # psutil subnet masks (keyed by InterfaceDescription, falls back to Name)
        psutil_mask: Dict[str, str] = {}
        try:
            import psutil
            for if_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2 and addr.netmask and addr.netmask != "0.0.0.0":
                        psutil_mask[if_name] = addr.netmask
        except Exception:
            pass

        for ad in adapters:
            name = ad.get("name", "")
            desc = ad.get("description", "")
            guid = ad.get("guid", "")
            mac = ad.get("mac", "").upper()
            if not mac or mac == "00:00:00:00:00:00":
                continue

            if not is_ethernet_adapter(name, desc):
                continue

            ipv4, ipv4_mask, ipv6_list = self._query_ip_info(guid, name)
            gateway = self._query_gateway(guid, name)
            dns = self._query_dns(guid, name)
            dhcp_enabled = self._query_dhcp_enabled(guid)
            dhcp_server = self._get_dhcp_value(guid, "DhcpServer") if dhcp_enabled else ""
            pnp_id = self._get_pnp_from_guid(guid) if guid else ""
            original_mac, is_modified = self._check_registry_mac(guid, desc, mac)

            # Subnet mask: prefer PowerShell, fall back to psutil by name/desc, then registry
            if not ipv4_mask:
                ipv4_mask = psutil_mask.get(name) or psutil_mask.get(desc) or ""
            if not ipv4_mask and dhcp_enabled:
                ipv4_mask = self._get_dhcp_value(guid, "DhcpSubnetMask")

            result.append(NetworkInterface(
                name=name,
                description=desc,
                mac_address=mac,
                original_mac=original_mac,
                is_mac_modified=is_modified,
                ipv4_address=ipv4,
                ipv4_mask=ipv4_mask,
                ipv4_gateway=gateway,
                ipv6_addresses=ipv6_list,
                dns_servers=dns,
                dhcp_enabled=dhcp_enabled,
                dhcp_server=dhcp_server,
                is_connected=(ad.get("status", "").lower() == "up"),
                link_speed=ad.get("speed", ""),
                mtu=ad.get("mtu", 0),
                guid=guid,
                pnp_instance_id=pnp_id,
                scapy_name=rf"\Device\NPF_{guid}" if guid else "",
            ))

        return result

    # ------------------------------------------------------------------
    # Scapy fallback (only used if Get-NetAdapter is unavailable)
    # ------------------------------------------------------------------

    def _enumerate_scapy_fallback(self) -> List[NetworkInterface]:
        result: List[NetworkInterface] = []
        try:
            from scapy.arch.windows import get_windows_if_list
            for s in get_windows_if_list():
                name = str(s.get("name", ""))
                desc = str(s.get("description", ""))
                if not is_ethernet_adapter(name, desc):
                    continue
                guid = s.get("guid", "")
                mac = s.get("mac", "").upper()
                if not mac or mac == "00:00:00:00:00:00":
                    continue
                ips = s.get("ips", [])
                ipv4 = next((ip for ip in ips if ":" not in ip), "")
                ipv6 = [ip for ip in ips if ":" in ip]
                ipv4_mask = ""
                gateway = self._query_gateway(guid, name)
                dns = self._query_dns(guid, name)
                dhcp_enabled = bool(ipv4 and not ipv4.startswith("169.254."))
                dhcp_server = self._get_dhcp_value(guid, "DhcpServer") if dhcp_enabled else ""
                pnp_id = self._get_pnp_from_guid(guid) if guid else ""
                orig_mac, is_mod = self._check_registry_mac(guid, desc, mac)
                result.append(NetworkInterface(
                    name=name, description=desc, mac_address=mac,
                    original_mac=orig_mac, is_mac_modified=is_mod,
                    ipv4_address=ipv4, ipv4_mask=ipv4_mask, ipv4_gateway=gateway,
                    ipv6_addresses=ipv6, dns_servers=dns,
                    dhcp_enabled=dhcp_enabled, dhcp_server=dhcp_server,
                    is_connected=True, link_speed="", mtu=0, guid=guid,
                    pnp_instance_id=pnp_id,
                    scapy_name=rf"\Device\NPF_{guid}" if guid else "",
                ))
        except Exception:
            pass
        return result

        return result

    # ------------------------------------------------------------------
    # PowerShell queries (single source of truth)
    # ------------------------------------------------------------------

    @staticmethod
    def _ps(cmd: str) -> str:
        """Run a PowerShell command and return stdout."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=10,
                encoding=locale.getpreferredencoding(False), errors="replace",
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            return r.stdout or ""
        except Exception:
            return ""

    def _query_net_adapters(self) -> List[Dict[str, Any]]:
        """Get-NetAdapter — single source for name, description, GUID, MAC,
        link speed, MTU, status. One call covers everything."""
        cmd = (
            "Get-NetAdapter | "
            "Where-Object {$_.MediaType -eq '802.3'} | "
            "Select-Object Name, InterfaceDescription, InterfaceGuid, "
            "MacAddress, LinkSpeed, MtuSize, Status | ConvertTo-Json -Compress"
        )
        out = self._ps(cmd)
        if not out.strip():
            return []
        try:
            import json
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            results: List[Dict[str, Any]] = []
            for d in data:
                # Normalize MAC: "40-C2-BA-90-5A-0D" -> "40:C2:BA:90:5A:0D"
                mac = (d.get("MacAddress") or "").replace("-", ":").upper()
                guid = d.get("InterfaceGuid") or ""
                speed = str(d.get("LinkSpeed") or "").strip()
                # MtuSize is int in newer PS, sometimes string
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
                })
            return results
        except Exception:
            return []

    def _query_ip_info(self, guid: str, iface_name: str) -> tuple:
        """Get-NetIPAddress for IPv4 + IPv6, PrefixLength for mask.
        Returns (ipv4, mask, [ipv6...])."""
        if not iface_name:
            return ("", "", [])
        cmd = (
            f'Get-NetIPAddress -InterfaceAlias \'{iface_name}\' | '
            f"Select-Object IPAddress, PrefixLength, AddressFamily | ConvertTo-Json -Compress"
        )
        out = self._ps(cmd)
        ipv4 = ""
        ipv4_mask = ""
        ipv6_list: List[str] = []
        if not out.strip():
            return ("", "", [])
        try:
            import json
            import ipaddress
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                ip = d.get("IPAddress", "")
                fam = d.get("AddressFamily", 0)
                prefix = d.get("PrefixLength", 0)
                if fam == 2 and ip and ":" not in ip:  # IPv4
                    if not ipv4:
                        ipv4 = ip
                        # Convert prefix length to dotted mask
                        if prefix and not ipv4_mask:
                            try:
                                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                                ipv4_mask = mask
                            except Exception:
                                pass
                elif fam == 23 and ip and ":" in ip and not ip.startswith("fe80"):  # IPv6
                    ipv6_list.append(ip)
        except Exception:
            pass
        return (ipv4, ipv4_mask, ipv6_list)

    def _query_gateway(self, guid: str, iface_name: str = "") -> str:
        """Get first IPv4 default gateway for the interface via PowerShell."""
        if not iface_name:
            return ""
        cmd = (
            f"Get-NetRoute -InterfaceAlias \'{iface_name}\' -DestinationPrefix '0.0.0.0/0' "
            f"-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NextHop"
        )
        out = self._ps(cmd)
        return out.strip()

    def _query_dns(self, guid: str, iface_name: str = "") -> List[str]:
        """Get DNS servers via PowerShell."""
        if not iface_name:
            return []
        cmd = (
            f'Get-DnsClientServerAddress -InterfaceAlias \'{iface_name}\' -AddressFamily IPv4 '
            f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json -Compress"
        )
        out = self._ps(cmd).strip()
        if not out:
            return []
        try:
            import json
            data = json.loads(out)
            if isinstance(data, str):
                data = [data]
            return [str(s).strip() for s in data if s]
        except Exception:
            return [line.strip() for line in out.splitlines() if line.strip()]

    def _query_dhcp_enabled(self, guid: str) -> bool:
        """Check DHCP enabled via registry EnableDHCP value."""
        if not guid:
            return False
        val = self._get_dhcp_value(guid, "EnableDHCP")
        return val == "1"

    # ------------------------------------------------------------------
    # DHCP server + subnet mask via registry
    # ------------------------------------------------------------------

    @staticmethod
    def _get_dhcp_value(guid: str, name: str) -> str:
        """Read a DHCP value from HKLM\...\Tcpip\Parameters\Interfaces\{GUID}."""
        if not guid:
            return ""
        try:
            import winreg
            path = rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            try:
                val, _ = winreg.QueryValueEx(key, name)
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val if v)
                return str(val) if val else ""
            finally:
                winreg.CloseKey(key)
        except FileNotFoundError:
            return ""
        except Exception:
            return ""

    @classmethod
    def _get_dhcp_server(cls, guid: str) -> str:
        return cls._get_dhcp_value(guid, "DhcpServer")

    # ------------------------------------------------------------------
    # Registry: subkey lookup (returns NAME, not opened handle)
    # ------------------------------------------------------------------

    _NET_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"

    def _find_registry_subkey_name(self, guid: str, desc: str) -> Optional[str]:
        """Return the subkey name (e.g. '0000') matching this adapter.

        We return just the name so callers can re-open the subkey with the
        access mask they need (KEY_READ for inspection, KEY_SET_VALUE for writes).
        """
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self._NET_CLASS)
        except OSError:
            return None
        idx = 0
        result = None
        while True:
            try:
                subkey_name = winreg.EnumKey(key, idx)
                idx += 1
                try:
                    subkey = winreg.OpenKey(key, subkey_name)
                except OSError:
                    continue
                # Match by NetCfgInstanceId (GUID) — exact, preferred
                try:
                    cfg_id = winreg.QueryValueEx(subkey, "NetCfgInstanceId")[0]
                    if cfg_id and cfg_id.upper() == guid.upper():
                        result = subkey_name
                        winreg.CloseKey(subkey)
                        break
                except FileNotFoundError:
                    pass
                # Fallback: match by DriverDesc
                try:
                    driver_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                    if driver_desc and desc and desc in driver_desc:
                        result = subkey_name
                        winreg.CloseKey(subkey)
                        break
                except FileNotFoundError:
                    pass
                winreg.CloseKey(subkey)
            except OSError:
                break
        winreg.CloseKey(key)
        return result

    def _check_registry_mac(self, guid: str, desc: str, current_mac: str):
        """Return (original_mac, is_modified) by reading NetworkAddress from registry."""
        import winreg
        subkey_name = self._find_registry_subkey_name(guid, desc)
        if not subkey_name:
            return ("", False)
        try:
            subkey = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self._NET_CLASS + "\\" + subkey_name
            )
            stored = winreg.QueryValueEx(subkey, "NetworkAddress")[0]
            winreg.CloseKey(subkey)
            stored_clean = stored.replace(":", "").replace("-", "").upper()
            current_clean = current_mac.replace(":", "").replace("-", "").upper()
            if stored_clean and stored_clean != current_clean:
                return (stored_clean, True)
            return ("", False)
        except FileNotFoundError:
            return ("", False)
        except Exception:
            return ("", False)

    def _write_registry_mac(self, iface: NetworkInterface, clean_mac: str) -> Optional[str]:
        """Write NetworkAddress to registry. Returns None on success, error string on failure."""
        import winreg
        subkey_name = self._find_registry_subkey_name(iface.guid, iface.description)
        if not subkey_name:
            return "Registry subkey not found for this adapter"
        try:
            subkey = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._NET_CLASS + "\\" + subkey_name,
                0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            )
        except PermissionError:
            return "Access denied writing to registry (need admin)"
        except OSError as e:
            return f"OpenKey failed: {e}"
        try:
            winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, clean_mac)
            winreg.CloseKey(subkey)
            return None
        except PermissionError:
            try:
                winreg.CloseKey(subkey)
            except Exception:
                pass
            return "Write denied (need admin)"
        except Exception as e:
            try:
                winreg.CloseKey(subkey)
            except Exception:
                pass
            return f"Write failed: {e}"

    def _delete_registry_mac(self, iface: NetworkInterface) -> Optional[str]:
        """Delete NetworkAddress value. Returns None on success, error string on failure."""
        import winreg
        subkey_name = self._find_registry_subkey_name(iface.guid, iface.description)
        if not subkey_name:
            return "Registry subkey not found for this adapter"
        try:
            subkey = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self._NET_CLASS + "\\" + subkey_name,
                0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            )
        except PermissionError:
            return "Access denied (need admin)"
        except OSError as e:
            return f"OpenKey failed: {e}"
        try:
            winreg.DeleteValue(subkey, "NetworkAddress")
            winreg.CloseKey(subkey)
            return None
        except FileNotFoundError:
            try:
                winreg.CloseKey(subkey)
            except Exception:
                pass
            return None  # Already absent — treat as success
        except PermissionError:
            try:
                winreg.CloseKey(subkey)
            except Exception:
                pass
            return "Delete denied (need admin)"
        except Exception as e:
            try:
                winreg.CloseKey(subkey)
            except Exception:
                pass
            return f"Delete failed: {e}"

    # ------------------------------------------------------------------
    # cfgmgr32: PnP device node
    # ------------------------------------------------------------------

    @staticmethod
    def _get_pnp_from_guid(guid: str) -> str:
        try:
            import winreg
            conn_path = (
                rf"SYSTEM\CurrentControlSet\Control\Network"
                r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                rf"\{guid}\Connection"
            )
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path)
            pnp = winreg.QueryValueEx(key, "PnPInstanceID")[0]
            winreg.CloseKey(key)
            return pnp or ""
        except Exception:
            return ""

    def _locate_dev_node(self, pnp_id: str) -> Optional[int]:
        if not pnp_id:
            return None
        dev_inst = wintypes.DWORD()
        rc = self._CM_Locate_DevNode(ctypes.byref(dev_inst), pnp_id, 0)
        return dev_inst.value if rc == 0 else None
