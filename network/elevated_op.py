#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Elevated helper for network adapter operations.

Launched via ShellExecuteW("runas") so it runs with admin rights.
Performs ONE operation, then shows a MessageBox with the result.

Set env LLDP_NO_MSG=1 to print to stdout instead of showing a MessageBox
(useful for testing).

Usage:
    python elevated_op.py modify-mac <iface_name> <mac>
    python elevated_op.py restore-mac <iface_name>
    python elevated_op.py restart-adapter <iface_name>
    python elevated_op.py set-static <iface_name> <ip> <mask> [gateway]
    python elevated_op.py set-dhcp <iface_name>
"""
import os
import subprocess
import sys

# If running with NO_MSG=1 in env, print instead of MessageBox
_NO_MSG = os.environ.get("LLDP_NO_MSG") == "1"

# Check if this is Windows (for MessageBox)
_IS_WINDOWS = sys.platform == "win32"


def _msg(title: str, body: str, kind: str = "info") -> int:
    if _NO_MSG or not _IS_WINDOWS:
        prefix = {"info": "[INFO]", "warn": "[WARN]", "error": "[ERR]"}.get(kind, "[INFO]")
        print(f"{prefix} {title}: {body}", flush=True)
        return 0
    import ctypes
    flags = {"info": 0x40, "warn": 0x30, "error": 0x10}.get(kind, 0x40)
    return ctypes.windll.user32.MessageBoxW(0, body, title, flags)


def _ok(title: str, body: str):
    _msg(title, body, "info")


def _fail(title: str, body: str):
    _msg(title, body, "error")


def _run_cmd(cmd):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def _restart_interface_darwin(iface_name):
    """Restart network interface on macOS."""
    # Bring down
    rc, out, err = _run_cmd(["ifconfig", iface_name, "down"])
    if rc != 0:
        return False, f"Failed to bring interface down: {err}"
    
    import time
    time.sleep(1)
    
    # Bring up
    rc, out, err = _run_cmd(["ifconfig", iface_name, "up"])
    if rc != 0:
        return False, f"Failed to bring interface up: {err}"
    
    return True, "Interface restarted"


def _set_mac_darwin(iface_name, mac):
    """Set MAC address on macOS.
    
    Strategy: try ether UP first (works on USB adapters), fall back to down/up.
    """
    import subprocess as _subprocess
    import time
    # Save original MAC before modifying
    try:
        r = _subprocess.run(["ifconfig", iface_name], capture_output=True, text=True, timeout=5)
        for _line in r.stdout.splitlines():
            if "ether " in _line:
                parts = _line.strip().split()
                if len(parts) >= 2 and parts[0] == "ether":
                    _ORIGINAL_MACS[iface_name] = parts[1]
                break
    except Exception:
        pass
    
    # Try lladdr/ether (any working approach)
    set_ok = False
    for cmd in ("ether", "lladdr"):
        rc, out, err = _run_cmd(["ifconfig", iface_name, cmd, mac])
        if rc == 0:
            set_ok = True
            break
    
    if not set_ok:
        # Last resort: down -> try -> up
        _run_cmd(["ifconfig", iface_name, "down"])
        time.sleep(0.3)
        for cmd in ("ether", "lladdr"):
            rc, out, err = _run_cmd(["ifconfig", iface_name, cmd, mac])
            if rc == 0:
                set_ok = True
                break
        _run_cmd(["ifconfig", iface_name, "up"])
    
    if not set_ok:
        return False, f"Failed to set MAC: {err}"
    
    # Bounce interface to make the driver apply the new MAC
    _run_cmd(["ifconfig", iface_name, "down"])
    time.sleep(0.5)
    _run_cmd(["ifconfig", iface_name, "up"])
    time.sleep(1.0)
    return True, f"MAC set to {mac}"


def _set_static_ip_darwin(iface_name, ip, mask, gateway="", dns=None):
    """Set static IP on macOS using networksetup -setmanual."""
    service = _device_to_service(iface_name)
    if gateway:
        rc, out, err = _run_cmd(["networksetup", "-setmanual", service, ip, mask, gateway])
    else:
        rc, out, err = _run_cmd(["networksetup", "-setmanual", service, ip, mask])
    if rc != 0:
        return False, f"Failed to set IP: {(err or out).strip()}"
    # Set DNS servers if provided
    if dns:
        dns_list = [d for d in dns if d]
        if dns_list:
            _run_cmd(["networksetup", "-setdnsservers", service] + dns_list)
    return True, f"Static IP set: {ip}/{mask}"


def _set_dhcp_darwin(iface_name):
    """Enable DHCP on macOS."""
    service = _device_to_service(iface_name)
    rc, out, err = _run_cmd(["networksetup", "-setdhcp", service])
    if rc == 0:
        return True, f"DHCP enabled on {iface_name}"
    else:
        return False, f"Failed to enable DHCP: {(err or out).strip()}"


def main():
    if len(sys.argv) < 2:
        _fail("Elevated Op", "Missing operation argument")
        return 1

    op = sys.argv[1]

    try:
        if sys.platform == "darwin":
            if op == "restart-adapter":
                if len(sys.argv) < 3:
                    _fail("Restart Adapter", "Usage: restart-adapter <iface_name>")
                    return 1
                iface_name = sys.argv[2]
                ok, msg = _restart_interface_darwin(iface_name)
                if ok:
                    _ok("Restart Adapter", msg)
                else:
                    _fail("Restart Adapter", msg)
                return 0 if ok else 1

            elif op == "modify-mac":
                if len(sys.argv) < 4:
                    _fail("Modify MAC", "Usage: modify-mac <iface_name> <mac>")
                    return 1
                iface_name = sys.argv[2]
                mac = sys.argv[3]
                ok, msg = _set_mac_darwin(iface_name, mac)
                if ok:
                    _ok("Modify MAC", msg)
                else:
                    _fail("Modify MAC", msg)
                return 0 if ok else 1

            elif op == "set-static":
                if len(sys.argv) < 5:
                    _fail("Set Static IP", "Usage: set-static <iface_name> <ip> <mask> [gateway]")
                    return 1
                iface_name = sys.argv[2]
                ip = sys.argv[3]
                mask = sys.argv[4]
                # Parse gateway (positional) and --dns (flag) properly
                gateway = ""
                dns = None
                i = 5
                while i < len(sys.argv):
                    if sys.argv[i] == "--dns":
                        dns = []
                        i += 1
                        while i < len(sys.argv) and not sys.argv[i].startswith("--"):
                            dns.append(sys.argv[i])
                            i += 1
                    elif i == 5:
                        # First non-flag positional arg after mask = gateway
                        gateway = sys.argv[i]
                        i += 1
                    else:
                        i += 1
                ok, msg = _set_static_ip_darwin(iface_name, ip, mask, gateway, dns)
                if ok:
                    _ok("Set Static IP", msg)
                else:
                    _fail("Set Static IP", msg)
                return 0 if ok else 1

            elif op == "restore-mac":
                if len(sys.argv) < 3:
                    _fail("Restore MAC", "Usage: restore-mac <iface_name>")
                    return 1
                iface_name = sys.argv[2]
                ok, msg = _restore_mac_darwin(iface_name)
                if ok:
                    _ok("Restore MAC", msg)
                else:
                    _fail("Restore MAC", msg)
                return 0 if ok else 1

            elif op == "set-dhcp":
                if len(sys.argv) < 3:
                    _fail("Enable DHCP", "Usage: set-dhcp <iface_name>")
                    return 1
                iface_name = sys.argv[2]
                ok, msg = _set_dhcp_darwin(iface_name)
                if ok:
                    _ok("DHCP Enabled", msg)
                else:
                    _fail("DHCP", msg)
                return 0 if ok else 1

            elif op == "clear-ip":
                if len(sys.argv) < 3:
                    _fail("Clear IP", "Usage: clear-ip <iface_name>")
                    return 1
                iface_name = sys.argv[2]
                rc, out, err = _run_cmd(["ifconfig", iface_name, "inet", "delete"])
                if rc == 0:
                    _ok("Clear IP", f"IP cleared on {iface_name}")
                else:
                    _fail("Clear IP", f"Failed: {(err or out).strip()}")
                return 0 if rc == 0 else 1

            else:
                _fail("Unknown Op", f"Unknown operation: {op}")
                return 1

        else:
            # Windows/Linux - use original backend approach
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sys.path.insert(0, project_root)

            from network.backends.platform import is_windows
            if is_windows():
                from network.backends.windows.adapter import WindowsNetworkBackend
            else:
                from network.backends.posix.adapter import PosixNetworkBackend

            be = WindowsNetworkBackend() if is_windows() else PosixNetworkBackend()

            if op == "modify-mac":
                if len(sys.argv) < 4:
                    _fail("Modify MAC", "Usage: modify-mac <guid> <mac>")
                    return 1
                guid = sys.argv[2]
                mac = sys.argv[3]
                iface = be.get_interface_info(guid)
                if not iface:
                    _fail("Modify MAC", f"Adapter not found: {guid}")
                    return 1
                ok = be.set_mac_address(guid, mac)
                if ok:
                    _ok("Modify MAC",
                        f"MAC set to {mac}\nAdapter restarted.\n\n"
                        "The new MAC will be active in a few seconds.")
                else:
                    _fail("Modify MAC",
                          f"Failed to set MAC:\n{be.last_error}\n\n"
                          "Check that the adapter supports MAC spoofing\n"
                          "(some drivers block this).")
                return 0 if ok else 1

            if op == "restore-mac":
                if len(sys.argv) < 3:
                    _fail("Restore MAC", "Usage: restore-mac <guid>")
                    return 1
                guid = sys.argv[2]
                iface = be.get_interface_info(guid)
                if not iface:
                    _fail("Restore MAC", f"Adapter not found: {guid}")
                    return 1
                ok = be.restore_mac(guid)
                if ok:
                    _ok("Restore MAC", "Default MAC restored.\nAdapter restarted.")
                else:
                    _fail("Restore MAC", f"Failed:\n{be.last_error}")
                return 0 if ok else 1

            if op == "restart-adapter":
                if len(sys.argv) < 3:
                    _fail("Restart Adapter", "Usage: restart-adapter <guid>")
                    return 1
                guid = sys.argv[2]
                ok = be.restart_interface(guid)
                if ok:
                    _ok("Restart Adapter", "Adapter restarted.")
                else:
                    _fail("Restart Adapter", f"Failed:\n{be.last_error}")
                return 0 if ok else 1

            if op == "set-static":
                if len(sys.argv) < 5:
                    _fail("Set Static IP", "Usage: set-static <name> <ip> <mask> [gateway]")
                    return 1
                name = sys.argv[2]
                ip = sys.argv[3]
                mask = sys.argv[4]
                gw = sys.argv[5] if len(sys.argv) > 5 else ""
                dns = []
                if len(sys.argv) > 6:
                    dns = [d for d in sys.argv[6:] if d]
                ok = be.set_static_ip(name, ip, mask, gw, dns if dns else None)
                if ok:
                    msg = f"Static IP configured:\n{ip} / {mask}"
                    if gw:
                        msg += f"\nGateway: {gw}"
                    if dns:
                        msg += f"\nDNS: {', '.join(dns)}"
                    _ok("Set Static IP", msg)
                else:
                    _fail("Set Static IP", f"Failed:\n{be.last_error}")
                return 0 if ok else 1

            if op == "set-dhcp":
                if len(sys.argv) < 3:
                    _fail("Enable DHCP", "Usage: set-dhcp <name>")
                    return 1
                name = sys.argv[2]
                ok = be.set_dhcp(name)
                if ok:
                    _ok("DHCP Enabled", f"DHCP enabled on {name}.")
                else:
                    _fail("DHCP", f"Failed:\n{be.last_error}")
                return 0 if ok else 1

            if op == "clear-ip":
                if len(sys.argv) < 3:
                    _fail("Clear IP", "Usage: clear-ip <name>")
                    return 1
                name = sys.argv[2]
                ok, msg = _restart_interface_darwin(name) if sys.platform == 'darwin' else (be.set_dhcp(name), "")
                if ok:
                    _ok("Clear IP", f"IP cleared on {name}.")
                else:
                    _fail("Clear IP", f"Failed: {msg if not ok else ''}")
                return 0 if ok else 1

            _fail("Unknown Op", f"Unknown operation: {op}")
            return 1

    except Exception as e:
        _fail("Error", f"Operation failed:\n{e}")
        return 1


# store original MACs before modification (used by restore-mac)
_ORIGINAL_MACS = {}


_DEVICE_TO_SERVICE_CACHE = None


def _build_device_to_service_map():
    """Build a mapping from device name to service name.
    macOS networksetup commands require the service name, not device name.
    """
    global _DEVICE_TO_SERVICE_CACHE
    if _DEVICE_TO_SERVICE_CACHE is not None:
        return _DEVICE_TO_SERVICE_CACHE
    mapping = {}
    rc, out, err = _run_cmd(["networksetup", "-listallhardwareports"])
    if rc == 0:
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
    _DEVICE_TO_SERVICE_CACHE = mapping
    return mapping


def _device_to_service(device_name):
    mapping = _build_device_to_service_map()
    return mapping.get(device_name, device_name)


def _restore_mac_darwin(iface_name):
    """Restore original MAC address on macOS."""
    try:
        r = subprocess.run(["networksetup", "-listallhardwareports"],
                           capture_output=True, text=True, timeout=10)
        current_dev = None
        current_mac = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Device:"):
                current_dev = line.split("Device:", 1)[1].strip()
            elif line.startswith("Ethernet Address:") and current_dev == iface_name:
                current_mac = line.split("Ethernet Address:", 1)[1].strip()
                break
        if not current_mac:
            return False, "Could not find original MAC for " + iface_name
        mac = current_mac.replace("-", ":").upper()
        return _set_mac_darwin(iface_name, mac)
    except Exception as e:
        return False, str(e)




if __name__ == "__main__":
    sys.exit(main() or 0)
