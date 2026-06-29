#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLDP Helper - Privileged helper for macOS network operations.

This script runs with elevated privileges and provides:
- Network interface listing (via networksetup + ifconfig)
- LLDP packet capture (via tcpdump)
- Network configuration (ifconfig, networksetup)

All operations use only system commands, no scapy/psutil dependencies.
"""

import argparse
import json
import subprocess
import sys
import time


SKIP_PREFIXES = [
    "lo", "utun", "awdl", "llw",
    "ap", "gif", "stf", "anpi", "bridge"
]


_DEVICE_TO_SERVICE_CACHE = None


def _build_device_to_service_map():
    """Build a mapping from device name (e.g. 'en0') to service name (e.g. 'Ethernet').

    macOS networksetup commands require the service name, not the device name.
    """
    global _DEVICE_TO_SERVICE_CACHE
    if _DEVICE_TO_SERVICE_CACHE is not None:
        return _DEVICE_TO_SERVICE_CACHE
    mapping = {}
    rc, out, err = run_cmd(["networksetup", "-listallhardwareports"])
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


def _device_to_service(device_name: str) -> str:
    mapping = _build_device_to_service_map()
    return mapping.get(device_name, device_name)



def run_cmd(cmd, capture_output=True):
    """Run a system command."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=60
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def list_interfaces():
    """List network interfaces using networksetup and ifconfig."""
    interfaces = []
    
    # Get hardware ports from networksetup
    rc, out, err = run_cmd(["networksetup", "-listallhardwareports"])
    if rc == 0:
        current_port = None
        current_dev = None
        current_mac = None
        
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                if current_dev and current_mac:
                    interfaces.append({
                        "name": current_dev,
                        "port_type": current_port,
                        "mac": current_mac,
                    })
                current_port = line.split("Hardware Port:", 1)[1].strip()
                current_dev = None
                current_mac = None
            elif line.startswith("Device:"):
                current_dev = line.split("Device:", 1)[1].strip()
            elif line.startswith("Ethernet Address:"):
                current_mac = line.split("Ethernet Address:", 1)[1].strip()
        
        if current_dev and current_mac:
            interfaces.append({
                "name": current_dev,
                "port_type": current_port,
                "mac": current_mac,
            })
    
    # Get interface status from ifconfig
    rc, out, err = run_cmd(["ifconfig"])
    if rc == 0:
        iface_info = {}
        current_iface = None
        
        for line in out.splitlines():
            if line and not line.startswith("\t") and ":" in line:
                parts = line.split(":")
                if len(parts) > 0:
                    current_iface = parts[0].strip()
                    # Initialize with inactive only if not already set
                    if current_iface not in iface_info:
                        iface_info[current_iface] = {"status": "inactive"}
            elif current_iface and "status: active" in line:
                iface_info[current_iface] = {"status": "active"}
            elif current_iface and "status: inactive" in line:
                iface_info[current_iface] = {"status": "inactive"}
        
        # Merge status info
        for iface in interfaces:
            if iface["name"] in iface_info:
                iface["status"] = iface_info[iface["name"]]["status"]
            else:
                iface["status"] = "unknown"
    
    # Filter interfaces
    filtered = []
    for iface in interfaces:
        name = iface["name"]
        # Skip virtual interfaces
        if any(name.startswith(p) for p in SKIP_PREFIXES):
            continue
        # Keep all physical interfaces (skip already filtered by SKIP_PREFIXES)
        filtered.append(iface)

    return filtered


def capture_lldp(iface, continuous=False):
    """Capture LLDP/CDP packets using tcpdump."""
    if continuous:
        cmd = [
            "tcpdump",
            "-i", iface,
            "-s", "1500",
            "-nn",
            "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
        ]
    else:
        cmd = [
            "tcpdump",
            "-i", iface,
            "-s", "1500",
            "-nn",
            "-XX",
            "-c", "1",
            "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
        ]
    
    rc, out, err = run_cmd(cmd)
    if rc == 0:
        return {"success": True, "output": out}
    else:
        return {"success": False, "error": (err or out).strip()}


def capture_lldp_continuous(iface):
    """Run continuous LLDP/CDP capture and print results."""
    import subprocess
    
    cmd = [
        "tcpdump",
        "-i", iface,
        "-s", "1500",
        "-nn",
        "-l",  # Line-buffered output
        "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
    ]
    
    print(f"Starting continuous LLDP/CDP capture on {iface}...")
    print("Press Ctrl+C to stop")
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line:
                print(f"[CAPTURED] {line}")
                
                # Detect protocol type
                if "0x88cc" in line.lower():
                    print("[PROTOCOL] LLDP")
                elif "01:00:0c:cc:cc:cc" in line.lower():
                    print("[PROTOCOL] CDP")
                    
    except KeyboardInterrupt:
        print("\nStopping capture...")
        process.terminate()
        process.wait()
    except Exception as e:
        print(f"[ERROR] {e}")


def restart_interface(iface):
    """Restart network interface."""
    # Bring down
    rc, out, err = run_cmd(["ifconfig", iface, "down"])
    if rc != 0:
        return {"success": False, "error": f"Failed to bring down: {err}"}
    
    time.sleep(1)
    
    # Bring up
    rc, out, err = run_cmd(["ifconfig", iface, "up"])
    if rc != 0:
        return {"success": False, "error": f"Failed to bring up: {err}"}
    
    return {"success": True}


def set_mac(iface, mac):
    """Set MAC address. Try while UP first, fall back to down/up."""
    # Try ether UP first (works on USB adapters)
    import time
    rc, out, err = run_cmd(["ifconfig", iface, "ether", mac])
    if rc == 0:
        return {"success": True, "mac": mac}
    # Try lladdr UP
    rc, out, err = run_cmd(["ifconfig", iface, "lladdr", mac])
    if rc == 0:
        return {"success": True, "mac": mac}
    # Fall back to down->ether->up
    rc, out, err = run_cmd(["ifconfig", iface, "down"])
    if rc != 0:
        return {"success": False, "error": f"Failed to bring down: {err}"}
    time.sleep(0.3)
    rc, out, err = run_cmd(["ifconfig", iface, "ether", mac])
    if rc != 0:
        run_cmd(["ifconfig", iface, "up"])
        return {"success": False, "error": f"Failed to set MAC: {err}"}
    time.sleep(0.5)
    rc, out, err = run_cmd(["ifconfig", iface, "up"])
    if rc != 0:
        return {"success": False, "error": f"Failed to bring up: {err}"}
    return {"success": True, "mac": mac}


def set_dhcp(iface):
    """Enable DHCP."""
    service = _device_to_service(iface)
    rc, out, err = run_cmd(["networksetup", "-setdhcp", service])
    if rc == 0:
        return {"success": True, "service": service}
    else:
        return {"success": False, "error": (err or out).strip()}


def set_static(iface, ip, mask, gateway="", dns=None):
    """Set static IP on macOS using networksetup -setmanual."""
    service = _device_to_service(iface)
    # gateway might be "--dns" if no real gateway was given
    if gateway and not gateway.startswith("--"):
        rc, out, err = run_cmd(["networksetup", "-setmanual", service, ip, mask, gateway])
    else:
        rc, out, err = run_cmd(["networksetup", "-setmanual", service, ip, mask])
    if rc != 0:
        return {"success": False, "error": f"Failed to set IP: {err or out}"}
    # Set DNS servers if provided
    if dns:
        dns_list = [d for d in dns if d]
        if dns_list:
            run_cmd(["networksetup", "-setdnsservers", service] + dns_list)
    return {"success": True, "ip": ip, "mask": mask, "gateway": gateway, "dns": dns}


def clear_ip(iface):
    """Clear IP address on macOS using ifconfig inet delete."""
    rc, out, err = run_cmd(["ifconfig", iface, "inet", "delete"])
    if rc != 0:
        return {"success": False, "error": f"Failed to clear IP: {err or out}"}
    return {"success": True}


def main():
    parser = argparse.ArgumentParser(description="LLDP Helper for macOS")
    parser.add_argument("--json-out", help="Output JSON to file instead of stdout")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # List interfaces
    subparsers.add_parser("list-ifaces", help="List network interfaces")
    
    # Capture LLDP
    capture_parser = subparsers.add_parser("capture", help="Capture LLDP packet")
    capture_parser.add_argument("iface", nargs="?", default="", help="Interface name")
    capture_parser.add_argument("--wait-for-link", action="store_true", help="Wait for link")
    capture_parser.add_argument("--thorough", action="store_true", help="Thorough scan")
    
    # Restart adapter
    restart_parser = subparsers.add_parser("restart", help="Restart interface")
    restart_parser.add_argument("iface", help="Interface name")
    
    # Set MAC
    mac_parser = subparsers.add_parser("set-mac", help="Set MAC address")
    mac_parser.add_argument("iface", help="Interface name")
    mac_parser.add_argument("mac", help="MAC address")
    
    # Set DHCP
    dhcp_parser = subparsers.add_parser("set-dhcp", help="Enable DHCP")
    dhcp_parser.add_argument("iface", help="Interface name")
    
    # Set static IP
    static_parser = subparsers.add_parser("set-static", help="Set static IP")
    static_parser.add_argument("iface", help="Interface name")
    static_parser.add_argument("ip", help="IP address")
    static_parser.add_argument("mask", help="Subnet mask")
    static_parser.add_argument("gateway", nargs="?", default="", help="Gateway")
    static_parser.add_argument("--dns", nargs="+", default=[], help="DNS server(s)")
    
    # Clear IP
    clear_parser = subparsers.add_parser("clear-ip", help="Clear IP address on interface")
    clear_parser.add_argument("iface", help="Interface name")
    
    args = parser.parse_args()
    
    if not args.command:
        print(json.dumps({"error": "No command specified"}))
        sys.exit(1)
    
    def output(result):
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                f.write(json.dumps(result))
        else:
            print(json.dumps(result))
    
    try:
        if args.command == "list-ifaces":
            result = list_interfaces()
            output(result)
        
        elif args.command == "capture":
            result = capture_lldp(args.iface, continuous=False)
            output(result)
        
        elif args.command == "restart":
            result = restart_interface(args.iface)
            output(result)
        
        elif args.command == "set-mac":
            result = set_mac(args.iface, args.mac)
            output(result)
        
        elif args.command == "set-dhcp":
            result = set_dhcp(args.iface)
            output(result)
        
        elif args.command == "clear-ip":
            result = clear_ip(args.iface)
            output(result)
        
        elif args.command == "set-static":
            result = set_static(args.iface, args.ip, args.mask, args.gateway, dns=args.dns)
            output(result)
        
        else:
            output({"error": f"Unknown command: {args.command}"})
            sys.exit(1)
    
    except Exception as e:
        output({"error": str(e)})
        sys.exit(1)


if __name__ == "__main__":
    main()
