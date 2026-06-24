#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Persistent Capture Engine - Always-on LLDP/CDP capture with link monitoring.

Architecture:
    Program Start
        ↓
    Interface Monitor Thread
        ↓
    Persistent Sniffer Thread (always running)
        ↓
    Link Up Event detected
        ↓
    Parse packets immediately
        ↓
    Received LLDP/CDP
        ↓
    Update GUI / Store results

This design:
- Never misses the first LLDP packet (sniffer already running)
- Doesn't rely on link down/up manipulation
- Works across Windows/macOS/Linux
"""

import logging
import queue
import threading
import time
from typing import Any, Callable, List, Optional, Set

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Platform-specific link status detection
# ------------------------------------------------------------------

def get_link_status_windows(iface_name: str) -> bool:
    """
    Get real link status on Windows using PowerShell Get-NetAdapter.
    Returns True only if the adapter status is 'Up' (not just isup flag).
    """
    try:
        import subprocess
        result = subprocess.check_output(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"Get-NetAdapter -Name '{iface_name}' | Select-Object -ExpandProperty Status"
            ],
            text=True,
            timeout=5,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        status = result.strip().lower()
        return status == "up"
    except Exception as e:
        logger.debug(f"Get-NetAdapter failed for {iface_name}: {e}")
        return False


def get_link_status_macos(iface_name: str) -> bool:
    """
    Get link status on macOS using ifconfig.
    Checks for 'status: active' in ifconfig output.
    """
    try:
        import subprocess
        result = subprocess.check_output(["ifconfig", iface_name], text=True, timeout=5)
        return "status: active" in result
    except Exception:
        return False


def get_link_status_posix(iface_name: str) -> bool:
    """
    Get link status on Linux/POSIX using /sys/class/net/.
    """
    try:
        with open(f"/sys/class/net/{iface_name}/operstate", "r") as f:
            state = f.read().strip().lower()
            return state in ("up", "unknown")
    except Exception:
        return False


def get_link_status(iface_name: str) -> bool:
    """Get link status for the current platform."""
    import platform
    system = platform.system()
    if system == "Windows":
        return get_link_status_windows(iface_name)
    elif system == "Darwin":
        return get_link_status_macos(iface_name)
    else:
        return get_link_status_posix(iface_name)


# ------------------------------------------------------------------
# Platform-specific all interfaces status
# ------------------------------------------------------------------

def get_all_interfaces_status_windows() -> dict:
    """Get status of all network interfaces on Windows."""
    import subprocess
    result = {}
    try:
        out = subprocess.check_output(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapter | Select-Object Name, Status | ConvertTo-Json -Compress"
            ],
            text=True,
            timeout=10,
            creationflags=0x08000000
        )
        import json
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        for item in data:
            name = item.get("Name", "")
            status = item.get("Status", "").lower()
            result[name] = status == "up"
    except Exception as e:
        logger.error(f"Failed to get Windows interface status: {e}")
    return result


def get_all_interfaces_status_macos() -> dict:
    """Get status of all network interfaces on macOS."""
    import subprocess
    result = {}
    try:
        out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
        current_iface = None
        for line in out.splitlines():
            line_stripped = line.strip()
            if line_stripped and not line_stripped.startswith("\t") and ": flags=" in line_stripped:
                current_iface = line_stripped.split(":")[0].strip()
                result[current_iface] = False
            elif current_iface and "status: active" in line:
                result[current_iface] = True
    except Exception as e:
        logger.error(f"Failed to get macOS interface status: {e}")
    return result


def get_all_interfaces_status_posix() -> dict:
    """Get status of all network interfaces on Linux."""
    import subprocess
    result = {}
    try:
        for iface in subprocess.check_output(["ls", "/sys/class/net"], text=True).split():
            try:
                with open(f"/sys/class/net/{iface}/operstate", "r") as f:
                    state = f.read().strip().lower()
                    result[iface] = state in ("up", "unknown")
            except (FileNotFoundError, PermissionError):
                result[iface] = False
    except Exception as e:
        logger.error(f"Failed to get POSIX interface status: {e}")
    return result


def get_all_interfaces_status() -> dict:
    """Get status of all interfaces for the current platform."""
    import platform
    system = platform.system()
    if system == "Windows":
        return get_all_interfaces_status_windows()
    elif system == "Darwin":
        return get_all_interfaces_status_macos()
    else:
        return get_all_interfaces_status_posix()


# ------------------------------------------------------------------
# Packet capture filter
# ------------------------------------------------------------------

def build_lldp_cdp_filter(own_mac: str = "") -> str:
    """Build BPF filter for LLDP (0x88cc) and CDP (01:00:0c:cc:cc:cc)."""
    base = "(ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc)"
    if own_mac:
        return f"{base} and not ether src {own_mac}"
    return base


# ------------------------------------------------------------------
# Packet parser
# ------------------------------------------------------------------

def parse_lldp_packet(raw: bytes) -> Optional[dict]:
    """Parse raw LLDP packet bytes into a dict."""
    try:
        from utils.protocol_parser import analyze_packet
        result = analyze_packet(raw, "LLDP")
        if result.get("success"):
            return result
    except Exception as e:
        logger.debug(f"LLDP parse error: {e}")
    return None


def parse_cdp_packet(raw: bytes) -> Optional[dict]:
    """Parse raw CDP packet bytes into a dict."""
    try:
        from utils.protocol_parser import analyze_packet
        result = analyze_packet(raw, "CDP")
        if result.get("success"):
            return result
    except Exception as e:
        logger.debug(f"CDP parse error: {e}")
    return None


def detect_and_parse_packet(raw: bytes, own_mac: str = "") -> Optional[dict]:
    """Detect protocol and parse packet."""
    if len(raw) < 14:
        return None

    # Get source MAC from Ethernet header
    src_mac = ":".join(f"{b:02X}" for b in raw[6:12])

    # Skip our own packets
    if own_mac and src_mac.upper().replace("-", ":") == own_mac.upper().replace("-", ":"):
        return None

    # Check ethertype (bytes 12-14)
    # LLDP: 0x88CC in network byte order = 0xCC 0x88
    # CDP: destination is 01:00:0c:cc:cc:cc (already filtered by BPF)
    ethertype = (raw[12] << 8) | raw[13]

    if ethertype == 0x88CC:
        return parse_lldp_packet(raw)
    else:
        # Could be CDP or other
        return parse_cdp_packet(raw)


# ------------------------------------------------------------------
# Persistent Capture Engine
# ------------------------------------------------------------------

class PersistentCaptureEngine:
    """
    Always-on LLDP/CDP capture engine with link monitoring.

    This engine runs persistent sniffer threads that are ready to
    capture packets as soon as they arrive, without needing to
    restart the sniffer on link events.

    Usage:
        def on_result(packets):
            for p in packets:
                print(f"Got: {p['protocol']} from {p['fields'].get('system_name')}")

        def on_link_change(iface, is_up):
            print(f"Link {'up' if is_up else 'down'} on {iface}")

        engine = PersistentCaptureEngine(
            interface="en0",
            on_result=on_result,
            on_link_change=on_link_change
        )
        engine.start()
        # ... program runs ...
        engine.stop()
    """

    def __init__(
        self,
        interface: str,
        on_result: Optional[Callable[[List[dict]], None]] = None,
        on_link_change: Optional[Callable[[str, bool], None]] = None,
        wait_for_first_packet_timeout: float = 5.0,
    ):
        """
        Initialize the capture engine.

        Args:
            interface: Network interface name (e.g., "en0", "Ethernet")
            on_result: Callback when packets are parsed. Called with list of results.
            on_link_change: Callback when link status changes. Called with (iface, is_up).
            wait_for_first_packet_timeout: Seconds to wait after link up for first packet.
        """
        self._interface = interface
        self._on_result = on_result
        self._on_link_change = on_link_change
        self._wait_timeout = wait_for_first_packet_timeout

        self._sniffer_thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packet_queue: queue.Queue = queue.Queue()

        self._last_link_status: bool = False
        self._last_link_check: Set[str] = set()
        self._link_up_time: float = 0
        self._packets_since_link_up: int = 0

        self._scapy_name: str = ""
        self._own_mac: str = ""

    @property
    def interface(self) -> str:
        """Get the monitored interface name."""
        return self._interface

    @property
    def is_running(self) -> bool:
        """Check if engine is running."""
        return (
            self._sniffer_thread is not None
            and self._sniffer_thread.is_alive()
        )

    def start(self):
        """Start the capture engine and link monitor threads."""
        if self.is_running:
            logger.warning("Capture engine already running")
            return

        self._stop_event.clear()

        # Get scapy interface name
        self._resolve_interface()

        # Start link monitor thread
        self._monitor_thread = threading.Thread(
            target=self._link_monitor_loop,
            daemon=True,
            name="LinkMonitor"
        )
        self._monitor_thread.start()

        # Start sniffer thread
        self._sniffer_thread = threading.Thread(
            target=self._sniffer_loop,
            daemon=True,
            name="PacketSniffer"
        )
        self._sniffer_thread.start()

        logger.info(f"Capture engine started on {self._interface}")

    def stop(self):
        """Stop the capture engine."""
        if not self.is_running and self._monitor_thread is None:
            return

        self._stop_event.set()

        # Stop the sniffer
        if hasattr(self, '_sniffer') and self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=5)
            self._sniffer_thread = None

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None

        logger.info(f"Capture engine stopped")

    def _resolve_interface(self):
        """Resolve the platform-specific interface name for scapy."""
        import platform
        system = platform.system()

        if system == "Windows":
            # On Windows, interface might be the friendly name or GUID
            # Scapy uses \Device\NPF_{GUID}
            self._scapy_name = self._interface
            self._own_mac = self._get_mac_windows()
        elif system == "Darwin":
            # macOS uses interface name directly
            self._scapy_name = self._interface
            self._own_mac = self._get_mac_macos()
        else:
            self._scapy_name = self._interface
            self._own_mac = self._get_mac_posix()

        logger.info(f"Resolved interface: {self._interface} -> scapy: {self._scapy_name}, MAC: {self._own_mac}")

    def _get_mac_windows(self) -> str:
        """Get MAC address on Windows."""
        try:
            from scapy.all import get_if_hwaddr
            return get_if_hwaddr(self._scapy_name).upper()
        except Exception:
            return ""

    def _get_mac_macos(self) -> str:
        """Get MAC address on macOS."""
        try:
            import subprocess
            out = subprocess.check_output(["ifconfig", self._interface], text=True)
            for line in out.splitlines():
                if "ether" in line:
                    return line.split("ether")[1].strip().split()[0].upper()
        except Exception:
            pass
        return ""

    def _get_mac_posix(self) -> str:
        """Get MAC address on Linux/POSIX."""
        try:
            with open(f"/sys/class/net/{self._interface}/address", "r") as f:
                return f.read().strip().upper()
        except Exception:
            return ""

    def _link_monitor_loop(self):
        """Monitor link status changes in a background thread."""
        logger.info("Link monitor thread started")

        # Track only interfaces we've explicitly registered as relevant
        # Start with empty set, will be populated on first scan
        tracked_interfaces: dict[str, bool] = {}

        while not self._stop_event.is_set():
            try:
                all_status = get_all_interfaces_status()

                # Get interfaces that are physically present and relevant
                current_relevant = {
                    iface for iface in all_status
                    if self._is_relevant_interface(iface)
                }

                # Add any new relevant interfaces to tracking
                for iface in current_relevant:
                    if iface not in tracked_interfaces:
                        tracked_interfaces[iface] = all_status.get(iface, False)
                        logger.debug(f"Tracking new interface: {iface} (initial: {'UP' if tracked_interfaces[iface] else 'DOWN'})")

                # Check for link status changes only on tracked interfaces
                for iface in tracked_interfaces:
                    is_up = all_status.get(iface, False)
                    was_up = tracked_interfaces[iface]

                    if is_up and not was_up:
                        logger.info(f"Link UP on {iface}")
                        self._link_up_time = time.time()
                        self._packets_since_link_up = 0
                        if self._on_link_change:
                            try:
                                self._on_link_change(iface, True)
                            except Exception as e:
                                logger.error(f"Link change callback error: {e}")

                    elif not is_up and was_up:
                        logger.info(f"Link DOWN on {iface}")
                        if self._on_link_change:
                            try:
                                self._on_link_change(iface, False)
                            except Exception as e:
                                logger.error(f"Link change callback error: {e}")

                    tracked_interfaces[iface] = is_up

                # Remove interfaces that are no longer relevant
                to_remove = [i for i in tracked_interfaces if i not in current_relevant]
                for iface in to_remove:
                    del tracked_interfaces[iface]
                    logger.debug(f"Stopped tracking interface: {iface}")

            except Exception as e:
                logger.error(f"Link monitor error: {e}")

            time.sleep(1.0)  # Poll every second

        logger.info("Link monitor thread stopped")

    def _is_relevant_interface(self, iface_name: str) -> bool:
        """Check if interface is a physical Ethernet adapter we care about."""
        import platform
        system = platform.system()

        # Skip virtual interfaces
        skip_prefixes = ["lo", "utun", "awdl", "llw", "ap", "gif", "stf", "anpi", "bridge", "vmenet"]

        if any(iface_name.startswith(p) for p in skip_prefixes):
            return False

        if system == "Darwin":
            # On macOS, check if it's an Ethernet port
            try:
                import subprocess
                out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
                for line in out.splitlines():
                    if line.startswith("Device:"):
                        device = line.split("Device:", 1)[1].strip()
                        if device == iface_name:
                            # Find the port name for this device
                            pass
                    if f"Device: {iface_name}" in line:
                        return True
            except Exception:
                pass

        return True

    def _sniffer_loop(self):
        """Persistent sniffer loop using scapy."""
        logger.info("Sniffer thread started")

        try:
            from scapy.all import AsyncSniffer, sniff
        except ImportError as e:
            logger.error(f"Scapy import failed: {e}")
            return

        bpf_filter = build_lldp_cdp_filter(self._own_mac)

        try:
            # Create persistent sniffer
            self._sniffer = AsyncSniffer(
                iface=self._scapy_name,
                filter=bpf_filter,
                prn=self._on_packet_received,
                store=False,
            )
            self._sniffer.start()
            logger.info(f"Sniffer started on {self._scapy_name}")

            # Keep thread alive until stopped
            while not self._stop_event.is_set():
                time.sleep(0.5)

        except Exception as e:
            logger.error(f"Sniffer error: {e}")
        finally:
            if hasattr(self, '_sniffer') and self._sniffer:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
            logger.info("Sniffer thread stopped")

    def _on_packet_received(self, packet):
        """Called by scapy when a packet is received."""
        try:
            raw = bytes(packet)
            link_up_duration = time.time() - self._link_up_time

            # Parse the packet
            result = detect_and_parse_packet(raw, self._own_mac)
            if not result:
                return

            # Add metadata
            result["_link_up_duration"] = link_up_duration
            result["_timestamp"] = time.time()

            self._packets_since_link_up += 1
            logger.info(
                f"Packet received: {result.get('protocol')} "
                f"({link_up_duration:.1f}s after link up), "
                f"total since link up: {self._packets_since_link_up}"
            )

            # Queue for processing
            self._packet_queue.put(result)

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def get_pending_packets(self, timeout: float = 0.1) -> List[dict]:
        """Get all pending packets from the queue."""
        results = []
        while True:
            try:
                result = self._packet_queue.get_nowait()
                results.append(result)
            except queue.Empty:
                break
        return results

    def wait_for_first_packet(self, timeout: float = None) -> Optional[dict]:
        """
        Wait for the first LLDP/CDP packet after link up.
        Returns the first packet result or None on timeout.
        """
        if timeout is None:
            timeout = self._wait_timeout

        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                result = self._packet_queue.get(timeout=0.5)
                if result:
                    return result
            except queue.Empty:
                continue

        return None


# ------------------------------------------------------------------
# Convenience factory functions
# ------------------------------------------------------------------

def create_capture_engine(
    interface: str,
    on_result: Optional[Callable[[List[dict]], None]] = None,
    on_link_change: Optional[Callable[[str, bool], None]] = None,
) -> PersistentCaptureEngine:
    """
    Create a persistent capture engine for the specified interface.

    Args:
        interface: Network interface name
        on_result: Callback when packets are parsed
        on_link_change: Callback when link status changes

    Returns:
        Configured PersistentCaptureEngine
    """
    return PersistentCaptureEngine(
        interface=interface,
        on_result=on_result,
        on_link_change=on_link_change,
    )


# ------------------------------------------------------------------
# CLI for testing
# ------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python capture_engine.py <interface>")
        print("Example: python capture_engine.py en0")
        sys.exit(1)

    iface = sys.argv[1]

    def on_link_change(iface, is_up):
        status = "UP" if is_up else "DOWN"
        print(f"\n>>> Link {status} on {iface}")

    def on_result(packets):
        for p in packets:
            fields = p.get("fields", {})
            print(f"\n>>> Packet received: {p.get('protocol')} from {fields.get('system_name', 'unknown')}")

    print(f"Starting capture engine on {iface}...")
    print("Press Ctrl+C to stop")

    engine = create_capture_engine(
        interface=iface,
        on_result=on_result,
        on_link_change=on_link_change,
    )
    engine.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        engine.stop()