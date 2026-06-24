#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Link Monitor - Background thread that monitors network interface status.

When an interface comes up (link up event), it triggers the LLDP sender
to immediately send LLDP/CDP packets by restarting the interface.

Architecture:
    link_monitor (thread)
          ↓
    detect en0 active
          ↓
    trigger event
          ↓
    lldp_sender.restart(iface)
          ↓
    send LLDP immediately
"""

import logging
import subprocess
import threading
import time
from typing import Callable, Optional, Set

logger = logging.getLogger(__name__)

# Physical Ethernet prefixes to skip (virtual interfaces)
SKIP_PREFIXES = ["lo", "utun", "awdl", "llw", "ap", "gif", "stf", "anpi", "bridge", "vmenet", "bridge"]


def get_active_ethernet_interfaces() -> Set[str]:
    """
    Get set of currently active physical Ethernet interface names.

    Returns:
        Set of interface names that are UP and are physical Ethernet adapters.
    """
    active = set()

    try:
        # Get all interfaces with their status
        out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
        lines = out.splitlines()

        current_iface = None
        iface_status = {}

        for line in lines:
            # Interface definition line: "en0: flags=..."
            # Not a tabbed line, contains ": flags="
            if line and not line.startswith("\t") and ": flags=" in line:
                current_iface = line.split(":")[0].strip()
                iface_status[current_iface] = "inactive"
            # Status line: "        status: active"
            elif current_iface and "\tstatus: active" in line:
                iface_status[current_iface] = "active"

    except Exception as e:
        logger.error(f"Error getting interface status: {e}")
        return set()

    # Get port type mapping from networksetup
    port_to_device = {}
    try:
        out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True, timeout=5)
        current_port = None

        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split("Hardware Port:", 1)[1].strip()
            elif line.startswith("Device:"):
                device = line.split("Device:", 1)[1].strip()
                if current_port:
                    port_to_device[current_port] = device
                    current_port = None

    except Exception as e:
        logger.warning(f"Error getting hardware ports: {e}")

    # Filter: must be active, not virtual, and is Ethernet
    for iface_name, status in iface_status.items():
        if status != "active":
            continue
        if any(iface_name.startswith(p) for p in SKIP_PREFIXES):
            continue

        # Check if it's an Ethernet port type
        is_ethernet = False
        for port, device in port_to_device.items():
            if device == iface_name and "ethernet" in port.lower():
                is_ethernet = True
                break

        if is_ethernet:
            active.add(iface_name)
            logger.debug(f"Found active Ethernet: {iface_name}")

    return active


class LinkMonitor:
    """
    Background monitor for network interface link status changes.

    Detects when physical Ethernet interfaces come up and triggers
    LLDP packet transmission by restarting the interface.

    Usage:
        def on_link_up(iface_name):
            print(f"Link up on {iface_name}")

        monitor = LinkMonitor(on_link_up=on_link_up)
        monitor.start()

        # ... later when done ...
        monitor.stop()
    """

    def __init__(
        self,
        on_link_up: Optional[Callable[[str], None]] = None,
        poll_interval: float = 1.0,
        target_interface: Optional[str] = None
    ):
        """
        Initialize link monitor.

        Args:
            on_link_up: Callback function when an interface comes up.
                        Called with interface name as argument.
            poll_interval: Seconds between status checks (default: 1.0)
            target_interface: If set, only monitor this specific interface.
                             If None, monitor all physical Ethernet interfaces.
        """
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._poll_interval = poll_interval
        self._on_link_up = on_link_up
        self._target_interface = target_interface
        self._last_active: Set[str] = set()
        self._started = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._started and self._thread is not None and self._thread.is_alive()

    def start(self):
        """Start the link monitor thread."""
        with self._lock:
            if self._started and self.is_running:
                logger.warning("Link monitor already running")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="LinkMonitor")
            self._thread.start()
            self._started = True
            logger.info("Link monitor started")

    def stop(self):
        """Stop the link monitor thread."""
        with self._lock:
            if not self._started:
                return

            self._stop_event.set()
            if self._thread is not None:
                self._thread.join(timeout=5)
                self._thread = None
            self._started = False
            logger.info("Link monitor stopped")

    def _run(self):
        """Main monitoring loop - runs in background thread."""
        # Initial scan
        try:
            self._last_active = get_active_ethernet_interfaces()
            logger.info(f"Initial active interfaces: {self._last_active}")
        except Exception as e:
            logger.error(f"Initial scan failed: {e}")
            self._last_active = set()

        while not self._stop_event.is_set():
            time.sleep(self._poll_interval)

            try:
                current_active = get_active_ethernet_interfaces()
            except Exception as e:
                logger.error(f"Error scanning interfaces: {e}")
                continue

            # Find newly up interfaces
            new_up = current_active - self._last_active

            for iface in new_up:
                if self._target_interface is None or iface == self._target_interface:
                    logger.info(f"Link up detected on {iface}")
                    if self._on_link_up:
                        try:
                            self._on_link_up(iface)
                        except Exception as e:
                            logger.error(f"Error in on_link_up callback: {e}")

            # Update last known state
            self._last_active = current_active


def create_link_monitor_for_lldp(
    target_interface: str = "en0",
    poll_interval: float = 1.0
) -> LinkMonitor:
    """
    Create a link monitor that triggers LLDP sending when interface comes up.

    Args:
        target_interface: Interface to monitor (default: "en0")
        poll_interval: Seconds between checks (default: 1.0)

    Returns:
        Configured LinkMonitor instance
    """
    from utils.lldp_sender import send_lldp_on_interface

    def on_link_up(iface: str):
        logger.info(f"Triggering LLDP send on {iface}")
        success, msg = send_lldp_on_interface(iface, use_helper=True)
        if success:
            logger.info(f"LLDP sent successfully on {iface}")
        else:
            logger.warning(f"Failed to send LLDP on {iface}: {msg}")

    return LinkMonitor(
        on_link_up=on_link_up,
        poll_interval=poll_interval,
        target_interface=target_interface
    )


if __name__ == "__main__":
    # Test: monitor and print link status changes
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    target = sys.argv[1] if len(sys.argv) > 1 else "en0"

    print(f"Monitoring link status for {target}...")
    print("Press Ctrl+C to stop")

    def on_link_up(iface: str):
        print(f"\n>>> Link UP: {iface}")

    monitor = LinkMonitor(
        on_link_up=on_link_up,
        poll_interval=1.0,
        target_interface=target
    )
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()