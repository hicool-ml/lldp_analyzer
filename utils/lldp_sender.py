#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLDP Sender - Triggers LLDP/CDP packet transmission by restarting interface.

When an interface is restarted (ifconfig down/up), the network stack
automatically sends LLDP (IEEE 802.1AB) and CDP (Cisco Discovery Protocol) packets.
"""

import logging
import subprocess
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)


def get_helper_path() -> str:
    """Get path to lldp_helper.py."""
    import os
    # Try to find lldp_helper.py relative to this file
    utils_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(utils_dir)
    helper_path = os.path.join(root_dir, "lldp_helper.py")
    if os.path.isfile(helper_path):
        return helper_path
    # Fallback: look in current directory
    if os.path.isfile("lldp_helper.py"):
        return "lldp_helper.py"
    raise FileNotFoundError("lldp_helper.py not found")


def restart_interface_send_lldp(iface_name: str) -> tuple:
    """
    Restart interface to trigger immediate LLDP/CDP packet transmission.

    Args:
        iface_name: Network interface name (e.g., "en0")

    Returns:
        (success, message)
    """
    try:
        helper = get_helper_path()
        cmd = [sys.executable, helper, "restart", iface_name]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            logger.info(f"Interface {iface_name} restarted, LLDP should be sent")
            return (True, f"Interface {iface_name} restarted successfully")
        else:
            error = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Failed to restart {iface_name}: {error}")
            return (False, error)

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout restarting {iface_name}")
        return (False, "Command timed out")
    except Exception as e:
        logger.error(f"Error restarting {iface_name}: {e}")
        return (False, str(e))


def restart_interface_direct(iface_name: str) -> tuple:
    """
    Directly restart interface using ifconfig (no helper).

    Args:
        iface_name: Network interface name

    Returns:
        (success, message)
    """
    try:
        # Bring down
        rc1 = subprocess.run(
            ["ifconfig", iface_name, "down"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if rc1.returncode != 0:
            return (False, f"Failed to bring down: {rc1.stderr}")

        time.sleep(1)

        # Bring up
        rc2 = subprocess.run(
            ["ifconfig", iface_name, "up"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if rc2.returncode != 0:
            return (False, f"Failed to bring up: {rc2.stderr}")

        logger.info(f"Interface {iface_name} restarted directly")
        return (True, f"Interface {iface_name} restarted")

    except subprocess.TimeoutExpired:
        return (False, "Command timed out")
    except Exception as e:
        return (False, str(e))


def send_lldp_on_interface(iface_name: str, use_helper: bool = True) -> tuple:
    """
    Send LLDP packet by restarting the interface.

    Args:
        iface_name: Network interface name
        use_helper: Use lldp_helper.py if True, direct ifconfig if False

    Returns:
        (success, message)
    """
    if use_helper:
        return restart_interface_send_lldp(iface_name)
    else:
        return restart_interface_direct(iface_name)


if __name__ == "__main__":
    # Test: send LLDP on specified interface
    import argparse
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Send LLDP packet by restarting interface")
    parser.add_argument("iface", help="Interface name (e.g., en0)")
    parser.add_argument("--no-helper", action="store_true", help="Use direct ifconfig instead of helper")
    args = parser.parse_args()

    success, msg = send_lldp_on_interface(args.iface, use_helper=not args.no_helper)
    print(msg)
    sys.exit(0 if success else 1)