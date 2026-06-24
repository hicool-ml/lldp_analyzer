#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-platform network adapter data model and abstract backend.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from abc import ABC, abstractmethod


@dataclass
class NetworkInterface:
    """Full information about a single network adapter."""
    name: str = ""                     # Friendly name (e.g. "以太网")
    description: str = ""              # Driver description
    mac_address: str = ""              # Current MAC (XX:XX:XX:XX:XX:XX)
    original_mac: str = ""             # Hardware MAC (from registry if spoofed)
    is_mac_modified: bool = False
    ipv4_address: str = ""
    ipv4_mask: str = ""
    ipv4_gateway: str = ""
    ipv6_addresses: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    dhcp_enabled: bool = False
    dhcp_server: str = ""              # DHCP server IP
    is_connected: bool = False
    link_speed: str = ""               # e.g. "1 Gbps"
    mtu: int = 0
    guid: str = ""                     # Windows GUID
    pnp_instance_id: str = ""          # For cfgmgr32 ops
    scapy_name: str = ""               # \Device\NPF_{GUID}


class NetworkAdapterBackend(ABC):
    """Abstract interface for platform-specific adapter operations."""

    @abstractmethod
    def get_interfaces(self) -> List[NetworkInterface]:
        ...

    @abstractmethod
    def get_interface_info(self, name_or_guid: str) -> Optional[NetworkInterface]:
        ...

    @abstractmethod
    def restart_interface(self, name_or_guid: str) -> bool:
        ...

    @abstractmethod
    def set_mac_address(self, name_or_guid: str, mac: str) -> bool:
        ...

    @abstractmethod
    def restore_mac(self, name_or_guid: str) -> bool:
        ...

    @abstractmethod
    def set_static_ip(self, name_or_guid: str, ip: str, mask: str,
                      gateway: str = "", dns: List[str] = None) -> bool:
        ...

    @abstractmethod
    def set_dhcp(self, name_or_guid: str) -> bool:
        ...
