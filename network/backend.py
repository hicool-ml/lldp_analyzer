#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Backend Abstraction Layer.

Defines the interface for network operations across platforms.
All platform-specific implementations should inherit from NetworkBackend.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    name: str
    mac_address: str
    status: str  # "active", "inactive", "unknown"
    port_type: str = "ethernet"
    guid: str = ""  # Windows-only: interface GUID
    ipv4_address: str = ""
    ipv4_mask: str = ""
    ipv6_addresses: List[str] = None
    
    def __post_init__(self):
        if self.ipv6_addresses is None:
            self.ipv6_addresses = []


@dataclass
class LLDPPacket:
    """Represents an LLDP packet."""
    source_mac: str
    destination_mac: str
    chassis_id: str
    port_id: str
    system_name: str = ""
    system_description: str = ""
    port_description: str = ""
    ttl: int = 0
    capabilities: Dict[str, bool] = None
    management_address: str = ""
    organization_specific: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = {}
        if self.organization_specific is None:
            self.organization_specific = []


class NetworkBackend(ABC):
    """Abstract base class for network backends."""
    
    @abstractmethod
    def list_interfaces(self) -> List[NetworkInterface]:
        """List all network interfaces.
        
        Returns:
            List of NetworkInterface objects.
        """
        pass
    
    @abstractmethod
    def get_interface_info(self, interface_id: str) -> Optional[NetworkInterface]:
        """Get detailed information about a specific interface.
        
        Args:
            interface_id: Interface name or GUID
            
        Returns:
            NetworkInterface object or None if not found.
        """
        pass
    
    @abstractmethod
    def capture_lldp(self, interface_name: str, timeout: int = 10) -> Optional[LLDPPacket]:
        """Capture an LLDP packet from the specified interface.
        
        Args:
            interface_name: The interface to capture on
            timeout: Maximum wait time in seconds
            
        Returns:
            LLDPPacket object or None if no packet captured.
        """
        pass
    
    @abstractmethod
    def restart_interface(self, interface_id: str) -> bool:
        """Restart a network interface.
        
        Args:
            interface_id: Interface name or GUID
            
        Returns:
            True if successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def set_mac_address(self, interface_id: str, mac_address: str) -> bool:
        """Set the MAC address of an interface.
        
        Args:
            interface_id: Interface name or GUID
            mac_address: The new MAC address
            
        Returns:
            True if successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def restore_mac(self, interface_id: str) -> bool:
        """Restore the original MAC address of an interface.
        
        Args:
            interface_id: Interface name or GUID
            
        Returns:
            True if successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def set_static_ip(self, interface_id: str, ip_address: str, subnet_mask: str, 
                      gateway: str = "", dns_servers: List[str] = None) -> bool:
        """Set static IP configuration.
        
        Args:
            interface_id: Interface name or GUID
            ip_address: The static IP address
            subnet_mask: The subnet mask
            gateway: Optional default gateway
            dns_servers: Optional list of DNS servers
            
        Returns:
            True if successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def set_dhcp(self, interface_id: str) -> bool:
        """Enable DHCP on an interface.
        
        Args:
            interface_id: Interface name or GUID
            
        Returns:
            True if successful, False otherwise.
        """
        pass
    
    @property
    def last_error(self) -> str:
        """Get the last error message."""
        return getattr(self, '_last_error', "")
    
    @last_error.setter
    def last_error(self, value: str):
        """Set the last error message."""
        self._last_error = value