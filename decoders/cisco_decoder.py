#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco LLDP/CDP decoder

Handles both:
- Cisco proprietary OUI 00:00:0C
- Shared OUI 00:12:BB (used by SG series and other Cisco SMB switches)
"""

import struct
from typing import Dict, Tuple, Any, List, Optional


class CiscoDecoder:
    """Cisco LLDP/CDP packet decoder."""

    # ------------------------------------------------------------------
    # TLV 127 entry point
    # ------------------------------------------------------------------

    @staticmethod
    def decode_tlv127(
        subtype: int, value: bytes, oui: str = "00:00:0C"
    ) -> Tuple[str, Dict[str, Any]]:
        """Unified Cisco TLV 127 decoder.

        Routes to the correct handler based on OUI so that subtype
        numbers are interpreted in the right namespace.
        """
        oui = oui.upper()
        if oui == "00:12:BB":
            return CiscoDecoder._decode_shared_oui(subtype, value)
        return CiscoDecoder._decode_cisco_oui(subtype, value)

    # ------------------------------------------------------------------
    # OUI 00:00:0C - classic Cisco proprietary extensions
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_cisco_oui(
        subtype: int, value: bytes
    ) -> Tuple[str, Dict[str, Any]]:
        name = f"Cisco Private Extension (Subtype {subtype})"
        parsed_data: Dict[str, Any] = {}

        try:
            if subtype == 1:
                decoded_text = value.decode("ascii", errors="replace").strip("\x00").strip()
                parsed_data["system_name"] = decoded_text
                name = "Cisco proprietary - System Name"

            elif subtype == 2:
                decoded_text = value.decode("ascii", errors="replace").strip("\x00").strip()
                parsed_data["port_description"] = decoded_text
                name = "Cisco proprietary - Port Description"

            elif subtype == 3:
                if len(value) >= 4:
                    capabilities = int.from_bytes(value[0:2], "big")
                    enabled = int.from_bytes(value[2:4], "big")
                    parsed_data["capabilities"] = f"0x{capabilities:04x}"
                    parsed_data["enabled"] = f"0x{enabled:04x}"
                    name = "Cisco proprietary - System Capabilities"

            elif subtype == 4:
                if len(value) >= 2:
                    addr_subtype = value[0]
                    if addr_subtype == 1 and len(value) >= 6:
                        ip_addr = ".".join(str(b) for b in value[2:6])
                        parsed_data["management_ip"] = ip_addr
                        name = "Cisco proprietary - Management Address"

            else:
                parsed_data["raw_hex"] = value.hex()

        except Exception as exc:
            parsed_data["parse_error"] = str(exc)
            parsed_data["raw_hex"] = value.hex()

        return name, parsed_data

    # ------------------------------------------------------------------
    # OUI 00:12:BB - shared LLDP extension (SG-series SMB switches)
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_shared_oui(
        subtype: int, value: bytes
    ) -> Tuple[str, Dict[str, Any]]:
        """Decode OUI 00:12:BB subtypes.

        The subtype layout is shared across Cisco SG-series, Ruijie,
        H3C, and Huawei.  We follow the same field-name conventions so
        that ``vendor_dispatcher._merge_vendor_fields`` can pick them
        up automatically.
        """
        name = f"Cisco Shared Extension (Subtype {subtype})"
        parsed_data: Dict[str, Any] = {}

        # Guard: strip OUI+subtype header if it was not removed upstream
        if len(value) >= 4 and value[0:3] == b"\x00\x12\xbb":
            payload = value[4:]
        else:
            payload = value

        try:
            # ----- string-type subtypes -----
            if subtype in (5, 6, 7, 8, 9, 10):
                decoded_text = (
                    payload.decode("ascii", errors="replace")
                    .strip("\x00")
                    .strip()
                )
                decoded_text = "".join(c for c in decoded_text if c.isprintable())

                if subtype == 5:
                    name = "Cisco proprietary - BootROM Version"
                    parsed_data["bootrom_version"] = decoded_text
                elif subtype == 6:
                    name = "Cisco proprietary - Main Software Version"
                    parsed_data["main_software_version"] = decoded_text
                elif subtype == 7:
                    name = "Cisco proprietary - Backup Software Version"
                    parsed_data["backup_rgos_version"] = decoded_text
                elif subtype == 8:
                    name = "Cisco proprietary - Serial Number"
                    parsed_data["serial_number"] = decoded_text
                elif subtype == 9:
                    name = "Cisco proprietary - Manufacturer"
                    parsed_data["manufacturer"] = decoded_text
                elif subtype == 10:
                    name = "Cisco proprietary - Device Model"
                    parsed_data["model_name"] = decoded_text

            # ----- binary subtypes -----
            elif subtype == 1:
                name = "Cisco proprietary - Hardware Feature ID"
                parsed_data["hardware_feature_id"] = f"0x{payload.hex()}"
                parsed_data["hardware_feature_status"] = "unresolved"

            elif subtype == 2:
                name = "Cisco proprietary - Port Speed/Duplex"
                if len(payload) >= 2:
                    bitmap = (
                        int.from_bytes(payload[:4], "big")
                        if len(payload) >= 4
                        else int.from_bytes(payload[:2], "big")
                    )
                    parsed_data["port_speed_bitmap"] = f"0x{bitmap:08x}"
                    if bitmap & 0x00800000:
                        parsed_data["speed"] = "1000M"
                        parsed_data["duplex"] = "Full"
                    elif bitmap & 0x00400000:
                        parsed_data["speed"] = "100M"
                    elif bitmap & 0x00200000:
                        parsed_data["speed"] = "10M"
                else:
                    parsed_data["raw_hex"] = payload.hex()

            elif subtype == 4:
                name = "Cisco proprietary - Internal Interface Index"
                if payload:
                    internal_index = int.from_bytes(payload, "big")
                    parsed_data["internal_index"] = internal_index
                    parsed_data["internal_index_hex"] = f"0x{internal_index:x}"
                    parsed_data["ifindex_note"] = "SNMP ifIndex for the local port"
                else:
                    parsed_data["raw_hex"] = payload.hex()

            elif subtype == 11:
                name = "Cisco proprietary - Reserved Status"
                try:
                    decoded_text = (
                        payload.decode("ascii", errors="strict")
                        .strip("\x00")
                        .strip()
                    )
                    if decoded_text and all(c.isprintable() for c in decoded_text):
                        parsed_data["reserved_status"] = decoded_text
                    else:
                        parsed_data["reserved_status"] = f"0x{payload.hex()}"
                        parsed_data["reserved_meaning"] = (
                            "No special status / default checksum"
                        )
                except (UnicodeDecodeError, ValueError):
                    parsed_data["reserved_status"] = f"0x{payload.hex()}"
                    parsed_data["reserved_meaning"] = (
                        "No special status / default checksum"
                    )

            else:
                parsed_data["raw_hex"] = payload.hex()

        except Exception as exc:
            parsed_data["parse_error"] = str(exc)
            parsed_data["raw_hex"] = payload.hex()

        return name, parsed_data

    # ------------------------------------------------------------------
    # Standalone CDP parser (legacy, kept for backward compat)
    # ------------------------------------------------------------------

    @staticmethod
    def analyze_cdp_packet(packet: bytes) -> Optional[Dict[str, Any]]:
        """Analyze a complete CDP packet (with Ethernet header)."""
        try:
            if len(packet) < 22:
                raise ValueError(
                    f"Packet too short for CDP: {len(packet)} bytes (minimum 22 bytes)"
                )

            snap_header = packet[14:22]
            if snap_header == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
                cdp_payload = packet[22:]
            else:
                cdp_payload = packet[14:]
                if cdp_payload.startswith(b"\xaa\xaa\x03"):
                    cdp_payload = cdp_payload[8:]
                else:
                    raise ValueError(
                        f"Invalid CDP packet format, SNAP: {snap_header.hex()}"
                    )

            if len(cdp_payload) < 8:
                raise ValueError("CDP payload too short")

            version = cdp_payload[0]
            ttl = cdp_payload[1]
            checksum = struct.unpack(">H", cdp_payload[2:4])[0]
            tlvs = CiscoDecoder._parse_cdp_tlvs(cdp_payload[4:])
            fields = CiscoDecoder._extract_cdp_fields(tlvs)

            return {
                "protocol": "CDP",
                "version": version,
                "ttl": ttl,
                "checksum": checksum,
                "tlvs": tlvs,
                "fields": fields,
                "tlv_count": len(tlvs),
            }

        except Exception as exc:
            return {"protocol": "CDP", "error": str(exc), "parse_failed": True}

    @staticmethod
    def _parse_cdp_tlvs(cdp_data: bytes) -> List[Dict]:
        tlvs = []
        offset = 0
        while offset + 4 <= len(cdp_data):
            tlv_type = struct.unpack(">H", cdp_data[offset : offset + 2])[0]
            tlv_length = struct.unpack(">H", cdp_data[offset + 2 : offset + 4])[0]
            if tlv_length < 4:
                break
            if offset + tlv_length > len(cdp_data):
                break
            value_start = offset + 4
            value_end = offset + tlv_length
            tlv_value = cdp_data[value_start:value_end]
            tlv_name = CiscoDecoder._get_cdp_tlv_name(tlv_type)
            tlvs.append(
                {
                    "type": tlv_type,
                    "type_name": tlv_name,
                    "length": tlv_length,
                    "value": tlv_value,
                    "raw_hex": tlv_value.hex(),
                    "offset": offset,
                }
            )
            if tlv_type == 0:
                break
            offset = value_end
        return tlvs

    @staticmethod
    def _get_cdp_tlv_name(tlv_type: int) -> str:
        tlv_names = {
            0x0000: "End of CDP",
            0x0001: "Device ID",
            0x0002: "Address",
            0x0003: "Port ID",
            0x0004: "Capabilities",
            0x0005: "Software Version",
            0x0006: "Platform",
            0x0007: "IP Prefix",
            0x0008: "Protocol Hello",
            0x0009: "VTP Management Domain",
            0x000A: "Native VLAN",
            0x000B: "Duplex",
            0x000C: "CDP Trust",
            0x000D: "Untrusted Port CoS",
            0x000E: "Management Address",
            0x0011: "MTU",
            0x0012: "Extended Trust",
            0x0013: "Untrusted Port CoS Extended",
            0x0014: "Availability-Management",
            0x0016: "SVID / VLAN ID",
            0x0017: "SVID / VLAN Name",
            0x001A: "Power Available",
            0x001B: "Power Request",
            0x001C: "Power Available Plus",
            0x001D: "Power Request Plus",
        }
        return tlv_names.get(tlv_type, f"Unknown (0x{tlv_type:04x})")

    @staticmethod
    def _extract_cdp_fields(tlvs: List[Dict]) -> Dict[str, Any]:
        fields: Dict[str, Any] = {
            "device_id": None,
            "addresses": [],
            "port_id": None,
            "capabilities": None,
            "software_version": None,
            "platform": None,
            "native_vlan": None,
            "duplex": None,
            "mtu": None,
        }
        for tlv in tlvs:
            tlv_type = tlv["type"]
            tlv_value = tlv["value"]
            try:
                if tlv_type == 0x0001:
                    fields["device_id"] = (
                        tlv_value.decode("ascii", errors="replace").strip("\x00")
                    )
                elif tlv_type == 0x0002:
                    fields["addresses"] = CiscoDecoder._parse_addresses(tlv_value)
                elif tlv_type == 0x0003:
                    fields["port_id"] = (
                        tlv_value.decode("ascii", errors="replace").strip("\x00")
                    )
                elif tlv_type == 0x0004:
                    if len(tlv_value) >= 4:
                        capabilities = int.from_bytes(tlv_value[0:4], "big")
                        fields["capabilities"] = f"0x{capabilities:08x}"
                elif tlv_type == 0x0005:
                    fields["software_version"] = (
                        tlv_value.decode("ascii", errors="replace").strip("\x00")
                    )
                elif tlv_type == 0x0006:
                    fields["platform"] = (
                        tlv_value.decode("ascii", errors="replace").strip("\x00")
                    )
                elif tlv_type == 0x000A:
                    if len(tlv_value) >= 2:
                        fields["native_vlan"] = int.from_bytes(
                            tlv_value[0:2], "big"
                        )
                elif tlv_type == 0x000B:
                    if len(tlv_value) >= 1:
                        fields["duplex"] = "Full" if tlv_value[0] else "Half"
                elif tlv_type == 0x0011:
                    if len(tlv_value) >= 4:
                        fields["mtu"] = int.from_bytes(tlv_value[0:4], "big")
            except Exception:
                continue
        return fields

    @staticmethod
    def _parse_addresses(address_bytes: bytes) -> List[str]:
        addresses: List[str] = []
        offset = 0
        try:
            if len(address_bytes) >= 4:
                num_addresses = struct.unpack(">I", address_bytes[0:4])[0]
                offset = 4
                for _ in range(num_addresses):
                    if offset + 3 > len(address_bytes):
                        break
                    addr_type = address_bytes[offset]
                    addr_length = address_bytes[offset + 1]
                    addr_length = (addr_length << 8) | address_bytes[offset + 2]
                    offset += 3
                    if offset + addr_length > len(address_bytes):
                        break
                    addr_data = address_bytes[offset : offset + addr_length]
                    if addr_type == 1:
                        if len(addr_data) >= 5:
                            ip_bytes = addr_data[1:5]
                            ip_addr = ".".join(str(b) for b in ip_bytes)
                            addresses.append(ip_addr)
                    offset += addr_length
        except Exception:
            pass
        return addresses

    @staticmethod
    def matches_fingerprint(packet_bytes: bytes) -> bool:
        try:
            cisco_keywords = [
                b"Cisco", b"CISCO", b"IOS", b"NX-OS",
                b"Catalyst", b"WS-C", b"C2960", b"C3850",
                b"SG300", b"SG350", b"SG500", b"SG550",
            ]
            return any(keyword in packet_bytes for keyword in cisco_keywords)
        except Exception:
            return False
