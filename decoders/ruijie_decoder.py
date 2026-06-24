#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ruijie LLDP decoder for OUI 00:12:BB private TLVs.

Ruijie shares OUI 00:12:BB with LLDP-MED.  vendor_dispatcher routes
here when the device fingerprint matches Ruijie (RGOS / Ruijie / Ruijie
Networks keywords in the System Description).
"""

from typing import Dict, Tuple, Any


class RuijieDecoder:
    """Ruijie LLDP private TLV decoder (OUI 00:12:BB, fingerprint-routed)."""

    @staticmethod
    def decode_mgmt_address(value: bytes, addr_len: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        try:
            if len(value) < 2:
                return result
            addr_subtype = value[1]
            addr_bytes = value[2 : 1 + addr_len]
            if addr_subtype == 1 and len(addr_bytes) == 4:
                result["management_ip"] = ".".join(str(b) for b in addr_bytes)
            elif addr_subtype == 2 and len(addr_bytes) == 16:
                result["management_ip"] = str(
                    __import__("ipaddress").IPv6Address(addr_bytes)
                )
            idx = 1 + addr_len
            if idx + 5 <= len(value):
                result["if_subtype"] = value[idx]
                result["if_index"] = int.from_bytes(value[idx + 1 : idx + 5], "big")
        except Exception:
            pass
        return result

    @staticmethod
    def decode_tlv127(subtype: int, value: bytes, oui: str = "00:12:BB") -> Tuple[str, Dict[str, Any]]:
        """Decode one Ruijie OUI 00:12:BB private TLV."""
        default_name = f"Ruijie Extension (Subtype {subtype})"
        parsed: Dict[str, Any] = {}

        # Strip OUI+subtype header if still present
        if len(value) >= 4 and value[0:3] == b"\x00\x12\xbb":
            payload = value[4:]
        else:
            payload = value

        try:
            # --- ASCII text subtypes ---
            if subtype == 5:
                text = _ascii_text(payload)
                parsed["bootrom_version"] = text
                return "Ruijie - BootROM Version", parsed

            if subtype == 6:
                text = _ascii_text(payload)
                parsed["main_rgos_version"] = text
                return "Ruijie - Primary RGOS Version", parsed

            if subtype == 7:
                text = _ascii_text(payload)
                parsed["backup_rgos_version"] = text
                return "Ruijie - Backup RGOS Version", parsed

            if subtype == 8:
                text = _ascii_text(payload)
                parsed["serial_number"] = text
                return "Ruijie - Serial Number", parsed

            if subtype == 9:
                text = _ascii_text(payload)
                parsed["manufacturer"] = text
                return "Ruijie - Manufacturer", parsed

            if subtype == 10:
                text = _ascii_text(payload)
                parsed["model_name"] = text
                return "Ruijie - Model", parsed

            # --- Binary subtypes ---
            if subtype == 1:
                parsed["hardware_feature_id"] = f"0x{payload.hex()}"
                parsed["hardware_feature_status"] = "unresolved"
                return "Ruijie - Hardware Feature ID", parsed

            if subtype == 2:
                if len(payload) >= 4:
                    bitmap = int.from_bytes(payload[:4], "big")
                    parsed["port_speed_bitmap"] = f"0x{bitmap:08x}"
                    if bitmap & 0x00800000:
                        parsed["speed"] = "1000M"
                        parsed["duplex"] = "Full"
                    elif bitmap & 0x00400000:
                        parsed["speed"] = "100M"
                    elif bitmap & 0x00200000:
                        parsed["speed"] = "10M"
                elif len(payload) >= 2:
                    parsed["port_speed_bitmap"] = f"0x{int.from_bytes(payload[:2], 'big'):04x}"
                else:
                    parsed["raw_hex"] = payload.hex()
                return "Ruijie - Port Speed/Duplex", parsed

            if subtype == 4:
                if payload:
                    internal_index = int.from_bytes(payload, "big")
                    parsed["internal_index"] = internal_index
                    parsed["internal_index_hex"] = f"0x{internal_index:x}"
                    parsed["ifindex_note"] = "SNMP ifIndex for the local port"
                else:
                    parsed["raw_hex"] = payload.hex()
                return "Ruijie - Internal Interface Index", parsed

            if subtype == 11:
                try:
                    decoded_text = payload.decode("ascii", errors="strict").strip("\x00").strip()
                    if decoded_text and all(c.isprintable() for c in decoded_text):
                        parsed["reserved_status"] = decoded_text
                    else:
                        parsed["reserved_status"] = f"0x{payload.hex()}"
                        parsed["reserved_meaning"] = "No special status / default checksum"
                except (UnicodeDecodeError, ValueError):
                    parsed["reserved_status"] = f"0x{payload.hex()}"
                    parsed["reserved_meaning"] = "No special status / default checksum"
                return "Ruijie - Reserved Status", parsed

            # Unknown subtypes
            parsed["raw_hex"] = payload.hex()
            return default_name, parsed

        except Exception as e:
            parsed["parse_error"] = str(e)
            parsed["raw_hex"] = payload.hex()
            return default_name, parsed

    @staticmethod
    def get_vendor_ouis() -> list:
        return ["00:12:BB"]

    @staticmethod
    def matches_fingerprint(packet_bytes: bytes) -> bool:
        """Detect Ruijie devices by strong keywords."""
        try:
            strong = [b"Ruijie", b"RUIJIE", b"RGOS", b"Ruijie Networks"]
            return any(kw in packet_bytes for kw in strong)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ascii_text(data: bytes) -> str:
    text = data.decode("ascii", errors="replace").strip("\x00").strip()
    return "".join(c for c in text if c.isprintable())
