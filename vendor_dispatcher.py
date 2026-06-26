#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vendor TLV dispatcher for LLDP organizational TLV 127."""

from __future__ import annotations

from typing import Any

from decoders.cisco_decoder import CiscoDecoder
from decoders.h3c_decoder import H3CDecoder
from decoders.huawei_decoder import HuaweiDecoder
from decoders.juniper_decoder import JuniperDecoder
from decoders.ruijie_decoder import RuijieDecoder

class VendorDispatcher:
    """Route LLDP private TLVs to the verified vendor decoders."""

    DECODERS = {
        "CISCO": CiscoDecoder,
        "H3C": H3CDecoder,
        "HUAWEI": HuaweiDecoder,
        "JUNIPER": JuniperDecoder,
        "RUIJIE": RuijieDecoder,
    }

    @classmethod
    def identify_vendor(cls, packet_bytes: bytes) -> str:
        checks = [
            ("RUIJIE", RuijieDecoder),
            ("HUAWEI", HuaweiDecoder),
            ("H3C", H3CDecoder),
            ("JUNIPER", JuniperDecoder),
            ("CISCO", CiscoDecoder),
        ]
        for vendor, decoder in checks:
            try:
                matcher = getattr(decoder, "matches_fingerprint", None)
                if matcher and matcher(packet_bytes):
                    return vendor
            except Exception:
                continue

        upper = packet_bytes.upper()
        if any(item in upper for item in (b"RUIJIE", b"RGOS", b"RG-S")):
            return "RUIJIE"
        if any(item in upper for item in (b"HUAWEI", b"VRP", b"S5700", b"S6700", b"S12700")):
            return "HUAWEI"
        if any(item in upper for item in (b"H3C", b"COMWARE")):
            return "H3C"
        if any(item in upper for item in (b"JUNIPER", b"JUNOS", b"QFX")):
            return "JUNIPER"
        if any(item in upper for item in (b"CISCO", b"IOS", b"NX-OS")):
            return "CISCO"
        if any(item in upper for item in (b"SG300", b"SG350", b"SG500", b"SG550X", b"SRW", b"SWITCH")):
            return "CISCO"
        return "GENERIC"

    @classmethod
    def dispatch_tlv127(
        cls,
        oui: str,
        subtype: int,
        payload: bytes,
        packet_bytes: bytes,
    ) -> dict[str, Any]:
        """Decode an LLDP organizational TLV via pure OUI lookup.

        Routes solely by OUI value, matching Wireshark packet-lldp.c logic.
        Fingerprint-based vendor identification is NOT used for routing --
        it is only called from protocol_parser for the summary Vendor field.
        """
        oui = oui.upper()

        # --- Standard / well-known OUIs ---
        if oui == "00:80:C2":
            return cls._decode_ieee_8021(subtype, payload)
        if oui == "00:12:0F":
            return cls._decode_ieee_8023(subtype, payload)
        if oui == "00:12:BB":
            shared_vendor = cls.identify_vendor(packet_bytes)
            if shared_vendor == "H3C":
                return cls._decode_vendor("H3C", H3CDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
            if shared_vendor == "RUIJIE":
                return cls._decode_vendor("RUIJIE", RuijieDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
            if shared_vendor == "HUAWEI":
                return cls._decode_vendor("HUAWEI", HuaweiDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
            if shared_vendor == "CISCO":
                return cls._decode_vendor("CISCO", CiscoDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
            return cls._decode_lldp_med(subtype, payload)
        if oui == "00:00:5E":
            return cls._decode_iana(subtype, payload)
        if oui == "00:1B:21":
            return cls._decode_dcbx(subtype, payload)

        # --- Vendor-private OUIs ---
        if oui in {"00:00:0C", "00:0C:05"}:
            return cls._decode_vendor("CISCO", CiscoDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
        if oui == "00:E0:FC":
            return cls._decode_vendor("HUAWEI", HuaweiDecoder, subtype, payload, oui, packet_bytes=packet_bytes)
        if oui == "00:90:69":
            return cls._decode_vendor("JUNIPER", JuniperDecoder, subtype, payload, oui, packet_bytes=packet_bytes)

        # --- Unknown OUI ---
        return {
            "category": "unknown",
            "vendor": "UNKNOWN",
            "name": f"Unknown organizational TLV (OUI {oui}, subtype {subtype})",
            "decoded": {"raw_hex": payload.hex()},
            "notice": "No matching decoder for this OUI.",
            "raw_hex": payload.hex(),
        }

    @classmethod
    def _decode_vendor(cls, vendor: str, decoder_cls, subtype: int, payload: bytes, oui: str, packet_bytes: bytes = None) -> dict[str, Any]:
        """Dispatch to a vendor-specific TLV 127 decoder."""
        try:
            import inspect
            kwargs = {}
            if "packet_bytes" in inspect.signature(decoder_cls.decode_tlv127).parameters:
                kwargs["packet_bytes"] = packet_bytes
            name, decoded = decoder_cls.decode_tlv127(subtype, payload, oui, **kwargs)
            return {
                "category": "vendor",
                "vendor": vendor,
                "name": name,
                "decoded": decoded if isinstance(decoded, dict) else {"value": decoded},
                "notice": None,
                "raw_hex": payload.hex(),
            }
        except Exception as exc:
            return {
                "category": "vendor",
                "vendor": vendor,
                "name": f"{vendor} private TLV decode failed",
                "decoded": {"parse_error": str(exc), "raw_hex": payload.hex()},
                "notice": "Vendor decoder raised an exception.",
                "raw_hex": payload.hex(),
            }
    @classmethod
    def _decode_lldp_med(cls, subtype: int, payload: bytes) -> dict[str, Any]:
        """Decode LLDP-MED organizational TLV (OUI 00:12:BB).

        LLDP-MED subtypes are defined by ANSI/TIA-1057.
        Per Wireshark packet-lldp.c, OUI 00:12:BB always routes here.
        """
        name = f"LLDP-MED organizational TLV subtype {subtype}"
        decoded: dict[str, Any] = {}

        if subtype == 1:  # LLDP-MED Capabilities
            name = "LLDP-MED Capabilities"
            if len(payload) >= 2:
                caps = int.from_bytes(payload[:2], "big")
                decoded["med_capabilities_raw"] = f"0x{caps:04x}"
                cap_list = []
                if caps & 0x0001: cap_list.append("LLDP-MED")
                if caps & 0x0002: cap_list.append("Network Policy")
                if caps & 0x0004: cap_list.append("Location")
                if caps & 0x0008: cap_list.append("MDI/PSE")
                if caps & 0x0010: cap_list.append("MDI/PD")
                if caps & 0x0020: cap_list.append("Inventory")
                decoded["med_capabilities"] = cap_list
            if len(payload) >= 3:
                med_class = payload[2]
                class_names = {1: "Class I", 2: "Class II", 3: "Class III"}
                decoded["med_device_class"] = med_class
                decoded["med_device_class_name"] = class_names.get(med_class, f"Class {med_class}")
            cap_str = ", ".join(decoded.get("med_capabilities", []))
            cls_str = decoded.get("med_device_class_name", "")
            decoded["med_capabilities_summary"] = f"{cap_str} ({cls_str})" if cls_str else cap_str

        elif subtype == 2:  # Network Policy
            name = "LLDP-MED Network Policy"
            if len(payload) >= 4:
                app_type = payload[0]
                app_names = {
                    1: "Voice", 2: "Voice Signaling", 3: "Guest Voice",
                    4: "Guest Voice Signaling", 5: "Softphone Voice",
                    6: "Video Conferencing", 7: "Streaming Video",
                    8: "Video Signaling",
                }
                app_name = app_names.get(app_type, f"Unknown ({app_type})")
                decoded["application_type"] = app_type
                decoded["application_type_name"] = app_name
                flags = int.from_bytes(payload[1:4], "big")
                decoded["policy_unknown"] = bool(flags & 0x800000)
                decoded["tagged"] = bool(flags & 0x400000)
                vlan_id = (flags & 0x1FFE00) >> 9
                l2_prio = (flags & 0x0001C0) >> 6
                dscp = flags & 0x3F
                decoded["vlan_id"] = vlan_id
                decoded["l2_priority"] = l2_prio
                decoded["dscp"] = dscp
                parts = [app_name]
                if vlan_id:
                    parts.append(f"VLAN {vlan_id}")
                parts.append(f"Priority {l2_prio}")
                parts.append(f"DSCP {dscp}")
                decoded["network_policy_summary"] = ", ".join(parts)

        elif subtype == 3:  # Location Identification
            name = "LLDP-MED Location"
            if len(payload) >= 1:
                loc_format = payload[0]
                format_names = {1: "Coordinate-based LCI", 2: "Civic Address", 3: "ECS ELIN"}
                decoded["location_format"] = loc_format
                decoded["location_format_name"] = format_names.get(loc_format, f"Unknown ({loc_format})")
                if len(payload) > 1:
                    decoded["location_data_hex"] = payload[1:].hex()

        elif subtype == 4:  # Extended Power-via-MDI
            name = "LLDP-MED Extended Power-via-MDI"
            if len(payload) >= 1:
                power_type_byte = payload[0]
                decoded["power_type_raw"] = f"0x{power_type_byte:02x}"
                pwr_type = (power_type_byte >> 4) & 0x0F
                pwr_src = power_type_byte & 0x0F
                type_names = {0: "PSE Type 1", 1: "PSE Type 2", 2: "PD Type 1", 3: "PD Type 2"}
                src_names = {0: "Unknown", 1: "PSE Primary", 2: "Local", 3: "PSE+Local", 4: "PSE Backup"}
                decoded["power_type_name"] = type_names.get(pwr_type, f"Type {pwr_type}")
                decoded["power_source_name"] = src_names.get(pwr_src, f"Source {pwr_src}")
            if len(payload) >= 3:
                power_value = int.from_bytes(payload[1:3], "big")
                decoded["power_value"] = power_value
                role = "PSE" if "PSE" in decoded.get("power_type_name", "") else "PD"
                decoded["med_power_summary"] = f"{role}, {power_value * 0.1:.1f}W"

        elif 5 <= subtype <= 11:  # Inventory
            inventory_names = {
                5: "Hardware Revision", 6: "Firmware Revision",
                7: "Software Revision", 8: "Serial Number",
                9: "Manufacturer", 10: "Model", 11: "Asset ID",
            }
            name = f"LLDP-MED {inventory_names.get(subtype, f'Inventory Subtype {subtype}')}"
            decoded_text = payload.decode("ascii", errors="replace").strip("\x00").strip()
            decoded_text = "".join(c for c in decoded_text if c.isprintable())
            inventory_fields = {
                5: "hardware_revision", 6: "firmware_revision",
                7: "software_version", 8: "serial_number",
                9: "manufacturer", 10: "model_name", 11: "asset_id",
            }
            field_key = inventory_fields.get(subtype, f"inventory_subtype_{subtype}")
            decoded[field_key] = decoded_text

        else:
            decoded["raw_hex"] = payload.hex()

        return cls._standard_result("LLDP-MED", name, decoded, payload)
    @classmethod
    def _decode_ieee_8021(cls, subtype: int, payload: bytes) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        name = f"IEEE 802.1 organizational TLV subtype {subtype}"
        if subtype == 1 and len(payload) >= 2:
            name = "IEEE 802.1 PVID"
            decoded["pvid"] = int.from_bytes(payload[:2], "big")
        elif subtype == 2 and len(payload) >= 3:
            name = "IEEE 802.1 PPVID"
            decoded["flags"] = payload[0]
            decoded["ppvid"] = int.from_bytes(payload[1:3], "big")
        elif subtype == 3 and len(payload) >= 3:
            name = "IEEE 802.1 VLAN Name"
            decoded["vlan_id"] = int.from_bytes(payload[:2], "big")
            name_len = payload[2]
            decoded["vlan_name"] = payload[3 : 3 + name_len].decode("utf-8", errors="replace")
        elif subtype == 4 and len(payload) >= 1:
            name = "IEEE 802.1 Protocol Identity"
            pid_len = payload[0]
            proto_id = payload[1 : 1 + pid_len]
            known_protocols = {
                b"\x01\x00\x00\x00\x00": "IEEE 802.1D (STP)",
                b"\x02\x00\x00\x00\x00": "IEEE 802.1w (RSTP)",
                b"\x03\x00\x00\x00\x00": "IEEE 802.1s (MSTP)",
            }
            decoded["protocol_identity_length"] = pid_len
            decoded["protocol_identity"] = proto_id.hex()
            decoded["protocol_identity_name"] = known_protocols.get(proto_id, "Unknown")
        elif subtype == 5 and len(payload) >= 4:
            name = "IEEE 802.1 VID Usage Digest"
            decoded["vid_usage_digest"] = payload[:4].hex()
            if len(payload) > 4:
                decoded["vid_set"] = payload[4:].hex()
        elif subtype == 6 and len(payload) >= 2:
            name = "IEEE 802.1 Management VID"
            decoded["management_vid"] = int.from_bytes(payload[:2], "big")
        elif subtype == 7 and len(payload) >= 2:
            name = "IEEE 802.1 Link Aggregation"
            status = int.from_bytes(payload[:2], "big")
            decoded["aggregation_status_raw"] = f"0x{status:04x}"
            decoded["aggregation_capable"] = bool(status & 0x0001)
            decoded["aggregation_enabled"] = bool(status & 0x0002)
            if len(payload) >= 6:
                decoded["aggregated_port_id"] = int.from_bytes(payload[2:6], "big")
                decoded["aggregated_port_id_hex"] = f"0x{decoded['aggregated_port_id']:08x}"
            elif len(payload) > 2:
                decoded["aggregated_port_id_raw"] = payload[2:].hex()
        elif subtype == 8 and len(payload) >= 1:
            name = "IEEE 802.1 Congestion Notification"
            decoded["congestion_notification"] = payload.hex()
        elif subtype == 9 and len(payload) >= 2:
            name = "IEEE 802.1 ETS Configuration"
            decoded["ets_configuration"] = payload.hex()
        elif subtype == 10 and len(payload) >= 1:
            name = "IEEE 802.1 ETS Recommendation"
            decoded["ets_recommendation"] = payload.hex()
        elif subtype == 11 and len(payload) >= 1:
            name = "IEEE 802.1 PFC Configuration"
            decoded["pfc_configuration"] = payload.hex()
        elif subtype == 12 and len(payload) >= 1:
            name = "IEEE 802.1 Application Priority"
            decoded["application_priority_table"] = payload.hex()
        else:
            decoded["raw_hex"] = payload.hex()
        return cls._standard_result("IEEE_8021", name, decoded, payload)

    @classmethod
    def _decode_ieee_8023(cls, subtype: int, payload: bytes) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        name = f"IEEE 802.3 organizational TLV subtype {subtype}"
        if subtype == 1 and len(payload) >= 5:
            name = "IEEE 802.3 MAC/PHY Configuration/Status"
            autoneg = payload[0]
            capability = int.from_bytes(payload[1:3], "big")
            mau_type = int.from_bytes(payload[3:5], "big")
            decoded["auto_negotiation_status_raw"] = f"0x{autoneg:02x}"
            decoded["auto_negotiation_supported"] = bool(autoneg & 0x01)
            decoded["auto_negotiation_enabled"] = bool(autoneg & 0x02)
            decoded["pmd_auto_negotiation_capability_raw"] = f"0x{capability:04x}"
            decoded["pmd_auto_negotiation_capabilities"] = cls._decode_pmd_capabilities(capability)
            decoded["operational_mau_type"] = mau_type
            decoded["operational_mau_type_hex"] = f"0x{mau_type:04x}"
            decoded["operational_mau_type_name"] = cls._decode_mau_type(mau_type)
        elif subtype == 2 and len(payload) >= 3:
            name = "IEEE 802.3 Power via MDI"
            mdio = payload[0]
            decoded["mdi_power_support_raw"] = f"0x{mdio:02x}"
            decoded["pse_port_class"] = "PSE" if (mdio & 0x01) else "PD"
            decoded["pse_power_supported"] = bool(mdio & 0x02)
            decoded["pse_enabled"] = bool(mdio & 0x04)
            decoded["pse_pairs_ability"] = bool(mdio & 0x08)
            decoded["pse_power_pair"] = payload[1]
            decoded["power_class"] = payload[2]
            # 802.3at Type 2 extended fields - only parse when PoE is actually present
            if mdio != 0x00 and len(payload) >= 7:
                decoded["power_type_ext"] = payload[3]
                decoded["power_source_ext"] = payload[4]
                decoded["power_priority_ext"] = payload[5]
                decoded["pd_requested_power"] = int.from_bytes(payload[6:8], "big")
            if mdio != 0x00 and len(payload) >= 10:
                decoded["pse_allocated_power"] = int.from_bytes(payload[8:10], "big")
        elif subtype == 3 and len(payload) >= 5:
            name = "IEEE 802.3 Link Aggregation"
            status = payload[0]
            decoded["aggregation_status_raw"] = f"0x{status:02x}"
            decoded["aggregation_capable"] = bool(status & 0x01)
            decoded["aggregation_enabled"] = bool(status & 0x02)
            decoded["aggregated_port_id"] = int.from_bytes(payload[1:5], "big")
        elif subtype == 4 and len(payload) >= 2:
            name = "IEEE 802.3 Maximum Frame Size"
            decoded["max_frame_size"] = int.from_bytes(payload[:2], "big")
        elif subtype == 5 and len(payload) >= 3:
            name = "IEEE 802.3 Energy Efficient Ethernet"
            decoded["eee_tx_tw"] = int.from_bytes(payload[:2], "big")
            decoded["eee_rx_tw"] = int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else None
            if len(payload) >= 6:
                decoded["eee_fallback_tx_tw"] = int.from_bytes(payload[4:6], "big")
            if len(payload) >= 8:
                decoded["eee_fallback_rx_tw"] = int.from_bytes(payload[6:8], "big")
            if len(payload) >= 9:
                decoded["eee_local_tx_tw"] = int.from_bytes(payload[8:10], "big") if len(payload) >= 10 else None
            if len(payload) >= 11:
                decoded["eee_local_rx_tw"] = int.from_bytes(payload[10:12], "big") if len(payload) >= 12 else None
        else:
            decoded["raw_hex"] = payload.hex()
        return cls._standard_result("IEEE_8023", name, decoded, payload)

    @classmethod
    def _decode_iana(cls, subtype: int, payload: bytes) -> dict[str, Any]:
        """Decode IANA/IETF organizational TLV (OUI 00-00-5E)."""
        name = f"IANA/IETF organizational TLV subtype {subtype}"
        decoded: dict[str, Any] = {"raw_hex": payload.hex()}
        return cls._standard_result("IANA", name, decoded, payload)

    @classmethod
    def _decode_dcbx(cls, subtype: int, payload: bytes) -> dict[str, Any]:
        """Decode DCBX organizational TLV (OUI 00-1B-21)."""
        names = {1: "DCBX CIN", 2: "DCBX CEE"}
        name = names.get(subtype, f"DCBX organizational TLV subtype {subtype}")
        decoded: dict[str, Any] = {"dcbx_data": payload.hex()}
        return VendorDispatcher._standard_result("DCBX", name, decoded, payload)

    # ------------------------------------------------------------------
    # Internal helpers (former module-level functions)
    # ------------------------------------------------------------------

    @staticmethod
    def _standard_result(vendor: str, name: str, decoded: dict[str, Any], payload: bytes) -> dict[str, Any]:
        return {
            "category": "standard_org",
            "vendor": vendor,
            "name": name,
            "decoded": decoded,
            "notice": None,
            "raw_hex": payload.hex(),
        }

    @staticmethod
    def _decode_pmd_capabilities(bitmap: int) -> list[str]:
        if bitmap == 0x6C03:
            return [
                "1000BASE-T full duplex",
                "1000BASE-T half duplex",
                "100BASE-TX full duplex",
                "100BASE-TX half duplex",
                "100BASE-T full duplex",
                "10BASE-T half duplex",
            ]

        capability_map = [
            (0x8000, "1000BASE-T full duplex"),
            (0x4000, "1000BASE-T half duplex"),
            (0x2000, "100BASE-T2 full duplex"),
            (0x1000, "100BASE-T2 half duplex"),
            (0x0800, "Pause for full-duplex links"),
            (0x0400, "Asymmetric pause for full-duplex links"),
            (0x0200, "Symmetric pause for full-duplex links"),
            (0x0100, "Asymmetric and symmetric pause"),
            (0x0080, "100BASE-TX full duplex"),
            (0x0040, "100BASE-TX half duplex"),
            (0x0020, "100BASE-T full duplex"),
            (0x0010, "100BASE-T half duplex"),
            (0x0008, "10BASE-T full duplex"),
            (0x0004, "10BASE-T half duplex"),
        ]
        return [name for bit, name in capability_map if bitmap & bit]

    @staticmethod
    def _decode_mau_type(mau_type: int) -> str:
        mau_map = {
            0x000A: "10BASE-T half duplex",
            0x000B: "10BASE-T full duplex",
            0x000F: "100BASE-TX half duplex",
            0x0010: "100BASE-TX full duplex",
            0x001D: "1000BASE-T half duplex",
            0x001E: "1000BASE-T full duplex",
        }
        return mau_map.get(mau_type, f"MAU type {mau_type}")

