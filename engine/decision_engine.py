#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decision Engine — adapter between protocol_parser dicts and port_profile.

Converts a parse_offline_file() result dict into PortFeatures, then runs
the inference pipeline.

Top-level keys on the result dict (set by parse_lldp_packet / parse_cdp_packet):
    protocol, vendor, chassis_id, port_id, packet, fields, tlvs, tlv_count

All semantic data (system_name, capabilities, management_addresses, mtu,
native_vlan, link_speed, duplex, ...) lives inside result["fields"].
"""

from typing import Dict, Any, Optional

from engine.port_profile import (
    PortFeatures, PortIntentProfile, infer_port_intent,
)


def extract_features_from_result(result: Dict[str, Any]) -> PortFeatures:
    """Extract PortFeatures from a parse_offline_file() result dict."""
    f = PortFeatures()

    # `fields` is where the parser stashes decoded TLV data; fall back to the
    # top-level dict so this also works with hand-built or CDP-style dicts.
    fields = result.get("fields") or {}
    tlvs = result.get("tlvs", [])

    # --- Capabilities ---
    caps = fields.get("capabilities") or {}
    if not isinstance(caps, dict):
        caps = {}
    caps_supported = caps.get("supported", []) or []
    caps_enabled = caps.get("enabled", []) or []
    caps_text = ", ".join([*caps_supported, *caps_enabled]).lower()

    # Walk TLVs too — vendor-specific TLVs sometimes carry bridge hints.
    for tlv in tlvs:
        parsed = tlv.get("parsed", {})
        decoded = parsed.get("decoded", {})
        if isinstance(decoded, dict):
            if decoded.get("aggregation_capable"):
                f.is_bridge = True
            cap_text = str(decoded.get("capabilities", "")).lower()
            if "bridge" in cap_text:
                f.is_bridge = True

    if "bridge" in caps_text or "switch" in caps_text:
        f.is_bridge = True
    if "router" in caps_text or "router_enabled" in caps_text:
        f.is_router = True
    if "wlan" in caps_text or "wireless" in caps_text:
        f.is_wlan = True
    if "telephone" in caps_text or "phone" in caps_text:
        f.is_telephone = True

    # --- VLAN ---
    # `port_vlan` (LLDP 802.1 subtype 1 / PVID) and `native_vlan` (CDP) are
    # both surfaced into fields; treat either as the access/native VLAN.
    native_vlan = fields.get("native_vlan") or fields.get("port_vlan")
    f.has_port_vlan = native_vlan is not None and native_vlan != 0

    vlan_count = 0
    has_protocol_vlan = False
    for tlv in tlvs:
        parsed = tlv.get("parsed", {})
        decoded = parsed.get("decoded", {})
        if not isinstance(decoded, dict):
            continue
        if "pvid" in decoded:
            vlan_count += 1
        if "ppvid" in decoded:
            has_protocol_vlan = True
            vlan_count += 1
        if "vlan_name" in decoded:
            vlan_count += 1
            name = str(decoded.get("vlan_name", "")).upper()
            if any(kw in name for kw in ("MGMT", "ADMIN", "MGT")):
                f.has_mgmt_vlan = True
            elif any(kw in name for kw in ("DATA", "USER", "OFFICE")):
                f.has_data_vlan = True
            elif any(kw in name for kw in ("VOICE", "PHONE")):
                f.has_voice_vlan = True
            elif any(kw in name for kw in ("STOR", "SAN", "NAS")):
                f.has_storage_vlan = True
    f.has_protocol_vlan = has_protocol_vlan

    # --- Link aggregation ---
    for tlv in tlvs:
        parsed = tlv.get("parsed", {})
        decoded = parsed.get("decoded", {})
        if isinstance(decoded, dict) and decoded.get("aggregation_enabled"):
            f.is_aggregated = True
            f.aggregation_id = decoded.get("aggregated_port_id")
            break

    # --- MTU (LLDP 802.3 max-frame-size; CDP MTU; also accept top-level alias) ---
    mtu = fields.get("mtu") or fields.get("max_frame_size")
    if not mtu:
        for tlv in tlvs:
            decoded = tlv.get("parsed", {}).get("decoded", {})
            if isinstance(decoded, dict) and decoded.get("max_frame_size"):
                mtu = decoded["max_frame_size"]
                break
    if mtu:
        try:
            mtu_val = int(mtu)
            f.high_mtu = mtu_val > 2000
            f.jumbo_frame = mtu_val > 9000
        except (ValueError, TypeError):
            pass

    # --- PoE (LLDP 802.3 subtype 4 / CDP) ---
    for tlv in tlvs:
        decoded = tlv.get("parsed", {}).get("decoded", {})
        if not isinstance(decoded, dict):
            continue
        raw = decoded.get("mdi_power_support_raw")
        if raw and raw != "0x00":
            f.has_poe = True
            break
        if decoded.get("power_type_raw"):
            f.has_poe = True
            break

    # --- Speed / Duplex ---
    link_speed = str(fields.get("link_speed", ""))
    duplex = str(fields.get("duplex", ""))
    if any(s in link_speed for s in ("10G", "25G", "40G", "100G", "10g", "25g", "40g", "100g")):
        f.speed_10g_plus = True
        f.speed_1g_plus = True
    elif any(s in link_speed for s in ("1000", "1G", "1g")):
        f.speed_1g_plus = True
    f.duplex_full = "full" in duplex.lower()

    # --- Management / description presence ---
    mgmt_addrs = fields.get("management_addresses", []) or []
    f.has_management_ip = bool(mgmt_addrs)
    sys_desc = fields.get("system_description", "") or ""
    f.has_system_description = bool(sys_desc)

    return f


class DecisionEngine:
    """Convenience wrapper: feed a result dict, get a PortIntentProfile."""

    def __init__(self):
        self._features: Optional[PortFeatures] = None
        self._intent: Optional[PortIntentProfile] = None

    def feed_from_result(self, result: Dict[str, Any]) -> None:
        self._features = extract_features_from_result(result)
        self._intent = infer_port_intent(self._features)

    def resolve(self) -> Optional[PortIntentProfile]:
        return self._intent
