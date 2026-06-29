#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Juniper LLDP decoder for OUI 00:90:69 private TLVs.

Three-layer architecture:
  1. OUI layer  (vendor_dispatcher.py routes 00:90:69 -> here)
  2. TLV function-class layer (subtype -> Serial / Model / Firmware / DCBX / ...)
  3. Bitmap schema layer (model + firmware + function_class -> bit definitions)

Layer 3 is a schema registry.  Juniper DCBXP is undocumented in Wireshark
(packet-lldp.c has no case for OUI 00:90:69), so the bit positions for
each capability bitmap vary across JUNOS versions and hardware families.
The schema registry lets us pick the correct interpretation per device
without hard-coding a single assumption.

Context flow (layer-3 input):
  Subtype 2 (Model) and Subtype 3 (Firmware) are typically emitted BEFORE
  Subtype 12 (DCBXP) in real JUNOS LLDPDU frames.  decode_tlv127 uses a
  class-level dict keyed by id(packet_bytes) to accumulate model/firmware
  across calls within a single packet, then feeds that context to the
  schema lookup when subtype 12 arrives.  No external API changes needed.
"""

import re
import struct
from typing import Dict, Tuple, Any, Optional


# ---------------------------------------------------------------------------
# Layer 3: bitmap schema registry
# ---------------------------------------------------------------------------

# Schema key: (model_prefix, fw_prefix, function_class)
#   model_prefix  - matched against ctx["device_model"] via startswith
#   fw_prefix     - matched against ctx["software_version"] via startswith
#                   ("any" is wildcard)
#   function_class - layer-2 classification string
#
# Schema value: {bit_position: feature_name}

_JUNIPER_BITMAP_SCHEMAS: Dict[Tuple[str, str, str], Dict[int, str]] = {
    # QFX10000 series
    ("QFX10016", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
        5: "ETS Recommendation",
        6: "Application Priority",
    },
    ("QFX10008", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
        5: "ETS Recommendation",
        6: "Application Priority",
    },
    # QFX5100 / QFX5110 / QFX5120 series
    ("QFX5110", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
        5: "ETS Recommendation",
        6: "Application Priority",
    },
    ("QFX5100", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
        5: "ETS Recommendation",
        6: "Application Priority",
    },
    # EX series (simpler DCBX — usually ETS + PFC only)
    ("EX4400", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
    },
    ("EX4300", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
    },
    # Default fallback
    ("default", "any", "DCBX_CAPABILITY"): {
        0: "ETS Configuration",
        2: "PFC",
        5: "ETS Recommendation",
        6: "Application Priority",
    },
}


def _lookup_bitmap_schema(
    ctx: Dict[str, Any],
    function_class: str,
) -> Tuple[Dict[int, str], str]:
    """Return (schema, source_label) for the given device context.

    Lookup precedence: exact model > model family > default.
    """
    model = str(ctx.get("device_model", "")).upper()
    fw = str(ctx.get("software_version", "")).upper()

    # Try exact model first, then family, then default
    candidates = []
    if model:
        candidates.append(model)
        family = _model_family(model)
        if family != model:
            candidates.append(family)
    candidates.append("default")

    for mkey in candidates:
        key = (mkey, "any", function_class)
        if key in _JUNIPER_BITMAP_SCHEMAS:
            return _JUNIPER_BITMAP_SCHEMAS[key], f"schema:{mkey}/any/{function_class}"

    key = ("default", "any", function_class)
    schema = _JUNIPER_BITMAP_SCHEMAS.get(key, {})
    return schema, f"schema:default/any/{function_class}"


_KNOWN_MODEL_PREFIXES = (
    "QFX10016", "QFX10008", "QFX5110", "QFX5100", "QFX5120",
    "EX4400", "EX4300", "EX4600", "EX9200",
    "MX240", "MX480", "MX960",
    "SRX4600",
)


def _model_family(model: str) -> str:
    """Extract family prefix (e.g. 'QFX10016-6C' -> 'QFX10016')."""
    for prefix in _KNOWN_MODEL_PREFIXES:
        if model.startswith(prefix):
            return prefix
    m = re.match(r"^([A-Z]+\d+)", model)
    return m.group(1) if m else model


# ---------------------------------------------------------------------------
# Layer 2: TLV function classification
# ---------------------------------------------------------------------------

_SUBTYPE_FUNCTION_CLASS = {
    1: "SERIAL",
    2: "MODEL",
    3: "FIRMWARE",
    4: "POWER_MDI",
    12: "DCBX_CAPABILITY",
}


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class JuniperDecoder:
    """Juniper LLDP private TLV decoder (OUI 00:90:69).

    Uses a class-level dict keyed by id(packet_bytes) to accumulate
    device model / firmware across TLV calls within a single packet.
    """

    SUBTYPE_NAMES = {
        1: "Serial Number",
        2: "Device Model",
        3: "Software Version",
        4: "Enhanced Power via MDI",
        12: "DCBXP Extension",
    }

    # Class-level context cache: id(packet_bytes) -> {key: value}
    _packet_contexts: Dict[int, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Context management (internal)
    # ------------------------------------------------------------------

    @classmethod
    def _update_context(cls, packet_bytes: Optional[bytes], key: str, val: Any) -> None:
        if packet_bytes is None:
            return
        pid = id(packet_bytes)
        if pid not in cls._packet_contexts:
            cls._packet_contexts[pid] = {}
        cls._packet_contexts[pid][key] = val

    @classmethod
    def _get_context(cls, packet_bytes: Optional[bytes]) -> Dict[str, Any]:
        if packet_bytes is None:
            return {}
        ctx = dict(cls._packet_contexts.get(id(packet_bytes), {}))
        if ctx.get("device_model"):
            return ctx
        # Fallback: extract model/firmware from the raw packet bytes
        ctx.update(_extract_context_from_packet(packet_bytes))
        return ctx

    @classmethod
    def clear_context(cls, packet_bytes: bytes) -> None:
        """Clear cached context after packet parsing is complete."""
        cls._packet_contexts.pop(id(packet_bytes), None)

    # ------------------------------------------------------------------
    # Public decode methods
    # ------------------------------------------------------------------

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
            elif addr_subtype == 6:
                result["management_mac"] = ":".join(f"{b:02x}" for b in addr_bytes)
            idx = 1 + addr_len
            if idx + 5 <= len(value):
                if_subtype = value[idx]
                if if_subtype == 2:
                    result["if_subtype"] = if_subtype
                    result["if_index"] = struct.unpack(">I", value[idx + 1 : idx + 5])[0]
                    oid_start = idx + 5
                    if oid_start < len(value):
                        oid_len = value[oid_start]
                        if oid_len > 0 and oid_start + 1 + oid_len <= len(value):
                            result["snmp_oid"] = value[oid_start + 1 : oid_start + 1 + oid_len].hex()
        except Exception as e:
            result["parse_error"] = str(e)
        return result

    @classmethod
    def decode_tlv127(
        cls,
        subtype: int,
        value: bytes,
        oui: str = "00:90:69",
        packet_bytes: Optional[bytes] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Decode one Juniper OUI 00:90:69 private TLV.

        The ``packet_bytes`` kwarg enables cross-TLV context sharing:
        subtype 2 (Model) and 3 (Firmware) populate a class-level cache
        keyed by id(packet_bytes), and subtype 12 (DCBXP) reads that
        cache to select the correct bitmap schema.

        If ``packet_bytes`` is None the decoder degrades gracefully:
        subtype 12 falls back to the default schema.
        """
        default_name = f"Juniper Extension (Subtype {subtype})"
        parsed: Dict[str, Any] = {}

        # Strip OUI+subtype header if still present
        if len(value) >= 4 and value[0:3] == b"\x00\x90\x69":
            payload = value[4:]
        else:
            payload = value

        function_class = _SUBTYPE_FUNCTION_CLASS.get(subtype, "UNKNOWN")

        try:
            # --- Context-collecting subtypes (layer 2) ---
            if subtype == 1:
                text = _ascii_text(payload)
                parsed["official_serial_number"] = text
                cls._update_context(packet_bytes, "serial_number", text)
                return "Juniper - Serial Number", parsed

            if subtype == 2:
                text = _ascii_text(payload)
                parsed["device_model"] = text
                cls._update_context(packet_bytes, "device_model", text)
                return "Juniper - Device Model", parsed

            if subtype == 3:
                text = _ascii_text(payload)
                parsed["software_version"] = text
                cls._update_context(packet_bytes, "software_version", text)
                return "Juniper - Software Version", parsed

            # --- Binary subtypes that consume context ---
            if subtype == 4:
                return "Juniper - Power via MDI", _parse_juniper_power_mdi(payload)

            if subtype == 12:
                ctx = cls._get_context(packet_bytes)
                return (
                    f"Juniper - DCBXP ({function_class})",
                    _parse_juniper_dcbxp(payload, ctx, function_class),
                )

            # Unknown subtypes
            parsed["raw_hex"] = payload.hex()
            parsed["function_class"] = function_class
            return default_name, parsed

        except Exception as e:
            parsed["parse_error"] = str(e)
            parsed["raw_hex"] = payload.hex()
            return default_name, parsed

    @staticmethod
    def get_vendor_ouis() -> list:
        return ["00:90:69"]

    @staticmethod
    def matches_fingerprint(packet_bytes: bytes) -> bool:
        """Detect Juniper JUNOS devices by strong keywords only."""
        try:
            strong = [b"Juniper", b"JUNOS", b"Juniper Networks"]
            return any(kw in packet_bytes for kw in strong)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Packet-level context extraction (fallback when private TLV 2/3 absent)
# ---------------------------------------------------------------------------

def _extract_context_from_packet(packet_bytes: bytes) -> Dict[str, Any]:
    """Scan raw packet bytes for model / firmware strings.

    Juniper LLDPDU typically carries the model name (e.g. 'qfx10016') and
    JUNOS version in the standard System Description TLV (type 6).  This
    fallback is used when private subtype 2/3 TLVs are not present.
    """
    result: Dict[str, Any] = {}
    try:
        text = packet_bytes.decode("ascii", errors="replace")

        # Model extraction: look for known Juniper model prefixes
        model_match = re.search(
            r"\b(qfx\d{4,5}|ex\d{4}|mx\d{3,4}|srx\d{4})\b",
            text, re.IGNORECASE,
        )
        if model_match:
            result["device_model"] = model_match.group(1).upper()

        # JUNOS version extraction (e.g. "JUNOS 22.4R3-S5.11")
        fw_match = re.search(r"JUNOS\s+(\d+\.\d+)", text, re.IGNORECASE)
        if fw_match:
            result["software_version"] = fw_match.group(1)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Layer 2 helpers
# ---------------------------------------------------------------------------

def _ascii_text(data: bytes) -> str:
    text = data.decode("ascii", errors="replace").strip("\x00").strip()
    return "".join(c for c in text if c.isprintable())


def _parse_juniper_power_mdi(payload: bytes) -> Dict[str, Any]:
    """Parse Juniper subtype 4 Enhanced Power via MDI."""
    result: Dict[str, Any] = {"raw_hex": payload.hex()}
    if len(payload) >= 1:
        result["power_type_raw"] = f"0x{payload[0]:02x}"
    if len(payload) >= 3:
        power = int.from_bytes(payload[1:3], "big")
        result["power_value"] = power
        result["power_summary"] = f"{power * 0.1:.1f}W"
    return result


def _parse_juniper_dcbxp(
    payload: bytes,
    ctx: Dict[str, Any],
    function_class: str,
) -> Dict[str, Any]:
    """Parse Juniper subtype 12 DCBXP with schema-driven bitmap decode.

    Layer 2: classify the payload structure.
    Layer 3: use device context to look up the correct bit schema.
    """
    result: Dict[str, Any] = {}
    if len(payload) == 0:
        result["notice"] = "Empty DCBXP payload"
        return result

    result["raw_hex"] = payload.hex()
    result["byte_dump"] = _byte_dump(payload)

    # ---- Layer 2: classify payload structure ----
    structure = _classify_dcbxp_payload(payload)
    result["structure_type"] = structure["type"]

    # ---- Layer 3: schema-driven bitmap decode ----
    if structure["type"] == "CAPABILITY_BITMAP":
        cap_byte = structure["capability_byte"]
        result["capability_offset"] = structure["capability_offset"]
        result["capability_bitmap"] = f"0x{cap_byte:02x}"

        schema, source = _lookup_bitmap_schema(ctx, function_class)
        result["schema_source"] = source
        result["device_model"] = ctx.get("device_model", "unknown")
        result["software_version"] = ctx.get("software_version", "unknown")

        if schema:
            features = [
                name for bit, name in sorted(schema.items())
                if cap_byte & (1 << bit)
            ]
            result["features"] = features
        else:
            result["features"] = []
            result["notice"] = "No matching bitmap schema for this device"

    elif structure["type"] == "SUB_TLV_LIST":
        result["sub_tlvs"] = structure["sub_tlvs"]
        result["notice"] = "Sub-TLV structure detected; per-sub-TLV decode not yet implemented"

    else:
        result["notice"] = "Unrecognized DCBXP payload structure"

    return result


def _classify_dcbxp_payload(payload: bytes) -> Dict[str, Any]:
    """Layer-2 classification of the DCBXP payload.

    Known patterns from QFX captures:
      - Single non-zero byte in otherwise zeroed payload -> CAPABILITY_BITMAP
      - Payload starting with type+length pairs            -> SUB_TLV_LIST
      - Anything else                                      -> UNKNOWN
    """
    nonzero = [(i, b) for i, b in enumerate(payload) if b != 0]

    if len(nonzero) == 1:
        idx, cap = nonzero[0]
        return {
            "type": "CAPABILITY_BITMAP",
            "capability_byte": cap,
            "capability_offset": idx,
        }

    if len(payload) >= 2 and _looks_like_subtlv(payload):
        return {
            "type": "SUB_TLV_LIST",
            "sub_tlvs": _extract_subtlvs(payload),
        }

    return {"type": "UNKNOWN"}


def _looks_like_subtlv(data: bytes) -> bool:
    """Heuristic: does data consist of valid type+length+value triples?"""
    offset = 0
    count = 0
    while offset + 2 <= len(data) and count < 8:
        tlv_len = data[offset + 1]
        if tlv_len == 0 or offset + 2 + tlv_len > len(data):
            return False
        offset += 2 + tlv_len
        count += 1
    return count > 0 and offset == len(data)


def _extract_subtlvs(data: bytes) -> list:
    """Extract {type, length, hex} entries from a sub-TLV stream."""
    result = []
    offset = 0
    while offset + 2 <= len(data):
        tlv_type = data[offset]
        tlv_len = data[offset + 1]
        if tlv_len == 0 or offset + 2 + tlv_len > len(data):
            break
        tlv_data = data[offset + 2 : offset + 2 + tlv_len]
        result.append({
            "type": tlv_type,
            "length": tlv_len,
            "hex": tlv_data.hex(),
        })
        offset += 2 + tlv_len
    return result


def _byte_dump(data: bytes) -> list:
    """Return offset/hex/decimal for each byte."""
    return [{"offset": i, "hex": f"0x{b:02x}", "decimal": b} for i, b in enumerate(data)]
