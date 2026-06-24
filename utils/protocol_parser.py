#!/usr/bin/env python3



# -*- coding: utf-8 -*-



"""Unified LLDP/CDP parser used by both online and offline modes."""







from __future__ import annotations







import re



import struct



from ipaddress import IPv6Address



from pathlib import Path



from typing import Any







from vendor_dispatcher import VendorDispatcher











LLDP_ETHERTYPE = 0x88CC



CDP_DST_MAC = b"\x01\x00\x0c\xcc\xcc\xcc"



CDP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"











def parse_offline_file(file_path: str, output_mode: str = "normal") -> dict[str, Any]:



    path = Path(file_path)



    text = path.read_text(encoding="utf-8", errors="ignore")



    packet = bytes.fromhex(clean_hex_text(text))



    result = analyze_packet(packet)
    result["raw_hex"] = packet.hex()



    result["source"] = str(path)



    print_analysis(result, output_mode=output_mode)



    return result











def analyze_packet(packet_bytes: bytes, protocol: str | None = None) -> dict[str, Any]:



    protocol = protocol or detect_protocol(packet_bytes)



    if protocol == "LLDP":



        return parse_lldp_packet(packet_bytes)



    if protocol == "CDP":



        return parse_cdp_packet(packet_bytes)



    return {



        "success": False,



        "protocol": "UNKNOWN",



        "error": "Unable to detect LLDP or CDP packet.",



        "packet": parse_ethernet_header(packet_bytes),



        "tlvs": [],



    }











def detect_protocol(packet_bytes: bytes) -> str:



    eth = parse_ethernet_header(packet_bytes)



    if eth.get("ethertype") == LLDP_ETHERTYPE:



        return "LLDP"



    if packet_bytes[:6] == CDP_DST_MAC:



        return "CDP"



    if packet_bytes.startswith(CDP_SNAP) or (len(packet_bytes) >= 8 and packet_bytes[:3] == b"\xaa\xaa\x03"):



        return "CDP"



    if _looks_like_lldpdu(packet_bytes):



        return "LLDP"



    return "UNKNOWN"











def parse_ethernet_header(packet_bytes: bytes) -> dict[str, Any]:



    if len(packet_bytes) < 14:



        return {"present": False, "length": len(packet_bytes)}



    ethertype = struct.unpack("!H", packet_bytes[12:14])[0]



    return {



        "present": True,



        "dst_mac": format_mac(packet_bytes[0:6]),



        "src_mac": format_mac(packet_bytes[6:12]),



        "ethertype": ethertype,



        "ethertype_hex": f"0x{ethertype:04x}",



    }











def parse_lldp_packet(packet_bytes: bytes) -> dict[str, Any]:



    eth = parse_ethernet_header(packet_bytes)



    if eth.get("ethertype") == LLDP_ETHERTYPE:



        payload = packet_bytes[14:]



    else:



        eth = {"present": False, "length": len(packet_bytes), "note": "Input appears to be a bare LLDPDU."}



        payload = packet_bytes







    tlvs = _parse_lldp_tlvs(payload, packet_bytes)



    fields = _extract_lldp_fields(tlvs)



    _apply_field_fallbacks(fields)



    return {



        "success": True,



        "protocol": "LLDP",



        "packet": eth,
        "raw_hex": packet_bytes.hex(),



        "vendor": VendorDispatcher.identify_vendor(packet_bytes),



        "chassis_id": fields.get("chassis_id", ""),



        "port_id": fields.get("port_id", ""),



        "fields": fields,



        "tlvs": tlvs,



        "tlv_count": len(tlvs),



    }











def parse_cdp_packet(packet_bytes: bytes) -> dict[str, Any]:



    eth = parse_ethernet_header(packet_bytes)



    payload = packet_bytes[14:] if eth.get("present") else packet_bytes



    snap = None



    if payload.startswith(CDP_SNAP):



        snap = payload[:8].hex()



        payload = payload[8:]



    elif payload.startswith(b"\xaa\xaa\x03") and len(payload) >= 8:



        snap = payload[:8].hex()



        payload = payload[8:]







    if len(payload) < 4:



        return {"success": False, "protocol": "CDP", "packet": eth, "error": "CDP payload is too short.", "tlvs": []}







    header = {



        "version": payload[0],



        "ttl": payload[1],



        "checksum": f"0x{struct.unpack('!H', payload[2:4])[0]:04x}",



        "snap": snap,



    }



    tlvs = _parse_cdp_tlvs(payload[4:])



    fields = _extract_cdp_fields(tlvs)
    _apply_field_fallbacks(fields)



    return {



        "success": True,



        "protocol": "CDP",



        "packet": eth,
        "raw_hex": packet_bytes.hex(),



        "header": header,



        "vendor": "CISCO",



        "chassis_id": fields.get("device_id", ""),



        "port_id": fields.get("port_id", ""),



        "fields": fields,



        "tlvs": tlvs,



        "tlv_count": len(tlvs),



    }











def print_analysis(result: dict[str, Any], output_mode: str = "normal") -> None:



    print("\n" + "=" * 90)



    print(f"{result.get('protocol', 'UNKNOWN')} packet analysis")



    print("=" * 90)



    if not result.get("success"):



        print(f"ERROR: {result.get('error')}")



        return







    packet = result.get("packet", {})



    if packet.get("present"):



        print(f"Ethernet: {packet.get('src_mac')} -> {packet.get('dst_mac')} ({packet.get('ethertype_hex')})")







    _print_summary(result, result.get("fields", {}))



    print("-" * 90)



    print(f"TLVs: {len(result.get('tlvs', []))}")



    print_tlv_pipeline(result.get("tlvs", []), output_mode=output_mode, protocol=result.get("protocol"))



    print("=" * 90)











def clean_hex_text(text: str) -> str:



    chunks = []



    for line in text.splitlines():



        line = line.split("#", 1)[0].split("//", 1)[0].strip()



        if not line:



            continue



        parts = line.split()



        if parts and re.fullmatch(r"[0-9a-fA-F]{4,8}", parts[0]) and len(parts) > 1:



            parts = parts[1:]



        byte_tokens = [part for part in parts if re.fullmatch(r"[0-9a-fA-F]{2}", part)]



        if byte_tokens:



            chunks.extend(byte_tokens)



        else:



            compact = re.sub(r"[^0-9a-fA-F]", "", line)



            if compact:



                chunks.append(compact)







    hex_data = "".join(chunks)



    if len(hex_data) % 2:



        print("[WARNING] Offline hex data has an odd number of digits; dropping the final dangling nibble.")



        hex_data = hex_data[:-1]



    if not hex_data:



        raise ValueError("Offline file does not contain hex packet data.")



    return hex_data











def format_mac(data: bytes) -> str:



    return ":".join(f"{b:02X}" for b in data)











def _parse_lldp_tlvs(payload: bytes, packet_bytes: bytes) -> list[dict[str, Any]]:



    tlvs: list[dict[str, Any]] = []



    offset = 0



    seq = 1



    while offset + 2 <= len(payload):



        header_offset = offset



        header = struct.unpack("!H", payload[offset : offset + 2])[0]



        tlv_type = header >> 9



        tlv_len = header & 0x01FF



        offset += 2



        available = len(payload) - offset



        truncated = tlv_len > available



        value = payload[offset : offset + min(tlv_len, available)]



        tlv = {



            "seq": seq,



            "offset": header_offset,



            "header": header,



            "header_hex": f"{header:04x}",



            "bitfield": f"type={tlv_type:07b} length={tlv_len:09b}",



            "type": tlv_type,



            "length": tlv_len,



            "value_length": len(value),



            "name": _lldp_tlv_name(tlv_type),



            "category": _lldp_tlv_category(tlv_type),



            "raw_hex": value.hex(),



            "parsed": {},



            "notice": "TLV length exceeds remaining packet bytes." if truncated else None,



        }



        try:



            tlv["parsed"] = _parse_lldp_value(tlv_type, value, packet_bytes)



            if tlv_type == 127 and isinstance(tlv["parsed"], dict):



                tlv["name"] = tlv["parsed"].get("name", tlv["name"])



                tlv["category"] = _org_tlv_category(tlv["parsed"])



                tlv["parsed"].pop("name", None)



                tlv["notice"] = tlv["parsed"].get("notice") or tlv["notice"]



        except Exception as exc:



            tlv["parsed"] = {"parse_error": str(exc)}







        tlvs.append(tlv)



        seq += 1



        offset += tlv_len



        if tlv_type == 0 or truncated:



            break



    if offset < len(payload):



        trailing = payload[offset:]



        tlvs.append({



            "seq": seq,



            "offset": offset,



            "type": -1,



            "length": len(trailing),



            "value_length": len(trailing),



            "name": "Trailing bytes after TLV stream",



            "category": "Malformed/Trailing",



            "raw_hex": trailing.hex(),



            "parsed": {},



            "notice": "Bytes remain after LLDP end or malformed TLV.",



        })



    return tlvs











def _parse_lldp_value(tlv_type: int, value: bytes, packet_bytes: bytes) -> dict[str, Any]:



    if tlv_type == 0:



        return {}



    if tlv_type == 1:



        return _parse_lldp_id(value, "chassis")



    if tlv_type == 2:



        return _parse_lldp_id(value, "port")



    if tlv_type == 3 and len(value) >= 2:



        return {"ttl": int.from_bytes(value[:2], "big")}



    if tlv_type == 4:



        return {"port_description": _decode_text(value)}



    if tlv_type == 5:



        return {"system_name": _decode_text(value)}



    if tlv_type == 6:



        return {"system_description": _decode_text(value)}



    if tlv_type == 7 and len(value) >= 4:



        return {



            "supported": _decode_capabilities(int.from_bytes(value[:2], "big")),



            "enabled": _decode_capabilities(int.from_bytes(value[2:4], "big")),



            "supported_raw": f"0x{int.from_bytes(value[:2], 'big'):04x}",



            "enabled_raw": f"0x{int.from_bytes(value[2:4], 'big'):04x}",



        }



    if tlv_type == 8:



        return _parse_lldp_management_address(value)



    if tlv_type == 127:



        if len(value) < 4:



            return {"notice": "Organizational TLV is shorter than OUI+subtype.", "raw_hex": value.hex()}



        oui = ":".join(f"{b:02X}" for b in value[:3])



        subtype = value[3]



        decoded = VendorDispatcher.dispatch_tlv127(oui, subtype, value[4:], packet_bytes)



        return {



            "vendor": decoded.get("vendor"),



            "oui": oui,



            "subtype": subtype,



            "decoded": decoded.get("decoded", {}),



            "name": decoded.get("name"),



            "notice": decoded.get("notice"),



        }



    return {"raw_hex": value.hex(), "notice": "No standard LLDP parser for this TLV type."}











def _parse_lldp_id(value: bytes, field: str) -> dict[str, Any]:



    if not value:



        return {"subtype": None, f"{field}_id": ""}



    subtype = value[0]



    data = value[1:]



    # Subtype 4 (MAC) for both chassis and port: 6 bytes -> formatted MAC



    if subtype == 4 and len(data) == 6:



        decoded = format_mac(data)



    # Subtype 3 (MAC) for port ID: 6 bytes -> formatted MAC



    elif field == "port" and subtype == 3 and len(data) == 6:



        decoded = format_mac(data)



    # Subtype 5 (networkAddress) for chassis, subtype 4 (networkAddress) for port



    # First byte of data is IANA AddressFamilyNumbers, rest is the address



    elif (field == "chassis" and subtype == 5) or (field == "port" and subtype == 4):



        decoded = _decode_network_address(data)



    else:



        decoded = _decode_text(data)



    return {"subtype": subtype, f"{field}_id": decoded}











def _decode_network_address(data: bytes) -> str:



    """Decode a networkAddress value: 1-byte address family + address bytes."""



    if not data:



        return ""



    addr_family = data[0]



    addr = data[1:]



    if addr_family == 1 and len(addr) == 4:  # IPv4



        return ".".join(str(b) for b in addr)



    if addr_family == 2 and len(addr) == 16:  # IPv6



        return str(IPv6Address(addr))



    if addr_family == 6 and len(addr) == 6:  # MAC



        return format_mac(addr)



    # Unknown family or length: return hex



    return data.hex()











def _parse_lldp_management_address(value: bytes) -> dict[str, Any]:



    if len(value) < 2:



        return {"parse_error": "Management address TLV too short.", "raw_hex": value.hex()}



    addr_len = value[0]



    addr_subtype = value[1]



    # addr_len includes the subtype byte; address data is value[2 : 1+addr_len]



    if len(value) < 1 + addr_len:



        return {"parse_error": "Management address length exceeds TLV size.", "raw_hex": value.hex()}



    addr = value[2 : 1 + addr_len]



    idx = 1 + addr_len







    result: dict[str, Any] = {"address_length": addr_len, "address_subtype": addr_subtype}



    if addr_subtype == 1 and len(addr) == 4:



        result["management_address"] = ".".join(str(b) for b in addr)



    elif addr_subtype == 2 and len(addr) == 16:



        result["management_address"] = str(IPv6Address(addr))



    elif addr_subtype == 6 and len(addr) == 6:



        result["management_address"] = format_mac(addr)



    else:



        result["management_address_raw"] = addr.hex()







    # Interface numbering (subtype 1 byte + number 4 bytes = 5 bytes total)



    iface_end = idx + 5  # expected end of interface subtype+number



    if idx < len(value):



        result["interface_subtype"] = value[idx]



    if idx + 1 + 4 <= len(value):



        result["interface_number"] = int.from_bytes(value[idx + 1 : idx + 5], "big")



    else:



        # Partial or missing interface number - do not attempt OID at idx+5



        iface_end = len(value)



        result["interface_number_partial"] = True







    # OID String (1-byte length + variable OID)



    oid_start = iface_end



    if oid_start < len(value):



        oid_len = value[oid_start]



        if oid_len > 0 and oid_start + 1 + oid_len <= len(value):



            result["oid_string"] = value[oid_start + 1 : oid_start + 1 + oid_len].hex()



    return result











def _parse_cdp_tlvs(payload: bytes) -> list[dict[str, Any]]:



    tlvs: list[dict[str, Any]] = []



    offset = 0



    seq = 1



    while offset + 4 <= len(payload):



        tlv_type = struct.unpack("!H", payload[offset : offset + 2])[0]



        tlv_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]



        if tlv_len < 4:



            tlvs.append(_malformed_cdp_tlv(seq, offset, tlv_type, tlv_len, payload[offset:], "CDP TLV length is smaller than header."))



            break



        if offset + tlv_len > len(payload):



            tlvs.append(_malformed_cdp_tlv(seq, offset, tlv_type, tlv_len, payload[offset + 4 :], "CDP TLV length exceeds remaining packet bytes."))



            break



        value = payload[offset + 4 : offset + tlv_len]



        tlvs.append({



            "seq": seq,



            "offset": offset,



            "type": tlv_type,



            "length": tlv_len,



            "value_length": len(value),



            "name": _cdp_tlv_name(tlv_type),



            "category": "CDP TLV",



            "raw_hex": value.hex(),



            "parsed": _parse_cdp_value(tlv_type, value),



            "notice": None,



        })



        offset += tlv_len



        seq += 1



    if offset < len(payload):



        tlvs.append({



            "seq": seq,



            "offset": offset,



            "type": -1,



            "length": len(payload) - offset,



            "value_length": len(payload) - offset,



            "name": "Trailing CDP bytes",



            "category": "Malformed/Trailing",



            "raw_hex": payload[offset:].hex(),



            "parsed": {},



            "notice": "Bytes remain after CDP TLV parsing.",



        })



    return tlvs











def _parse_cdp_value(tlv_type: int, value: bytes) -> dict[str, Any]:



    if tlv_type in (0x0001, 0x0003, 0x0005, 0x0006, 0x0009, 0x0014):



        return {"text": _decode_text(value)}



    if tlv_type in (0x0002, 0x000E, 0x0016):



        records = _parse_cdp_addresses(value)



        return {"addresses": [item["address"] for item in records], "address_records": records}



    if tlv_type == 0x0004:



        return _decode_cdp_capabilities(value)



    if tlv_type == 0x000A and len(value) >= 2:



        return {"native_vlan": int.from_bytes(value[:2], "big")}



    if tlv_type == 0x000B and value:



        return {"duplex": "Full" if value[0] else "Half", "duplex_raw": value[0]}



    if tlv_type == 0x000F and len(value) >= 3:



        return {"voice_vlan": int.from_bytes(value[1:3], "big"), "voip_vlan_unknown": bool(value[0] & 0x20)}



    if tlv_type == 0x0010 and len(value) >= 2:



        return {"power_consumption_mw": int.from_bytes(value[:2], "big")}



    if tlv_type == 0x0011 and len(value) >= 4:



        return {"mtu": int.from_bytes(value[:4], "big")}



    if tlv_type == 0x0012 and len(value) >= 1:



        return {"trust_bitmap": f"0x{value[0]:02x}"}



    if tlv_type == 0x0013 and len(value) >= 1:



        return {"untrusted_port_cos": f"0x{value[0]:02x}"}



    if tlv_type == 0x0017:



        return {"location": _decode_cdp_location(value)}



    if tlv_type == 0x0019 and len(value) >= 6:



        return {"power_requested_mw": int.from_bytes(value[2:6], "big"), "request_id": int.from_bytes(value[:2], "big")}



    if tlv_type == 0x001A and len(value) >= 8:



        result = {"request_id": int.from_bytes(value[:2], "big"), "management_id": int.from_bytes(value[2:4], "big")}



        power_values = []



        for off in range(4, len(value) - 3, 4):



            pw = int.from_bytes(value[off:off+4], "big")



            power_values.append(pw)



        display = []



        for pw in power_values:



            if pw in (0, 0xFFFFFFFF):



                display.append("N/A")



            else:



                display.append(f"{pw} mW")



        result["power_available_display"] = ", ".join(display) if display else "None"



        result["power_available_mw"] = power_values



        return result



    return {"raw_hex": value.hex(), "notice": "No standard CDP parser for this TLV type."}











def _parse_cdp_addresses(value: bytes) -> list[dict[str, Any]]:



    records: list[dict[str, Any]] = []



    if len(value) < 4:



        return records



    count = struct.unpack("!I", value[:4])[0]



    offset = 4



    for _ in range(count):



        if offset + 3 > len(value):



            break



        protocol_type = value[offset]



        protocol_len = value[offset + 1]



        offset += 2



        protocol = value[offset : offset + protocol_len]



        offset += protocol_len



        if offset + 2 > len(value):



            break



        addr_len = struct.unpack("!H", value[offset : offset + 2])[0]



        offset += 2



        addr = value[offset : offset + addr_len]



        offset += addr_len



        record: dict[str, Any] = {



            "protocol_type": protocol_type,



            "protocol_hex": protocol.hex(),



            "length": addr_len,



            "raw_hex": addr.hex(),



        }



        if protocol_type == 1 and protocol == b"\xcc" and len(addr) == 4:



            record["family"] = "IPv4"



            record["address"] = ".".join(str(b) for b in addr)



        elif _is_cdp_ipv6_protocol(protocol) and len(addr) == 16:



            record["family"] = "IPv6"



            record["address"] = str(IPv6Address(addr))



        else:



            record["family"] = "Unknown"



            record["address"] = addr.hex()



        records.append(record)



    return records











def _extract_lldp_fields(tlvs: list[dict[str, Any]]) -> dict[str, Any]:



    fields: dict[str, Any] = {"management_addresses": []}



    for tlv in tlvs:



        parsed = tlv.get("parsed") or {}



        tlv_type = tlv.get("type")



        if tlv_type == 1:



            fields["chassis_id"] = parsed.get("chassis_id", "")



        elif tlv_type == 2:



            fields["port_id"] = parsed.get("port_id", "")



        elif tlv_type == 4:



            fields["port_description"] = parsed.get("port_description", "")



        elif tlv_type == 5:



            fields["system_name"] = parsed.get("system_name", "")



        elif tlv_type == 6:



            fields["system_description"] = parsed.get("system_description", "")



        elif tlv_type == 7:



            fields["capabilities"] = parsed



        elif tlv_type == 8 and parsed.get("management_address"):



            fields["management_addresses"].append(parsed["management_address"])



        elif tlv_type == 127 and isinstance(parsed, dict):



            _merge_vendor_fields(fields, parsed.get("decoded", {}))



    return fields











def _extract_cdp_fields(tlvs: list[dict[str, Any]]) -> dict[str, Any]:



    fields: dict[str, Any] = {"management_addresses": []}



    for tlv in tlvs:



        parsed = tlv.get("parsed") or {}



        tlv_type = tlv.get("type")



        if tlv_type == 0x0001:



            fields["device_id"] = parsed.get("text", "")



            fields["system_name"] = parsed.get("text", "")



        elif tlv_type == 0x0002:



            fields["management_addresses"].extend(parsed.get("addresses", []))



        elif tlv_type == 0x0003:



            fields["port_id"] = parsed.get("text", "")



        elif tlv_type == 0x0005:



            fields["software_version"] = parsed.get("text", "")



            fields["system_description"] = parsed.get("text", "")



        elif tlv_type == 0x0006:



            fields["platform"] = parsed.get("text", "")



        elif tlv_type == 0x000A:



            fields["native_vlan"] = parsed.get("native_vlan")



        elif tlv_type == 0x000B:



            fields["duplex"] = parsed.get("duplex")



        elif tlv_type == 0x0011:



            fields["mtu"] = parsed.get("mtu")



    return fields











def _merge_vendor_fields(fields: dict[str, Any], decoded: dict[str, Any]) -> None:



    mapping = {



        "system_name": "system_name",



        "model": "platform",



        "model_name": "platform",



        "device_model": "platform",



        "software": "software_version",



        "software_detail": "software_version",



        "software_version": "software_version",



        "main_software_version": "software_version",



        "main_rgos_version": "software_version",



        "comware_version": "software_version",



        "vrp_version_string": "software_version",



        "mgmt_ip": "management_addresses",



        "management_ip": "management_addresses",



        "serial": "serial",



        "serial_number": "serial",



        "official_serial_number": "serial",



        "port_speed": "link_speed",



        "port_speed_raw": "link_speed",



        "port_speed_bitmap": "link_bitmap",



        "speed": "link_speed",



        "duplex": "duplex",

        "pvid": "native_vlan",

        "max_frame_size": "mtu",

        "operational_mau_type_name": "mac_phy",

        "pse_power_supported": "poe_supported",

        "power_class": "power_class",



    }



    for src, dst in mapping.items():



        value = decoded.get(src)



        if value is None:



            continue



        if isinstance(value, (str, list, dict)) and not value:



            continue



        if dst == "management_addresses":



            fields.setdefault(dst, [])



            if value not in fields[dst]:



                fields[dst].append(value)



        elif not fields.get(dst):



            fields[dst] = value

    # Handle aggregation specially: use _format_lag_status for proper human-readable string
    if "aggregation_capable" in decoded:
        fields["aggregation"] = _format_lag_status(decoded)
    elif "aggregation_enabled" in decoded:
        fields["aggregation"] = _format_lag_status(decoded)











def _apply_field_fallbacks(fields: dict[str, Any]) -> None:



    if fields.get("platform") or not fields.get("system_description"):



        return



    patterns = [



        r"Huawei\s+Switch\s+([A-Za-z0-9][A-Za-z0-9._/-]+)",



        r"\b(H3C\s+[A-Za-z0-9][A-Za-z0-9._/-]+)",



        r"\b(RG-[A-Za-z0-9][A-Za-z0-9._/-]+)",



        r"\b(qfx[0-9a-z-]+)\b",



    ]



    for pattern in patterns:



        match = re.search(pattern, fields["system_description"], flags=re.IGNORECASE)



        if match:



            fields["platform"] = match.group(1) if match.lastindex else match.group(0)



            return











def _print_summary(result: dict[str, Any], fields: dict[str, Any]) -> None:



    rows = [



        ("Protocol", result.get("protocol")),



        ("Vendor", result.get("vendor", "UNKNOWN")),



        ("Device ID", fields.get("device_id") or fields.get("system_name") or result.get("chassis_id") or "Unknown"),



        ("Port ID", result.get("port_id") or fields.get("port_id") or "Unknown"),



        ("Address", fields.get("management_addresses")),



        ("Platform", fields.get("platform")),



        ("Serial", fields.get("serial")),



        ("Software", fields.get("software_version") or fields.get("system_description")),



        ("Link", _format_link_summary(fields)),



        ("Native VLAN", fields.get("native_vlan")),



        ("MTU", fields.get("mtu")),



    ]



    for label, value in rows:



        if value not in (None, "", [], {}):



            print(f"{label:<12}: {_display_value(value)}")











def _print_tlv_details(tlv: dict[str, Any]) -> None:



    parsed = tlv.get("parsed")



    if not parsed:



        return



    if tlv.get("type") == 127 and isinstance(parsed, dict):



        org = [str(parsed.get("vendor")), str(parsed.get("oui")), f"subtype={parsed.get('subtype')}"]



        print(f"     org: {' / '.join(item for item in org if item and item != 'None')}")



        if parsed.get("decoded"):



            print(f"     decoded: {_display_value(parsed['decoded'])}")



        return



    if isinstance(parsed, dict):



        print(f"     parsed: {_display_value(parsed)}")



    else:



        print(f"     parsed: {parsed}")











def print_tlv_pipeline(tlvs: list[dict[str, Any]], output_mode: str = "normal", protocol: str | None = None) -> None:



    for tlv in tlvs:



        print_tlv(tlv, output_mode=output_mode, protocol=protocol)











def print_tlv(tlv: dict[str, Any], output_mode: str = "normal", protocol: str | None = None) -> None:



    print(f"TLV#{tlv['seq']:02d} [{_short_category(tlv)}]")



    if output_mode in {"verbose", "debug"}:



        print(f"  Type: {_format_tlv_type(protocol, tlv['type'])}")



        print(f"  Len: {tlv['length']}")



        subtype = _tlv_subtype(tlv)



        if subtype is not None:



            print(f"  Subtype: {subtype}")







    label, value = _natural_tlv_value(tlv)



    if label and value not in (None, "", [], {}):



        print(f"  {label}: {_display_value(value)}")



        extra = _verbose_extra_tlv_value(tlv, label)



        if output_mode in {"verbose", "debug"} and extra:



            for extra_label, extra_value in extra:



                print(f"  {extra_label}: {_display_value(extra_value)}")



    elif tlv.get("notice"):



        print(f"  Notice: {tlv['notice']}")







    if output_mode == "debug":



        if "offset" in tlv:



            print(f"  Offset: {tlv['offset']}")



        if tlv.get("header_hex"):



            print(f"  Header: 0x{tlv['header_hex']}")



        if tlv.get("bitfield"):



            print(f"  Bitfield: {tlv['bitfield']}")



        print(f"  Raw: {tlv.get('raw_hex', '')}")



        if tlv.get("notice") and label:



            print(f"  Notice: {tlv['notice']}")



    print()











def _short_category(tlv: dict[str, Any]) -> str:



    tlv_type = tlv.get("type", 0)



    category = tlv.get("category", "")



    name = tlv.get("name", "")







    if category == "End TLV":



        return f"Type 0 - End"







    if category == "IEEE 802.1AB Standard TLV":



        return f"Type {tlv_type} - {name}"







    if category in ("IEEE 802.1 Organizational TLV", "IEEE 802.3 Organizational TLV"):



        std = "802.1" if "802.1" in category else "802.3"



        short = name



        for prefix in ("IEEE 802.1 ", "IEEE 802.3 "):



            if short.startswith(prefix):



                short = short[len(prefix):]



                break



        return f"Type 127, {std} - {short}"







    if category.endswith(" Vendor TLV"):



        vendor = category.split()[0]



        short = name



        for sep in (



            "Ruijie - ",

            "Juniper - ",

            "HUAWEI - ",

            "H3C - ",

            "CISCO - ",



            "锐捷私有扩展 - ",

            "华为私有扩展 - ",

            "H3C私有扩展 - ",

            "Juniper私有扩展 - ",



            " proprietary - ",

            " Private Extension ",

            " Shared Extension ",



        ):



            if sep in short:



                short = short.split(sep)[-1]



                break



        return f"Type 127, {vendor} - {short}"







    if category == "CDP TLV":



        return f"Type 0x{tlv_type:04X} - {name}"







    if name and category not in ("", "Reserved/Unknown TLV"):



        return f"Type {tlv_type} - {name}"







    return category or "Unknown"



















def _tlv_subtype(tlv: dict[str, Any]) -> Any:



    parsed = tlv.get("parsed")



    if not isinstance(parsed, dict):



        return None



    if tlv.get("type") == 127:



        return parsed.get("subtype")



    return parsed.get("subtype")











def _natural_tlv_value(tlv: dict[str, Any]) -> tuple[str, Any]:



    parsed = tlv.get("parsed")



    if tlv.get("type") == 0:



        return "End", "LLDPDU"



    if not isinstance(parsed, dict):



        return tlv.get("name", "Value"), parsed







    tlv_type = tlv.get("type")



    # CDP TLV display (type numbers overlap with LLDP; use category to distinguish)



    if tlv.get("category") == "CDP TLV":



        return _natural_cdp_tlv_value(tlv_type, parsed)







    if tlv_type == 1:



        return "Chassis ID", parsed.get("chassis_id")



    if tlv_type == 2:



        return "Port ID", parsed.get("port_id")



    if tlv_type == 3:



        return "TTL", parsed.get("ttl")



    if tlv_type == 4:



        return "Port Description", parsed.get("port_description")



    if tlv_type == 5:



        return "System Name", parsed.get("system_name")



    if tlv_type == 6:



        return "System Description", parsed.get("system_description")



    if tlv_type == 7:



        return "Capabilities", _format_capability_value(parsed)



    if tlv_type == 8:



        return "Management Address", parsed.get("management_address") or parsed.get("management_address_raw")



    if tlv_type == 127:



        decoded = parsed.get("decoded", {})



        return _natural_org_label(tlv, parsed), _natural_org_value(decoded)



    if "raw_hex" in parsed:



        return "Raw", parsed.get("raw_hex")



    return tlv.get("name", "Value"), parsed











def _natural_cdp_tlv_value(tlv_type: int, parsed: dict[str, Any]) -> tuple[str, Any]:



    """CDP-specific TLV value display - clean label/value pairs."""



    if tlv_type in (0x0001, 0x0003):



        return ("Device ID" if tlv_type == 0x0001 else "Port ID"), parsed.get("text")



    if tlv_type in (0x0002, 0x000E, 0x0016):



        return "Address", parsed.get("addresses")



    if tlv_type == 0x0004:



        return "Capabilities", parsed.get("capabilities", parsed.get("capabilities_raw"))



    if tlv_type in (0x0005, 0x0006):



        return ("Software" if tlv_type == 0x0005 else "Platform"), parsed.get("text")



    if tlv_type == 0x0009:



        return "VTP Domain", parsed.get("text")



    if tlv_type == 0x000A:



        return "Native VLAN", parsed.get("native_vlan")



    if tlv_type == 0x000B:



        return "Duplex", parsed.get("duplex")



    if tlv_type == 0x000F:



        return "Voice VLAN", parsed.get("voice_vlan")



    if tlv_type == 0x0010:



        return "Power", parsed.get("power_consumption_mw")



    if tlv_type == 0x0011:



        return "MTU", parsed.get("mtu")



    if tlv_type == 0x0012:



        return "Trust Bitmap", parsed.get("trust_bitmap")



    if tlv_type == 0x0013:



        return "Untrusted CoS", parsed.get("untrusted_port_cos")



    if tlv_type == 0x0014:



        return "System Name", parsed.get("text")



    if tlv_type == 0x0017:



        return "Location", parsed.get("location")



    if tlv_type == 0x0019:



        return "Power Requested", parsed.get("power_requested_mw")



    if tlv_type == 0x001A:



        return "Power Available", parsed.get("power_available_display", parsed.get("power_available_mw"))



    if "raw_hex" in parsed:



        return "Raw", parsed["raw_hex"]



    return "Value", parsed







def _format_poe_summary(decoded: dict[str, Any]) -> str:



    """Format Power via MDI fields into a human-readable summary."""



    pse_class = decoded.get("pse_port_class", "")



    power_class = decoded.get("power_class", "")



    supported = decoded.get("pse_power_supported", False)



    enabled = decoded.get("pse_enabled", False)



    if not supported:



        return "Not supported"



    parts = [f"{pse_class} Class {power_class}"]



    if enabled:



        parts.append("Enabled")



    pd_power = decoded.get("pd_requested_power")



    if pd_power is not None:



        parts.append(f"{pd_power * 0.1:.1f}W")



    return ", ".join(parts)











def _natural_org_label(tlv: dict[str, Any], parsed: dict[str, Any]) -> str:



    decoded = parsed.get("decoded", {})



    name = tlv.get("name", "")



    label_by_key = {



        "operational_mau_type_name": "MAC/PHY",



        "aggregation_capable": "Link Aggregation",



        "pvid": "PVID",



        "ppvid": "PPVID",



        "vlan_name": "VLAN Name",



        "vlan_id": "VLAN ID",



        "max_frame_size": "MTU",



        "serial_number": "Serial",



        "official_serial_number": "Serial",



        "model_name": "Model",



        "device_model": "Model",



        "main_rgos_version": "Software",



        "backup_rgos_version": "Backup Software",



        "main_software_version": "Software",



        "comware_version": "Software",



        "vrp_version_string": "Software",



        "manufacturer": "Manufacturer",



        "aggregated_port_id": "Link Aggregation",



        "poe_class": "PoE / Hardware Feature",



        "speed": "Link",



        "port_speed_bitmap": "Link Bitmap",



        "port_speed_raw": "Link",



        "port_speed": "Link",



        "bootrom_version": "BootROM",



        "hardware_feature_id": "Hardware Feature",



        "internal_index": "Internal Index",



        "reserved_status": "Reserved",



    }



    for key, label in label_by_key.items():



        if key in decoded:



            return label



    if parsed.get("oui") == "00:12:0F" and "MAC/PHY" in name:



        return "MAC/PHY"



    return name or "Organization TLV"











def _natural_org_value(decoded: dict[str, Any]) -> Any:



    if decoded.get("operational_mau_type_name"):



        return _format_mac_phy_capabilities(decoded)



    if "aggregation_capable" in decoded:



        return _format_lag_status(decoded)



    # Juniper DCBXP capability bitmap



    if decoded.get("structure_type") == "CAPABILITY_BITMAP" and decoded.get("features"):



        model = decoded.get("device_model", "unknown")



        fw = decoded.get("software_version", "unknown")



        bitmap = decoded.get("capability_bitmap", "")



        schema = decoded.get("schema_source", "")



        features = ", ".join(decoded["features"])



        parts = [f"Bitmap {bitmap}"]



        if model != "unknown":



            parts.append(f"Model {model}")



        if fw != "unknown":



            parts.append(f"FW {fw}")



        parts.append(f"[{features}]")



        parts.append(f"({schema})")



        return " | ".join(parts)



    if decoded.get("hardware_feature_status") == "unresolved":



        return f"{decoded.get('hardware_feature_id')} (unresolved)"



    if decoded.get("internal_index") is not None and decoded.get("internal_index_hex"):



        return f"{decoded['internal_index']} ({decoded['internal_index_hex']})"



    if decoded.get("reserved_status") is not None and decoded.get("reserved_meaning"):



        return f"{decoded['reserved_status']} ({decoded['reserved_meaning']})"







    preferred_keys = [



        "pvid",



        "ppvid",



        "vlan_name",



        "max_frame_size",



        "serial_number",



        "official_serial_number",



        "model_name",



        "device_model",



        "main_rgos_version",



        "backup_rgos_version",



        "main_software_version",



        "comware_version",



        "vrp_version_string",



        "manufacturer",



        "aggregated_port_id",



        "speed",



        "port_speed_bitmap",



        "port_speed_raw",



        "port_speed",



        "bootrom_version",



        "hardware_feature_id",



        "internal_index",



        "reserved_status",



        "pse_port_class",



        "power_class",



        "mdi_power_support_raw",



        "internal_version",



        "asset_control",



        "dcbxp_data",



        "protocol_identity",



        "vid_usage_digest",



        "management_vid",



        "eee_tx_tw",



    ]



    for key in preferred_keys:



        if decoded.get(key) not in (None, "", [], {}):



            if key == "speed" and decoded.get("duplex"):



                return f"{decoded['speed']} {decoded['duplex']}"



            if key == "pse_port_class":



                return _format_poe_summary(decoded)



            return decoded[key]



    return decoded











def _format_link_summary(fields: dict[str, Any]) -> str:



    speed = fields.get("link_speed")



    duplex = fields.get("duplex")



    if speed and duplex:



        return f"{speed} {duplex}"



    return speed or ""











def _format_mac_phy_capabilities(decoded: dict[str, Any]) -> str:



    capabilities = decoded.get("pmd_auto_negotiation_capabilities", [])



    rates = []



    for rate in ("10", "100", "1000"):



        if any(item.startswith(f"{rate}BASE-T") for item in capabilities):



            rates.append(rate)







    duplex = []



    if any("full duplex" in item for item in capabilities):



        duplex.append("Full")



    if any("half duplex" in item for item in capabilities):



        duplex.append("Half")







    extras = []



    if any("pause" in item.lower() for item in capabilities):



        extras.append("Pause")







    parts = []



    if rates:



        parts.append(f"{'/'.join(rates)}BASE-T")



    if duplex:



        parts.append("/".join(duplex))



    parts.extend(extras)



    return ", ".join(parts) if parts else _display_value(capabilities)











def _format_lag_status(decoded: dict[str, Any]) -> str:



    if not decoded.get("aggregation_capable"):



        return "Not Supported"



    if decoded.get("aggregation_enabled"):



        bundle_id = decoded.get("aggregated_port_id")



        return f"Active (Bundle ID: {bundle_id})" if bundle_id else "Active"



    return "Enabled (Standalone)"











def _verbose_extra_tlv_value(tlv: dict[str, Any], primary_label: str) -> list[tuple[str, Any]]:



    parsed = tlv.get("parsed")



    if not isinstance(parsed, dict) or tlv.get("type") != 127:



        return []



    decoded = parsed.get("decoded", {})



    if not isinstance(decoded, dict):



        return []



    extras = []



    if primary_label == "Link" and decoded.get("port_speed_bitmap"):



        extras.append(("Bitmap", decoded["port_speed_bitmap"]))



    return extras











def _format_capability_value(parsed: dict[str, Any]) -> str:



    supported = parsed.get("supported", [])



    enabled = parsed.get("enabled", [])



    if supported == enabled:



        return ", ".join(supported)



    sup = ", ".join(supported)



    ena = ", ".join(enabled)



    return f"supported: [{sup}], enabled: [{ena}]"











def _format_tlv_type(protocol: str | None, tlv_type: int) -> str:



    if tlv_type < 0:



        return str(tlv_type)



    return f"0x{tlv_type:04x}" if protocol == "CDP" else str(tlv_type)











def _looks_like_lldpdu(packet_bytes: bytes) -> bool:



    if len(packet_bytes) < 2:



        return False



    first_header = struct.unpack("!H", packet_bytes[:2])[0]



    first_type = first_header >> 9



    first_len = first_header & 0x01FF



    return first_type == 1 and 1 <= first_len <= len(packet_bytes) - 2











def _decode_text(data: bytes) -> str:



    return data.decode("utf-8", errors="replace").strip("\x00").strip()











def _display_value(value: Any) -> str:



    if isinstance(value, list):



        return ", ".join(str(v) for v in value)



    if isinstance(value, dict):



        return ", ".join(f"{k}={_display_value(v)}" for k, v in value.items() if v not in (None, "", [], {}))



    text = str(value)



    return text if len(text) <= 180 else text[:177] + "..."











def _lldp_tlv_name(tlv_type: int) -> str:



    return {



        0: "End of LLDPDU",



        1: "Chassis ID",



        2: "Port ID",



        3: "Time To Live",



        4: "Port Description",



        5: "System Name",



        6: "System Description",



        7: "System Capabilities",



        8: "Management Address",



        127: "Organizationally Specific",



    }.get(tlv_type, f"Reserved/Unknown LLDP TLV type {tlv_type}")











def _lldp_tlv_category(tlv_type: int) -> str:



    if tlv_type == 0:



        return "End TLV"



    if 1 <= tlv_type <= 8:



        return "IEEE 802.1AB Standard TLV"



    if tlv_type == 127:



        return "Organizational TLV"



    return "Reserved/Unknown TLV"











def _org_tlv_category(parsed: dict[str, Any]) -> str:



    oui = parsed.get("oui")



    vendor = parsed.get("vendor")



    if oui == "00:80:C2":



        return "IEEE 802.1 Organizational TLV"



    if oui == "00:12:0F":



        return "IEEE 802.3 Organizational TLV"



    if vendor and vendor not in {"UNKNOWN", "IEEE_8021", "IEEE_8023"}:



        return f"{vendor} Vendor TLV"



    return "Organizational TLV"











def _cdp_tlv_name(tlv_type: int) -> str:



    return {



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



        0x000E: "VoIP VLAN Reply",



        0x000F: "VoIP VLAN Query",



        0x0010: "Power Consumption",



        0x0011: "MTU",



        0x0012: "Trust Bitmap",



        0x0013: "Untrusted Port CoS",



        0x0014: "System Name",



        0x0015: "System OID",



        0x0016: "Management Address",



        0x0017: "Location",



        0x0018: "External Port-ID",



        0x0019: "Power Requested",



        0x001A: "Power Available",



        0x001B: "Port Unidirectional",



        0x001D: "EnergyWise",



        0x001F: "Spare Pair PoE",



    }.get(tlv_type, f"Unknown CDP TLV type 0x{tlv_type:04x}")











def _decode_cdp_capabilities(value: bytes) -> dict[str, Any]:



    """Decode CDP Capabilities TLV per packet-cdp.c bit definitions."""



    if len(value) < 4:



        return {"capabilities_raw": f"0x{value.hex()}"}



    caps = int.from_bytes(value[:4], "big")



    cap_bits = [



        (0x00000001, "Router"), (0x00000002, "Transparent Bridge"),



        (0x00000004, "Source Route Bridge"), (0x00000008, "Switch"),



        (0x00000010, "Host"), (0x00000020, "IGMP Capable"),



        (0x00000040, "Repeater"), (0x00000080, "VoIP Phone"),



        (0x00000100, "Remotely Managed"), (0x00000200, "CVTA"),



        (0x00000400, "MAC Relay"),



    ]



    enabled = [name for bit, name in cap_bits if caps & bit]



    return {"capabilities_raw": f"0x{caps:08x}", "capabilities": enabled}











def _decode_cdp_location(value: bytes) -> str:



    """Decode CDP Location TLV (type 0x0017)."""



    if len(value) < 1:



        return ""



    loc_type = value[0]



    if loc_type == 0 and len(value) > 1:



        return value[1:].decode("utf-8", errors="replace")



    return value.hex()











def _decode_capabilities(bits: int) -> list[str]:



    names = [



        (0x0001, "Other"),



        (0x0002, "Repeater"),



        (0x0004, "Bridge"),



        (0x0008, "WLAN AP"),



        (0x0010, "Router"),



        (0x0020, "Telephone"),



        (0x0040, "DOCSIS cable device"),



        (0x0080, "Station only"),



        (0x0100, "C-VLAN"),



        (0x0200, "S-VLAN"),



        (0x0400, "TPMR"),



    ]



    return [name for bit, name in names if bits & bit]











def _is_cdp_ipv6_protocol(protocol: bytes) -> bool:



    return protocol.endswith(b"\x86\xdd") or protocol in {



        b"\xaa\xaa\x03\x00\x00\x00\x86\xdd",



        b"\xaa\xaa\x03\x00\x00\x00\x08\x00",



    }











def _malformed_cdp_tlv(seq: int, offset: int, tlv_type: int, tlv_len: int, value: bytes, notice: str) -> dict[str, Any]:



    return {



        "seq": seq,



        "offset": offset,



        "type": tlv_type,



        "length": tlv_len,



        "value_length": len(value),



        "name": _cdp_tlv_name(tlv_type),



        "category": "Malformed/Trailing",



        "raw_hex": value.hex(),



        "parsed": {},



        "notice": notice,



    }



