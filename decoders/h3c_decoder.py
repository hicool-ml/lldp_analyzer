#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H3C专用LLDP解析引擎
基于真实H3C Comware设备报文结构严格对齐的封闭子程序
"""

from typing import Dict, Tuple, Any


class H3CDecoder:
    """H3C LLDP报文专用解析器"""

    @staticmethod
    def decode_mgmt_address(value: bytes, addr_len: int) -> Dict[str, Any]:
        """
        H3C标准管理地址解析（结构相对简单，通常不带复杂OID）
        """
        result = {}
        try:
            if len(value) < 2:
                return result

            addr_subtype = value[1]
            addr_bytes = value[2:2 + addr_len]

            if addr_subtype == 1 and len(addr_bytes) == 4:  # IPv4
                result["ipv4"] = ".".join(str(b) for b in addr_bytes)
            elif addr_subtype == 2 and len(addr_bytes) == 16:  # IPv6
                parts = [addr_bytes[i:i+2] for i in range(0, 16, 2)]
                result["ipv6"] = ":".join(f"{int.from_bytes(p,'big'):x}" for p in parts if p)
            elif addr_subtype == 6:  # MAC
                result["mac"] = ":".join(f"{b:02x}" for b in addr_bytes)

            # H3C的接口信息处理
            idx = 1 + addr_len
            if idx + 5 <= len(value):
                result["if_subtype"] = value[idx]
                result["ifIndex"] = int.from_bytes(value[idx+1:idx+5], 'big')

        except Exception as e:
            result["parse_error"] = str(e)

        return result

    @staticmethod
    def decode_tlv127(subtype: int, value: bytes, oui: str = "00:12:BB") -> Tuple[str, Dict[str, Any]]:
        """
        H3C私有 OUI (00:12:bb) 的TLV #127解析

        H3C主要使用00:12:bb OUI，需要与华为、锐捷的相同OUI区分
        """
        name = f"H3C Private Extension (Subtype {subtype})"
        parsed_data = {}

        # 【核心防御】：智能检测并剥离OUI+Subtype头部
        if len(value) >= 4 and value[0:3] == b'\x00\x12\xbb':
            payload = value[4:]  # 剥离头部
        else:
            payload = value      # 主程序已经剥离过了，直接使用

        try:
            # 字符串类型的 Subtype (5, 6, 7, 8, 9, 10)
            if subtype in [5, 6, 7, 8, 9, 10]:
                decoded_text = payload.decode('ascii', errors='replace').strip('\x00').strip()
                # 过滤掉非打印字符
                decoded_text = "".join(c for c in decoded_text if c.isprintable())

                if subtype == 5:
                    name = "H3C私有扩展 - BootROM/版本信息"
                    parsed_data["bootrom_version"] = decoded_text
                elif subtype == 6:
                    name = "H3C私有扩展 - 内部版本号"
                    parsed_data["internal_version"] = decoded_text
                elif subtype == 7:
                    name = "H3C私有扩展 - Comware软件版本"
                    parsed_data["comware_version"] = decoded_text
                elif subtype == 8:
                    name = "H3C私有扩展 - 设备序列号/SN"
                    parsed_data["serial_number"] = decoded_text
                elif subtype == 9:
                    name = "H3C私有扩展 - 厂商名称"
                    parsed_data["manufacturer"] = decoded_text
                elif subtype == 10:
                    name = "H3C私有扩展 - 精确设备型号"
                    parsed_data["model_name"] = decoded_text

            elif subtype == 1:  # 硬件特性ID
                name = "H3C私有扩展 - 硬件特性ID"
                parsed_data["hardware_feature_id"] = f"0x{payload.hex()}"

            elif subtype == 4:  # 内部接口索引
                name = "H3C私有扩展 - 内部接口索引"
                if len(payload) >= 3:
                    internal_index = int.from_bytes(payload[:3], 'big')
                    parsed_data["internal_index"] = internal_index
                else:
                    parsed_data["raw_hex"] = payload.hex()

            elif subtype == 11:  # 保留状态位
                name = "H3C私有扩展 - 保留状态位"
                try:
                    # ASCII/Hex自适应探测 - 华三可能填充纯文本如"Unknown"
                    decoded_text = payload.decode('ascii', errors='strict').strip('\x00').strip()
                    if decoded_text and all(c.isprintable() for c in decoded_text):
                        parsed_data["reserved_status"] = decoded_text
                    else:
                        # 如果不是有效ASCII文本，则显示为hex
                        parsed_data["reserved_status"] = f"0x{payload.hex()}"
                except (UnicodeDecodeError, ValueError):
                    # ASCII解码失败，作为hex处理
                    parsed_data["reserved_status"] = f"0x{payload.hex()}"

            else:
                parsed_data["raw_hex"] = payload.hex()

        except Exception as e:
            parsed_data["parse_error"] = str(e)
            parsed_data["raw_hex"] = payload.hex()

        return name, parsed_data

    @staticmethod
    def get_vendor_ouis() -> list:
        """返回H3C使用的OUI列表"""
        return ["00:12:bb", "00:00:00"]  # H3C主要使用共用OUI

    @staticmethod
    def matches_fingerprint(packet_bytes: bytes) -> bool:
        """
        检查报文是否符合H3C设备指纹

        H3C特征：System Description包含"H3C"、"Comware"等关键词
        """
        try:
            h3c_keywords = [b"H3C", b"h3c", b"Comware", b"comware"]
            return any(keyword in packet_bytes for keyword in h3c_keywords)
        except:
            return False
