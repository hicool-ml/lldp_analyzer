#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
华为专用LLDP解析引擎
基于真实华为 S12700E VRP 报文结构严格对齐的封闭子程序
"""

import struct
from typing import Dict, Tuple, Any


class HuaweiDecoder:
    """华为LLDP报文专用解析器"""

    @staticmethod
    def decode_mgmt_address(value: bytes, addr_len: int) -> Dict[str, Any]:
        """
        根据华为真机报文严格对齐的 TLV 8 解析
        报文样例：05 01 c0 a8 a8 f2 02 00 00 02 1f 11 06 0f 2b 06 01 04 01 8f 5b ...

        字节流结构：
        - Byte 0: 地址长度 (05)
        - Byte 1: 地址子类型 (01 = IPv4)
        - Bytes 2-5: IPv4地址 (c0 a8 a8 f2 = 192.168.168.242)
        - Bytes 6-9: 接口子类型 + ifIndex (02 00 00 02 1f)
        - Bytes 10+: SNMP OID路径 (06 0f 2b 06 01 04 01 8f 5b ...)
        """
        result = {}
        try:
            if len(value) < 2:
                return result

            # 1. 基础网络地址解析 (指针从第2字节开始，切出网络层地址)
            addr_subtype = value[1]
            # addr_len 包括了 addr_subtype，所以实际地址长度是 addr_len - 1
            addr_bytes = value[2 : 1 + addr_len]

            if addr_subtype == 1 and len(addr_bytes) == 4:    # IPv4
                result["management_ip"] = ".".join(str(b) for b in addr_bytes)
            elif addr_subtype == 2 and len(addr_bytes) == 16:  # IPv6
                parts = [addr_bytes[i:i+2] for i in range(0, 16, 2)]
                result["management_ip"] = ":".join(f"{int.from_bytes(p,'big'):x}" for p in parts if p)
            elif addr_subtype == 6:                            # MAC
                result["management_ip"] = ":".join(f"{b:02x}" for b in addr_bytes)

            # 2. 动态计算接口（Interface）信息的指针
            # 刚好落在第 1 + addr_len 字节
            idx = 1 + addr_len
            if idx + 5 <= len(value):
                result["if_subtype"] = value[idx]
                result["if_index"] = int.from_bytes(value[idx+1 : idx+5], "big")

                # 3. 动态剥离华为特有的尾部 SNMP OID 路径（彻底消灭尾部乱码）
                oid_idx = idx + 5
                if oid_idx < len(value):
                    oid_len = value[oid_idx]
                    oid_payload = value[oid_idx + 1 : oid_idx + 1 + oid_len]
                    if oid_payload:
                        # 转换成干净的十六进制表示，不再盲目打印ASCII乱码
                        result["snmp_oid"] = oid_payload.hex()

        except Exception as e:
            result["parse_error"] = f"Huawei Mgmt Parse Error: {str(e)}"

        return result

    @staticmethod
    def decode_tlv127(subtype: int, value: bytes, oui: str = "00:12:BB") -> Tuple[str, Dict[str, Any]]:
        """
        华为私有 OUI (00:12:bb) 的子程序
        针对华为 VRP 系统发出的扩展字段进行清洗
        """
        name = f"Huawei Private Extension (Subtype {subtype})"
        parsed_data = {}

        try:
            # 字符串类型的 Subtype (5: BootROM, 6: 主系统, 7: VRP版本, 9: 制造商)
            if subtype in [5, 6, 7, 9]:
                decoded_text = value.decode('ascii', errors='replace').strip('\x00')
                # 过滤掉非打印字符
                decoded_text = "".join(c for c in decoded_text if c.isprintable())

                if subtype == 5:
                    name = "华为私有扩展 - BootROM版本"
                    parsed_data["bootrom_version"] = decoded_text
                elif subtype == 6:
                    name = "华为私有扩展 - 主用软件版本"
                    parsed_data["firmware_revision"] = decoded_text
                elif subtype == 7:
                    name = "华为私有扩展 - VRP系统运行版本详细信息"
                    parsed_data["vrp_version_string"] = decoded_text
                elif subtype == 9:
                    name = "华为私有扩展 - 设备制造商"
                    parsed_data["manufacturer"] = decoded_text

            elif subtype == 1:  # 硬件特性ID
                name = "华为私有扩展 - 硬件特性标识"
                parsed_data["hardware_feature_id"] = f"0x{value.hex()}"

            elif subtype == 4:  # 内部接口索引
                name = "华为私有扩展 - 内部接口索引"
                if len(value) >= 2:
                    parsed_data["internal_index"] = int.from_bytes(value[:2], "big")
                    if len(value) > 2:
                        parsed_data["extra_bytes"] = value[2:].hex()

            elif subtype == 8:  # 资产控制位
                name = "华为私有扩展 - 资产控制位"
                if len(value) >= 1:
                    parsed_data["asset_control"] = f"0x{value[0]:02x}"

            elif subtype == 10:  # 设备型号
                name = "华为私有扩展 - 精确设备型号"
                decoded_text = value.decode('ascii', errors='replace').strip('\x00').strip()
                decoded_text = "".join(c for c in decoded_text if c.isprintable())
                parsed_data["model_name"] = decoded_text

            elif subtype == 11:  # 保留状态位
                name = "华为私有扩展 - 保留状态"
                parsed_data["reserved_status"] = f"0x{value.hex()}"

            else:
                parsed_data["raw_hex"] = value.hex()

        except Exception as e:
            parsed_data["parse_error"] = str(e)
            parsed_data["raw_hex"] = value.hex()

        return name, parsed_data

    @staticmethod
    def get_vendor_ouis() -> list:
        """返回华为使用的OUI列表"""
        return ["00:e0:fc", "00:12:bb"]

    @staticmethod
    def matches_fingerprint(packet_bytes: bytes) -> bool:
        """
        检查报文是否符合华为设备指纹
        华为特征：System Description包含"Huawei"、"VRP"等关键词
        """
        try:
            return b"Huawei" in packet_bytes or b"VRP" in packet_bytes
        except:
            return False
