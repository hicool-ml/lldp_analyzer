#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Semantic Inference Engine.

Architecture:
  TLV → Feature Extraction → Rule Engine (Priority-based) →
  DeviceType → PortRole → Dynamic Confidence → Intent

Self-contained: only depends on stdlib.
The adapter that feeds protocol_parser dicts lives in decision_engine.py.
"""

from dataclasses import dataclass
from typing import List, Optional, Set
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PortRole(Enum):
    ACCESS_TERMINAL = "Access Terminal"
    ACCESS_WIRELESS = "Access Wireless"
    ACCESS_VOICE = "Access Voice"
    TRUNK_NATIVE = "Trunk (Native)"
    TRUNK_NO_NATIVE = "Trunk (No Native)"
    UPLINK_LAG = "Uplink (LAG)"
    UPLINK_SINGLE = "Uplink (Single)"
    CORE_DISTRIBUTION = "Core/Distribution"
    STORAGE_NETWORK = "Storage Network"
    INFRASTRUCTURE = "Infrastructure"
    UNKNOWN = "Unknown"


class DeviceType(Enum):
    ACCESS_POINT = "Access Point"
    IP_PHONE = "IP Phone"
    SWITCH = "Switch"
    ROUTER = "Router"
    FIREWALL = "Firewall"
    SERVER = "Server"
    STORAGE = "Storage"
    TERMINAL = "Terminal"
    UNKNOWN = "Unknown"


class NetworkIntent(Enum):
    TERMINAL_ACCESS = "Terminal Access"
    WIRELESS_ACCESS = "Wireless Access"
    VOICE_PROVISIONING = "Voice Provisioning"
    TRUNK_TRANSPORT = "Trunk Transport"
    UPLINK_REDUNDANCY = "Uplink Redundancy"
    HIGH_SPEED_STORAGE = "High-Speed Storage"
    NETWORK_MANAGEMENT = "Network Management"


class RuleID(Enum):
    def __new__(cls, value, description):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.description = description
        return obj

    RULE_AGGREGATION = ("RULE_AGGREGATION", "Link aggregation -> uplink")
    RULE_PROTOCOL_VLAN = ("RULE_PROTOCOL_VLAN", "Protocol VLAN -> trunk")
    RULE_HIGH_MTU_SPEED = ("RULE_HIGH_MTU_SPEED", "High MTU + high speed -> storage/uplink")
    RULE_ROUTER_CAPABILITY = ("RULE_ROUTER_CAPABILITY", "Router capability -> uplink")
    RULE_DEVTYPE_AP = ("RULE_DEVTYPE_AP", "Device=AP -> wireless access")
    RULE_DEVTYPE_PHONE = ("RULE_DEVTYPE_PHONE", "Device=Phone -> voice access")
    RULE_DEVTYPE_SWITCH = ("RULE_DEVTYPE_SWITCH", "Device=Switch/Router -> core")
    RULE_PORT_VLAN_ONLY = ("RULE_PORT_VLAN_ONLY", "Port VLAN only -> access")
    RULE_POE_LOWSPEED = ("RULE_POE_LOWSPEED", "PoE + low speed -> terminal")
    RULE_HIGHSPEED_BRIDGE = ("RULE_HIGHSPEED_BRIDGE", "10G+bridge -> core")
    RULE_MULTIVLAN_BRIDGE = ("RULE_MULTIVLAN_BRIDGE", "Multi-VLAN bridge -> core switch")
    RULE_MGMTIP_HIGHSPEED = ("RULE_MGMTIP_HIGHSPEED", "Mgmt IP + high speed -> infrastructure")
    RULE_DEVTYPE_POE_WLAN = ("RULE_DEVTYPE_POE_WLAN", "PoE+wlan -> AP")
    RULE_DEVTYPE_POE_NOWLAN = ("RULE_DEVTYPE_POE_NOWLAN", "PoE no wlan -> phone")
    RULE_DEVTYPE_ROUTER = ("RULE_DEVTYPE_ROUTER", "Router cap -> Router")
    RULE_DEVTYPE_BRIDGE_AGG = ("RULE_DEVTYPE_BRIDGE_AGG", "Bridge+agg -> Switch")
    RULE_DEVTYPE_JUMBO = ("RULE_DEVTYPE_JUMBO", "Jumbo+10G -> Storage")
    RULE_DEVTYPE_BRIDGE = ("RULE_DEVTYPE_BRIDGE", "Bridge -> Switch")
    RULE_DEVTYPE_MGMTIP = ("RULE_DEVTYPE_MGMTIP", "Mgmt IP+desc -> Server")
    RULE_DEVTYPE_MGMT_TLV = ("RULE_DEVTYPE_MGMT_TLV", "Mgmt Address TLV -> network device")


# ---------------------------------------------------------------------------
# Feature abstraction
# ---------------------------------------------------------------------------

@dataclass
class PortFeatures:
    """Semantic features extracted from TLV data."""
    has_port_vlan: bool = False
    has_protocol_vlan: bool = False
    port_vlan_tagged: bool = False
    is_aggregated: bool = False
    aggregation_id: Optional[int] = None
    high_mtu: bool = False
    jumbo_frame: bool = False
    has_poe: bool = False
    poe_power_allocated: Optional[int] = None
    is_router: bool = False
    is_bridge: bool = False
    is_wlan: bool = False
    is_repeater: bool = False
    is_telephone: bool = False
    speed_1g_plus: bool = False
    speed_10g_plus: bool = False
    duplex_full: bool = False
    has_management_ip: bool = False
    has_system_description: bool = False
    has_mgmt_vlan: bool = False
    has_data_vlan: bool = False
    has_voice_vlan: bool = False
    has_storage_vlan: bool = False


@dataclass
class PortIntentProfile:
    """Result of port intent inference."""
    role: PortRole = PortRole.UNKNOWN
    device_type: DeviceType = DeviceType.UNKNOWN
    intent: NetworkIntent = NetworkIntent.TERMINAL_ACCESS
    confidence: int = 0
    features: PortFeatures = None
    tlv_evidence: List[str] = None
    operational_insight: str = ""
    configuration_suggestion: str = ""
    is_managed: bool = False
    auto_discovery_issues: List[str] = None
    semantic_reasons: Set[RuleID] = None


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

@dataclass
class InferenceRule:
    rule_id: RuleID
    name: str
    priority: int
    condition_fn: callable
    action_fn: callable
    description: str


# DeviceType inference rules (ordered by priority)
_DEVTYPE_RULES = [
    InferenceRule(RuleID.RULE_DEVTYPE_POE_WLAN, "PoE+WLAN=AP", 1,
                  lambda f: f.has_poe and f.is_wlan,
                  lambda f: DeviceType.ACCESS_POINT,
                  "PoE + wireless -> AP"),
    InferenceRule(RuleID.RULE_DEVTYPE_ROUTER, "Router cap", 1,
                  lambda f: f.is_router,
                  lambda f: DeviceType.ROUTER,
                  "Router capability -> Router"),
    InferenceRule(RuleID.RULE_DEVTYPE_BRIDGE_AGG, "Bridge+Agg", 1,
                  lambda f: f.is_bridge and f.is_aggregated,
                  lambda f: DeviceType.SWITCH,
                  "Bridge + aggregation -> Switch"),
    InferenceRule(RuleID.RULE_DEVTYPE_JUMBO, "Jumbo+10G", 1,
                  lambda f: f.jumbo_frame and f.speed_10g_plus,
                  lambda f: DeviceType.STORAGE,
                  "Jumbo frame + 10G -> Storage"),
    InferenceRule(RuleID.RULE_DEVTYPE_MGMT_TLV, "Mgmt TLV", 1,
                  lambda f: f.has_management_ip,
                  lambda f: DeviceType.SWITCH,
                  "Management Address -> network device"),
    InferenceRule(RuleID.RULE_DEVTYPE_POE_NOWLAN, "PoE no wlan", 2,
                  lambda f: f.has_poe and not f.is_wlan and not f.is_bridge
                  and not f.is_router,
                  lambda f: DeviceType.IP_PHONE,
                  "PoE, no wlan, no bridge/router -> phone"),
    InferenceRule(RuleID.RULE_DEVTYPE_BRIDGE, "Bridge", 2,
                  lambda f: f.is_bridge,
                  lambda f: DeviceType.SWITCH,
                  "Bridge -> Switch"),
    InferenceRule(RuleID.RULE_DEVTYPE_MGMTIP, "Mgmt+Desc", 2,
                  lambda f: f.has_management_ip and f.has_system_description,
                  lambda f: DeviceType.SERVER,
                  "Mgmt IP + description -> Server"),
]

# Priority-1 (absolute) port role rules
_PRIORITY_RULES = [
    InferenceRule(RuleID.RULE_AGGREGATION, "Aggregation", 1,
                  lambda f, dt: f.is_aggregated,
                  lambda f, dt: PortRole.UPLINK_LAG,
                  "Aggregation -> uplink LAG"),
    InferenceRule(RuleID.RULE_PROTOCOL_VLAN, "Protocol VLAN", 1,
                  lambda f, dt: f.has_protocol_vlan,
                  lambda f, dt: PortRole.TRUNK_NATIVE if f.has_port_vlan
                  else PortRole.TRUNK_NO_NATIVE,
                  "Protocol VLAN -> trunk"),
    InferenceRule(RuleID.RULE_HIGH_MTU_SPEED, "High MTU+speed", 1,
                  lambda f, dt: f.high_mtu and f.speed_1g_plus,
                  lambda f, dt: PortRole.STORAGE_NETWORK if f.jumbo_frame
                  else PortRole.UPLINK_SINGLE,
                  "High MTU + speed -> storage or uplink"),
    InferenceRule(RuleID.RULE_ROUTER_CAPABILITY, "Router", 1,
                  lambda f, dt: f.is_router,
                  lambda f, dt: PortRole.UPLINK_SINGLE,
                  "Router -> uplink"),
    InferenceRule(RuleID.RULE_DEVTYPE_AP, "DevType=AP", 1,
                  lambda f, dt: dt == DeviceType.ACCESS_POINT,
                  lambda f, dt: PortRole.ACCESS_WIRELESS,
                  "AP -> wireless access"),
    InferenceRule(RuleID.RULE_DEVTYPE_PHONE, "DevType=Phone", 1,
                  lambda f, dt: dt == DeviceType.IP_PHONE,
                  lambda f, dt: PortRole.ACCESS_VOICE,
                  "Phone -> voice access"),
    InferenceRule(RuleID.RULE_DEVTYPE_SWITCH, "DevType=Switch", 1,
                  lambda f, dt: dt in (DeviceType.ROUTER, DeviceType.SWITCH),
                  lambda f, dt: PortRole.CORE_DISTRIBUTION,
                  "Switch/Router -> core"),
]

# Priority-2 (secondary) rules
_SECONDARY_RULES = [
    InferenceRule(RuleID.RULE_PORT_VLAN_ONLY, "Port VLAN only", 2,
                  lambda f, dt: f.has_port_vlan and not f.has_protocol_vlan,
                  lambda f, dt: PortRole.ACCESS_TERMINAL,
                  "Port VLAN only -> access"),
    InferenceRule(RuleID.RULE_POE_LOWSPEED, "PoE+low speed", 2,
                  lambda f, dt: f.has_poe and not f.speed_1g_plus,
                  lambda f, dt: PortRole.ACCESS_TERMINAL,
                  "PoE + low speed -> terminal"),
    InferenceRule(RuleID.RULE_HIGHSPEED_BRIDGE, "10G+bridge", 2,
                  lambda f, dt: f.speed_10g_plus and f.is_bridge,
                  lambda f, dt: PortRole.CORE_DISTRIBUTION,
                  "10G + bridge -> core"),
    InferenceRule(RuleID.RULE_MULTIVLAN_BRIDGE, "Multi-VLAN bridge", 2,
                  lambda f, dt: f.is_bridge and (
                      f.has_mgmt_vlan + f.has_data_vlan +
                      f.has_voice_vlan + f.has_storage_vlan >= 2),
                  lambda f, dt: PortRole.CORE_DISTRIBUTION,
                  "Multi-VLAN bridge -> core switch"),
    InferenceRule(RuleID.RULE_MGMTIP_HIGHSPEED, "Mgmt+high speed", 2,
                  lambda f, dt: f.has_management_ip and f.speed_1g_plus,
                  lambda f, dt: PortRole.INFRASTRUCTURE,
                  "Mgmt IP + high speed -> infrastructure"),
]

_BASE_CONFIDENCE = {
    PortRole.ACCESS_TERMINAL: 70, PortRole.ACCESS_WIRELESS: 82,
    PortRole.ACCESS_VOICE: 80, PortRole.TRUNK_NATIVE: 84,
    PortRole.TRUNK_NO_NATIVE: 82, PortRole.UPLINK_LAG: 88,
    PortRole.UPLINK_SINGLE: 78, PortRole.CORE_DISTRIBUTION: 84,
    PortRole.STORAGE_NETWORK: 84, PortRole.INFRASTRUCTURE: 76,
    PortRole.UNKNOWN: 20,
}

_STRONG_RULE_BONUS = {
    RuleID.RULE_AGGREGATION: 7, RuleID.RULE_PROTOCOL_VLAN: 6,
    RuleID.RULE_HIGH_MTU_SPEED: 6, RuleID.RULE_ROUTER_CAPABILITY: 5,
    RuleID.RULE_DEVTYPE_AP: 8, RuleID.RULE_DEVTYPE_PHONE: 8,
    RuleID.RULE_DEVTYPE_SWITCH: 6,
}


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def _infer_device_type(features: PortFeatures) -> DeviceType:
    for rule in sorted(_DEVTYPE_RULES, key=lambda r: r.priority):
        if rule.condition_fn(features):
            return rule.action_fn(features)
    return DeviceType.TERMINAL


def _run_priority_rules(features, device_type):
    for rule in sorted(_PRIORITY_RULES, key=lambda r: r.priority):
        if rule.condition_fn(features, device_type):
            return rule.action_fn(features, device_type), rule.rule_id
    return None, None


def _run_secondary_rules(features, device_type):
    for rule in sorted(_SECONDARY_RULES, key=lambda r: r.priority):
        if rule.condition_fn(features, device_type):
            return rule.action_fn(features, device_type), rule.rule_id
    if features.has_management_ip:
        return PortRole.ACCESS_TERMINAL, RuleID.RULE_PORT_VLAN_ONLY
    return PortRole.UNKNOWN, RuleID.RULE_PORT_VLAN_ONLY


def _calculate_confidence(role, device_type, features, rule_ids):
    conf = _BASE_CONFIDENCE.get(role, 50)
    for rid in rule_ids:
        conf += _STRONG_RULE_BONUS.get(rid, 3)
    supporting = [
        features.has_port_vlan, features.has_protocol_vlan,
        features.is_aggregated, features.high_mtu, features.has_poe,
        features.is_router, features.is_bridge, features.is_wlan,
        features.speed_1g_plus, features.speed_10g_plus,
        features.has_management_ip, features.has_system_description,
    ]
    conf += min(8, sum(1 for x in supporting if x) * 2)
    if device_type in (DeviceType.UNKNOWN, DeviceType.TERMINAL) and role != PortRole.ACCESS_TERMINAL:
        conf -= 8
    if role == PortRole.UNKNOWN:
        conf = min(conf, 35)
    return max(0, min(98, conf))


def _map_role_to_intent(role):
    mapping = {
        PortRole.ACCESS_TERMINAL: NetworkIntent.TERMINAL_ACCESS,
        PortRole.ACCESS_WIRELESS: NetworkIntent.WIRELESS_ACCESS,
        PortRole.ACCESS_VOICE: NetworkIntent.VOICE_PROVISIONING,
        PortRole.TRUNK_NATIVE: NetworkIntent.TRUNK_TRANSPORT,
        PortRole.TRUNK_NO_NATIVE: NetworkIntent.TRUNK_TRANSPORT,
        PortRole.UPLINK_LAG: NetworkIntent.UPLINK_REDUNDANCY,
        PortRole.UPLINK_SINGLE: NetworkIntent.UPLINK_REDUNDANCY,
        PortRole.STORAGE_NETWORK: NetworkIntent.HIGH_SPEED_STORAGE,
        PortRole.CORE_DISTRIBUTION: NetworkIntent.NETWORK_MANAGEMENT,
        PortRole.INFRASTRUCTURE: NetworkIntent.NETWORK_MANAGEMENT,
    }
    return mapping.get(role, NetworkIntent.TERMINAL_ACCESS)


def _generate_evidence(features, device_type, rule_ids):
    ev = []
    if features.is_aggregated:
        ev.append("Link Aggregation enabled")
    if features.has_protocol_vlan:
        ev.append("Protocol VLAN present")
    if features.has_port_vlan:
        ev.append(f"Port VLAN (tagged={features.port_vlan_tagged})")
    if features.high_mtu:
        ev.append("High MTU")
    if features.has_poe:
        ev.append("PoE supported")
    if features.is_router:
        ev.append("Router capability")
    if features.is_bridge:
        ev.append("Bridge capability")
    if features.speed_10g_plus:
        ev.append("10G+ speed")
    elif features.speed_1g_plus:
        ev.append("1G+ speed")
    if features.has_management_ip:
        ev.append("Management IP present")
    for rid in rule_ids:
        if rid.description not in ev:
            ev.append(rid.description)
    return ev


def _generate_insight(role, device_type, features):
    insights = {
        PortRole.TRUNK_NATIVE: "Trunk port with native VLAN — carries multiple VLANs between switches.",
        PortRole.TRUNK_NO_NATIVE: "Pure trunk port — all VLANs tagged.",
        PortRole.UPLINK_LAG: "Aggregated uplink — high-bandwidth redundant path to upstream.",
        PortRole.UPLINK_SINGLE: "Single-link uplink — no redundancy.",
        PortRole.ACCESS_TERMINAL: "Terminal access port — endpoint device.",
        PortRole.ACCESS_VOICE: "Voice access port — IP phone with voice VLAN.",
        PortRole.ACCESS_WIRELESS: "Wireless AP port — PoE + WLAN capability.",
        PortRole.CORE_DISTRIBUTION: "Core/distribution interconnect.",
        PortRole.STORAGE_NETWORK: "Storage network — jumbo frames + high speed.",
        PortRole.INFRASTRUCTURE: "Infrastructure port — managed high-speed link.",
    }
    return insights.get(role, "Unknown port role.")

    suggestions = {
        PortRole.TRUNK_NATIVE: "Verify allowed VLAN list and native VLAN consistency.",
        PortRole.UPLINK_LAG: "Check LACP mode and member link count.",
        PortRole.ACCESS_TERMINAL: "Confirm port-security and BPDU guard.",
        PortRole.ACCESS_VOICE: "Verify voice VLAN configuration and QoS.",
    }
    return suggestions.get(role, "")


def _discover_issues(features):
    issues = []
    if features.has_poe and not features.speed_1g_plus:
        issues.append("PoE device at sub-1G speed — possible legacy endpoint")
    if features.is_aggregated and not features.duplex_full:
        issues.append("Aggregated link without full duplex — check negotiation")
    return issues


def infer_port_intent(features: PortFeatures) -> PortIntentProfile:
    """Run the full inference pipeline on extracted features."""
    device_type = _infer_device_type(features)
    priority_role, priority_rule = _run_priority_rules(features, device_type)

    rule_ids = set()
    if priority_role:
        final_role = priority_role
        rule_ids.add(priority_rule)
    else:
        final_role, secondary_rule = _run_secondary_rules(features, device_type)
        rule_ids.add(secondary_rule)

    confidence = _calculate_confidence(final_role, device_type, features, rule_ids)

    return PortIntentProfile(
        role=final_role,
        device_type=device_type,
        intent=_map_role_to_intent(final_role),
        confidence=confidence,
        features=features,
        tlv_evidence=_generate_evidence(features, device_type, rule_ids),
        operational_insight=_generate_insight(final_role, device_type, features),
        is_managed=features.has_management_ip,
        auto_discovery_issues=_discover_issues(features),
        semantic_reasons=rule_ids,
    )
