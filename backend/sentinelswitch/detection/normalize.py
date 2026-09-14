"""Convert source-native telemetry records into the SentinelSwitch normalized event schema.

Normalized event (dict) fields common to all sources:
    ts            ISO-8601 UTC with milliseconds
    source        suricata | zeek | radius | syslog
    kind          alert | notice | auth | syslog
    severity      high | medium | low | info
    summary       one-line human description
    actor keys    src_ip, mac, interface (whichever the source can provide)
    raw           the original record

Source-specific enrichment (interface class, gateway comparison, parsed Zeek notice fields) happens
here so the correlation rules can stay declarative.
"""

from __future__ import annotations

import re
from typing import Any

from simulator.canonical import Environment, mac_norm, parse_ts, short_ifname, ts_iso

from .suricata_rules import load_rules

_MAC_CISCO = re.compile(r"\b([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})\b", re.I)
_IFACE = re.compile(r"\b((?:Gi|GigabitEthernet|Te|TenGigabitEthernet)\d+/\d+/\d+)\b")
_DAI = re.compile(r"\(\[([0-9a-f.]+)/([\d.]+)/([0-9a-f.]+)/([\d.]+)/")
_SCAN_PORTS = re.compile(r"scanned at least (\d+) unique ports of host ([\d.]+)")
_SCAN_HOSTS = re.compile(r"scanned at least (\d+) unique hosts on port (\d+)/(\w+)")
_KV = re.compile(r"(\w+)=([^\s]+)")


def _cisco_to_mac(m: re.Match) -> str:
    h = (m.group(1) + m.group(2) + m.group(3)).upper()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def _severity_from_num(n: int) -> str:
    return {1: "high", 2: "medium", 3: "low"}.get(int(n), "info")


def _port_class(env: Environment, interface: str | None) -> str | None:
    if not interface:
        return None
    p = env.ports.get(short_ifname(interface))
    return p.port_class if p else None


def _coerce(v: str) -> Any:
    if v in {"T", "true", "True"}:
        return True
    if v in {"F", "false", "False"}:
        return False
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


def normalize_suricata(env: Environment, rec: dict[str, Any]) -> dict[str, Any]:
    alert = rec.get("alert", {})
    sid = int(alert.get("signature_id", 0))
    rule = load_rules().get(sid)
    sev_num = int(alert.get("severity", rule.severity if rule else 3))
    src = rec.get("src_ip")
    # Signatures tracked by destination (e.g. NXDOMAIN responses) describe the *destination* host.
    actor_ip = rec.get("dest_ip") if (rule and rule.track == "by_dst") else src
    dev = env.device_by_ip(actor_ip) if actor_ip else None
    return {
        "ts": rec["_ts_iso"] if "_ts_iso" in rec else _suricata_iso(rec["timestamp"]),
        "source": "suricata",
        "kind": "alert",
        "severity": _severity_from_num(sev_num),
        "signature_id": sid,
        "signature": alert.get("signature", rule.msg if rule else "unknown"),
        "category": alert.get("category", rule.category if rule else ""),
        "sentinel_class": rule.sentinel_class if rule else "misc",
        "src_ip": src,
        "actor_ip": actor_ip,
        "src_port": rec.get("src_port"),
        "dest_ip": rec.get("dest_ip"),
        "dest_port": rec.get("dest_port"),
        "proto": rec.get("proto"),
        "app_proto": rec.get("app_proto"),
        "flow_id": rec.get("flow_id"),
        "mac": dev.mac if dev else None,
        "interface": dev.interface if dev and not dev.via_trunk else None,
        "device": dev.hostname if dev else None,
        "summary": alert.get("signature", ""),
        "scenario": rec.get("_scenario"),
        "instance": rec.get("_instance"),
        "raw": {k: v for k, v in rec.items() if not k.startswith("_")},
    }


def normalize_zeek_notice(env: Environment, rec: dict[str, Any]) -> dict[str, Any]:
    note = rec.get("note", "")
    msg = rec.get("msg", "")
    sub = rec.get("sub", "") or ""
    src = rec.get("src") or rec.get("id.orig_h")
    dev = env.device_by_ip(src) if src else None
    extra: dict[str, Any] = {}
    for k, v in _KV.findall(sub):
        extra[k] = _coerce(v)
    m = _SCAN_PORTS.search(msg)
    if m:
        extra["ports_scanned"] = int(m.group(1))
        target = m.group(2)
        vlan = env.vlan_for_ip(target)
        extra["targets_servers"] = bool(vlan and vlan.id == 30)
        extra["target"] = target
    m = _SCAN_HOSTS.search(msg)
    if m:
        extra["hosts_scanned"] = int(m.group(1))
        extra["port"] = int(m.group(2))
    severity = (
        "high"
        if note.startswith("Scan::Address_Scan")
        else "medium"
        if note.startswith("Scan::") or "Burst" in note
        else "low"
    )
    ev = {
        "ts": ts_iso(parse_ts(rec["_ts_iso"])) if "_ts_iso" in rec else ts_iso(_from_epoch(rec["ts"])),
        "source": "zeek",
        "kind": "notice",
        "severity": severity,
        "note": note,
        "msg": msg,
        "sub": sub,
        "src_ip": src,
        "actor_ip": src,
        "dest_ip": rec.get("dst"),
        "dest_port": rec.get("p"),
        "mac": dev.mac if dev else None,
        "interface": dev.interface if dev and not dev.via_trunk else None,
        "device": dev.hostname if dev else None,
        "summary": f"{note}: {msg}",
        "scenario": rec.get("_scenario"),
        "instance": rec.get("_instance"),
        "raw": {k: v for k, v in rec.items() if not k.startswith("_")},
    }
    ev.update(extra)
    return ev


def _from_epoch(ts: float):
    from datetime import UTC, datetime

    return datetime.fromtimestamp(float(ts), tz=UTC)


def _suricata_iso(stamp: str) -> str:
    """'2026-03-17T21:14:33.507000+0000' -> '2026-03-17T21:14:33.507Z'"""
    base = stamp.split("+")[0]
    return ts_iso(parse_ts(base + "+00:00"))


def normalize_radius(env: Environment, rec: dict[str, Any]) -> dict[str, Any]:
    mac = mac_norm(rec["calling_station_id"])
    interface = short_ifname(rec["nas_port_id"])
    result = rec["result"]
    dev = env.device_by_mac(mac)
    sev = "low" if result == "Access-Reject" else "info"
    return {
        "ts": rec["timestamp"],
        "source": "radius",
        "kind": "auth",
        "severity": sev,
        "username": rec.get("username"),
        "identity": rec.get("identity"),
        "result": result,
        "method": rec.get("method"),
        "reason": rec.get("reason"),
        "assigned_vlan": rec.get("assigned_vlan"),
        "mac": mac,
        "interface": interface,
        "port_class": _port_class(env, interface),
        "nas_port_id": rec.get("nas_port_id"),
        "audit_session_id": rec.get("audit_session_id"),
        "device": dev.hostname if dev else None,
        "summary": f"{result} {rec.get('method')} {rec.get('username')} on {interface}"
        + (f": {rec.get('reason')}" if rec.get("reason") else ""),
        "scenario": rec.get("_scenario"),
        "instance": rec.get("_instance"),
        "raw": {k: v for k, v in rec.items() if not k.startswith("_")},
    }


SECURITY_MNEMONICS = {
    "SW_DAI-4-DHCP_SNOOPING_DENY",
    "SW_DAI-4-INVALID_ARP",
    "DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT",
    "PORT_SECURITY-2-PSECURE_VIOLATION",
    "SPANTREE-2-BLOCK_BPDUGUARD",
    "PM-4-ERR_DISABLE",
    "MAB-5-FAIL",
    "DOT1X-5-FAIL",
    "AUTHMGR-5-FAIL",
    "SEC_LOGIN-4-LOGIN_FAILED",
    "SW_MATM-4-MACFLAP_NOTIF",
    "STORM_CONTROL-3-FILTERED",
}


def normalize_syslog(env: Environment, rec: dict[str, Any]) -> dict[str, Any]:
    facility, severity_num, mnemonic, message = rec["facility"], int(rec["severity"]), rec["mnemonic"], rec["message"]
    key = f"{facility}-{severity_num}-{mnemonic}"
    interface = rec.get("interface")
    if not interface:
        m = _IFACE.search(message)
        interface = short_ifname(m.group(1)) if m else None
    else:
        interface = short_ifname(interface)
    mac = rec.get("mac")
    if not mac:
        m = _MAC_CISCO.search(message)
        mac = _cisco_to_mac(m) if m else None
    else:
        mac = mac_norm(mac)
    ev: dict[str, Any] = {
        "ts": rec["ts"] if isinstance(rec["ts"], str) else ts_iso(rec["ts"]),
        "source": "syslog",
        "kind": "syslog",
        "severity": "high"
        if severity_num <= 2 and key in SECURITY_MNEMONICS
        else "medium"
        if key in SECURITY_MNEMONICS
        else "info",
        "facility": facility,
        "severity_num": severity_num,
        "mnemonic": key,
        "message": message,
        "interface": interface,
        "port_class": _port_class(env, interface),
        "mac": mac,
        "summary": f"%{key}: {message}",
        "scenario": rec.get("_scenario"),
        "instance": rec.get("_instance"),
        "raw": {k: v for k, v in rec.items() if not k.startswith("_")},
    }
    if key.startswith("SW_DAI-4"):
        m = _DAI.search(message)
        if m:
            sender_mac = _cisco_to_mac(_MAC_CISCO.search(m.group(1)))
            sender_ip = m.group(2)
            ev["mac"] = sender_mac
            ev["sender_ip"] = sender_ip
            vm = re.search(r"vlan (\d+)", message)
            vlan = int(vm.group(1)) if vm else None
            ev["vlan"] = vlan
            ev["claims_gateway"] = bool(vlan and env.gateway_for_vlan(vlan) == sender_ip)
    if key == "PORT_SECURITY-2-PSECURE_VIOLATION":
        ev["new_mac"] = mac
    if key == "DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT":
        m = re.search(r"message type: (\w+)", message)
        ev["dhcp_message_type"] = m.group(1) if m else None
    dev = env.device_by_mac(mac) if mac else None
    ev["device"] = dev.hostname if dev else None
    return ev


def normalize(env: Environment, source: str, rec: dict[str, Any]) -> dict[str, Any]:
    if source == "suricata":
        return normalize_suricata(env, rec)
    if source == "zeek":
        return normalize_zeek_notice(env, rec)
    if source == "radius":
        return normalize_radius(env, rec)
    if source == "syslog":
        return normalize_syslog(env, rec)
    raise ValueError(f"unknown source {source}")
