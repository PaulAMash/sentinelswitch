"""Builders for source-native telemetry records (Suricata EVE, Zeek notice, RADIUS, IOS syslog)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinelswitch.detection.suricata_rules import load_rules
from simulator.canonical import Environment, long_ifname, mac_cisco, ts_epoch, ts_iso

from .base import stable_rng


def suricata_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


class RecordFactory:
    """Creates raw records tagged with the scenario/instance that produced them."""

    def __init__(self, env: Environment, scenario: str | None = None, instance: str | None = None):
        self.env = env
        self.scenario = scenario
        self.instance = instance
        self.rng = stable_rng(env, "records", scenario or "-", instance or "-")
        self.records: list[tuple[str, dict[str, Any]]] = []

    def _tag(self, rec: dict[str, Any]) -> dict[str, Any]:
        if self.scenario:
            rec["_scenario"] = self.scenario
            rec["_instance"] = self.instance
        return rec

    def suricata_alert(
        self,
        ts: datetime,
        sid: int,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        proto: str,
        app_proto: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        rule = load_rules()[sid]
        rec = {
            "timestamp": suricata_ts(ts),
            "flow_id": self.rng.randint(10**15, 2 * 10**15),
            "in_iface": "eth1",
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto.upper(),
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sid,
                "rev": rule.rev,
                "signature": rule.msg,
                "category": rule.category,
                "severity": rule.severity,
                "metadata": {"sentinel_class": [rule.sentinel_class], "sentinel_severity": [rule.sentinel_severity]},
            },
        }
        if app_proto:
            rec["app_proto"] = app_proto
        rec.update(extra)
        rec["_ts_iso"] = ts_iso(ts)
        self.records.append(("suricata", self._tag(rec)))
        return rec

    def zeek_notice(
        self,
        ts: datetime,
        note: str,
        msg: str,
        sub: str,
        src: str,
        dst: str | None = None,
        p: int | None = None,
        proto: str | None = None,
        n: int | None = None,
        alarm: bool = True,
    ) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "ts": ts_epoch(ts),
            "note": note,
            "msg": msg,
            "sub": sub,
            "src": src,
            "peer_descr": "zeek",
            "actions": ["Notice::ACTION_LOG"] + (["Notice::ACTION_ALARM"] if alarm else []),
            "email_dest": [],
            "suppress_for": 3600.0,
        }
        if dst:
            rec["dst"] = dst
        if p is not None:
            rec["p"] = p
        if proto:
            rec["proto"] = proto
        if n is not None:
            rec["n"] = n
        rec["_ts_iso"] = ts_iso(ts)
        self.records.append(("zeek", self._tag(rec)))
        return rec

    def radius(self, ev: dict[str, Any]) -> dict[str, Any]:
        rec = dict(ev)
        self.records.append(("radius", self._tag(rec)))
        return rec

    def syslog(
        self,
        ts: datetime,
        facility: str,
        severity: int,
        mnemonic: str,
        message: str,
        interface: str | None = None,
        mac: str | None = None,
    ) -> dict[str, Any]:
        rec = {
            "ts": ts_iso(ts),
            "facility": facility,
            "severity": severity,
            "mnemonic": mnemonic,
            "message": message,
            "interface": interface,
            "mac": mac,
        }
        self.records.append(("syslog", self._tag(rec)))
        return rec

    # ---- common IOS message helpers ------------------------------------------------------------
    def link_up(self, ts: datetime, interface: str) -> None:
        from simulator.canonical import add_seconds

        self.syslog(ts, "LINK", 3, "UPDOWN", f"Interface {long_ifname(interface)}, changed state to up", interface)
        self.syslog(
            add_seconds(ts, 1.004),
            "LINEPROTO",
            5,
            "UPDOWN",
            f"Line protocol on Interface {long_ifname(interface)}, changed state to up",
            interface,
        )

    def link_down(self, ts: datetime, interface: str) -> None:
        from simulator.canonical import add_seconds

        self.syslog(ts, "LINK", 3, "UPDOWN", f"Interface {long_ifname(interface)}, changed state to down", interface)
        self.syslog(
            add_seconds(ts, 0.008),
            "LINEPROTO",
            5,
            "UPDOWN",
            f"Line protocol on Interface {long_ifname(interface)}, changed state to down",
            interface,
        )

    def dai_deny(
        self, ts: datetime, interface: str, vlan: int, sender_mac: str, sender_ip: str, target_ip: str, op: str = "Res"
    ) -> None:
        stamp = ts.strftime("%H:%M:%S UTC %a %b %d %Y")
        self.syslog(
            ts,
            "SW_DAI",
            4,
            "DHCP_SNOOPING_DENY",
            f"1 Invalid ARPs ({op}) on {interface}, vlan {vlan}.([{mac_cisco(sender_mac)}/{sender_ip}/0000.0000.0000/{target_ip}/{stamp}])",
            interface,
            sender_mac,
        )

    def snooping_drop(self, ts: datetime, interface: str, msg_type: str, mac: str) -> None:
        self.syslog(
            ts,
            "DHCP_SNOOPING",
            5,
            "DHCP_SNOOPING_UNTRUSTED_PORT",
            f"DHCP_SNOOPING drop message on untrusted port, message type: {msg_type}, MAC sa: {mac_cisco(mac)}",
            interface,
            mac,
        )

    def psecure_violation(self, ts: datetime, interface: str, mac: str) -> None:
        self.syslog(
            ts,
            "PORT_SECURITY",
            2,
            "PSECURE_VIOLATION",
            f"Security violation occurred, caused by MAC address {mac_cisco(mac)} on port {long_ifname(interface)}.",
            interface,
            mac,
        )

    def bpdu_guard(self, ts: datetime, interface: str) -> None:
        from simulator.canonical import add_seconds

        self.syslog(
            ts,
            "SPANTREE",
            2,
            "BLOCK_BPDUGUARD",
            f"Received BPDU on port {interface} with BPDU Guard enabled. Disabling port.",
            interface,
        )
        self.syslog(
            add_seconds(ts, 0.005),
            "PM",
            4,
            "ERR_DISABLE",
            f"bpduguard error detected on {interface}, putting {interface} in err-disable state",
            interface,
        )

    def mab_fail(self, ts: datetime, interface: str, mac: str, session_id: str) -> None:
        self.syslog(
            ts,
            "MAB",
            5,
            "FAIL",
            f"Authentication failed for client ({mac_cisco(mac)}) on Interface {interface} AuditSessionID {session_id}",
            interface,
            mac,
        )

    def dot1x_fail(self, ts: datetime, interface: str, mac: str, session_id: str) -> None:
        from simulator.canonical import add_seconds

        self.syslog(
            ts,
            "DOT1X",
            5,
            "FAIL",
            f"Authentication failed for client ({mac_cisco(mac)}) on Interface {interface} AuditSessionID {session_id}",
            interface,
            mac,
        )
        self.syslog(
            add_seconds(ts, 0.018),
            "AUTHMGR",
            5,
            "FAIL",
            f"Authorization failed or unapplied for client ({mac_cisco(mac)}) on Interface {interface} AuditSessionID {session_id}",
            interface,
            mac,
        )
