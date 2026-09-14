"""Cisco IOS syslog line builders for routine (non-scenario) events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from simulator.canonical import Environment, add_seconds, long_ifname, mac_cisco, parse_ts

from .radius import link_events_for_day


def _stamp(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S UTC %a %b %d %Y")


def baseline_syslog(env: Environment, auth_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return unsorted syslog records: {ts: datetime, facility, severity, mnemonic, message, interface, mac}."""
    lines: list[dict[str, Any]] = []

    def add(
        ts: datetime,
        facility: str,
        severity: int,
        mnemonic: str,
        message: str,
        interface: str | None = None,
        mac: str | None = None,
    ):
        lines.append(
            {
                "ts": ts,
                "facility": facility,
                "severity": severity,
                "mnemonic": mnemonic,
                "message": message,
                "interface": interface,
                "mac": mac,
            }
        )

    # Link state for scheduled devices and movements
    for ts, iface, state, _host in link_events_for_day(env):
        ln = long_ifname(iface)
        if state == "up":
            add(ts, "LINK", 3, "UPDOWN", f"Interface {ln}, changed state to up", iface)
            add(
                add_seconds(ts, 1.004),
                "LINEPROTO",
                5,
                "UPDOWN",
                f"Line protocol on Interface {ln}, changed state to up",
                iface,
            )
        else:
            add(ts, "LINK", 3, "UPDOWN", f"Interface {ln}, changed state to down", iface)
            add(
                add_seconds(ts, 0.008),
                "LINEPROTO",
                5,
                "UPDOWN",
                f"Line protocol on Interface {ln}, changed state to down",
                iface,
            )

    # Authentication results as the switch logs them
    for ev in auth_events:
        ts = parse_ts(ev["timestamp"])
        iface = ev["nas_port_id"].replace("GigabitEthernet", "Gi")
        mac = ev["calling_station_id"].replace("-", ":")
        sid = ev["audit_session_id"]
        cmac = mac_cisco(mac)
        if ev["result"] == "Access-Accept":
            fac = "MAB" if ev["method"] == "MAB" else "DOT1X"
            add(
                add_seconds(ts, 0.031),
                fac,
                5,
                "SUCCESS",
                f"Authentication successful for client ({cmac}) on Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )
            add(
                add_seconds(ts, 0.058),
                "AUTHMGR",
                5,
                "SUCCESS",
                f"Authorization succeeded for client ({cmac}) on Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )
        elif ev["result"] == "Access-Reject":
            fac = "MAB" if ev["method"] == "MAB" else "DOT1X"
            add(
                add_seconds(ts, 0.026),
                fac,
                5,
                "FAIL",
                f"Authentication failed for client ({cmac}) on Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )
            if fac == "DOT1X":
                add(
                    add_seconds(ts, 0.044),
                    "AUTHMGR",
                    5,
                    "FAIL",
                    f"Authorization failed or unapplied for client ({cmac}) on Interface {iface} AuditSessionID {sid}",
                    iface,
                    mac,
                )
        elif ev["result"] == "Guest-VLAN":
            add(
                add_seconds(ts, 0.012),
                "DOT1X",
                5,
                "FAIL",
                f"Authentication failed for client (Unknown MAC) on Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )
            add(
                add_seconds(ts, 0.041),
                "AUTHMGR",
                5,
                "VLANASSIGN",
                f"VLAN {ev['assigned_vlan']} assigned to Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )
            add(
                add_seconds(ts, 0.063),
                "AUTHMGR",
                5,
                "SUCCESS",
                f"Authorization succeeded for client ({cmac}) on Interface {iface} AuditSessionID {sid}",
                iface,
                mac,
            )

    # Routine housekeeping lines
    day = env.day_start
    add(
        add_seconds(day, 12.4),
        "SYS",
        6,
        "LOGGINGHOST_STARTSTOP",
        "Logging to host 10.99.0.10 port 514 started - CLI initiated",
    )
    add(
        add_seconds(day, 3 * 3600 + 21.7),
        "SYS",
        6,
        "CLOCKUPDATE",
        f"System clock has been updated from {_stamp(add_seconds(day, 3 * 3600 + 21))} to {_stamp(add_seconds(day, 3 * 3600 + 21.7))}, configured from console by console.",
    )

    # Interactive configuration sessions that produced the deliberate configuration drift
    for inj in env.drift_injections:
        ts, user, iface = parse_ts(inj["at"]), inj["by"], inj["interface"]
        add(
            add_seconds(ts, -18.3),
            "SEC_LOGIN",
            5,
            "LOGIN_SUCCESS",
            f"Login Success [user: {user}] [Source: 10.10.10.20] [localport: 22] at {_stamp(add_seconds(ts, -18.3))}",
        )
        add(ts, "SYS", 5, "CONFIG_I", f"Configured from console by {user} on vty0 (10.10.10.20)", iface)
    # SentinelSwitch controller health-check logins (read-only `show` polling every 15 minutes)
    for i in range(0, 24 * 4):
        ts = add_seconds(day, i * 900 + 7.2)
        if i % 8 == 0:
            add(
                ts,
                "SEC_LOGIN",
                5,
                "LOGIN_SUCCESS",
                f"Login Success [user: sentinel-ro] [Source: 10.99.0.10] [localport: 22] at {_stamp(ts)}",
            )
    return lines
