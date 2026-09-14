"""Synthetic FreeRADIUS / 802.1X authentication telemetry for the dataset day."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from simulator.canonical import Device, Environment, add_seconds, long_ifname, mac_cisco, parse_ts, ts_iso

from .base import stable_rng

REAUTH_SECONDS = 14400  # `authentication timer reauthenticate server` -> Session-Timeout 14400

# Endpoint movements during the day that are not captured by the simple attach/detach schedule.
MOVEMENTS = [
    # kmurphy took ENG-LT-035 into conference room A for a design review.
    {
        "hostname": "ENG-LT-035",
        "interface": "Gi1/0/29",
        "start": "2026-03-17T14:02:11Z",
        "end": "2026-03-17T14:55:40Z",
        "return_interface": "Gi1/0/35",
        "return_at": "2026-03-17T14:57:32Z",
    },
]


def _idx(interface: str) -> int:
    return int(interface.rsplit("/", 1)[-1])


def session_id(interface: str, mac: str, seq: int) -> str:
    return f"0A0A0A02{_idx(interface):08X}{(int(mac.replace(':', '')[-6:], 16) + seq * 7919) & 0xFFFFFFFF:08X}"


def _calling(mac: str) -> str:
    return mac.replace(":", "-").upper()


class RadiusGenerator:
    def __init__(self, env: Environment):
        self.env = env
        self.events: list[dict[str, Any]] = []
        self._seq = 0

    def _event(
        self,
        ts: datetime,
        dev: Device | None,
        interface: str,
        mac: str,
        *,
        result: str,
        method: str,
        username: str,
        identity: str,
        reason: str | None = None,
        assigned_vlan: int | None = None,
        vlan_source: str = "port-default",
        user: str | None = None,
        scenario: str | None = None,
    ) -> dict[str, Any]:
        self._seq += 1
        idx = _idx(interface)
        ev = {
            "timestamp": ts_iso(ts),
            "event_id": f"RAD-{self._seq:05d}",
            "username": username,
            "identity": identity,
            "user": user,
            "device": dev.hostname if dev else None,
            "calling_station_id": _calling(mac),
            "called_station_id": _calling(self.env.switch["base_mac"]),
            "nas_identifier": self.env.hostname,
            "nas_ip_address": self.env.switch["management_ip"],
            "nas_port": 50000 + idx,
            "nas_port_id": long_ifname(interface),
            "nas_port_type": "Ethernet",
            "service_type": "Framed-User" if method != "MAB" else "Call-Check",
            "result": result,
            "method": method,
            "eap_type": {"EAP-TLS": 13, "PEAP-MSCHAPv2": 25}.get(method),
            "assigned_vlan": assigned_vlan,
            "vlan_source": vlan_source if assigned_vlan else None,
            "session_timeout": REAUTH_SECONDS if result == "Access-Accept" else None,
            "reason": reason,
            "audit_session_id": session_id(interface, mac, self._seq),
            "scenario": scenario,
        }
        self.events.append(ev)
        return ev

    # ---- baseline day ------------------------------------------------------------------------
    def generate(self) -> list[dict[str, Any]]:
        env = self.env
        day = env.day_start
        for dev in env.devices:
            rng = stable_rng(env, "radius", dev.hostname)
            if dev.auth in {"eap-tls", "peap"}:
                method = "EAP-TLS" if dev.auth == "eap-tls" else "PEAP-MSCHAPv2"
                identity = f"{dev.user}@corp.example.com" if dev.auth == "eap-tls" else f"CORP\\{dev.user}"
                if dev.schedule:
                    first = add_seconds(dev.schedule[0], rng.uniform(2.1, 4.6))
                    if dev.hostname == "MKT-WS-022":
                        first = self._cert_failure_story(dev, rng)
                    elif dev.hostname == "ENG-LT-047":
                        first = add_seconds(dev.schedule[0], 14.512)
                        self._event(
                            first,
                            dev,
                            dev.interface,
                            dev.mac,
                            result="Access-Accept",
                            method=method,
                            username=dev.user,
                            identity=identity,
                            assigned_vlan=20,
                            user=dev.user,
                        )
                    else:
                        self._event(
                            first,
                            dev,
                            dev.interface,
                            dev.mac,
                            result="Access-Accept",
                            method=method,
                            username=dev.user,
                            identity=identity,
                            assigned_vlan=20,
                            user=dev.user,
                        )
                    t = add_seconds(first, REAUTH_SECONDS)
                    while t < dev.schedule[1]:
                        self._event(
                            add_seconds(t, rng.uniform(0.02, 0.4)),
                            dev,
                            dev.interface,
                            dev.mac,
                            result="Access-Accept",
                            method=method,
                            username=dev.user,
                            identity=identity,
                            assigned_vlan=20,
                            user=dev.user,
                        )
                        t = add_seconds(t, REAUTH_SECONDS)
                else:
                    phase = rng.uniform(0, REAUTH_SECONDS)
                    t = add_seconds(day, phase)
                    while t < env.day_end:
                        if dev.hostname == "FIN-WS-015" and 8 * 3600 <= (t - day).total_seconds() < 12 * 3600:
                            self._peap_failure_story(dev, rng)
                        else:
                            self._event(
                                t,
                                dev,
                                dev.interface,
                                dev.mac,
                                result="Access-Accept",
                                method=method,
                                username=dev.user,
                                identity=identity,
                                assigned_vlan=20,
                                user=dev.user,
                            )
                        t = add_seconds(t, REAUTH_SECONDS)
            elif dev.auth == "mab":
                phase = rng.uniform(0, REAUTH_SECONDS)
                t = add_seconds(day, phase)
                while t < env.day_end:
                    self._event(
                        t,
                        dev,
                        dev.interface,
                        dev.mac,
                        result="Access-Accept",
                        method="MAB",
                        username=mac_cisco(dev.mac).replace(".", ""),
                        identity=_calling(dev.mac),
                        assigned_vlan=20,
                        user=None,
                    )
                    t = add_seconds(t, REAUTH_SECONDS)
            elif dev.vlan == 40 and dev.schedule:
                # Guest device: MAB is tried first and rejected, 802.1X times out, guest VLAN authorises locally.
                ts = add_seconds(dev.schedule[0], rng.uniform(0.3, 0.9))
                self._guest_story(dev, ts)
            elif dev.hostname == "CONF-A-TV01":
                # Always-on guest display: its session was re-established after the BPDU incident restore.
                self._guest_story(dev, parse_ts("2026-03-17T09:35:41.204Z"))
        for mv in MOVEMENTS:
            dev = env.device_by_hostname(mv["hostname"])
            rng = stable_rng(env, "radius", "move", dev.hostname)
            identity = f"{dev.user}@corp.example.com"
            self._event(
                add_seconds(parse_ts(mv["start"]), rng.uniform(2.0, 4.0)),
                dev,
                mv["interface"],
                dev.mac,
                result="Access-Accept",
                method="EAP-TLS",
                username=dev.user,
                identity=identity,
                assigned_vlan=20,
                user=dev.user,
            )
            self._event(
                add_seconds(parse_ts(mv["return_at"]), rng.uniform(2.0, 4.0)),
                dev,
                mv["return_interface"],
                dev.mac,
                result="Access-Accept",
                method="EAP-TLS",
                username=dev.user,
                identity=identity,
                assigned_vlan=20,
                user=dev.user,
            )
        self.events.sort(key=lambda e: e["timestamp"])
        return self.events

    def _guest_story(self, dev: Device, ts: datetime) -> None:
        self._event(
            ts,
            dev,
            dev.interface,
            dev.mac,
            result="Access-Reject",
            method="MAB",
            username=mac_cisco(dev.mac).replace(".", ""),
            identity=_calling(dev.mac),
            reason="MAC not found in endpoint database",
            user=None,
        )
        self._event(
            add_seconds(ts, 6.42),
            dev,
            dev.interface,
            dev.mac,
            result="Guest-VLAN",
            method="dot1x (no supplicant response)",
            username="(none)",
            identity=_calling(dev.mac),
            assigned_vlan=40,
            vlan_source="guest-vlan",
            reason="No EAPOL response after 2 x tx-period; guest VLAN authorised locally by the switch",
            user=None,
        )

    def _cert_failure_story(self, dev: Device, rng) -> datetime:
        identity = f"{dev.user}@corp.example.com"
        self._event(
            parse_ts("2026-03-17T08:03:41.207Z"),
            dev,
            dev.interface,
            dev.mac,
            result="Access-Reject",
            method="EAP-TLS",
            username=dev.user,
            identity=identity,
            reason="TLS Alert read:fatal:certificate expired (client certificate notAfter=2026-03-16T23:59:59Z)",
            user=dev.user,
        )
        self._event(
            parse_ts("2026-03-17T08:05:12.844Z"),
            dev,
            dev.interface,
            dev.mac,
            result="Access-Reject",
            method="EAP-TLS",
            username=dev.user,
            identity=identity,
            reason="TLS Alert read:fatal:certificate expired (client certificate notAfter=2026-03-16T23:59:59Z)",
            user=dev.user,
        )
        first = parse_ts("2026-03-17T08:37:55.318Z")
        self._event(
            first,
            dev,
            dev.interface,
            dev.mac,
            result="Access-Accept",
            method="EAP-TLS",
            username=dev.user,
            identity=identity,
            assigned_vlan=20,
            user=dev.user,
        )
        return first

    def _peap_failure_story(self, dev: Device, rng) -> None:
        identity = f"CORP\\{dev.user}"
        for stamp in ("2026-03-17T08:12:03.512Z", "2026-03-17T08:12:41.088Z", "2026-03-17T08:13:20.451Z"):
            self._event(
                parse_ts(stamp),
                dev,
                dev.interface,
                dev.mac,
                result="Access-Reject",
                method="PEAP-MSCHAPv2",
                username=dev.user,
                identity=identity,
                reason="MSCHAPv2 authentication failed: bad password (E=691)",
                user=dev.user,
            )
        self._event(
            parse_ts("2026-03-17T08:14:02.377Z"),
            dev,
            dev.interface,
            dev.mac,
            result="Access-Accept",
            method="PEAP-MSCHAPv2",
            username=dev.user,
            identity=identity,
            assigned_vlan=20,
            user=dev.user,
        )


def link_events_for_day(env: Environment) -> list[tuple[datetime, str, str, str]]:
    """(ts, interface, 'up'|'down', hostname) for every scheduled attach/detach and movement during the day."""
    out: list[tuple[datetime, str, str, str]] = []
    for dev in env.devices:
        if dev.schedule and not dev.via_trunk:
            s, e = dev.schedule
            out.append((s, dev.interface, "up", dev.hostname))
            if e < env.day_end - timedelta(seconds=1):
                out.append((e, dev.interface, "down", dev.hostname))
    for mv in MOVEMENTS:
        dev = env.device_by_hostname(mv["hostname"])
        out.append((add_seconds(parse_ts(mv["start"]), -95.0), mv["return_interface"], "down", dev.hostname))
        out.append((parse_ts(mv["start"]), mv["interface"], "up", dev.hostname))
        out.append((parse_ts(mv["end"]), mv["interface"], "down", dev.hostname))
        out.append((parse_ts(mv["return_at"]), mv["return_interface"], "up", dev.hostname))
    out.sort(key=lambda x: x[0])
    return out
