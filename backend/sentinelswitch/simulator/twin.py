"""Simulated Cisco Catalyst 2960-X state (the digital twin).

The twin holds everything a controller would read from or write to a real access switch: interface
configuration and operational state, the MAC address table, DHCP snooping bindings, port-security
status, counters, the logging buffer and a record of configuration changes. It is deliberately a plain
in-memory object with `to_dict`/`from_dict` so it can be persisted as JSON, copied for isolated
validation runs, and diffed for configuration-drift detection.
"""

from __future__ import annotations

import copy
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from simulator.canonical import Environment, add_seconds, long_ifname, mac_norm, parse_ts, ts_iso


@dataclass
class Interface:
    name: str
    description: str
    mode: str  # access | trunk
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: list[int]
    admin_status: str  # up | down
    oper_status: str  # connected | notconnect | disabled | err-disabled | monitoring
    speed: str
    duplex: str
    port_class: str
    protected: bool
    span_destination: bool
    settings: dict[str, Any]  # configuration lines other than mode/vlan (port-security, dot1x, ...)
    oper_vlan: int | None = None  # VLAN the authorized session is actually in (dynamic assignment)
    auth_state: str | None = None  # authorized | unauthorized | guest | n/a
    auth_method: str | None = None
    auth_user: str | None = None
    quarantined: bool = False
    original_vlan: int | None = None
    quarantine_reason: str | None = None
    quarantine_workflow: str | None = None
    hold: bool = False  # administrative shutdown applied by SentinelSwitch
    errdisable_reason: str | None = None
    last_change: str | None = None
    last_input: str | None = None
    last_output: str | None = None
    counters: dict[str, int] = field(default_factory=dict)
    port_security: dict[str, Any] = field(default_factory=dict)
    sticky_macs: list[str] = field(default_factory=list)

    @property
    def is_trunk(self) -> bool:
        return self.mode == "trunk"

    @property
    def long_name(self) -> str:
        return long_ifname(self.name)


@dataclass
class MacEntry:
    mac: str
    vlan: int
    interface: str
    entry_type: str  # DYNAMIC | STATIC
    learned_at: str


@dataclass
class DhcpBinding:
    mac: str
    ip: str
    vlan: int
    interface: str
    lease_expires: str
    binding_type: str = "dhcp-snooping"
    lease_start: str | None = None


@dataclass
class MacObservation:
    mac: str
    interface: str
    vlan: int
    first_seen: str
    last_seen: str


@dataclass
class ConfigChange:
    ts: str
    actor: str
    source: str
    interface: str | None
    commands: list[str]
    reason: str | None = None


@dataclass
class LogLine:
    ts: str
    seq: int
    facility: str
    severity: int
    mnemonic: str
    message: str

    def render(self) -> str:
        dt = parse_ts(self.ts)
        stamp = dt.strftime("%b %d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        return f"{self.seq:06d}: {stamp}: %{self.facility}-{self.severity}-{self.mnemonic}: {self.message}"


class SwitchTwin:
    """In-memory model of SW01. Mutations are only performed through explicit methods so the
    containment controller and the adapter can be tested against a well-defined state machine."""

    def __init__(self, env: Environment, now: datetime | None = None):
        self.env = env
        self.hostname: str = env.switch["hostname"]
        self.model: str = env.switch["model"]
        self.ios_version: str = env.switch["ios_version"]
        self.image: str = env.switch["image"]
        self.serial: str = env.switch["serial"]
        self.base_mac: str = mac_norm(env.switch["base_mac"])
        self.management_ip: str = env.switch["management_ip"]
        self.management_vlan: int = int(env.switch["management_vlan"])
        self.uptime_reference: str = env.switch["uptime_reference"]
        self.now: datetime = now or env.baseline_now
        self.interfaces: dict[str, Interface] = {}
        self.mac_table: list[MacEntry] = []
        self.dhcp_bindings: list[DhcpBinding] = []
        self.mac_history: list[MacObservation] = []
        self.config_changes: list[ConfigChange] = []
        self.audit: list[dict[str, Any]] = []
        self.log: list[LogLine] = []
        self.log_seq: int = 0
        self.vlans: dict[int, dict[str, Any]] = {
            v.id: {"id": v.id, "name": v.name, "subnet": v.subnet, "gateway": v.gateway, "purpose": v.purpose}
            for v in env.vlans.values()
        }
        self.span = dict(env.switch["span_session"])
        self.dhcp_snooping_vlans = sorted(v.id for v in env.vlans.values() if v.dhcp_snooping)
        self.dai_vlans = sorted(v.id for v in env.vlans.values() if v.dai)

    # ---------------------------------------------------------------------------------------
    # Construction
    # ---------------------------------------------------------------------------------------
    @classmethod
    def baseline(cls, env: Environment, now: datetime | None = None, apply_drift: bool = True) -> SwitchTwin:
        """Build the switch as it looks at `now` (default: the dataset baseline instant)."""
        twin = cls(env, now)
        rng = random.Random(env.seed ^ 0x5157)
        for name, intent in env.ports.items():
            s = intent.settings
            mode = s.get("mode", "access")
            iface = Interface(
                name=name,
                description=intent.description,
                mode=mode,
                access_vlan=s.get("access_vlan") if mode == "access" else None,
                native_vlan=s.get("native_vlan") if mode == "trunk" else None,
                allowed_vlans=list(s.get("allowed_vlans", [])) if mode == "trunk" else [],
                admin_status="down" if s.get("admin_shutdown") else "up",
                oper_status="notconnect",
                speed="auto",
                duplex="auto",
                port_class=intent.port_class,
                protected=intent.protected,
                span_destination=intent.span_destination,
                settings={
                    k: copy.deepcopy(v)
                    for k, v in s.items()
                    if k not in {"mode", "access_vlan", "native_vlan", "allowed_vlans", "admin_shutdown"}
                },
                oper_vlan=s.get("access_vlan") if mode == "access" else None,
                auth_state="n/a",
                last_change=ts_iso(parse_ts(env.switch["uptime_reference"])),
                counters={
                    "in_packets": 0,
                    "out_packets": 0,
                    "in_bytes": 0,
                    "out_bytes": 0,
                    "input_errors": 0,
                    "crc": 0,
                    "output_errors": 0,
                },
                port_security={
                    "enabled": bool(s.get("port_security", {}).get("enabled", False)),
                    "violation_count": 0,
                    "last_source": None,
                },
            )
            if name.startswith("Te"):
                iface.speed, iface.duplex = "auto", "auto"
            if s.get("admin_shutdown"):
                iface.oper_status = "disabled"
            if intent.span_destination:
                iface.oper_status = "monitoring"
                iface.speed, iface.duplex = "a-1000", "a-full"
            twin.interfaces[name] = iface

        # Attach devices present at `now`
        for dev in env.devices:
            if not dev.present_at(twin.now):
                continue
            iface = twin.interfaces[dev.interface]
            if dev.via_trunk:
                iface.oper_status = "connected"
                iface.speed, iface.duplex = "a-1000", "a-full"
                for vlan in sorted({dev.vlan, *dev.secondary_ips.keys(), *dev.gateways.keys()}):
                    if vlan in iface.allowed_vlans:
                        twin._learn(
                            dev.mac, vlan, dev.interface, at=twin.now, entry_type="DYNAMIC", ago=rng.randint(30, 280)
                        )
                continue
            twin.attach(
                dev.mac,
                dev.interface,
                dev.vlan,
                ip=dev.ip,
                auth=dev.auth,
                user=dev.user,
                at=_attach_time(dev, twin.now),
                quiet=True,
            )
            iface.counters = _counters_for(dev.role, rng)
            if dev.auth in {"eap-tls", "peap", "mab"} or dev.role in {"guest-laptop", "display"}:
                iface.port_security["last_source"] = dev.mac
                if iface.settings.get("port_security", {}).get("sticky"):
                    iface.sticky_macs = [dev.mac]
        # Leases for devices that left earlier today but whose lease has not expired yet
        for dev in env.devices:
            if dev.schedule and not dev.present_at(twin.now) and dev.ip and dev.vlan in twin.dhcp_snooping_vlans:
                start, end = dev.schedule
                if end < twin.now and not dev.dhcp_reservation and dev.role not in {"guest-laptop"}:
                    expires = _lease_expiry(env, start, end)
                    if expires > twin.now:
                        twin.dhcp_bindings.append(
                            DhcpBinding(
                                dev.mac,
                                dev.ip,
                                dev.vlan,
                                dev.interface,
                                ts_iso(expires),
                                "dhcp-snooping",
                                ts_iso(add_seconds(start, 1.8)),
                            )
                        )
        # MAC history from the day's movements
        for dev in env.devices:
            if dev.via_trunk:
                continue
            start = dev.schedule[0] if dev.schedule else env.day_start
            end = dev.schedule[1] if dev.schedule else twin.now
            twin.mac_history.append(
                MacObservation(dev.mac, dev.interface, dev.vlan, ts_iso(start), ts_iso(min(end, twin.now)))
            )
        if apply_drift:
            twin.apply_drift(env.drift_injections)
        twin._seed_log(rng)
        return twin

    def apply_drift(self, injections: list[dict[str, Any]]) -> None:
        for inj in injections:
            iface = self.interfaces[inj["interface"]]
            setting, observed = inj["setting"], inj.get("observed")
            if setting == "admin_status":
                iface.admin_status = observed
                if observed == "up" and iface.oper_status == "disabled":
                    iface.oper_status = "notconnect"
            elif setting == "description":
                iface.description = observed
            elif observed is None:
                iface.settings.pop(setting, None)
            else:
                iface.settings[setting] = observed

    # ---------------------------------------------------------------------------------------
    # Low-level state helpers
    # ---------------------------------------------------------------------------------------
    def _learn(
        self, mac: str, vlan: int, interface: str, at: datetime, entry_type: str = "DYNAMIC", ago: int = 0
    ) -> MacEntry:
        mac = mac_norm(mac)
        self.mac_table = [e for e in self.mac_table if not (e.mac == mac and e.vlan == vlan)]
        entry = MacEntry(mac, vlan, interface, entry_type, ts_iso(add_seconds(at, -ago)))
        self.mac_table.append(entry)
        return entry

    def _forget_interface(self, interface: str) -> None:
        self.mac_table = [e for e in self.mac_table if e.interface != interface]

    def attach(
        self,
        mac: str,
        interface: str,
        vlan: int,
        *,
        ip: str | None = None,
        auth: str = "none",
        user: str | None = None,
        at: datetime | None = None,
        quiet: bool = False,
        auth_state: str | None = None,
    ) -> None:
        """Bring a device up on an access port: link up, (optional) authorization, MAC learn, DHCP binding."""
        at = at or self.now
        mac = mac_norm(mac)
        iface = self.interfaces[interface]
        if iface.oper_status == "connected" and any(e.mac == mac for e in self.mac_table if e.interface == interface):
            return  # already attached; keep the existing session and lease
        iface.oper_status = "connected"
        iface.speed, iface.duplex = "a-1000", "a-full"
        iface.last_change = ts_iso(at)
        iface.last_input = ts_iso(self.now)
        iface.last_output = ts_iso(self.now)
        if auth_state == "unauthorized":
            iface.auth_state = "unauthorized"
            iface.auth_method = None
            iface.auth_user = None
            iface.oper_vlan = iface.access_vlan
            self.mac_history.append(MacObservation(mac, interface, vlan, ts_iso(at), ts_iso(at)))
            return
        if auth in {"eap-tls", "peap"}:
            iface.auth_state, iface.auth_method, iface.auth_user = "authorized", "dot1x", user
        elif auth == "mab":
            iface.auth_state, iface.auth_method, iface.auth_user = "authorized", "mab", mac
        elif auth_state == "guest" or vlan == 40:
            iface.auth_state, iface.auth_method, iface.auth_user = "guest", "dot1x-timeout", None
        else:
            iface.auth_state = "n/a"
        iface.oper_vlan = vlan
        self._learn(mac, vlan, interface, at=at)
        if ip and vlan in self.dhcp_snooping_vlans:
            dev = self.env.device_by_mac(mac)
            self.dhcp_bindings = [b for b in self.dhcp_bindings if not (b.mac == mac and b.vlan == vlan)]
            if auth == "static":
                # Static hosts get an `ip source binding` so IP Source Guard / DAI permit them.
                self.dhcp_bindings.append(
                    DhcpBinding(
                        mac, ip, vlan, interface, ts_iso(add_seconds(self.now, 10 * 365 * 86400)), "static", ts_iso(at)
                    )
                )
            else:
                reservation = bool(dev and dev.dhcp_reservation)
                lease_at = add_seconds(at, 1.8)
                expires = (
                    _lease_expiry(self.env, lease_at, self.now) if not reservation else add_seconds(self.now, 86400)
                )
                self.dhcp_bindings.append(
                    DhcpBinding(mac, ip, vlan, interface, ts_iso(expires), "dhcp-snooping", ts_iso(lease_at))
                )
        if not quiet:
            self.mac_history.append(MacObservation(mac, interface, vlan, ts_iso(at), ts_iso(at)))

    def advance_to(self, now: datetime) -> None:
        """Move the simulated clock forward, renewing leases of connected hosts (clients renew at T1)
        and expiring leases of hosts that are no longer attached."""
        self.now = now
        keep: list[DhcpBinding] = []
        for b in self.dhcp_bindings:
            if b.binding_type == "static":
                keep.append(b)
                continue
            iface = self.interfaces.get(b.interface)
            connected = bool(
                iface
                and iface.oper_status == "connected"
                and any(e.mac == b.mac for e in self.mac_table if e.interface == b.interface)
            )
            if connected and b.lease_start:
                dev = self.env.device_by_mac(b.mac)
                if dev and dev.dhcp_reservation:
                    b.lease_expires = ts_iso(add_seconds(now, 86400))
                else:
                    b.lease_expires = ts_iso(_lease_expiry(self.env, parse_ts(b.lease_start), now))
                keep.append(b)
            elif parse_ts(b.lease_expires) > now:
                keep.append(b)
        self.dhcp_bindings = keep
        for iface in self.interfaces.values():
            if iface.oper_status == "connected":
                iface.last_input = ts_iso(now)
                iface.last_output = ts_iso(now)

    def detach(self, interface: str, at: datetime | None = None, keep_binding: bool = True) -> None:
        at = at or self.now
        iface = self.interfaces[interface]
        iface.oper_status = "notconnect" if iface.admin_status == "up" else iface.oper_status
        iface.auth_state = "n/a"
        iface.auth_method = None
        iface.auth_user = None
        iface.oper_vlan = iface.access_vlan
        iface.last_change = ts_iso(at)
        self._forget_interface(interface)
        if not keep_binding:
            self.dhcp_bindings = [b for b in self.dhcp_bindings if b.interface != interface]

    # ---------------------------------------------------------------------------------------
    # Queries used by the correlation engine
    # ---------------------------------------------------------------------------------------
    def find_binding_by_ip(self, ip: str) -> DhcpBinding | None:
        for b in self.dhcp_bindings:
            if b.ip == ip:
                return b
        return None

    def find_bindings_by_mac(self, mac: str) -> list[DhcpBinding]:
        mac = mac_norm(mac)
        return [b for b in self.dhcp_bindings if b.mac == mac]

    def find_mac(self, mac: str) -> list[MacEntry]:
        mac = mac_norm(mac)
        return [e for e in self.mac_table if e.mac == mac]

    def macs_on_interface(self, interface: str) -> list[MacEntry]:
        return [e for e in self.mac_table if e.interface == interface]

    def observations_for_mac(self, mac: str) -> list[MacObservation]:
        mac = mac_norm(mac)
        return [o for o in self.mac_history if o.mac == mac]

    def interface(self, name: str) -> Interface:
        return self.interfaces[name]

    # ---------------------------------------------------------------------------------------
    # Configuration mutations (what the adapter performs)
    # ---------------------------------------------------------------------------------------
    def set_access_vlan(
        self, interface: str, vlan: int, *, actor: str, reason: str | None, at: datetime, workflow: str | None = None
    ) -> dict[str, Any]:
        iface = self.interfaces[interface]
        if iface.is_trunk:
            raise ValueError(f"{interface} is a trunk; access VLAN cannot be set")
        before = iface.access_vlan
        iface.access_vlan = vlan
        iface.oper_vlan = vlan
        iface.last_change = ts_iso(at)
        # IOS removes DHCP snooping bindings tied to the old VLAN on this port and re-learns MACs in the new VLAN.
        moved = [e for e in self.mac_table if e.interface == interface]
        self.mac_table = [e for e in self.mac_table if e.interface != interface]
        for e in moved:
            self._learn(e.mac, vlan, interface, at=at)
            self.mac_history.append(MacObservation(e.mac, interface, vlan, ts_iso(at), ts_iso(at)))
        self.dhcp_bindings = [b for b in self.dhcp_bindings if b.interface != interface]
        self._record_change(
            at, actor, interface, [f"interface {iface.long_name}", f" switchport access vlan {vlan}"], reason
        )
        return {"interface": interface, "from_vlan": before, "to_vlan": vlan}

    def quarantine(
        self, interface: str, quarantine_vlan: int, *, reason: str, workflow: str, at: datetime
    ) -> dict[str, Any]:
        iface = self.interfaces[interface]
        original = iface.oper_vlan or iface.access_vlan
        original_access = iface.access_vlan
        result = self.set_access_vlan(
            interface, quarantine_vlan, actor="sentinel", reason=reason, at=at, workflow=workflow
        )
        iface.quarantined = True
        iface.original_vlan = original_access
        iface.quarantine_reason = reason
        iface.quarantine_workflow = workflow
        self.audit.append(
            {
                "ts": ts_iso(at),
                "action": "quarantine_vlan",
                "interface": interface,
                "from_vlan": original,
                "to_vlan": quarantine_vlan,
                "workflow": workflow,
                "reason": reason,
            }
        )
        result.update({"original_oper_vlan": original, "original_access_vlan": original_access})
        return result

    def shutdown(
        self,
        interface: str,
        *,
        actor: str,
        reason: str | None,
        at: datetime,
        hold: bool = False,
        workflow: str | None = None,
    ) -> dict[str, Any]:
        iface = self.interfaces[interface]
        before = iface.admin_status
        iface.admin_status = "down"
        iface.oper_status = "disabled"
        iface.last_change = ts_iso(at)
        iface.auth_state = "n/a"
        iface.auth_method = None
        iface.auth_user = None
        if hold:
            iface.hold = True
            iface.quarantine_reason = reason
            iface.quarantine_workflow = workflow
        was_up = iface.oper_status in {"connected", "err-disabled"} or before == "up"
        self._forget_interface(interface)
        self._record_change(at, actor, interface, [f"interface {iface.long_name}", " shutdown"], reason)
        if was_up:
            self.syslog(
                add_seconds(at, 0.004),
                "LINK",
                5,
                "CHANGED",
                f"Interface {iface.long_name}, changed state to administratively down",
            )
            self.syslog(
                add_seconds(at, 0.006),
                "LINEPROTO",
                5,
                "UPDOWN",
                f"Line protocol on Interface {iface.long_name}, changed state to down",
            )
        if hold:
            self.audit.append(
                {
                    "ts": ts_iso(at),
                    "action": "port_shutdown",
                    "interface": interface,
                    "workflow": workflow,
                    "reason": reason,
                }
            )
        return {"interface": interface, "from_admin": before, "to_admin": "down"}

    def no_shutdown(self, interface: str, *, actor: str, reason: str | None, at: datetime) -> dict[str, Any]:
        iface = self.interfaces[interface]
        before = iface.admin_status
        iface.admin_status = "up"
        iface.oper_status = "notconnect"
        iface.hold = False
        iface.errdisable_reason = None
        iface.last_change = ts_iso(at)
        self._record_change(at, actor, interface, [f"interface {iface.long_name}", " no shutdown"], reason)
        return {"interface": interface, "from_admin": before, "to_admin": "up"}

    def errdisable(self, interface: str, reason: str, at: datetime) -> None:
        iface = self.interfaces[interface]
        iface.oper_status = "err-disabled"
        iface.errdisable_reason = reason
        iface.auth_state = "n/a"
        iface.last_change = ts_iso(at)
        self._forget_interface(interface)

    def restore(self, interface: str, *, actor: str, reason: str | None, at: datetime) -> dict[str, Any]:
        """Undo a SentinelSwitch containment action on an interface."""
        iface = self.interfaces[interface]
        result: dict[str, Any] = {"interface": interface}
        if iface.quarantined and iface.original_vlan is not None:
            original = iface.original_vlan
            r = self.set_access_vlan(interface, original, actor=actor, reason=reason, at=at)
            iface.quarantined = False
            iface.original_vlan = None
            iface.quarantine_reason = None
            iface.quarantine_workflow = None
            self.audit.append(
                {
                    "ts": ts_iso(at),
                    "action": "restore_vlan",
                    "interface": interface,
                    "to_vlan": original,
                    "actor": actor,
                    "reason": reason,
                }
            )
            result.update({"action": "restore_vlan", **r})
        elif iface.hold or iface.admin_status == "down":
            r = self.no_shutdown(interface, actor=actor, reason=reason, at=at)
            iface.quarantine_reason = None
            iface.quarantine_workflow = None
            self.audit.append(
                {"ts": ts_iso(at), "action": "release_hold", "interface": interface, "actor": actor, "reason": reason}
            )
            result.update({"action": "no_shutdown", **r})
        else:
            result.update({"action": "none"})
        return result

    def port_security_violation(self, interface: str, mac: str, at: datetime) -> None:
        iface = self.interfaces[interface]
        iface.port_security["violation_count"] = int(iface.port_security.get("violation_count", 0)) + 1
        iface.port_security["last_source"] = mac_norm(mac)
        iface.port_security["last_violation"] = ts_iso(at)

    def _record_change(
        self, at: datetime, actor: str, interface: str | None, commands: list[str], reason: str | None
    ) -> None:
        source_ip = "10.99.0.10" if actor == "sentinel" else "10.10.10.20"
        vty = "vty1" if actor == "sentinel" else "vty0"
        self.config_changes.append(ConfigChange(ts_iso(at), actor, f"{vty} ({source_ip})", interface, commands, reason))
        stamp = at.strftime("%H:%M:%S UTC %a %b %d %Y")
        self.syslog(
            add_seconds(at, -0.212),
            "SEC_LOGIN",
            5,
            "LOGIN_SUCCESS",
            f"Login Success [user: {actor}] [Source: {source_ip}] [localport: 22] at {stamp}",
        )
        self.syslog(at, "SYS", 5, "CONFIG_I", f"Configured from console by {actor} on {vty} ({source_ip})")

    # ---------------------------------------------------------------------------------------
    # Logging
    # ---------------------------------------------------------------------------------------
    def syslog(self, at: datetime, facility: str, severity: int, mnemonic: str, message: str) -> LogLine:
        self.log_seq += 1
        line = LogLine(ts_iso(at), self.log_seq, facility, severity, mnemonic, message)
        self.log.append(line)
        self.log.sort(key=lambda entry: (entry.ts, entry.seq))
        return line

    def _seed_log(self, rng: random.Random) -> None:
        """Start the buffer sequence where the collector's day began; routine lines are loaded from the dataset."""
        if not self.log:
            self.log_seq = 1816

    # ---------------------------------------------------------------------------------------
    # Serialisation
    # ---------------------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "model": self.model,
            "ios_version": self.ios_version,
            "image": self.image,
            "serial": self.serial,
            "base_mac": self.base_mac,
            "management_ip": self.management_ip,
            "management_vlan": self.management_vlan,
            "uptime_reference": self.uptime_reference,
            "now": ts_iso(self.now),
            "vlans": self.vlans,
            "span": self.span,
            "dhcp_snooping_vlans": self.dhcp_snooping_vlans,
            "dai_vlans": self.dai_vlans,
            "interfaces": {k: asdict(v) for k, v in self.interfaces.items()},
            "mac_table": [asdict(e) for e in self.mac_table],
            "dhcp_bindings": [asdict(b) for b in self.dhcp_bindings],
            "mac_history": [asdict(o) for o in self.mac_history],
            "config_changes": [asdict(c) for c in self.config_changes],
            "audit": list(self.audit),
            "log": [asdict(line) for line in self.log],
            "log_seq": self.log_seq,
        }

    @classmethod
    def from_dict(cls, env: Environment, data: dict[str, Any]) -> SwitchTwin:
        twin = cls(env, parse_ts(data["now"]))
        twin.vlans = {int(k): v for k, v in data["vlans"].items()}
        twin.span = data["span"]
        twin.dhcp_snooping_vlans = list(data["dhcp_snooping_vlans"])
        twin.dai_vlans = list(data["dai_vlans"])
        twin.interfaces = {k: Interface(**v) for k, v in data["interfaces"].items()}
        twin.mac_table = [MacEntry(**e) for e in data["mac_table"]]
        twin.dhcp_bindings = [DhcpBinding(**b) for b in data["dhcp_bindings"]]
        twin.mac_history = [MacObservation(**o) for o in data["mac_history"]]
        twin.config_changes = [ConfigChange(**c) for c in data["config_changes"]]
        twin.audit = list(data.get("audit", []))
        twin.log = [LogLine(**line) for line in data["log"]]
        twin.log_seq = int(data.get("log_seq", len(twin.log)))
        return twin

    def copy(self) -> SwitchTwin:
        return SwitchTwin.from_dict(self.env, copy.deepcopy(self.to_dict()))

    # ---------------------------------------------------------------------------------------
    # Summaries
    # ---------------------------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        st = {
            "connected": 0,
            "notconnect": 0,
            "disabled": 0,
            "err-disabled": 0,
            "monitoring": 0,
            "trunk": 0,
            "quarantined": 0,
            "protected": 0,
        }
        for iface in self.interfaces.values():
            if iface.is_trunk:
                st["trunk"] += 1
            st[iface.oper_status] = st.get(iface.oper_status, 0) + 1
            if iface.quarantined:
                st["quarantined"] += 1
            if iface.protected:
                st["protected"] += 1
        return st


# -------------------------------------------------------------------------------------------------
# helpers
# -------------------------------------------------------------------------------------------------
def _attach_time(dev, now: datetime) -> datetime:
    """Always-on devices were attached before the dataset day began."""
    if dev.schedule:
        return dev.schedule[0]
    return add_seconds(now, -3600 * 27)


def _lease_expiry(env: Environment, lease_start: datetime, now: datetime) -> datetime:
    """DHCP clients renew at T1 (half the lease). Given the first lease at `lease_start`, return the
    expiry of the most recent renewal at or before `now`."""
    lease = int(env.dhcp["lease_seconds"])
    renew_every = lease // 2
    elapsed = max(0, int((now - lease_start).total_seconds()))
    renewals = elapsed // renew_every
    last_renewal = add_seconds(lease_start, renewals * renew_every)
    return add_seconds(last_renewal, lease)


def _counters_for(role: str, rng: random.Random) -> dict[str, int]:
    scale = {
        "workstation": 1.0,
        "laptop": 0.8,
        "printer": 0.05,
        "guest-laptop": 0.4,
        "display": 0.6,
        "directory": 3.0,
        "file-server": 6.0,
        "aaa": 0.3,
        "web": 1.5,
        "git": 2.0,
        "update-mirror": 4.0,
        "jump-host": 0.4,
        "pdu": 0.01,
    }.get(role, 0.5)
    in_pk = int(rng.randint(180_000, 420_000) * scale)
    out_pk = int(rng.randint(150_000, 380_000) * scale)
    return {
        "in_packets": in_pk,
        "out_packets": out_pk,
        "in_bytes": int(in_pk * rng.randint(420, 760)),
        "out_bytes": int(out_pk * rng.randint(380, 900)),
        "input_errors": 0,
        "crc": 0,
        "output_errors": 0,
    }
