"""Attribution engine.

Given an actor (an IP, a MAC, and/or a physical interface) the engine walks the access-layer data
sources in order and records every hop, including the ones that fail, so an analyst can see exactly
how a source address was tied to a switch port:

    IP -> DHCP snooping binding -> MAC -> MAC address table -> switch / interface -> VLAN -> identity

Every hop is a `Step` with a status (resolved / missing / conflict / fallback / skipped), the source
that answered, and the evidence. Edge cases the engine handles explicitly: unknown MAC, expired DHCP
binding, MAC seen on several interfaces (movement), protected ports, trunk interfaces, SPAN
destinations, and hosts with no binding at all.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment, add_seconds, mac_norm, parse_ts, short_ifname, ts_iso


class Clock:
    """A tiny simulated clock so processing steps get deterministic timestamps."""

    def __init__(self, now: datetime):
        self.now = now

    def advance(self, seconds: float) -> datetime:
        self.now = add_seconds(self.now, seconds)
        return self.now


@dataclass
class Step:
    name: str
    status: str  # resolved | missing | conflict | fallback | skipped | refused
    source: str
    input: str | None
    output: str | None
    detail: str
    ts: str


@dataclass
class Attribution:
    ip: str | None
    mac: str | None
    switch: str
    interface: str | None
    vlan: int | None
    access_vlan: int | None
    port_class: str | None
    port_mode: str | None
    protected: bool
    trunk: bool
    span_destination: bool
    device: str | None
    user: str | None
    department: str | None
    criticality: str | None
    vendor: str | None
    resolved: bool
    confidence: float
    flags: list[str]
    steps: list[Step] = field(default_factory=list)
    binding: dict[str, Any] | None = None
    mac_entries: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    impersonated_device: str | None = None
    port_owner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @property
    def chain(self) -> list[str]:
        parts = []
        if self.ip:
            parts.append(self.ip)
        if self.mac:
            parts.append(self.mac)
        parts.append(self.switch)
        if self.interface:
            parts.append(self.interface)
        if self.vlan is not None:
            parts.append(f"VLAN {self.vlan}")
        return parts


class CorrelationEngine:
    def __init__(self, env: Environment, twin: SwitchTwin, timing: dict[str, float] | None = None):
        self.env = env
        self.twin = twin
        self.timing = timing or {"open": 0.08, "dhcp": 0.14, "mac": 0.24, "identity": 0.09}

    def resolve(
        self,
        *,
        ip: str | None = None,
        mac: str | None = None,
        interface: str | None = None,
        at: datetime | None = None,
        hints: dict[str, Any] | None = None,
        clock: Clock | None = None,
    ) -> Attribution:
        hints = hints or {}
        clock = clock or Clock(at or self.twin.now)
        started = clock.now
        steps: list[Step] = []
        flags: list[str] = []
        confidence = 1.0
        mac = mac_norm(mac) if mac else None
        iface_name = short_ifname(interface) if interface else None
        clock.advance(self.timing.get("open", 0.08))

        # ---- 1. IP -> DHCP snooping binding -> MAC ------------------------------------------
        binding = None
        clock.advance(self.timing.get("dhcp", 0.14))
        if ip:
            binding = self.twin.find_binding_by_ip(ip)
            if binding:
                expired = parse_ts(binding.lease_expires) < clock.now and binding.binding_type != "static"
                if expired:
                    flags.append("expired_binding")
                    confidence -= 0.25
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "conflict",
                            "show ip dhcp snooping binding",
                            ip,
                            binding.mac,
                            f"Binding for {ip} exists but lease expired {binding.lease_expires}; treating MAC {binding.mac} as best effort",
                            ts_iso(clock.now),
                        )
                    )
                else:
                    remaining = int((parse_ts(binding.lease_expires) - clock.now).total_seconds())
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "resolved",
                            "show ip dhcp snooping binding",
                            ip,
                            binding.mac,
                            f"{ip} -> {binding.mac} ({binding.binding_type}, VLAN {binding.vlan}, {binding.interface}, {'static' if binding.binding_type == 'static' else f'{remaining}s remaining'})",
                            ts_iso(clock.now),
                        )
                    )
                if mac and mac != mac_norm(binding.mac):
                    flags.append("mac_conflict")
                    confidence -= 0.3
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "conflict",
                            "show ip dhcp snooping binding",
                            ip,
                            binding.mac,
                            f"Caller supplied MAC {mac} but binding says {binding.mac}",
                            ts_iso(clock.now),
                        )
                    )
                else:
                    mac = mac_norm(binding.mac)
            else:
                flags.append("no_binding")
                if mac:
                    confidence -= 0.05
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "missing",
                            "show ip dhcp snooping binding",
                            ip,
                            None,
                            f"No DHCP snooping binding for {ip}; continuing with MAC supplied by the detection source",
                            ts_iso(clock.now),
                        )
                    )
                else:
                    static = self.env.device_by_ip(ip)
                    if static is not None:
                        mac = mac_norm(static.mac)
                        confidence -= 0.1
                        flags.append("static_inventory_fallback")
                        steps.append(
                            Step(
                                "dhcp_binding",
                                "fallback",
                                "asset inventory (static address)",
                                ip,
                                mac,
                                f"No DHCP snooping binding for {ip} (VLAN not snooped or static host); MAC {mac} taken from the inventory record for {static.hostname}",
                                ts_iso(clock.now),
                            )
                        )
                    else:
                        confidence -= 0.4
                        steps.append(
                            Step(
                                "dhcp_binding",
                                "missing",
                                "show ip dhcp snooping binding",
                                ip,
                                None,
                                f"No DHCP snooping binding for {ip} and no other MAC evidence",
                                ts_iso(clock.now),
                            )
                        )
        else:
            if mac:
                bindings = self.twin.find_bindings_by_mac(mac)
                if bindings:
                    b = bindings[0]
                    binding = b
                    ip = b.ip
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "resolved",
                            "show ip dhcp snooping binding",
                            mac,
                            b.ip,
                            f"{mac} -> {b.ip} (VLAN {b.vlan}, {b.interface})",
                            ts_iso(clock.now),
                        )
                    )
                else:
                    steps.append(
                        Step(
                            "dhcp_binding",
                            "missing",
                            "show ip dhcp snooping binding",
                            mac,
                            None,
                            "No binding for this MAC (expected when the port never authorised or the device is static)",
                            ts_iso(clock.now),
                        )
                    )
                    flags.append("no_binding")
            else:
                steps.append(
                    Step(
                        "dhcp_binding",
                        "skipped",
                        "show ip dhcp snooping binding",
                        None,
                        None,
                        "No IP or MAC to look up",
                        ts_iso(clock.now),
                    )
                )

        # ---- 2. MAC -> MAC address table -> interface / VLAN ------------------------------
        clock.advance(self.timing.get("mac", 0.24))
        entries = self.twin.find_mac(mac) if mac else []
        vlan: int | None = None
        if entries:
            ifaces = sorted({e.interface for e in entries})
            if len(ifaces) > 1:
                flags.append("multiple_observations")
                confidence -= 0.2
                chosen = sorted(entries, key=lambda e: e.learned_at)[-1]
                steps.append(
                    Step(
                        "mac_table",
                        "conflict",
                        "show mac address-table address",
                        mac,
                        chosen.interface,
                        f"{mac} learned on {', '.join(ifaces)}; using most recent entry {chosen.interface} (VLAN {chosen.vlan})",
                        ts_iso(clock.now),
                    )
                )
                resolved_iface, vlan = chosen.interface, chosen.vlan
            else:
                chosen = entries[0]
                resolved_iface, vlan = chosen.interface, chosen.vlan
                steps.append(
                    Step(
                        "mac_table",
                        "resolved",
                        "show mac address-table address",
                        mac,
                        resolved_iface,
                        f"{mac} -> {self.twin.hostname} {resolved_iface} (VLAN {vlan}, {chosen.entry_type})",
                        ts_iso(clock.now),
                    )
                )
            if iface_name and iface_name != resolved_iface:
                flags.append("interface_conflict")
                steps.append(
                    Step(
                        "mac_table",
                        "conflict",
                        "show mac address-table address",
                        mac,
                        resolved_iface,
                        f"Detection source reported {iface_name} but the MAC table has the address on {resolved_iface}; the reporting interface is used because the frames were dropped before learning",
                        ts_iso(clock.now),
                    )
                )
                resolved_iface = iface_name
            iface_name = resolved_iface
        else:
            if iface_name:
                flags.append("mac_not_learned")
                confidence -= 0.05
                src = hints.get("interface_source", "syslog / AAA NAS-Port-Id")
                steps.append(
                    Step(
                        "mac_table",
                        "fallback",
                        "show mac address-table address",
                        mac,
                        iface_name,
                        f"No MAC table entry for {mac or 'unknown MAC'} (port not authorised); interface {iface_name} taken from {src}",
                        ts_iso(clock.now),
                    )
                )
            elif mac:
                flags.append("mac_not_learned")
                confidence -= 0.5
                steps.append(
                    Step(
                        "mac_table",
                        "missing",
                        "show mac address-table address",
                        mac,
                        None,
                        f"{mac} not present in the MAC address table and no interface hint",
                        ts_iso(clock.now),
                    )
                )
            else:
                steps.append(
                    Step(
                        "mac_table",
                        "skipped",
                        "show mac address-table address",
                        None,
                        None,
                        "No MAC to look up",
                        ts_iso(clock.now),
                    )
                )

        # ---- 2b. MAC movement ---------------------------------------------------------------
        observations = self.twin.observations_for_mac(mac) if mac else []
        recent = [o for o in observations if parse_ts(o.last_seen) >= add_seconds(clock.now, -6 * 3600)]
        if len({o.interface for o in recent}) > 1:
            flags.append("mac_moved")
            confidence -= 0.05
            steps.append(
                Step(
                    "mac_history",
                    "conflict",
                    "mac-notification history",
                    mac,
                    iface_name,
                    f"{mac} observed on {', '.join(sorted({o.interface for o in recent}))} in the last 6h; most recent {iface_name}",
                    ts_iso(clock.now),
                )
            )

        # ---- 3. interface properties ---------------------------------------------------------
        port = self.twin.interfaces.get(iface_name) if iface_name else None
        access_vlan = port.access_vlan if port else None
        if port and vlan is None:
            vlan = port.oper_vlan or port.access_vlan
        protected = bool(port and port.protected)
        trunk = bool(port and port.is_trunk)
        span = bool(port and port.span_destination)
        if port:
            notes = []
            if protected:
                notes.append("PROTECTED infrastructure port")
                flags.append("protected_port")
            if trunk:
                notes.append("trunk: host is behind another device")
                flags.append("trunk_interface")
            if span:
                notes.append("SPAN destination")
                flags.append("span_destination")
            steps.append(
                Step(
                    "interface",
                    "resolved",
                    "show interfaces switchport",
                    iface_name,
                    f"VLAN {vlan}",
                    f"{iface_name} '{port.description}' mode={port.mode} access_vlan={port.access_vlan} oper_vlan={port.oper_vlan} class={port.port_class} status={port.oper_status}"
                    + (f" [{'; '.join(notes)}]" if notes else ""),
                    ts_iso(clock.now),
                )
            )
        else:
            steps.append(
                Step(
                    "interface",
                    "missing",
                    "show interfaces switchport",
                    iface_name,
                    None,
                    "No interface could be determined",
                    ts_iso(clock.now),
                )
            )
            flags.append("unresolved")

        # ---- 4. identity ---------------------------------------------------------------------
        clock.advance(self.timing.get("identity", 0.09))
        device = self.env.device_by_mac(mac) if mac else None
        if device is None and ip:
            device = self.env.device_by_ip(ip)
        impersonated = None
        port_owner = self.env.device_by_interface(iface_name) if iface_name else None
        if device and iface_name and device.interface != iface_name and not device.via_trunk:
            # The MAC belongs to an inventory asset that lives on a different port: impersonation.
            impersonated = device
            flags.append("mac_impersonation")
            confidence -= 0.1
            steps.append(
                Step(
                    "identity",
                    "conflict",
                    "asset inventory / AAA session",
                    mac,
                    None,
                    f"{mac} is registered to {device.hostname} on {device.interface} but was seen on {iface_name}; treating the source as an unknown device impersonating {device.hostname}"
                    + (f" (port owner: {port_owner.hostname})" if port_owner else ""),
                    ts_iso(clock.now),
                )
            )
            device = None
        user = self.env.users.get(device.user) if device and device.user else None
        if device:
            steps.append(
                Step(
                    "identity",
                    "resolved",
                    "asset inventory / AAA session",
                    mac or ip,
                    device.hostname,
                    f"{device.hostname} ({device.role}, {device.vendor}, {device.os}) criticality={device.criticality}"
                    + (f" user={user.username} ({user.display_name}, {user.department})" if user else ""),
                    ts_iso(clock.now),
                )
            )
        elif impersonated is None and port_owner and not mac:
            flags.append("identity_from_port")
            steps.append(
                Step(
                    "identity",
                    "fallback",
                    "asset inventory (port assignment)",
                    iface_name,
                    port_owner.hostname,
                    f"No MAC in the event; {port_owner.hostname} is the endpoint assigned to {iface_name} ({port_owner.role}, criticality={port_owner.criticality})",
                    ts_iso(clock.now),
                )
            )
            device = port_owner
            user = self.env.users.get(device.user) if device.user else None
        elif impersonated is None:
            flags.append("unknown_device")
            confidence -= 0.05
            steps.append(
                Step(
                    "identity",
                    "missing",
                    "asset inventory / AAA session",
                    mac or ip,
                    None,
                    f"{mac or ip} is not in the asset inventory"
                    + (f" (OUI vendor: {self.env.vendor_for_mac(mac)})" if mac else ""),
                    ts_iso(clock.now),
                )
            )

        resolved = port is not None and not trunk
        attribution = Attribution(
            ip=ip,
            mac=mac,
            switch=self.twin.hostname,
            interface=iface_name,
            vlan=vlan,
            access_vlan=access_vlan,
            port_class=port.port_class if port else None,
            port_mode=port.mode if port else None,
            protected=protected,
            trunk=trunk,
            span_destination=span,
            device=device.hostname if device else None,
            user=user.username if user else None,
            department=user.department if user else None,
            criticality=device.criticality if device else (port_owner.criticality if port_owner else None),
            vendor=device.vendor if device else (self.env.vendor_for_mac(mac) if mac else None),
            resolved=resolved,
            confidence=round(max(0.0, min(1.0, confidence)), 2),
            flags=flags,
            steps=steps,
            binding=asdict(binding) if binding else None,
            mac_entries=[asdict(e) for e in entries],
            observations=[asdict(o) for o in observations],
            started_at=ts_iso(started),
            completed_at=ts_iso(clock.now),
            impersonated_device=impersonated.hostname if impersonated else None,
            port_owner=port_owner.hostname if port_owner else None,
        )
        return attribution
