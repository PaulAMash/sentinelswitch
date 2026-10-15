"""Canonical environment model.

Everything in the repository that describes the lab (inventory, VLANs, port intent, scenarios) is loaded
from `simulator/fixtures` and `simulator/scenarios` through this module. Generators, the digital twin and
the API all consume the same objects, which is what keeps the dashboard, the Cisco artifacts, the evidence
bundles and the documentation numerically consistent.
"""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "simulator" / "fixtures"
SCENARIOS = ROOT / "simulator" / "scenarios"


# ---------------------------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------------------------
def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (with optional fractional seconds and Z suffix) into aware UTC."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def ts_iso(dt: datetime) -> str:
    """Render an aware datetime as ISO-8601 with millisecond precision and a Z suffix."""
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ts_epoch(dt: datetime) -> float:
    return round(dt.timestamp(), 6)


def add_seconds(dt: datetime, seconds: float) -> datetime:
    """Add seconds with millisecond rounding so repeated additions never drift."""
    return dt + timedelta(milliseconds=round(seconds * 1000))


def short_ifname(name: str) -> str:
    return name.replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")


def long_ifname(name: str) -> str:
    if name.startswith("Gi"):
        return "GigabitEthernet" + name[2:]
    if name.startswith("Te"):
        return "TenGigabitEthernet" + name[2:]
    return name


def mac_cisco(mac: str) -> str:
    """AA:BB:CC:DD:EE:FF -> aabb.ccdd.eeff"""
    h = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def mac_norm(mac: str) -> str:
    h = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------------------------
@dataclass
class Vlan:
    id: int
    name: str
    subnet: str | None
    gateway: str | None
    purpose: str
    dhcp_snooping: bool
    dai: bool


@dataclass
class User:
    username: str
    display_name: str
    department: str
    title: str
    auth_method: str
    roles: list[str] = field(default_factory=list)


@dataclass
class Device:
    hostname: str
    role: str
    vendor: str
    os: str
    mac: str
    ip: str | None
    vlan: int
    interface: str
    criticality: str
    auth: str
    schedule: tuple[datetime, datetime] | None  # None => always attached
    user: str | None = None
    tags: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    via_trunk: bool = False
    secondary_ips: dict[int, str] = field(default_factory=dict)
    gateways: dict[int, str] = field(default_factory=dict)
    sensor_mac: str | None = None
    dhcp_reservation: bool = False
    dhcp_hostname: str | None = None
    asset_tag: str | None = None
    notes: str | None = None
    zone: str | None = None

    @property
    def device_type(self) -> str:
        return self.role

    def present_at(self, when: datetime) -> bool:
        if self.schedule is None:
            return True
        start, end = self.schedule
        return start <= when <= end

    @property
    def is_endpoint(self) -> bool:
        return self.role in {"workstation", "laptop", "printer", "guest-laptop", "display"}


@dataclass
class UnknownDevice:
    label: str
    description: str
    mac: str
    interface: str
    schedule: tuple[datetime, datetime]


@dataclass
class PortIntent:
    name: str
    profile: str
    description: str
    port_class: str
    protected: bool = False
    span_destination: bool = False
    settings: dict[str, Any] = field(default_factory=dict)

    @property
    def mode(self) -> str:
        return self.settings.get("mode", "access")

    @property
    def access_vlan(self) -> int | None:
        return self.settings.get("access_vlan")

    @property
    def admin_shutdown(self) -> bool:
        return bool(self.settings.get("admin_shutdown", False))


@dataclass
class ExternalService:
    fqdn: str
    ip: str
    ports: list[int]
    kind: str
    approved: bool = True


@dataclass
class ScenarioInstance:
    name: str
    start: datetime
    parameters: dict[str, Any]
    expected: dict[str, Any]
    incident_id: str | None = None
    resolution: dict[str, Any] | None = None
    actor_override: dict[str, Any] | None = None


@dataclass
class Scenario:
    id: str
    name: str
    short: str
    klass: str
    rule: str
    mitre: list[str]
    description: str
    actor: dict[str, Any]
    instances: dict[str, ScenarioInstance]
    timing: dict[str, float]
    setup: list[dict[str, Any]] = field(default_factory=list)
    teardown: list[dict[str, Any]] = field(default_factory=list)
    flagship: bool = False

    def actor_for(self, instance: str) -> dict[str, Any]:
        inst = self.instances[instance]
        actor = dict(self.actor)
        if inst.actor_override:
            actor.update(inst.actor_override)
        return actor


@dataclass
class Environment:
    organization: dict[str, Any]
    dataset: dict[str, Any]
    switch: dict[str, Any]
    vlans: dict[int, Vlan]
    dhcp: dict[str, Any]
    port_defaults: dict[str, dict[str, Any]]
    ports: dict[str, PortIntent]
    drift_injections: list[dict[str, Any]]
    devices: list[Device]
    unknown_devices: list[UnknownDevice]
    users: dict[str, User]
    oui_vendors: dict[str, str]
    external_services: list[ExternalService]
    internal_services: list[dict[str, Any]]
    approved_ntp: list[str]
    approved_dns: list[str]
    scenarios: dict[str, Scenario]

    # ---- convenience lookups --------------------------------------------------------------
    @property
    def day_start(self) -> datetime:
        return parse_ts(self.dataset["start"])

    @property
    def day_end(self) -> datetime:
        return parse_ts(self.dataset["end"])

    @property
    def baseline_now(self) -> datetime:
        return parse_ts(self.dataset["baseline_now"])

    @property
    def seed(self) -> int:
        return int(self.dataset["seed"])

    @property
    def hostname(self) -> str:
        return self.switch["hostname"]

    def device_by_ip(self, ip: str) -> Device | None:
        for d in self.devices:
            if d.ip == ip or ip in d.secondary_ips.values() or ip in d.gateways.values():
                return d
        return None

    def device_by_mac(self, mac: str) -> Device | None:
        m = mac_norm(mac)
        for d in self.devices:
            if mac_norm(d.mac) == m:
                return d
        return None

    def device_by_hostname(self, hostname: str) -> Device | None:
        for d in self.devices:
            if d.hostname == hostname:
                return d
        return None

    def device_by_interface(self, interface: str) -> Device | None:
        for d in self.devices:
            if d.interface == interface and not d.via_trunk:
                return d
        return None

    def vendor_for_mac(self, mac: str) -> str:
        prefix = mac_norm(mac)[:8]
        return self.oui_vendors.get(prefix, "Unknown")

    def vlan_for_ip(self, ip: str) -> Vlan | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for v in self.vlans.values():
            if v.subnet and addr in ipaddress.ip_network(v.subnet):
                return v
        return None

    def gateway_for_vlan(self, vlan_id: int) -> str | None:
        v = self.vlans.get(vlan_id)
        return v.gateway if v else None

    def all_gig_interfaces(self) -> list[str]:
        return [f"Gi1/0/{i}" for i in range(1, int(self.switch["gig_ports"]) + 1)]

    def all_tengig_interfaces(self) -> list[str]:
        return [f"Te1/0/{i}" for i in range(1, int(self.switch.get("tengig_ports", 0)) + 1)]

    def flagship(self) -> Scenario:
        for s in self.scenarios.values():
            if s.flagship:
                return s
        raise KeyError("no flagship scenario defined")


# ---------------------------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------------------------
def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _schedule(value: Any, day: str) -> tuple[datetime, datetime] | None:
    if value in (None, "always"):
        return None
    start, end = value
    s = parse_ts(f"{day}T{start}:00Z")
    e = parse_ts(f"{day}T{end}:00Z") if end != "23:59" else parse_ts(f"{day}T23:59:59Z")
    return (s, e)


def _build_ports(env_raw: dict[str, Any]) -> dict[str, PortIntent]:
    defaults = env_raw["port_defaults"]
    gig = int(env_raw["switch"]["gig_ports"])
    tengig = int(env_raw["switch"].get("tengig_ports", 0))
    listed = env_raw["ports"]
    ports: dict[str, PortIntent] = {}
    names = [f"Gi1/0/{i}" for i in range(1, gig + 1)] + [f"Te1/0/{i}" for i in range(1, tengig + 1)]
    for name in names:
        spec = listed.get(name)
        if spec is None:
            settings = copy.deepcopy(defaults["unused_port"])
            ports[name] = PortIntent(
                name=name, profile="unused_port", description="UNUSED", port_class="unused", settings=settings
            )
            continue
        settings = copy.deepcopy(defaults[spec["profile"]])
        for key, val in spec.items():
            if key in {"profile", "description", "protected", "class", "span_destination"}:
                continue
            settings[key] = val
        ports[name] = PortIntent(
            name=name,
            profile=spec["profile"],
            description=spec["description"],
            port_class=spec.get("class", "unknown"),
            protected=bool(spec.get("protected", False)),
            span_destination=bool(spec.get("span_destination", False)),
            settings=settings,
        )
    return ports


def _load_scenarios(day: str) -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    for path in sorted(SCENARIOS.glob("*.yaml")):
        raw = _read_yaml(path)
        instances: dict[str, ScenarioInstance] = {}
        for name, inst in raw["instances"].items():
            instances[name] = ScenarioInstance(
                name=name,
                start=parse_ts(inst["start"]),
                parameters=dict(inst.get("parameters", {})),
                expected=dict(inst.get("expected", {})),
                incident_id=inst.get("incident_id"),
                resolution=inst.get("resolution"),
                actor_override=inst.get("actor_override"),
            )
        scenarios[raw["id"]] = Scenario(
            id=raw["id"],
            name=raw["name"],
            short=raw.get("short", ""),
            klass=raw["class"],
            rule=raw["rule"],
            mitre=list(raw.get("mitre", [])),
            description=" ".join(str(raw.get("description", "")).split()),
            actor=dict(raw["actor"]),
            instances=instances,
            timing={k: float(v) for k, v in raw["timing"].items()},
            setup=list(raw.get("setup", [])),
            teardown=list(raw.get("teardown", [])),
            flagship=bool(raw.get("flagship", False)),
        )
    return scenarios


@lru_cache(maxsize=1)
def load_environment() -> Environment:
    env_raw = _read_yaml(FIXTURES / "environment.yaml")
    inv_raw = _read_yaml(FIXTURES / "inventory.yaml")
    users_raw = _read_yaml(FIXTURES / "users.yaml")
    ext_raw = _read_yaml(FIXTURES / "external.yaml")
    day = env_raw["dataset"]["day"]

    vlans = {
        int(v["id"]): Vlan(
            id=int(v["id"]),
            name=v["name"],
            subnet=v.get("subnet"),
            gateway=v.get("gateway"),
            purpose=v.get("purpose", ""),
            dhcp_snooping=bool(v.get("dhcp_snooping", False)),
            dai=bool(v.get("dai", False)),
        )
        for v in env_raw["vlans"]
    }

    devices: list[Device] = []
    for d in inv_raw["devices"]:
        devices.append(
            Device(
                hostname=d["hostname"],
                role=d["role"],
                vendor=d.get("vendor", "Unknown"),
                os=d.get("os", ""),
                mac=mac_norm(d["mac"]),
                ip=d.get("ip"),
                vlan=int(d["vlan"]),
                interface=d["interface"],
                criticality=d.get("criticality", "standard"),
                auth=d.get("auth", "none"),
                schedule=_schedule(d.get("schedule", "always"), day),
                user=d.get("user"),
                tags=list(d.get("tags", [])),
                services=list(d.get("services", [])),
                via_trunk=bool(d.get("via_trunk", False)),
                secondary_ips={int(k): v for k, v in d.get("secondary_ips", {}).items()},
                gateways={int(k): v for k, v in d.get("gateways", {}).items()},
                sensor_mac=d.get("sensor_mac"),
                dhcp_reservation=bool(d.get("dhcp_reservation", False)),
                dhcp_hostname=d.get("dhcp_hostname"),
                asset_tag=d.get("asset_tag"),
                notes=d.get("notes"),
                zone=d.get("zone"),
            )
        )

    unknown = [
        UnknownDevice(
            label=u["label"],
            description=u["description"],
            mac=mac_norm(u["mac"]),
            interface=u["interface"],
            schedule=_schedule(u["schedule"], day),  # type: ignore[arg-type]
        )
        for u in inv_raw.get("unknown_devices", [])
    ]

    users = {
        u["username"]: User(
            username=u["username"],
            display_name=u["display_name"],
            department=u["department"],
            title=u.get("title", ""),
            auth_method=u.get("auth_method", "eap-tls"),
            roles=list(u.get("roles", [])),
        )
        for u in users_raw["users"]
    }

    external = [
        ExternalService(
            fqdn=e["fqdn"], ip=e["ip"], ports=list(e["ports"]), kind=e["kind"], approved=bool(e.get("approved", True))
        )
        for e in ext_raw["external_services"]
    ]

    return Environment(
        organization=env_raw["organization"],
        dataset=env_raw["dataset"],
        switch=env_raw["switch"],
        vlans=vlans,
        dhcp=env_raw["dhcp"],
        port_defaults=env_raw["port_defaults"],
        ports=_build_ports(env_raw),
        drift_injections=list(env_raw.get("drift_injections", [])),
        devices=devices,
        unknown_devices=unknown,
        users=users,
        oui_vendors={mac_norm(k + ":00:00:00")[:8]: v for k, v in inv_raw.get("oui_vendors", {}).items()},
        external_services=external,
        internal_services=list(ext_raw.get("internal_services", [])),
        approved_ntp=list(ext_raw.get("approved_ntp_servers", [])),
        approved_dns=list(ext_raw.get("approved_dns_servers", [])),
        scenarios=_load_scenarios(day),
    )
