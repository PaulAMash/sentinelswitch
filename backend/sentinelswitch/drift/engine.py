"""Compare the declared port intent (simulator/fixtures/environment.yaml) with the observed switch."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment, long_ifname

CHECKED_SETTINGS = [
    "admin_status",
    "description",
    "mode",
    "access_vlan",
    "port_security",
    "bpduguard",
    "storm_control",
    "dhcp_snooping_trust",
    "dai_trust",
    "ip_source_guard",
    "dot1x",
    "mab",
    "spanning_tree_portfast",
]


@dataclass
class DriftFinding:
    id: str
    scope: str
    interface: str | None
    setting: str
    expected: Any
    observed: Any
    severity: str
    recommendation: str
    status: str  # open | approved
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _severity_for(setting: str, iface_class: str) -> str:
    if setting in {"access_vlan", "mode", "dhcp_snooping_trust", "dai_trust"}:
        return "high"
    if setting in {"admin_status", "port_security", "bpduguard", "ip_source_guard", "dot1x", "mab"}:
        return "medium"
    if setting in {"storm_control", "spanning_tree_portfast"}:
        return "low"
    return "info"


def _recommend(iface_name: str, setting: str, expected: Any) -> str:
    ln = long_ifname(iface_name)
    if setting == "admin_status":
        return f"interface {ln}\n {'shutdown' if expected == 'down' else 'no shutdown'}"
    if setting == "description":
        return f"interface {ln}\n description {expected}"
    if setting == "storm_control":
        lines = [f"interface {ln}"]
        for kind in ("broadcast", "multicast"):
            if expected and kind in expected:
                lines.append(f" storm-control {kind} level {expected[kind]}")
        lines.append(" storm-control action trap")
        return "\n".join(lines)
    if setting == "access_vlan":
        return f"interface {ln}\n switchport access vlan {expected}"
    if setting == "bpduguard":
        return f"interface {ln}\n spanning-tree bpduguard {'enable' if expected else 'disable'}"
    if setting == "ip_source_guard":
        return f"interface {ln}\n {'' if expected else 'no '}ip verify source"
    if setting == "port_security":
        return (
            f"interface {ln}\n switchport port-security\n switchport port-security violation {expected.get('violation', 'restrict')}"
            if expected and expected.get("enabled")
            else f"interface {ln}\n no switchport port-security"
        )
    return f"interface {ln}\n ! re-apply template value for {setting}: {expected}"


class DriftEngine:
    def __init__(self, env: Environment):
        self.env = env

    def evaluate(self, twin: SwitchTwin) -> dict[str, Any]:
        findings: list[DriftFinding] = []
        checks = 0
        n = 0
        for name, intent in self.env.ports.items():
            iface = twin.interfaces.get(name)
            if iface is None:
                continue
            desired = dict(intent.settings)
            observed_map: dict[str, Any] = {
                "admin_status": iface.admin_status,
                "description": iface.description,
                "mode": iface.mode,
                "access_vlan": iface.access_vlan,
                **{
                    k: iface.settings.get(k)
                    for k in CHECKED_SETTINGS
                    if k not in {"admin_status", "description", "mode", "access_vlan"}
                },
            }
            expected_map: dict[str, Any] = {
                "admin_status": "down" if desired.get("admin_shutdown") else "up",
                "description": intent.description,
                "mode": desired.get("mode", "access"),
                "access_vlan": desired.get("access_vlan") if desired.get("mode", "access") == "access" else None,
                **{
                    k: desired.get(k)
                    for k in CHECKED_SETTINGS
                    if k not in {"admin_status", "description", "mode", "access_vlan"}
                },
            }
            for setting in CHECKED_SETTINGS:
                checks += 1
                exp, obs = expected_map.get(setting), observed_map.get(setting)
                if setting == "port_security" and (exp or {}).get("enabled") is False and not obs:
                    continue
                if setting == "port_security" and exp and obs:
                    exp = {k: v for k, v in exp.items() if k != "sticky_macs"}
                if exp == obs:
                    continue
                status, note = "open", None
                if setting == "admin_status" and iface.hold:
                    status, note = (
                        "approved",
                        f"Administrative hold applied by SentinelSwitch workflow {iface.quarantine_workflow}",
                    )
                if setting == "access_vlan" and iface.quarantined:
                    status, note = (
                        "approved",
                        f"Quarantine applied by SentinelSwitch workflow {iface.quarantine_workflow} (original VLAN {iface.original_vlan})",
                    )
                n += 1
                findings.append(
                    DriftFinding(
                        f"DRIFT-{n:03d}",
                        "interface",
                        name,
                        setting,
                        exp,
                        obs,
                        _severity_for(setting, intent.port_class),
                        _recommend(name, setting, exp),
                        status,
                        note,
                    )
                )
        # global checks
        globals_ = [
            ("vlans", sorted(self.env.vlans), sorted(twin.vlans)),
            (
                "dhcp_snooping_vlans",
                sorted(v.id for v in self.env.vlans.values() if v.dhcp_snooping),
                sorted(twin.dhcp_snooping_vlans),
            ),
            ("dai_vlans", sorted(v.id for v in self.env.vlans.values() if v.dai), sorted(twin.dai_vlans)),
            ("span_session", dict(self.env.switch["span_session"]), dict(twin.span)),
        ]
        for setting, exp, obs in globals_:
            checks += 1
            if exp != obs:
                n += 1
                findings.append(
                    DriftFinding(
                        f"DRIFT-{n:03d}",
                        "global",
                        None,
                        setting,
                        exp,
                        obs,
                        "high",
                        f"! re-apply global template for {setting}",
                        "open",
                    )
                )
        open_findings = [f for f in findings if f.status == "open"]
        return {
            "checked_interfaces": len(self.env.ports),
            "checks": checks,
            "findings": [f.to_dict() for f in findings],
            "open": len(open_findings),
            "approved": len(findings) - len(open_findings),
            "by_severity": {
                s: sum(1 for f in open_findings if f.severity == s) for s in ("high", "medium", "low", "info")
            },
            "compliant_interfaces": len(self.env.ports) - len({f.interface for f in open_findings if f.interface}),
        }
