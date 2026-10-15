"""Control catalog.

Each control names the exact source of truth it reads inside the digital twin or the application
store, the states it can reach, its severity when it fails, the freshness window applied to
event-derived evidence, and a limited mapping to NIST CSF 2.0 subcategories. The mapping is a
documentation aid for simulated checks, not a framework assessment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# NIST CSF 2.0 subcategory texts (NIST CSWP 29, February 2024). Only identifiers verified against the
# published Core are used here; see the verification note in docs/controls.md (NIST CSF 2.0 mapping).
CSF = {
    "ID.AM-01": "Inventories of hardware managed by the organization are maintained",
    "ID.AM-03": "Representations of the organization's authorized network communication and internal and external network data flows are maintained",
    "PR.AA-03": "Users, services, and hardware are authenticated",
    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
    "PR.PS-01": "Configuration management practices are established and applied",
    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
    "DE.AE-03": "Information is correlated from multiple sources",
    "RS.MA-01": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
    "RS.AN-06": "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved",
    "RS.MI-01": "Incidents are contained",
    "RC.RP-01": "The recovery portion of the incident response plan is executed once initiated from the incident response process",
    "RC.RP-04": "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms",
}


@dataclass
class Control:
    id: str
    name: str
    description: str
    category: str  # human grouping used by the UI
    severity: str  # severity of a FAIL finding: high | medium | low
    scope_type: str  # interface | incident | source | vlan | global
    source_of_truth: str
    csf: list[str] = field(default_factory=list)  # NIST CSF 2.0 subcategory ids
    freshness_window: int | None = None  # seconds; None = state-based evidence read live from the twin
    states: list[str] = field(default_factory=lambda: ["PASS", "FAIL"])
    remediation: str = ""
    limitations: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["csf"] = [{"id": c, "text": CSF[c]} for c in self.csf]
        return d


CONTROLS: list[Control] = [
    Control(
        id="CTL-VLAN-INTENT",
        name="Access port carries its intended VLAN",
        description="Every configured access port is in the VLAN declared in the port intent, unless an authorized and verified containment workflow moved it to the quarantine VLAN.",
        category="Segmentation",
        severity="high",
        scope_type="interface",
        source_of_truth="simulator/fixtures/environment.yaml port intent vs SwitchTwin.interfaces[*].access_vlan, quarantine flags and containment_actions",
        csf=["PR.IR-01", "ID.AM-03"],
        states=["PASS", "FAIL"],
        remediation="Re-apply the intended access VLAN from the port template (switchport access vlan <intent>).",
    ),
    Control(
        id="CTL-DOT1X-ENFORCED",
        name="802.1X / MAB enforced on user ports",
        description="Ports in the user-port profile run 802.1X with MAB fallback (authentication port-control auto, mab).",
        category="Access control",
        severity="high",
        scope_type="interface",
        source_of_truth="port intent (dot1x/mab) vs SwitchTwin.interfaces[*].settings",
        csf=["PR.AA-03", "PR.IR-01"],
        remediation="Re-apply the 802.1X stanza from cisco/templates/user-port.ios.tmpl.",
    ),
    Control(
        id="CTL-ENDPOINT-IDENTITY",
        name="Connected endpoints have a verified identity",
        description="Every MAC learned on a connected access port belongs to an inventoried asset with a recent authentication result. Identity evidence older than the re-authentication period is reported as STALE.",
        category="Identity",
        severity="medium",
        scope_type="interface",
        source_of_truth="SwitchTwin.mac_table + inventory (devices table) + auth_events (last RADIUS result per MAC)",
        csf=["ID.AM-01", "PR.AA-03"],
        freshness_window=14400 + 900,  # reauthentication timer (server Session-Timeout 14400) + 15 min grace
        states=["PASS", "FAIL", "UNKNOWN", "STALE"],
        remediation="Register the asset in the inventory or re-authenticate the session (clear authentication sessions interface <port>).",
        limitations="Guest-VLAN sessions have no periodic re-authentication, so their identity evidence ages until the port is bounced.",
    ),
    Control(
        id="CTL-PORT-SECURITY",
        name="Port security matches the port profile",
        description="Port security is enabled with the profile's maximum address count, violation mode and sticky setting on every access port that requires it.",
        category="Access control",
        severity="medium",
        scope_type="interface",
        source_of_truth="port intent port_security vs SwitchTwin.interfaces[*].settings.port_security",
        csf=["PR.IR-01", "PR.AA-03"],
        remediation="Re-apply the port-security lines from the port template.",
    ),
    Control(
        id="CTL-CONFIG-BASELINE",
        name="Interface configuration matches the baseline",
        description="No configuration drift between the rendered baseline (configuration as code) and the observed running configuration for the interface.",
        category="Configuration",
        severity="medium",
        scope_type="interface",
        source_of_truth="DriftEngine (desired intent vs observed twin settings)",
        csf=["PR.PS-01"],
        remediation="Apply the recommended IOS commands produced by the drift engine.",
    ),
    Control(
        id="CTL-UNUSED-PORTS",
        name="Unused ports are shut down and parked",
        description="Every port without an assigned asset is administratively down and parked in the black-hole VLAN 999.",
        category="Hardening",
        severity="medium",
        scope_type="interface",
        source_of_truth="port intent class 'unused' vs SwitchTwin.interfaces[*].admin_status / access_vlan",
        csf=["PR.IR-01", "PR.PS-01"],
        remediation="shutdown + switchport access vlan 999 on each listed port.",
    ),
    Control(
        id="CTL-TRUST-BOUNDARY",
        name="DHCP snooping / DAI trust limited to infrastructure trunks",
        description="Only the protected infrastructure trunks are DHCP-snooping and ARP-inspection trusted; every access port is untrusted.",
        category="Segmentation",
        severity="high",
        scope_type="global",
        source_of_truth="SwitchTwin.interfaces[*].settings dhcp_snooping_trust / dai_trust vs port intent protected trunks",
        csf=["PR.IR-01"],
        remediation="Remove trust from non-infrastructure ports; add trust to protected trunks.",
    ),
    Control(
        id="CTL-TELEMETRY-FRESH",
        name="Required telemetry sources are current",
        description="The SPAN feed (Zeek), RADIUS accounting and IOS syslog have produced records within their expected intervals. Sources without a liveness signal in the simulation are reported UNKNOWN.",
        category="Monitoring",
        severity="medium",
        scope_type="source",
        source_of_truth="traffic_buckets (Zeek conn), auth_events (RADIUS), SwitchTwin.log (syslog); Suricata has no stats events in the dataset",
        csf=["DE.CM-01"],
        states=["PASS", "STALE", "UNKNOWN"],
        remediation="Investigate the collector or SPAN session; restore the feed.",
        limitations="Freshness windows are per source and measured against the simulated clock.",
    ),
    Control(
        id="CTL-SENSOR-COVERAGE",
        name="Endpoint VLANs are mirrored to the sensor",
        description="Every VLAN that carries endpoints (20, 30, 40, 50) is a source of the SPAN session that feeds Zeek and Suricata.",
        category="Monitoring",
        severity="medium",
        scope_type="vlan",
        source_of_truth="SwitchTwin.span.source_vlans vs VLANs with endpoints",
        csf=["DE.CM-01", "ID.AM-03"],
        remediation="monitor session 1 source vlan <vlan> both",
        limitations="A quarantined host's traffic is invisible to the sensor until VLAN 50 is mirrored.",
    ),
    Control(
        id="CTL-RESPONSE-AUTHORIZED",
        name="Containment actions were authorized before execution",
        description="Every executed containment action carries an authorization record (policy tier or analyst approval) whose timestamp precedes execution.",
        category="Response",
        severity="high",
        scope_type="incident",
        source_of_truth="containment_actions[*].authorization vs applied_at",
        csf=["RS.MA-01", "RS.AN-06"],
        states=["PASS", "FAIL", "UNKNOWN"],
        remediation="Record the authorization decision; review the workflow that executed without one.",
    ),
    Control(
        id="CTL-QUARANTINE-VERIFIED",
        name="Containment state independently verified",
        description="For every contained incident the switch twin currently reports the containment state (quarantine VLAN or administrative shutdown) and the controller's read-back verification succeeded.",
        category="Response",
        severity="high",
        scope_type="incident",
        source_of_truth="containment_actions[*].verification + live SwitchTwin interface state",
        csf=["RS.MI-01", "RS.AN-06"],
        states=["PASS", "FAIL", "UNKNOWN"],
        remediation="Re-apply the containment action and re-verify.",
    ),
    Control(
        id="CTL-RECOVERY-VERIFIED",
        name="Restored interfaces returned to their expected state",
        description="For every resolved incident the interface is back in its intended VLAN and administrative state after containment was released.",
        category="Recovery",
        severity="high",
        scope_type="incident",
        source_of_truth="containment_actions[*].restored_at + port intent + live SwitchTwin interface state",
        csf=["RC.RP-01", "RC.RP-04"],
        states=["PASS", "FAIL"],
        remediation="Restore the interface to its intended configuration.",
    ),
    Control(
        id="CTL-EVIDENCE-COMPLETE",
        name="Incident evidence bundle is complete",
        description="Every incident has an evidence bundle on disk containing all eleven required artifacts.",
        category="Evidence",
        severity="low",
        scope_type="incident",
        source_of_truth="data/incidents/<id>/ vs evidence.bundle.BUNDLE_FILES",
        csf=["RS.AN-06", "DE.AE-03"],
        states=["PASS", "FAIL"],
        remediation="Regenerate the bundle with the incident's evidence writer.",
    ),
]

CONTROLS_BY_ID = {c.id: c for c in CONTROLS}


def catalog() -> list[dict[str, Any]]:
    return [c.to_dict() for c in CONTROLS]
