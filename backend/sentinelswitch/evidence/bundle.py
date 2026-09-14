"""Write an incident evidence bundle to data/incidents/<INCIDENT-ID>/.

The bundle is deliberately plain JSON + Markdown so it can be reviewed without the application. All
timestamps are simulated-clock timestamps from the scenario, never wall-clock, which keeps the bundle
byte-for-byte reproducible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

BUNDLE_FILES = [
    "incident.json",
    "timeline.json",
    "alerts.json",
    "network-context.json",
    "dhcp-binding.json",
    "mac-table.json",
    "switch-port.json",
    "containment.json",
    "related-connections.json",
    "related-dns.json",
    "README.md",
]


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_bundle(
    root: Path,
    incident: dict[str, Any],
    *,
    timeline: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    attribution: dict[str, Any],
    decision: dict[str, Any],
    action: dict[str, Any] | None,
    network_context: dict[str, Any],
    switch_port: dict[str, Any],
    flows: list[dict[str, Any]],
    dns: list[dict[str, Any]],
) -> Path:
    inc_dir = root / incident["id"]
    inc_dir.mkdir(parents=True, exist_ok=True)
    manifest_incident = dict(incident)
    manifest_incident["artifacts"] = BUNDLE_FILES
    _dump(inc_dir / "incident.json", manifest_incident)
    _dump(inc_dir / "timeline.json", timeline)
    _dump(inc_dir / "alerts.json", alerts)
    _dump(inc_dir / "network-context.json", network_context)
    _dump(
        inc_dir / "dhcp-binding.json",
        {
            "binding": attribution.get("binding"),
            "resolution_step": next((s for s in attribution.get("steps", []) if s["name"] == "dhcp_binding"), None),
        },
    )
    _dump(
        inc_dir / "mac-table.json",
        {
            "entries": attribution.get("mac_entries", []),
            "observations": attribution.get("observations", []),
            "resolution_step": next((s for s in attribution.get("steps", []) if s["name"] == "mac_table"), None),
        },
    )
    _dump(inc_dir / "switch-port.json", switch_port)
    _dump(inc_dir / "containment.json", {"decision": decision, "action": action})
    _dump(inc_dir / "related-connections.json", flows)
    _dump(inc_dir / "related-dns.json", dns)
    (inc_dir / "README.md").write_text(
        render_report(incident, timeline, alerts, attribution, decision, action, switch_port, len(flows), len(dns)),
        encoding="utf-8",
    )
    return inc_dir


def render_report(
    incident: dict[str, Any],
    timeline: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    attribution: dict[str, Any],
    decision: dict[str, Any],
    action: dict[str, Any] | None,
    switch_port: dict[str, Any],
    n_flows: int,
    n_dns: int,
) -> str:
    lines = [
        f"# {incident['id']} — {incident['title']}",
        "",
        f"**Severity:** {incident['severity']}  ",
        f"**Confidence:** {incident['confidence']:.2f}  ",
        f"**Status:** {incident['status']}  ",
        f"**Opened:** {incident['opened_at']}  ",
        f"**Rule:** `{incident['rule']}`  ",
        f"**Endpoint:** {incident.get('device') or 'unknown'} ({incident.get('user') or 'no user'})  ",
        f"**Switch / interface:** {incident['switch']} {incident.get('interface') or '-'}  ",
        f"**VLAN:** {incident.get('original_vlan')} → {incident.get('current_vlan')}  ",
        "",
        "> Simulated lab telemetry. This bundle was produced by the SentinelSwitch digital twin; no production",
        "> system was involved.",
        "",
        "## Summary",
        "",
        incident.get("summary", ""),
        "",
        "## Attribution chain",
        "",
        "```",
        " → ".join(str(x) for x in incident.get("chain", [])),
        "```",
        "",
        "| step | status | source | evidence |",
        "| --- | --- | --- | --- |",
    ]
    for s in attribution.get("steps", []):
        lines.append(f"| {s['name']} | {s['status']} | {s['source']} | {s['detail']} |")
    lines += [
        "",
        "## Policy decision",
        "",
        f"- Disposition: **{decision['disposition']}**",
        f"- Action: `{decision['action']}`",
        f"- Reason: {decision['reason']}",
    ]
    if decision.get("guards_triggered"):
        lines.append(f"- Guards triggered: {', '.join(decision['guards_triggered'])}")
    if action:
        lines += [
            "",
            "## Containment",
            "",
            f"- Workflow: `{action['workflow_id']}`",
            f"- Mechanism: {action['mechanism']}",
            f"- Interface: {action['interface']} ({action['from_vlan']} → {action['to_vlan']})"
            if action.get("to_vlan")
            else f"- Interface: {action['interface']}",
            f"- Applied: {action['applied_at']}",
            f"- Verified: {action['verified_at']} ({'OK' if action.get('verification', {}).get('ok') else 'FAILED'})",
            f"- Status: {action['status']}",
        ]
        if action.get("restored_at"):
            lines.append(f"- Restored: {action['restored_at']} by {action['restored_by']} — {action['restore_note']}")
        if action.get("transcript"):
            lines += ["", "```", action["transcript"], "```"]
    lines += ["", "## Timeline", "", "| time (UTC) | phase | event |", "| --- | --- | --- |"]
    for t in timeline:
        lines.append(f"| {t['ts'][11:23]} | {t['phase']} | {t['message']} |")
    lines += [
        "",
        "## Source detections",
        "",
        "| time (UTC) | source | severity | detail |",
        "| --- | --- | --- | --- |",
    ]
    for a in alerts:
        lines.append(f"| {a['ts'][11:23]} | {a['source']} | {a.get('severity', '')} | {a.get('summary', '')} |")
    lines += [
        "",
        "## Switch port",
        "",
        "```",
        switch_port.get("after", {}).get("show_switchport", ""),
        "```",
        "",
        f"Related connections: {n_flows}, related DNS records: {n_dns} (see JSON artifacts).",
        "",
    ]
    return "\n".join(lines)
