"""Analyst response decisions for detections that policy routed to manual review.

`approve` records an analyst authorization, executes the containment through the same controller and
adapter the automatic path uses, verifies the read-back, opens an incident and writes evidence.
`reject` records that containment was explicitly declined. Both are appended to the detection's
timeline; neither rewrites the original policy decision.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelswitch.app.config import Settings
from sentinelswitch.containment.adapters import SimulatedCisco2960XAdapter
from sentinelswitch.containment.controller import ContainmentController, authorization_record
from sentinelswitch.containment.policy import Decision, PolicyEngine
from sentinelswitch.correlation.engine import Attribution, Clock, Step
from sentinelswitch.evidence.bundle import write_bundle
from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment, add_seconds, parse_ts, ts_iso

from .store import Store
from .telemetry import FileTelemetry


def _attribution_from_dict(d: dict[str, Any]) -> Attribution:
    steps = [Step(**s) for s in d.get("steps", [])]
    fields = {k: v for k, v in d.items() if k not in {"steps"}}
    return Attribution(steps=steps, **fields)


def _decision_from_dict(d: dict[str, Any]) -> Decision:
    return Decision(**d)


def approve_review(
    store: Store,
    env: Environment,
    settings: Settings,
    detection_id: str,
    *,
    actor: str,
    note: str,
    at: datetime | None = None,
    channel: str | None = None,
) -> dict[str, Any]:
    """`channel` records how the analyst decision was made when it was not a person at the console
    (for example `scripted-demo`); it is stored on the authorization record and shown wherever it is."""
    review = store.review(detection_id)
    if review is None:
        raise KeyError(detection_id)
    if review.get("status") != "review":
        raise RuntimeError(f"{detection_id} is {review.get('status')}; only open reviews can be approved")
    attribution = _attribution_from_dict(review["attribution"])
    decision = _decision_from_dict(review["decision"])
    policy = PolicyEngine()
    action_type = policy.policy["actions"].get(review.get("class") or _class_for_rule(review["rule"]), "none")
    if action_type == "none" or not attribution.interface or attribution.protected or attribution.trunk:
        raise RuntimeError(
            "no executable containment action for this detection (protected port, trunk or non-containable class)"
        )
    twin = store.load_twin()
    at = at or add_seconds(max(twin.now, parse_ts(review["opened_at"])), 120.0)
    twin.advance_to(at)
    approved = Decision(
        disposition="automatic_containment",
        action=action_type,
        reason=f"Analyst approval by {actor}: {note}",
        factors=decision.factors,
        guards_triggered=decision.guards_triggered,
        quarantine_vlan=int(policy.policy["quarantine_vlan"]) if action_type == "quarantine_vlan" else None,
        tier_before_guards=decision.disposition,
    )
    authorization = authorization_record(approved, at=at, mode="analyst", authorized_by=actor, note=note)
    if channel:
        authorization["channel"] = channel
    controller = ContainmentController(
        SimulatedCisco2960XAdapter(twin), quarantine_vlan=int(policy.policy["quarantine_vlan"])
    )
    incident_id = _next_incident_id(store)
    clock = Clock(at)
    action = controller.contain(
        decision=approved,
        attribution=attribution,
        detection_id=detection_id,
        summary=review["title"],
        incident_id=incident_id,
        clock=clock,
        timing={"apply": 0.41, "verify": 0.13},
        authorization=authorization,
    )
    timeline = store.timeline(detection_id)
    timeline.append(
        {
            "ts": ts_iso(at),
            "phase": "authorization",
            "actor": actor,
            "message": f"Containment authorized by analyst {actor}: {note}",
            "details": {"mode": "analyst", "guards_overridden": decision.guards_triggered},
        }
    )
    if action.status in {"applied", "verified", "failed"}:
        timeline.append(
            {
                "ts": action.applied_at,
                "phase": "containment",
                "actor": "sentinel",
                "message": f"{action.switch} {action.interface}: {action.action} (workflow {action.workflow_id})",
                "details": {"commands": action.commands},
            }
        )
        timeline.append(
            {
                "ts": action.verified_at,
                "phase": "verification",
                "actor": "sentinel",
                "message": f"Verification {'succeeded' if action.verification.get('ok') else 'FAILED'}: {action.verification.get('expected')}",
                "details": None,
            }
        )
    incident = {
        "id": incident_id,
        "title": review["title"],
        "severity": review["severity"],
        "confidence": review["confidence"],
        "status": "contained" if action.status == "verified" else "containment_failed",
        "opened_at": ts_iso(at),
        "closed_at": None,
        "rule": review["rule"],
        "rule_name": review["title"].split(" — ")[0],
        "class": review.get("class") or _class_for_rule(review["rule"]),
        "mitre": [],
        "scenario": review.get("scenario"),
        "instance": "day",
        "detection_id": detection_id,
        "device": attribution.device,
        "user": attribution.user,
        "department": attribution.department,
        "ip": attribution.ip,
        "mac": attribution.mac,
        "vendor": attribution.vendor,
        "switch": attribution.switch,
        "interface": attribution.interface,
        "original_vlan": attribution.vlan,
        "current_vlan": twin.interfaces[attribution.interface].oper_vlan,
        "port_class": attribution.port_class,
        "chain": attribution.chain
        + ([f"VLAN {approved.quarantine_vlan}"] if approved.action == "quarantine_vlan" else ["shutdown"]),
        "summary": f"Opened from manual review {detection_id} after analyst approval.",
        "disposition": "analyst_approved",
        "action": approved.action,
        "attribution_confidence": attribution.confidence,
        "flags": attribution.flags,
        "impersonated_device": attribution.impersonated_device,
        "authorization": authorization,
        "workflow_id": action.workflow_id,
        "mechanism": action.mechanism,
        "contained_at": action.verified_at,
    }
    evidence_at = add_seconds(parse_ts(action.verified_at or action.applied_at or ts_iso(at)), 0.339)
    incident["evidence_finalized_at"] = ts_iso(evidence_at)
    timeline.append(
        {
            "ts": ts_iso(evidence_at),
            "phase": "evidence",
            "actor": "sentinel",
            "message": f"Evidence bundle written to data/incidents/{incident_id}/",
            "details": None,
        }
    )
    store.put_incident(incident)
    store.put_action(action.to_dict())
    store.put_timeline(incident_id, timeline)
    _write_evidence(
        store, env, settings, incident, review, attribution, approved, action.to_dict(), twin, timeline, evidence_at
    )
    review.update(
        {
            "status": "approved",
            "closed_at": ts_iso(at),
            "closed_by": actor,
            "note": note,
            "incident_id": incident_id,
            "authorization": authorization,
        }
    )
    store.put_review(review)
    det = store.detection(detection_id)
    if det:
        det.update({"disposition": "analyst_approved", "incident_id": incident_id})
        store.put_detection(det)
    for a in store.alerts(limit=100000):
        if a.get("detection_id") == detection_id:
            a.update({"status": incident["status"], "incident_id": incident_id})
            store.put_alert(a)
    store.save_twin(twin)
    return {"incident": incident, "action": action.to_dict(), "review": review}


def reject_review(
    store: Store, env: Environment, detection_id: str, *, actor: str, note: str, at: datetime | None = None
) -> dict[str, Any]:
    review = store.review(detection_id)
    if review is None:
        raise KeyError(detection_id)
    if review.get("status") != "review":
        raise RuntimeError(f"{detection_id} is {review.get('status')}; only open reviews can be rejected")
    twin = store.load_twin()
    at = at or add_seconds(max(twin.now, parse_ts(review["opened_at"])), 120.0)
    decision = _decision_from_dict(review["decision"])
    authorization = authorization_record(decision, at=at, mode="rejected", authorized_by=actor, note=note)
    review.update(
        {"status": "closed", "closed_at": ts_iso(at), "closed_by": actor, "note": note, "authorization": authorization}
    )
    timeline = store.timeline(detection_id)
    timeline.append(
        {
            "ts": ts_iso(at),
            "phase": "resolution",
            "actor": actor,
            "message": f"Containment declined by {actor}: {note}",
            "details": {"mode": "rejected"},
        }
    )
    store.put_timeline(detection_id, timeline)
    review["timeline"] = timeline
    store.put_review(review)
    for a in store.alerts(limit=100000):
        if a.get("detection_id") == detection_id:
            a["status"] = "closed"
            store.put_alert(a)
    return {"review": review}


def _write_evidence(
    store: Store,
    env: Environment,
    settings: Settings,
    incident: dict[str, Any],
    review: dict[str, Any],
    attribution: Attribution,
    decision: Decision,
    action: dict[str, Any],
    twin: SwitchTwin,
    timeline: list[dict[str, Any]],
    evidence_at: datetime,
) -> Path:
    """The same eleven-artifact bundle the automatic path writes, built from the persisted review."""
    iface = attribution.interface
    actor_ip = attribution.ip
    start = add_seconds(parse_ts(review["opened_at"]), -900)
    telemetry = FileTelemetry(settings.zeek_dir)
    flows = telemetry.flows_for(actor_ip, start, evidence_at) if actor_ip else []
    dns = telemetry.dns_for(actor_ip, start, evidence_at) if actor_ip else []
    flows.sort(key=lambda f: (f["ts"], f["id.orig_h"], f["id.resp_h"], f["id.resp_p"]))
    dns.sort(key=lambda d: (d["ts"], d["query"]))
    port_after = {
        "interface": iface,
        "state": twin.interfaces[iface].__dict__ if iface else None,
        "show_switchport": cli_render.show_interface_switchport(twin, iface) if iface else "",
        "show_status": cli_render.show_interface_status_single(twin, iface) if iface else "",
        "show_mac_table": cli_render.show_mac_address_table(twin, interface=iface) if iface else "",
        "show_running_config": cli_render.show_running_config_interface(twin, iface) if iface else "",
        "show_port_security": cli_render.show_port_security_interface(twin, iface) if iface else "",
    }
    network_context = {
        "actor": {
            "device": attribution.device,
            "ip": attribution.ip,
            "mac": attribution.mac,
            "user": attribution.user,
            "interface": iface,
            "vlan": attribution.vlan,
        },
        "attribution": attribution.to_dict(),
        "vlans": {str(k): v for k, v in twin.vlans.items()},
        "interface_intent": {
            "description": env.ports[iface].description,
            "class": env.ports[iface].port_class,
            "profile": env.ports[iface].profile,
            "protected": env.ports[iface].protected,
        }
        if iface
        else None,
        "span_session": twin.span,
        "sensor": "SEC-TP01 eth1 (SPAN destination Gi1/0/47), Zeek + Suricata",
        "analyst_decision": {
            "detection_id": review["detection_id"],
            "review_opened_at": review["opened_at"],
            "authorization": incident.get("authorization"),
        },
        "simulation_notice": "Synthetic telemetry generated by the SentinelSwitch digital twin.",
    }
    alerts = [a for a in store.alerts(limit=100000) if a.get("detection_id") == review["detection_id"]]
    return write_bundle(
        settings.incidents_dir,
        incident,
        timeline=timeline,
        alerts=alerts,
        attribution=attribution.to_dict(),
        decision=decision.to_dict(),
        action=action,
        network_context=network_context,
        switch_port={
            "before": {
                "access_vlan": incident["original_vlan"],
                "oper_vlan": incident["original_vlan"],
                "oper_status": "connected",
            },
            "after": port_after,
        },
        flows=flows,
        dns=dns,
    )


def _class_for_rule(rule_id: str) -> str:
    from sentinelswitch.detection.engine import load_rules

    r = load_rules().get(rule_id)
    return r.klass if r else "compromised_host"


def _next_incident_id(store: Store) -> str:
    ids = [i["id"] for i in store.incidents() if i["id"].startswith("INC-2026-")]
    n = max([int(i.split("-")[-1]) for i in ids] + [42])
    return f"INC-2026-{n + 1:04d}"


__all__ = ["approve_review", "reject_review"]
