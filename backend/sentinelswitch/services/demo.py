"""Flagship demo orchestration against the persisted twin."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sentinelswitch.app.config import Settings
from sentinelswitch.containment.adapters import SimulatedCisco2960XAdapter
from sentinelswitch.simulator.scenario import SECURITY_SYSLOG_PREFIXES, RunResult, ScenarioRunner
from simulator.canonical import Environment, parse_ts, ts_iso

from .store import Store
from .telemetry import FileTelemetry


def demo_status(store: Store) -> dict[str, Any]:
    return store.kv_get("demo", {"stage": "unseeded"})


def run_flagship(
    store: Store, env: Environment, settings: Settings, *, on_event: Callable[[dict[str, Any]], None] | None = None
) -> RunResult:
    scenario = env.flagship()
    status = demo_status(store)
    if status.get("stage") == "contained":
        raise RuntimeError("flagship incident already applied; run `sentinelswitch reset` first")
    twin = store.load_twin()
    runner = ScenarioRunner(
        env, twin, evidence_root=settings.incidents_dir, telemetry=FileTelemetry(settings.zeek_dir), incident_seq=41
    )
    result = runner.run(scenario, "day", write_evidence=True)
    _persist(store, result, on_event)
    store.save_twin(twin)
    store.kv_set(
        "demo",
        {
            "stage": "contained",
            "flagship_incident": result.incident["id"] if result.incident else None,
            "ran_at": result.metrics.get("evidence"),
            "checks": result.checks,
        },
    )
    return result


def _persist(store: Store, result: RunResult, on_event: Callable[[dict[str, Any]], None] | None) -> None:
    # Alerts from the flagship telemetry
    existing = store.alerts(limit=100000)
    n = len(existing)
    inc = result.incident
    for e in sorted(result.events, key=lambda x: x["ts"]):
        src = e["source"]
        worthy = (
            src in {"suricata", "zeek"}
            or (src == "radius" and e["result"] == "Access-Reject")
            or (src == "syslog" and e["mnemonic"].startswith(SECURITY_SYSLOG_PREFIXES))
        )
        if not worthy:
            continue
        n += 1
        row = {
            "id": f"ALT-{n:05d}",
            "ts": e["ts"],
            "source": src,
            "severity": e.get("severity", "info"),
            "signature": e.get("signature")
            or e.get("note")
            or (f"%{e['mnemonic']}" if src == "syslog" else f"RADIUS {e['result']}"),
            "signature_id": e.get("signature_id"),
            "category": e.get("category")
            or e.get("sentinel_class")
            or ("aaa" if src == "radius" else "switch-security"),
            "src_ip": e.get("src_ip"),
            "src_port": e.get("src_port"),
            "dest_ip": e.get("dest_ip"),
            "dest_port": e.get("dest_port"),
            "proto": e.get("proto"),
            "mac": e.get("mac"),
            "interface": e.get("interface"),
            "device": e.get("device"),
            "summary": e.get("summary"),
            "status": inc["status"] if inc else (result.review["status"] if result.review else "monitor"),
            "detection_id": result.detection.id if result.detection else None,
            "incident_id": inc["id"] if inc else None,
            "scenario": e.get("scenario"),
            "raw": e.get("raw"),
        }
        store.put_alert(row)
        if on_event:
            on_event(
                {
                    "type": "alert",
                    "payload": {
                        "id": row["id"],
                        "ts": row["ts"],
                        "signature": row["signature"],
                        "severity": row["severity"],
                    },
                }
            )
    for d in result.detections:
        rec = d.to_dict()
        is_primary = result.detection is not None and d.id == result.detection.id
        rec.update(
            {
                "scenario": result.scenario.id,
                "instance": "day",
                "disposition": result.decision.disposition if is_primary and result.decision else "monitor",
                "incident_id": inc["id"] if is_primary and inc else None,
                "review": result.review if is_primary else None,
            }
        )
        store.put_detection(rec)
    if inc:
        store.put_incident(inc)
        store.put_timeline(inc["id"], result.timeline)
        if result.action:
            store.put_action(result.action.to_dict())
        if on_event:
            on_event(
                {
                    "type": "incident",
                    "payload": {"id": inc["id"], "status": inc["status"], "interface": inc["interface"]},
                }
            )
    if result.review:
        rv = dict(result.review)
        rv.update(
            {
                "scenario": result.scenario.id,
                "rule": result.scenario.rule,
                "actor": result.actor,
                "attribution": result.attribution.to_dict() if result.attribution else None,
                "decision": result.decision.to_dict() if result.decision else None,
                "timeline": result.timeline,
                "severity": result.detection.severity,
                "confidence": result.detection.confidence,
                "title": f"{result.scenario.name} — {result.attribution.device if result.attribution else ''}",
            }
        )
        store.put_review(rv)
        store.put_timeline(result.review["detection_id"], result.timeline)
    # traffic bucket alert counts already include the flagship alerts (generated with the dataset)


def restore_incident(
    store: Store, env: Environment, incident_id: str, *, actor: str, note: str, at: str | None = None
) -> dict[str, Any]:
    inc = store.incident(incident_id)
    if inc is None:
        raise KeyError(incident_id)
    if inc["status"] != "contained":
        raise RuntimeError(f"{incident_id} is {inc['status']}; only contained incidents can be restored")
    actions = store.actions_for_incident(incident_id)
    action = next((a for a in actions if a["status"] == "verified"), None)
    if action is None:
        raise RuntimeError("no verified containment action to restore")
    twin = store.load_twin()
    when = parse_ts(at) if at else _restore_time(twin, action)
    adapter = SimulatedCisco2960XAdapter(twin)
    res = adapter.restore(action["interface"], actor=actor, reason=note, at=when)
    action.update(
        {
            "restored_at": ts_iso(when),
            "restored_by": actor,
            "restore_note": note,
            "restore_transcript": res.transcript,
            "status": "restored",
        }
    )
    store.put_action(action)
    inc.update(
        {
            "status": "resolved",
            "closed_at": ts_iso(when),
            "closed_by": actor,
            "resolution_note": note,
            "current_vlan": twin.interfaces[action["interface"]].oper_vlan,
        }
    )
    store.put_incident(inc)
    tl = store.timeline(incident_id)
    tl.append(
        {
            "ts": ts_iso(when),
            "phase": "resolution",
            "actor": actor,
            "message": f"Containment released by {actor}: {note}",
            "details": {"transcript": res.transcript},
        }
    )
    store.put_timeline(incident_id, tl)
    for a in store.alerts(limit=100000):
        if a.get("incident_id") == incident_id:
            a["status"] = "resolved"
            store.put_alert(a)
    store.save_twin(twin)
    demo = store.kv_get("demo", {})
    if demo.get("flagship_incident") == incident_id:
        demo["stage"] = "restored"
        store.kv_set("demo", demo)
    return {"incident": inc, "action": action, "transcript": res.transcript}


def _restore_time(twin, action: dict[str, Any]):
    """Restores happen on the simulated clock: shortly after the last recorded activity."""
    from simulator.canonical import add_seconds

    base = max(parse_ts(action["verified_at"]), twin.now)
    return add_seconds(base, 1800.0)
