"""Analyst response decisions (services/response.py): approving or rejecting a detection that policy
routed to manual review records an authorization distinct from the policy tier."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelswitch.app.config import Settings
from sentinelswitch.assurance.engine import AssessmentEngine
from sentinelswitch.services.response import approve_review, reject_review
from sentinelswitch.services.seed import seed_database
from sentinelswitch.services.store import Store
from simulator.canonical import ROOT

OPEN_REVIEW = "DET-20260317T20371618-PORT"  # critical-asset-scan, withheld by the critical_assets guard
CLOSED_REVIEW = "DET-20260317T14192804-DNS-"
NEW_INCIDENT = "INC-2026-0043"
HISTORICAL = {"INC-2026-0039", "INC-2026-0040", "INC-2026-0041"}


@pytest.fixture()
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "t.db",
        data_dir=ROOT / "data",
        incidents_dir=tmp_path / "incidents",
        artifacts_dir=tmp_path / "artifacts",
        frontend_dist=Path("/nonexistent"),
    )


@pytest.fixture()
def store(env, settings, seed_ready) -> Store:
    settings.incidents_dir.mkdir()
    s = Store(env, settings.db_path)
    seed_database(s, env, ROOT / "data" / "seed", settings.incidents_dir, run_validation_suite=False)
    return s


def _alerts_for(store: Store, detection_id: str) -> list[dict]:
    return [a for a in store.alerts(limit=100000) if a.get("detection_id") == detection_id]


def test_open_review_is_the_guarded_critical_asset_scan(store):
    review = store.review(OPEN_REVIEW)
    assert review["status"] == "review" and review["scenario"] == "critical-asset-scan"
    assert review["decision"]["disposition"] == "manual_review" and review["decision"]["action"] == "none"
    assert review["decision"]["guards_triggered"] == ["critical_assets"]
    assert review["decision"]["tier_before_guards"] == "automatic_containment"
    assert review["attribution"]["interface"] == "Gi1/0/12" and review["attribution"]["protected"] is False
    assert store.counts()["reviews_open"] == 1
    assert [r["detection_id"] for r in store.reviews() if r["status"] == "review"] == [OPEN_REVIEW]
    assert _alerts_for(store, OPEN_REVIEW) and all(a["status"] == "review" for a in _alerts_for(store, OPEN_REVIEW))


def test_approve_executes_analyst_authorized_quarantine(env, settings, store):
    before = store.load_twin().interfaces["Gi1/0/12"]
    assert before.access_vlan == 30 and not before.quarantined and before.port_class == "server"
    assert {i["id"] for i in store.incidents()} == HISTORICAL
    actions_before = len(store.actions())

    res = approve_review(store, env, settings, OPEN_REVIEW, actor="tlee", note="confirmed scan from compromised server")
    inc, action, review = res["incident"], res["action"], res["review"]

    assert inc["id"] == NEW_INCIDENT and inc["status"] == "contained" and inc["class"] == "compromised_host"
    assert inc["disposition"] == "analyst_approved" and inc["action"] == "quarantine_vlan"
    assert inc["detection_id"] == OPEN_REVIEW and inc["scenario"] == "critical-asset-scan"
    assert inc["interface"] == "Gi1/0/12" and inc["original_vlan"] == 30 and inc["current_vlan"] == 50
    assert inc["chain"][-2:] == ["VLAN 30", "VLAN 50"] and inc["opened_at"] == "2026-03-17T21:16:00.000Z"
    auth = inc["authorization"]
    assert auth["mode"] == "analyst" and auth["status"] == "authorized" and auth["authorized_by"] == "tlee"
    assert auth["authorized_at"] == inc["opened_at"] and auth["note"] == "confirmed scan from compromised server"
    assert auth["basis"].startswith("policy tier automatic_containment") and auth["guards"] == ["critical_assets"]
    assert auth["reason"].startswith("Analyst approval by tlee")
    # Authorization is recorded before execution, and execution before verification.
    assert auth["authorized_at"] <= action["applied_at"] < action["verified_at"]
    assert action["status"] == "verified" and action["verification"]["ok"] is True
    assert action["authorization"] == auth and action["incident_id"] == NEW_INCIDENT
    assert action["action"] == "quarantine_vlan" and action["from_vlan"] == 30 and action["to_vlan"] == 50
    assert action["workflow_id"].startswith("WF-2026-0043") and inc["workflow_id"] == action["workflow_id"]
    assert [c.strip() for c in action["commands"]] == [
        "configure terminal",
        "interface GigabitEthernet1/0/12",
        "switchport access vlan 50",
        "end",
        "write memory",
    ]
    assert "Access Mode VLAN: 50" in action["verification"]["transcript"]

    twin = store.load_twin()
    gi12 = twin.interfaces["Gi1/0/12"]
    assert gi12.access_vlan == 50 and gi12.quarantined and gi12.quarantine_workflow == action["workflow_id"]
    assert gi12.original_vlan == 30 and all(m.vlan == 50 for m in twin.macs_on_interface("Gi1/0/12"))

    # Persisted state: incident, action, review, detection, alerts and timeline.
    assert store.incident(NEW_INCIDENT)["status"] == "contained"
    assert len(store.actions()) == actions_before + 1 and store.action(action["workflow_id"])["status"] == "verified"
    assert review["status"] == "approved" and review["incident_id"] == NEW_INCIDENT and review["closed_by"] == "tlee"
    assert review["authorization"] == auth and store.review(OPEN_REVIEW)["status"] == "approved"
    assert store.detection(OPEN_REVIEW)["disposition"] == "analyst_approved"
    assert store.detection(OPEN_REVIEW)["incident_id"] == NEW_INCIDENT
    alerts = _alerts_for(store, OPEN_REVIEW)
    assert alerts and all(a["status"] == "contained" and a["incident_id"] == NEW_INCIDENT for a in alerts)
    timeline = store.timeline(NEW_INCIDENT)
    assert [t["phase"] for t in timeline[-4:]] == ["authorization", "containment", "verification", "evidence"]
    assert timeline[-4]["actor"] == "tlee" and timeline[-4]["details"] == {
        "mode": "analyst",
        "guards_overridden": ["critical_assets"],
    }
    assert timeline[-2]["message"].startswith("Verification succeeded")
    assert [t["ts"] for t in timeline] == sorted(t["ts"] for t in timeline)
    assert store.counts()["reviews_open"] == 0

    # The assurance layer accepts the analyst authorization as valid prior authorization.
    run = AssessmentEngine(env, store, settings.incidents_dir).run("after-approval")
    authorized = store.assessment(f"ASM-RESPONSE-AUTHORIZED-{NEW_INCIDENT}")
    assert authorized["status"] == "PASS" and "analyst, tlee" in authorized["explanation"]
    assert store.assessment(f"ASM-QUARANTINE-VERIFIED-{NEW_INCIDENT}")["status"] == "PASS"
    vlan_intent = store.assessment("ASM-VLAN-INTENT-Gi1-0-12")
    assert vlan_intent["status"] == "PASS" and f"quarantined by {action['workflow_id']}" in vlan_intent["observed"]
    # approve_review writes the same eleven-artifact bundle the automatic path writes.
    assert store.assessment(f"ASM-EVIDENCE-COMPLETE-{NEW_INCIDENT}")["status"] == "PASS"
    bundle = settings.incidents_dir / NEW_INCIDENT
    assert (bundle / "README.md").exists() and (bundle / "containment.json").exists()
    assert inc["evidence_finalized_at"] > action["verified_at"]
    assert store.timeline(NEW_INCIDENT)[-1]["phase"] == "evidence"
    # 5 baseline findings + 3 missing historical bundles (this store's incidents dir holds none of them).
    assert run["findings_open"] == 8

    with pytest.raises(RuntimeError, match="only open reviews can be approved"):
        approve_review(store, env, settings, OPEN_REVIEW, actor="tlee", note="again")
    with pytest.raises(RuntimeError, match="only open reviews can be rejected"):
        reject_review(store, env, OPEN_REVIEW, actor="tlee", note="too late")
    assert {i["id"] for i in store.incidents()} == HISTORICAL | {NEW_INCIDENT}


def test_reject_records_declined_authorization_without_touching_the_switch(env, settings, store):
    twin_before = store.load_twin()
    changes_before = len(twin_before.config_changes)
    baseline_run = store.assessment_runs()[0]

    res = reject_review(store, env, OPEN_REVIEW, actor="tlee", note="benign vulnerability scan by IT")
    review = res["review"]
    assert review["status"] == "closed" and review["closed_by"] == "tlee"
    assert review["note"] == "benign vulnerability scan by IT" and review.get("incident_id") is None
    assert review["closed_at"] == "2026-03-17T21:16:00.000Z"
    auth = review["authorization"]
    assert auth["mode"] == "rejected" and auth["status"] == "rejected" and auth["authorized_by"] == "tlee"
    assert auth["authorized_at"] == review["closed_at"] and auth["guards"] == ["critical_assets"]
    assert auth["basis"] == "policy tier manual_review (before guards: automatic_containment)"
    assert review["timeline"][-1]["phase"] == "resolution" and review["timeline"][-1]["actor"] == "tlee"
    assert review["timeline"][-1]["details"] == {"mode": "rejected"}
    assert review["decision"]["disposition"] == "manual_review"  # the policy decision itself is never rewritten

    assert store.review(OPEN_REVIEW)["status"] == "closed" and store.counts()["reviews_open"] == 0
    assert store.timeline(OPEN_REVIEW)[-1]["message"].startswith("Containment declined by tlee")
    alerts = _alerts_for(store, OPEN_REVIEW)
    assert alerts and all(a["status"] == "closed" and a.get("incident_id") is None for a in alerts)
    assert {i["id"] for i in store.incidents()} == HISTORICAL and len(store.actions()) == 3

    twin = store.load_twin()
    gi12 = twin.interfaces["Gi1/0/12"]
    assert gi12.access_vlan == 30 and not gi12.quarantined and len(twin.config_changes) == changes_before
    assert twin.to_dict() == twin_before.to_dict()

    with pytest.raises(RuntimeError, match="only open reviews can be rejected"):
        reject_review(store, env, OPEN_REVIEW, actor="tlee", note="again")
    with pytest.raises(RuntimeError, match="only open reviews can be approved"):
        approve_review(store, env, settings, OPEN_REVIEW, actor="tlee", note="changed my mind")

    run = AssessmentEngine(env, store, settings.incidents_dir).run("after-rejection")
    assert run["counts"] == baseline_run["counts"]
    assert not [a for a in store.assessments() if a["scope"]["id"] == NEW_INCIDENT]


def test_unknown_and_already_closed_reviews(env, settings, store):
    with pytest.raises(KeyError):
        approve_review(store, env, settings, "DET-NOPE", actor="tlee", note="x")
    with pytest.raises(KeyError):
        reject_review(store, env, "DET-NOPE", actor="tlee", note="x")
    assert store.review(CLOSED_REVIEW)["status"] == "closed"
    with pytest.raises(RuntimeError, match="is closed"):
        approve_review(store, env, settings, CLOSED_REVIEW, actor="tlee", note="x")
    with pytest.raises(RuntimeError, match="is closed"):
        reject_review(store, env, CLOSED_REVIEW, actor="tlee", note="x")
    assert store.counts()["reviews_open"] == 1 and {i["id"] for i in store.incidents()} == HISTORICAL
