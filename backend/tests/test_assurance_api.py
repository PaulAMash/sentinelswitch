"""SentinelSwitch 2.0 assurance API. Every test receives a fresh application on its own copy of the
baseline database (see `api_client` in conftest.py), so each test sets up the state it needs and the
tests pass alone, in any order, and as part of the full suite."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from sentinelswitch.assurance.engine import FINDING_OPEN_STATES

OPEN_REVIEW = "DET-20260317T20371618-PORT"
CLOSED_REVIEW = "DET-20260317T14192804-DNS-"
DRIFT_FINDING = "FND-CONFIG-BASELINE-Gi1-0-22"
BODY = {"actor": "tlee", "note": "analyst decision"}


def _status_counts(client) -> tuple[Counter, list[dict]]:
    rows = client.get("/api/assessments").json()
    return Counter(a["status"] for a in rows), rows


def test_posture_totals_match_assessments(api_client):
    posture = api_client.get("/api/posture").json()
    counts, rows = _status_counts(api_client)
    t = posture["totals"]
    assert t["assessments"] == len(rows) > 0 and t["controls"] == 13
    assert (t["pass"], t["fail"], t["unknown"], t["stale"]) == (
        counts["PASS"],
        counts["FAIL"],
        counts["UNKNOWN"],
        counts["STALE"],
    )
    assert t["determinate"] == t["pass"] + t["fail"]
    assert t["coverage_pct"] == round(100 * t["determinate"] / t["assessments"], 1)
    assert t["pass_rate_of_determinate_pct"] == round(100 * t["pass"] / t["determinate"], 1)
    assert t["pass_rate_of_all_pct"] == round(100 * t["pass"] / t["assessments"], 1)
    for status in ("PASS", "FAIL", "UNKNOWN", "STALE"):
        assert len(api_client.get("/api/assessments", params={"status": status}).json()) == counts[status]
    assert {a["id"] for a in rows if a["status"] == "FAIL"} >= {
        "ASM-CONFIG-BASELINE-Gi1-0-22",
        "ASM-UNUSED-PORTS-Gi1-0-41",
        "ASM-SENSOR-COVERAGE-vlan-50",
    }
    # The API's incidents directory is a temporary one without the historical bundles: a missing bundle
    # is a failed control (a finding to act on), never a pass.
    assert {a["status"] for a in rows if a["control_id"] == "CTL-EVIDENCE-COMPLETE"} == {"FAIL"}
    assert {u["id"] for u in posture["unverified"]} == {a["id"] for a in rows if a["status"] in {"UNKNOWN", "STALE"}}
    assert posture["findings"]["open"] == len(api_client.get("/api/findings", params={"open_only": "true"}).json())
    runs = api_client.get("/api/assessments/runs").json()
    assert posture["runs"] == len(runs) == 1 and posture["last_run"]["run_id"] == runs[0]["run_id"]
    assert runs[0]["trigger"] == "baseline-seed" and runs[0]["counts"] == {
        "PASS": counts["PASS"],
        "FAIL": counts["FAIL"],
        "UNKNOWN": counts["UNKNOWN"],
        "STALE": counts["STALE"],
    }


def test_controls_catalog_and_detail(api_client):
    body = api_client.get("/api/controls").json()
    assert len(body["catalog"]) == 13 and len(body["status"]) == 13
    assert {c["id"] for c in body["catalog"]} == {s["control_id"] for s in body["status"]}
    assert all(c["csf"] and all({"id", "text"} <= set(m) for m in c["csf"]) for c in body["catalog"])
    assert {c["severity"] for c in body["catalog"]} == {"high", "medium", "low"}
    assert body["last_run"]["run_id"] == api_client.get("/api/assessments/runs").json()[0]["run_id"]
    status = {s["control_id"]: s for s in body["status"]}
    assert status["CTL-CONFIG-BASELINE"]["status"] == "FAIL" and status["CTL-CONFIG-BASELINE"]["fail"] == 2
    assert status["CTL-QUARANTINE-VERIFIED"]["status"] == "NOT_ASSESSED"
    one = api_client.get("/api/controls/CTL-CONFIG-BASELINE").json()
    assert one["control"]["id"] == "CTL-CONFIG-BASELINE" and len(one["assessments"]) == 50
    assert all(a["control_id"] == "CTL-CONFIG-BASELINE" for a in one["assessments"])
    assert {f["id"] for f in one["findings"]} == {"FND-CONFIG-BASELINE-Gi1-0-22", "FND-CONFIG-BASELINE-Gi1-0-35"}
    assert api_client.get("/api/controls/CTL-NOPE").status_code == 404


def test_assessment_detail_and_runs(api_client):
    detail = api_client.get("/api/assessments/ASM-UNUSED-PORTS-Gi1-0-41").json()
    assert detail["assessment"]["status"] == "FAIL" and detail["control"]["id"] == "CTL-UNUSED-PORTS"
    assert detail["finding"]["id"] == "FND-UNUSED-PORTS-Gi1-0-41" and detail["finding"]["status"] == "open"
    assert [h["run_id"] for h in detail["history"]] == [detail["assessment"]["run_id"]]
    unknown = api_client.get("/api/assessments/ASM-TELEMETRY-FRESH-suricata").json()
    assert unknown["assessment"]["status"] == "UNKNOWN" and unknown["finding"] is None
    assert api_client.get("/api/assessments/ASM-NOPE").status_code == 404
    runs = api_client.get("/api/assessments/runs").json()
    run = api_client.get(f"/api/assessments/runs/{runs[0]['run_id']}").json()
    assert run["run"]["run_id"] == runs[0]["run_id"] and len(run["assessments"]) == runs[0]["assessments"]
    assert api_client.get("/api/assessments/runs/ASR-NOPE").status_code == 404


def test_findings_listing_and_detail(api_client):
    open_rows = api_client.get("/api/findings", params={"open_only": "true"}).json()
    assert open_rows and all(f["status"] in FINDING_OPEN_STATES for f in open_rows)
    assert {f["id"] for f in open_rows} == {
        DRIFT_FINDING,
        "FND-CONFIG-BASELINE-Gi1-0-35",
        "FND-ENDPOINT-IDENTITY-Gi1-0-30",
        "FND-SENSOR-COVERAGE-vlan-50",
        "FND-UNUSED-PORTS-Gi1-0-41",
        "FND-EVIDENCE-COMPLETE-INC-2026-0039",  # no bundles in the API's temporary incidents directory
        "FND-EVIDENCE-COMPLETE-INC-2026-0040",
        "FND-EVIDENCE-COMPLETE-INC-2026-0041",
    }
    all_rows = api_client.get("/api/findings").json()
    assert len(all_rows) == len(open_rows)
    assert len(api_client.get("/api/findings", params={"status": "open"}).json()) == len(open_rows)
    assert api_client.get("/api/findings", params={"status": "verified"}).json() == []
    detail = api_client.get(f"/api/findings/{DRIFT_FINDING}").json()
    assert detail["finding"]["id"] == DRIFT_FINDING and detail["finding"]["status"] == "open"
    assert [e["event"] for e in detail["events"]] == ["opened"]
    assert detail["assessment"]["id"] == "ASM-CONFIG-BASELINE-Gi1-0-22" and detail["assessment"]["status"] == "FAIL"
    assert detail["control"]["id"] == "CTL-CONFIG-BASELINE" and len(detail["history"]) == 1
    assert api_client.get("/api/findings/FND-NOPE").status_code == 404


def test_remediate_drift_finding(api_client):
    runs_before = len(api_client.get("/api/assessments/runs").json())
    r = api_client.post(f"/api/findings/{DRIFT_FINDING}/remediate", json={"actor": "tlee", "note": "re-apply template"})
    assert r.status_code == 200
    body = r.json()
    assert body["executed"] is True and body["finding"]["status"] == "verified"
    assert body["finding"]["verification"]["after_remediation"] is True
    assert body["finding"]["verification"]["run_id"] == body["run"]["run_id"]
    assert body["finding"]["remediation"]["requested_by"] == "tlee"
    assert "description MKT-WS-022" in body["transcript"] and " description MKT-WS-022" in body["commands"]
    iface = api_client.get("/api/switch/interfaces/Gi1/0/22").json()
    assert iface["interface"]["description"] == "MKT-WS-022" == iface["intent"]["description"]
    detail = api_client.get(f"/api/findings/{DRIFT_FINDING}").json()
    assert detail["finding"]["status"] == "verified"
    assert [e["event"] for e in detail["events"]] == [
        "opened",
        "remediation_requested",
        "remediation_executed",
        "verified",
    ]
    assert [h["status"] for h in detail["history"]] == ["FAIL", "PASS"]
    assert DRIFT_FINDING not in {f["id"] for f in api_client.get("/api/findings", params={"open_only": "true"}).json()}
    assert api_client.get("/api/posture").json()["findings"]["by_status"] == {"open": 7, "verified": 1}
    assert len(api_client.get("/api/assessments/runs").json()) == runs_before + 1
    # Repeating the remediation is a conflict; an unknown finding is not found.
    again = api_client.post(f"/api/findings/{DRIFT_FINDING}/remediate")
    assert again.status_code == 409 and "already verified" in again.json()["detail"]
    assert api_client.post("/api/findings/FND-NOPE/remediate").status_code == 404


def test_run_assessment_increments_runs(api_client):
    # Precondition: a verified finding, so the run below can show that verification survives a re-run.
    r = api_client.post(f"/api/findings/{DRIFT_FINDING}/remediate", json={"actor": "tlee", "note": "re-apply template"})
    assert r.status_code == 200 and r.json()["finding"]["status"] == "verified"
    before = api_client.get("/api/posture").json()["runs"]
    r = api_client.post("/api/assessments/run", json={"actor": "tlee"})
    assert r.status_code == 200
    run = r.json()
    assert run["run_id"].startswith("ASR-") and run["trigger"] == "api" and run["actor"] == "tlee"
    assert sum(run["counts"].values()) == run["assessments"] and run["controls"] == 13
    runs = api_client.get("/api/assessments/runs").json()
    # Runs are listed by simulated assessed_at; the API run uses the persisted twin clock, which sits
    # behind the remediation reassessment's clock, so membership (not position) is the invariant.
    assert len(runs) == before + 1 and run["run_id"] in {r["run_id"] for r in runs}
    assert api_client.get(f"/api/assessments/runs/{run['run_id']}").json()["run"]["trigger"] == "api"
    posture = api_client.get("/api/posture").json()
    assert posture["runs"] == before + 1 and posture["last_run"]["run_id"] == runs[0]["run_id"]
    history = api_client.get("/api/assessments/ASM-UNUSED-PORTS-Gi1-0-41").json()["history"]
    assert history[-1]["run_id"] == run["run_id"] and len(history) == before + 1
    assert api_client.get(f"/api/findings/{DRIFT_FINDING}").json()["finding"]["status"] == "verified"


def test_review_decisions(api_client):
    review = api_client.get(f"/api/reviews/{OPEN_REVIEW}").json()
    assert review["status"] == "review" and review["scenario"] == "critical-asset-scan"
    assert api_client.get("/api/reviews/DET-NOPE").status_code == 404
    assert api_client.post("/api/reviews/DET-NOPE/approve", json=BODY).status_code == 404
    assert api_client.post("/api/reviews/DET-NOPE/reject", json=BODY).status_code == 404
    assert api_client.post(f"/api/reviews/{CLOSED_REVIEW}/reject", json=BODY).status_code == 409
    assert api_client.post(f"/api/reviews/{CLOSED_REVIEW}/approve", json=BODY).status_code == 409

    r = api_client.post(f"/api/reviews/{OPEN_REVIEW}/approve", json=BODY)
    assert r.status_code == 200
    body = r.json()
    assert body["incident"]["id"] == "INC-2026-0043" and body["incident"]["status"] == "contained"
    assert body["incident"]["authorization"]["mode"] == "analyst"
    assert body["incident"]["authorization"]["authorized_by"] == "tlee"
    assert body["action"]["status"] == "verified" and body["review"]["status"] == "approved"
    assert body["assessment_run"]["trigger"] == "post-containment-INC-2026-0043"
    assert api_client.get(f"/api/reviews/{OPEN_REVIEW}").json()["status"] == "approved"
    assert (
        api_client.get("/api/assessments/ASM-EVIDENCE-COMPLETE-INC-2026-0043").json()["assessment"]["status"] == "PASS"
    )
    incident = api_client.get("/api/incidents/INC-2026-0043").json()["incident"]
    assert incident["status"] == "contained" and incident["interface"] == "Gi1/0/12"
    iface = api_client.get("/api/switch/interfaces/Gi1/0/12").json()["interface"]
    assert iface["access_vlan"] == 50 and iface["quarantined"] and iface["state"] == "quarantined"
    assert api_client.get("/api/overview").json()["kpis"]["quarantined_hosts"] == 1
    assert api_client.post(f"/api/reviews/{OPEN_REVIEW}/approve", json=BODY).status_code == 409
    assert api_client.post(f"/api/reviews/{OPEN_REVIEW}/reject", json=BODY).status_code == 409

    run = api_client.post("/api/assessments/run").json()
    authorized = api_client.get("/api/assessments/ASM-RESPONSE-AUTHORIZED-INC-2026-0043").json()["assessment"]
    assert authorized["status"] == "PASS" and authorized["run_id"] == run["run_id"]
    assert (
        api_client.get("/api/assessments/ASM-QUARANTINE-VERIFIED-INC-2026-0043").json()["assessment"]["status"]
        == "PASS"
    )
    assert api_client.get("/api/posture").json()["incidents"] == {"total": 4, "open": 1, "resolved": 3}


def test_reports_generate_and_fetch(api_client):
    settings = api_client.app.state.settings
    # Precondition: an analyst-approved incident, so the exports must carry a runtime-created incident.
    assert api_client.post(f"/api/reviews/{OPEN_REVIEW}/approve", json=BODY).status_code == 200
    r = api_client.post("/api/reports/generate")
    assert r.status_code == 200
    body = r.json()
    j, h = Path(body["json"]), Path(body["html"])
    assert j.exists() and h.exists()
    assert settings.artifacts_dir in j.parents and settings.artifacts_dir in h.parents
    assert j.parent == h.parent == settings.artifacts_dir / "reports"
    doc = json.loads(j.read_text(encoding="utf-8"))
    assert doc["schema_version"] == "2.0"
    assert len(doc["assessments"]) == body["assessments"] and len(doc["findings"]) == body["findings"]
    assert h.read_text(encoding="utf-8").startswith("<!doctype html>")
    if body["pdf"]:
        assert Path(body["pdf"]).exists() and Path(body["pdf"]).parent == j.parent
        pdf = api_client.get("/api/reports/posture.pdf")
        assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    else:
        assert api_client.get("/api/reports/posture.pdf").status_code == 404

    rj = api_client.get("/api/reports/posture.json")
    assert rj.status_code == 200
    live = rj.json()
    assert (
        live["schema_version"] == "2.0" and live["posture"]["totals"] == api_client.get("/api/posture").json()["totals"]
    )
    assert live["posture"]["totals"] == doc["posture"]["totals"]
    assert {i["incident"]["id"] for i in live["incidents"]} >= {"INC-2026-0043"}
    rh = api_client.get("/api/reports/posture.html")
    assert rh.status_code == 200 and rh.headers["content-type"].startswith("text/html")
    assert "<h2>1. Executive summary</h2>" in rh.text and "<h2>10. Limitations and reproducibility</h2>" in rh.text
    assert "No real network was assessed." in rh.text and "INC-2026-0043" in rh.text
