"""SentinelSwitch 2.0 assurance layer: assessment engine, freshness, history, remediation, posture,
export and the end-to-end evidence workflow. Every test seeds its own temporary store."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import pytest

from sentinelswitch.app.config import Settings
from sentinelswitch.assurance.controls import CONTROLS, CONTROLS_BY_ID, CSF
from sentinelswitch.assurance.engine import FINDING_OPEN_STATES, AssessmentEngine
from sentinelswitch.assurance.export import build_export, render_html, write_html, write_json
from sentinelswitch.assurance.posture import SEVERITY_ORDER, summary
from sentinelswitch.assurance.remediation import RemediationError, RemediationService
from sentinelswitch.containment.adapters import SimulatedCisco2960XAdapter
from sentinelswitch.evidence.bundle import BUNDLE_FILES
from sentinelswitch.services import demo as demo_service
from sentinelswitch.services.seed import seed_database
from sentinelswitch.services.store import Store
from sentinelswitch.simulator.scenario import ScenarioRunner
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import ROOT, add_seconds, parse_ts, ts_iso

HISTORICAL = ("INC-2026-0039", "INC-2026-0040", "INC-2026-0041")
FLAGSHIP = "INC-2026-0042"
BASELINE_COUNTS = {"PASS": 200, "FAIL": 4, "UNKNOWN": 1, "STALE": 1}
BASELINE_TOTAL = 206
BASELINE_FINDINGS = 5
BASELINE_FAILS = {
    "ASM-CONFIG-BASELINE-Gi1-0-22",
    "ASM-CONFIG-BASELINE-Gi1-0-35",
    "ASM-UNUSED-PORTS-Gi1-0-41",
    "ASM-SENSOR-COVERAGE-vlan-50",
}
IDENTITY_WINDOW = 14400 + 900
HTML_SECTIONS = [
    "1. Executive summary",
    "2. Assessment counts and methodology",
    "3. Control findings",
    "4. Affected assets",
    "5. Supporting evidence",
    "6. Incident timeline",
    "7. Containment authorization and verification",
    "8. Outstanding remediation",
    "9. Framework mapping (NIST CSF 2.0)",
    "10. Limitations and reproducibility",
]


def _copy_bundles(incidents_dir: Path) -> None:
    for src in (ROOT / "data" / "incidents").iterdir():
        if src.is_dir() and src.name in HISTORICAL:
            shutil.copytree(src, incidents_dir / src.name)


def _seed(env, root: Path, *, with_bundles: bool = True) -> tuple[Store, Path, dict]:
    incidents = root / "incidents"
    incidents.mkdir(parents=True, exist_ok=True)
    if with_bundles:
        _copy_bundles(incidents)
    store = Store(env, root / "t.db")
    seeded = seed_database(store, env, ROOT / "data" / "seed", incidents, run_validation_suite=False)
    return store, incidents, seeded["assessment"]


@pytest.fixture()
def seeded(env, tmp_path, seed_ready):
    """Fresh store at the dataset baseline with the historical evidence bundles present."""
    return _seed(env, tmp_path)


@pytest.fixture()
def engine(env, seeded) -> AssessmentEngine:
    store, incidents, _ = seeded
    return AssessmentEngine(env, store, incidents)


@pytest.fixture()
def remediation(env, seeded, engine) -> RemediationService:
    store, _, _ = seeded
    return RemediationService(env, store, engine)


def _events(store: Store, finding_id: str) -> list[str]:
    return [e["event"] for e in store.finding_events(finding_id)]


# -------------------------------------------------------------------------------------------------
# 1. Baseline assessment
# -------------------------------------------------------------------------------------------------
def test_baseline_assessment_results(seeded):
    store, _, run = seeded
    assert run["run_id"].startswith("ASR-") and run["trigger"] == "baseline-seed"
    assert run["controls"] == len(CONTROLS) == 13
    assert run["counts"] == BASELINE_COUNTS and run["assessments"] == sum(BASELINE_COUNTS.values()) == BASELINE_TOTAL
    assert run["retired"] == 0
    rows = store.assessments()
    assert len(rows) == run["assessments"]
    assert all(a["id"].startswith("ASM-") and a["run_id"] == run["run_id"] for a in rows)
    assert Counter(a["status"] for a in rows) == BASELINE_COUNTS
    by_id = {a["id"]: a for a in rows}
    assert len(by_id) == len(rows)

    # Config baseline: the two interface drifts that no dedicated control owns fail, with the drift
    # engine's severities. The Gi1/0/41 admin_status drift belongs to CTL-UNUSED-PORTS (one deviation,
    # one finding) and the global span_session drift to CTL-SENSOR-COVERAGE.
    assert {a["id"] for a in rows if a["status"] == "FAIL"} == BASELINE_FAILS
    baseline_fail = {
        a["scope"]["interface"]: a for a in rows if a["control_id"] == "CTL-CONFIG-BASELINE" and a["status"] == "FAIL"
    }
    assert set(baseline_fail) == {"Gi1/0/22", "Gi1/0/35"}
    assert baseline_fail["Gi1/0/22"]["severity"] == "low" and baseline_fail["Gi1/0/22"]["observed"] == {
        "description": "MKT-WS-022 loaner"
    }
    assert baseline_fail["Gi1/0/35"]["expected"] == {"storm_control": {"broadcast": "1.00", "multicast": "1.00"}}
    assert by_id["ASM-CONFIG-BASELINE-Gi1-0-41"]["status"] == "PASS"  # owned by CTL-UNUSED-PORTS, not double counted
    assert sum(1 for a in rows if a["control_id"] == "CTL-CONFIG-BASELINE") == 50

    gi41 = by_id["ASM-UNUSED-PORTS-Gi1-0-41"]
    assert gi41["status"] == "FAIL" and gi41["severity"] == "medium"
    assert (
        gi41["observed"] == "admin up, access VLAN 999" and gi41["expected"] == "administratively down, access VLAN 999"
    )
    assert gi41["remediation"]["action"] == {"type": "shutdown_unused", "interfaces": ["Gi1/0/41"]}
    assert gi41["remediation"]["commands"] == [
        "interface GigabitEthernet1/0/41",
        " switchport access vlan 999",
        " shutdown",
    ]
    assert gi41["scope"]["type"] == "interface" and gi41["scope"]["asset"] is None and gi41["scope"]["vlan"] == 999
    assert sum(1 for a in rows if a["control_id"] == "CTL-UNUSED-PORTS") == 12
    assert sum(1 for a in rows if a["control_id"] == "CTL-UNUSED-PORTS" and a["status"] == "PASS") == 11

    span = by_id["ASM-SENSOR-COVERAGE-vlan-50"]
    assert span["status"] == "FAIL" and span["scope"]["vlan"] == 50 and span["observed"] == "sources [20, 30, 40]"
    assert span["remediation"]["action"] == {"type": "add_span_source", "vlan": 50}
    assert all(by_id[f"ASM-SENSOR-COVERAGE-vlan-{v}"]["status"] == "PASS" for v in (20, 30, 40))

    stale = by_id["ASM-ENDPOINT-IDENTITY-Gi1-0-30"]
    assert stale["status"] == "STALE" and stale["scope"]["asset"] == "CONF-A-TV01"
    assert [a["id"] for a in rows if a["status"] == "STALE"] == [stale["id"]]

    suricata = by_id["ASM-TELEMETRY-FRESH-suricata"]
    assert suricata["status"] == "UNKNOWN" and suricata["finding_id"] is None
    assert [a["id"] for a in rows if a["status"] == "UNKNOWN"] == [suricata["id"]]
    for src in ("zeek-conn", "radius", "syslog"):
        assert by_id[f"ASM-TELEMETRY-FRESH-{src}"]["status"] == "PASS"

    for inc in HISTORICAL:
        authorized = by_id[f"ASM-RESPONSE-AUTHORIZED-{inc}"]
        assert authorized["status"] == "PASS" and authorized["related_incidents"] == [inc]
        assert authorized["scope"] == {
            "type": "incident",
            "id": inc,
            "asset": authorized["scope"]["interface"],
            "switch": "SW01",
            "interface": authorized["scope"]["interface"],
            "vlan": authorized["scope"]["vlan"],
        }
        assert {e["source"] for e in authorized["evidence"]} == {"containment-action", "policy-decision"}
        assert by_id[f"ASM-EVIDENCE-COMPLETE-{inc}"]["status"] == "PASS"
        assert by_id[f"ASM-RECOVERY-VERIFIED-{inc}"]["status"] == "PASS"
    assert not [a for a in rows if a["control_id"] == "CTL-QUARANTINE-VERIFIED"]

    # Every assessment carries the catalog's framework mapping and a non-empty evidence list.
    for a in rows:
        control = CONTROLS_BY_ID[a["control_id"]]
        assert [m["id"] for m in a["framework"]["nist_csf_2_0"]] == control.csf
        assert a["control_name"] == control.name and a["category"] == control.category
        assert a["evidence"] and all({"source", "ref", "collected_at", "detail"} <= set(e) for e in a["evidence"])
        assert a["detector"] == "sentinelswitch-assurance"


def test_findings_open_only_for_fail_and_stale(seeded):
    store, _, run = seeded
    rows = store.assessments()
    findings = store.findings()
    expected_ids = {"FND-" + a["id"][len("ASM-") :] for a in rows if a["status"] in {"FAIL", "STALE"}}
    assert {f["id"] for f in findings} == expected_ids and len(findings) == BASELINE_FINDINGS
    assert run["findings_open"] == BASELINE_FINDINGS and store.counts()["findings_open"] == BASELINE_FINDINGS
    assert all(f["id"].startswith("FND-") for f in findings)
    for a in rows:
        fid = "FND-" + a["id"][len("ASM-") :]
        if a["status"] in {"FAIL", "STALE"}:
            assert a["finding_id"] == fid
        else:
            assert a["finding_id"] is None and store.finding(fid) is None
    assert store.finding("FND-TELEMETRY-FRESH-suricata") is None
    for f in findings:
        assert f["status"] == "open" and f["occurrences"] == 1
        assert f["first_run_id"] == f["last_run_id"] == run["run_id"] and f["opened_at"] == run["assessed_at"]
        assert f["remediation"]["status"] == "not_started" and f["remediation"]["action"]
        assert f["verification"] == {"outcome": None, "at": None, "run_id": None} and f["resolved_at"] is None
        assert _events(store, f["id"]) == ["opened"]
    by_id = {f["id"]: f for f in findings}
    assert by_id["FND-ENDPOINT-IDENTITY-Gi1-0-30"]["result"] == "STALE"
    assert {f["result"] for f in findings if f["id"] != "FND-ENDPOINT-IDENTITY-Gi1-0-30"} == {"FAIL"}
    assert by_id["FND-UNUSED-PORTS-Gi1-0-41"]["asset"] is None  # an unused port has no inventoried asset
    assert by_id["FND-UNUSED-PORTS-Gi1-0-41"]["scope"]["interface"] == "Gi1/0/41"


# -------------------------------------------------------------------------------------------------
# 2. Freshness / STALE
# -------------------------------------------------------------------------------------------------
def test_stale_identity_evidence_and_severity_downgrade(seeded):
    store, _, _ = seeded
    control = CONTROLS_BY_ID["CTL-ENDPOINT-IDENTITY"]
    assert control.freshness_window == IDENTITY_WINDOW and control.severity == "medium"
    a = store.assessment("ASM-ENDPOINT-IDENTITY-Gi1-0-30")
    fr = a["freshness"]
    assert fr["window_seconds"] == IDENTITY_WINDOW
    assert fr["applied"] is True and fr["fresh"] is False and fr["age_seconds"] > fr["window_seconds"]
    assert fr["age_seconds"] == int((parse_ts(a["assessed_at"]) - parse_ts(fr["oldest_evidence_at"])).total_seconds())
    radius = [e for e in a["evidence"] if e["source"] == "radius"]
    assert len(radius) == 1 and radius[0]["collected_at"] == fr["oldest_evidence_at"]
    assert radius[0]["detail"].startswith("Guest-VLAN")
    assert a["status"] == "STALE" and a["severity"] == "low"
    assert f"older than the {IDENTITY_WINDOW // 60}-minute freshness window" in a["explanation"]
    assert a["limitations"] and "Guest-VLAN" in a["limitations"]
    finding = store.finding("FND-ENDPOINT-IDENTITY-Gi1-0-30")
    assert finding["result"] == "STALE" and finding["severity"] == "low"
    assert finding["remediation"]["action"] == {"type": "reauthenticate", "interface": "Gi1/0/30"}
    # State-based controls never apply a window.
    assert store.assessment("ASM-CONFIG-BASELINE-Gi1-0-41")["freshness"] == {"window_seconds": None, "applied": False}


def test_fresh_auth_event_turns_stale_into_pass(seeded, engine):
    store, _, run1 = seeded
    twin = store.load_twin()
    macs = twin.macs_on_interface("Gi1/0/30")
    assert [m.mac for m in macs] == ["8C:71:F8:2D:30:02"]
    fresh_at = ts_iso(add_seconds(twin.now, -600))
    store.put_auth_event(
        {
            "event_id": "RAD-TEST-00001",
            "timestamp": fresh_at,
            "calling_station_id": macs[0].mac.replace(":", "-"),
            "username": "(none)",
            "result": "Guest-VLAN",
            "method": "dot1x (no supplicant response)",
            "nas_port_id": "GigabitEthernet1/0/30",
        }
    )
    run2 = engine.run("fresh-identity")
    assert run2["run_id"] != run1["run_id"]
    assert run2["counts"] == {**BASELINE_COUNTS, "PASS": BASELINE_COUNTS["PASS"] + 1, "STALE": 0}
    a = store.assessment("ASM-ENDPOINT-IDENTITY-Gi1-0-30")
    assert a["run_id"] == run2["run_id"] and a["status"] == "PASS" and a["severity"] == "medium"
    assert a["freshness"] == {
        "window_seconds": IDENTITY_WINDOW,
        "applied": True,
        "oldest_evidence_at": fresh_at,
        "age_seconds": 600,
        "fresh": True,
    }
    assert any(e["ref"] == "RAD-TEST-00001" for e in a["evidence"])
    f = store.finding("FND-ENDPOINT-IDENTITY-Gi1-0-30")
    assert f["status"] == "verified" and f["resolved_at"] == run2["assessed_at"]
    assert f["verification"] == {
        "outcome": "PASS",
        "at": run2["assessed_at"],
        "run_id": run2["run_id"],
        "after_remediation": False,
    }
    assert _events(store, f["id"]) == ["opened", "verified"]
    assert run2["findings_open"] == BASELINE_FINDINGS - 1


def test_identity_evidence_ages_past_the_window(env, seeded, engine):
    store, _, _ = seeded
    fresh = [
        a["id"]
        for a in store.assessments(control_id="CTL-ENDPOINT-IDENTITY")
        if a["status"] == "PASS" and a["freshness"]["applied"]
    ]
    static = [
        a["id"]
        for a in store.assessments(control_id="CTL-ENDPOINT-IDENTITY")
        if a["status"] == "PASS" and not a["freshness"]["applied"]
    ]
    assert fresh and static
    # A day later every RADIUS result in the dataset (which ends at midnight) is older than the window.
    later = add_seconds(store.load_twin().now, 24 * 3600)
    run = engine.run("one-day-later", at=later)
    assert run["assessed_at"] == ts_iso(later)
    for aid in fresh:
        a = store.assessment(aid)
        assert a["status"] == "STALE" and a["severity"] == "low"
        assert a["freshness"]["fresh"] is False and a["freshness"]["age_seconds"] > IDENTITY_WINDOW
        assert parse_ts(a["freshness"]["oldest_evidence_at"]) <= env.day_end
        assert a["freshness"]["age_seconds"] == int(
            (later - parse_ts(a["freshness"]["oldest_evidence_at"])).total_seconds()
        )
        f = store.finding("FND-" + aid[len("ASM-") :])
        assert f["status"] == "open" and f["result"] == "STALE" and f["first_run_id"] == run["run_id"]
    for aid in static:
        a = store.assessment(aid)
        assert a["status"] == "PASS" and a["freshness"]["applied"] is False
    assert run["counts"]["STALE"] >= len(fresh) + 1


# -------------------------------------------------------------------------------------------------
# 3. History and reopen
# -------------------------------------------------------------------------------------------------
def test_history_occurrences_verification_and_reopen(seeded, engine, remediation, env):
    store, _, run1 = seeded
    ids = {a["id"] for a in store.assessments()}
    run2 = engine.run("second", at=add_seconds(store.load_twin().now, 60))
    assert run2["run_id"] != run1["run_id"] and run2["counts"] == run1["counts"]
    assert {a["id"] for a in store.assessments()} == ids  # stable ids across runs
    for aid in ids:
        assert [h["run_id"] for h in store.assessment_history(assessment_id=aid)] == [run1["run_id"], run2["run_id"]]
    assert len(store.assessment_history(run_id=run2["run_id"])) == run2["assessments"]
    assert [r["run_id"] for r in store.assessment_runs()] == [run2["run_id"], run1["run_id"]]
    for f in store.findings():
        assert f["occurrences"] == 2 and f["status"] == "open"
        assert f["first_run_id"] == run1["run_id"] and f["last_run_id"] == run2["run_id"]
        assert _events(store, f["id"]) == ["opened"]  # repeated FAIL does not spam events

    fid, aid = "FND-CONFIG-BASELINE-Gi1-0-22", "ASM-CONFIG-BASELINE-Gi1-0-22"
    res = remediation.remediate(fid, actor="tlee", note="re-apply the template description")
    assert res["executed"] is True and res["run"]["findings_open"] == BASELINE_FINDINGS - 1
    f = store.finding(fid)
    assert f["status"] == "verified" and f["occurrences"] == 2  # PASS never increments occurrences
    assert f["verification"]["outcome"] == "PASS" and f["verification"]["after_remediation"] is True
    assert f["verification"]["run_id"] == res["run"]["run_id"] and f["resolved_at"] == f["verification"]["at"]
    assert store.load_twin().interfaces["Gi1/0/22"].description == env.ports["Gi1/0/22"].description
    history_before = store.assessment_history(assessment_id=aid)
    assert [h["status"] for h in history_before] == ["FAIL", "FAIL", "PASS"]

    # Regression: the same drift is re-introduced by hand.
    twin = store.load_twin()
    twin.apply_drift([{"interface": "Gi1/0/22", "setting": "description", "observed": "MKT-WS-022 loaner"}])
    store.save_twin(twin)
    run4 = engine.run("regression", at=add_seconds(twin.now, 60))
    assert run4["counts"]["FAIL"] == run1["counts"]["FAIL"] and run4["findings_open"] == BASELINE_FINDINGS
    f = store.finding(fid)
    assert f["status"] == "reopened" and f["resolved_at"] is None and f["occurrences"] == 3
    assert f["last_run_id"] == run4["run_id"] and f["first_run_id"] == run1["run_id"]
    assert f["observed"] == {"description": "MKT-WS-022 loaner"}
    assert f["verification"]["outcome"] == "PASS"  # the earlier verification record is kept
    assert _events(store, fid) == ["opened", "remediation_requested", "remediation_executed", "verified", "reopened"]
    actors = {e["event"]: e["actor"] for e in store.finding_events(fid)}
    assert actors["remediation_requested"] == "tlee" and actors["remediation_executed"] == "sentinel"
    assert actors["verified"] == "sentinel-assurance"  # the analyst asks, the switch executes, the engine verifies
    assert store.assessment(aid)["status"] == "FAIL" and store.assessment(aid)["finding_id"] == fid
    history = store.assessment_history(assessment_id=aid)
    assert history[: len(history_before)] == history_before and [h["status"] for h in history] == [
        "FAIL",
        "FAIL",
        "PASS",
        "FAIL",
    ]
    assert [r["trigger"] for r in store.assessment_runs()] == [
        "regression",
        f"remediation-{fid}",
        "second",
        "baseline-seed",
    ]
    assert fid in {x["id"] for x in store.findings() if x["status"] in FINDING_OPEN_STATES}


# -------------------------------------------------------------------------------------------------
# 4. RemediationService
# -------------------------------------------------------------------------------------------------
def test_remediate_unused_port_shuts_it_down_and_verifies(seeded, remediation):
    store, _, run = seeded
    fid = "FND-UNUSED-PORTS-Gi1-0-41"
    before = store.load_twin().interfaces["Gi1/0/41"]
    assert before.admin_status == "up" and before.access_vlan == 999
    res = remediation.remediate(fid, actor="tlee", note="park the port")
    assert res["executed"] is True
    assert res["commands"] == [
        "configure terminal",
        "interface GigabitEthernet1/0/41",
        " shutdown",
        " switchport access vlan 999",
        "end",
        "write memory",
    ]
    assert "SW01(config-if)#shutdown" in res["transcript"] and "[OK]" in res["transcript"]
    twin = store.load_twin()
    after = twin.interfaces["Gi1/0/41"]
    assert after.admin_status == "down" and after.oper_status == "disabled" and after.access_vlan == 999
    change = twin.config_changes[-1]
    assert change.actor == "tlee" and change.interface == "Gi1/0/41" and fid in (change.reason or "")

    f = res["finding"]
    assert f["status"] == "verified" and f["remediation"]["status"] == "executed"
    assert f["remediation"]["requested_by"] == "tlee" and f["remediation"]["executed_by"] == "sentinel"
    assert f["remediation"]["note"] == "park the port" and f["remediation"]["transcript"] == res["transcript"]
    assert parse_ts(f["remediation"]["requested_at"]) < parse_ts(f["remediation"]["executed_at"])
    assert parse_ts(f["remediation"]["executed_at"]) < parse_ts(f["verification"]["at"])
    assert f["verification"]["after_remediation"] is True and f["verification"]["run_id"] == res["run"]["run_id"]
    assert _events(store, fid) == ["opened", "remediation_requested", "remediation_executed", "verified"]

    # One deviation, one finding, one remediation: the config-baseline row for the same port never failed.
    assert store.assessment("ASM-UNUSED-PORTS-Gi1-0-41")["status"] == "PASS"
    assert store.assessment("ASM-CONFIG-BASELINE-Gi1-0-41")["status"] == "PASS"
    assert store.finding("FND-CONFIG-BASELINE-Gi1-0-41") is None
    assert res["run"]["counts"]["FAIL"] == run["counts"]["FAIL"] - 1
    assert res["run"]["findings_open"] == BASELINE_FINDINGS - 1


def test_remediate_sensor_coverage_adds_span_source(seeded, remediation):
    store, _, _ = seeded
    assert store.load_twin().span["source_vlans"] == [20, 30, 40]
    res = remediation.remediate("FND-SENSOR-COVERAGE-vlan-50", actor="tlee")
    twin = store.load_twin()
    assert twin.span["source_vlans"] == [20, 30, 40, 50]
    assert res["commands"] == [
        "configure terminal",
        " monitor session 1 source vlan 20 , 30 , 40 , 50 both",
        "end",
        "write memory",
    ]
    assert res["finding"]["status"] == "verified" and res["finding"]["verification"]["after_remediation"] is True
    a = store.assessment("ASM-SENSOR-COVERAGE-vlan-50")
    assert a["status"] == "PASS" and a["observed"] == "sources [20, 30, 40, 50]"
    assert res["run"]["counts"]["FAIL"] == BASELINE_COUNTS["FAIL"] - 1


def test_remediate_endpoint_identity_records_fresh_auth_events(seeded, remediation):
    store, _, _ = seeded
    fid = "FND-ENDPOINT-IDENTITY-Gi1-0-30"
    before = {e["event_id"] for e in store.auth_events(limit=100000)}
    res = remediation.remediate(fid, actor="tlee")
    assert res["commands"] == ["clear authentication sessions interface GigabitEthernet1/0/30"]
    new = [e for e in store.auth_events(limit=100000) if e["event_id"] not in before]
    assert new and all(e["calling_station_id"] == "8C-71-F8-2D-30-02" for e in new)
    assert {e["result"] for e in new} == {"Access-Reject", "Guest-VLAN"}
    executed_at = parse_ts(res["finding"]["remediation"]["executed_at"])
    assert all(parse_ts(e["timestamp"]) > executed_at for e in new)
    a = store.assessment("ASM-ENDPOINT-IDENTITY-Gi1-0-30")
    assert a["status"] == "PASS" and a["severity"] == "medium"
    assert a["freshness"]["fresh"] is True and 0 <= a["freshness"]["age_seconds"] < 60
    guest = next(e for e in new if e["result"] == "Guest-VLAN")
    assert a["freshness"]["oldest_evidence_at"] == guest["timestamp"]
    f = res["finding"]
    assert f["status"] == "verified" and f["verification"]["after_remediation"] is True
    assert res["run"]["counts"]["STALE"] == 0
    # The reauthentication left a syslog trail on the twin.
    assert any(ln.mnemonic == "VLANASSIGN" for ln in store.load_twin().log)


def test_remediate_rejects_closed_unknown_and_non_executable_findings(seeded, remediation):
    store, _, _ = seeded
    fid = "FND-SENSOR-COVERAGE-vlan-50"
    remediation.remediate(fid, actor="tlee")
    assert store.finding(fid)["status"] == "verified"
    with pytest.raises(RemediationError, match="already verified"):
        remediation.remediate(fid, actor="tlee")
    with pytest.raises(KeyError):
        remediation.remediate("FND-NOPE", actor="tlee")
    manual = store.finding("FND-CONFIG-BASELINE-Gi1-0-35")
    manual["remediation"]["action"] = None
    store.put_finding(manual)
    with pytest.raises(RemediationError, match="no executable remediation"):
        remediation.remediate(manual["id"], actor="tlee")
    assert store.finding(manual["id"])["status"] == "open"


def test_remediation_targeting_protected_interface_is_refused(seeded, engine, remediation):
    store, _, _ = seeded
    fid = "FND-CONFIG-BASELINE-Gi1-0-22"
    f = store.finding(fid)
    f["remediation"]["action"] = {"type": "apply_config", "interface": "Gi1/0/1", "lines": ["description"]}
    store.put_finding(f)
    twin_before = store.load_twin()
    keys = (
        "description",
        "mode",
        "native_vlan",
        "allowed_vlans",
        "admin_status",
        "oper_status",
        "settings",
        "protected",
    )
    before = {k: v for k, v in asdict(twin_before.interfaces["Gi1/0/1"]).items() if k in keys}
    changes_before = len(twin_before.config_changes)
    assert before["protected"] and before["mode"] == "trunk"

    res = remediation.remediate(fid, actor="tlee", note="forced")
    assert res["executed"] is False and "run" not in res
    assert "Gi1/0/1 is a protected infrastructure interface" in res["refused"]
    f = store.finding(fid)
    assert f["status"] == "remediation_failed" and f["remediation"]["status"] == "refused"
    assert f["remediation"]["transcript"] == res["refused"] and f["remediation"]["requested_by"] == "tlee"
    events = store.finding_events(fid)
    assert [e["event"] for e in events] == ["opened", "remediation_requested", "remediation_refused"]
    assert events[-1]["actor"] == "switch-adapter"

    twin = store.load_twin()
    assert {k: v for k, v in asdict(twin.interfaces["Gi1/0/1"]).items() if k in keys} == before
    assert len(twin.config_changes) == changes_before
    assert twin.interfaces["Gi1/0/22"].description == "MKT-WS-022 loaner"  # the drift is still there

    # A later run keeps the failed state (the condition is still FAIL) instead of reopening or verifying.
    run = engine.run("after-refusal")
    f = store.finding(fid)
    assert f["status"] == "remediation_failed" and f["occurrences"] == 2 and f["last_run_id"] == run["run_id"]
    assert run["findings_open"] == BASELINE_FINDINGS and fid in {
        x["id"] for x in store.findings() if x["status"] in FINDING_OPEN_STATES
    }


# -------------------------------------------------------------------------------------------------
# 5. Verification failure path
# -------------------------------------------------------------------------------------------------
def test_failed_read_back_verification_opens_quarantine_finding(env, seeded, engine, monkeypatch):
    store, incidents, _ = seeded
    monkeypatch.setattr(
        SimulatedCisco2960XAdapter,
        "verify_vlan",
        lambda self, interface, vlan: (False, "simulated read-back mismatch"),
    )
    twin = SwitchTwin.baseline(env)
    runner = ScenarioRunner(env, twin, evidence_root=incidents, incident_seq=41)
    result = runner.run(env.flagship(), "day")
    action = result.action
    assert action.status == "failed" and action.verification["ok"] is False
    assert action.verification["transcript"] == "simulated read-back mismatch"
    assert action.applied_at and action.verified_at and action.authorization["status"] == "authorized"
    assert result.incident["id"] == FLAGSHIP and result.incident["status"] == "containment_failed"
    assert result.checks["detect"] and result.checks["attribute"] and not result.checks["contain"]
    assert not result.passed
    assert any(t["phase"] == "verification" and "FAILED" in t["message"] for t in result.timeline)
    assert twin.interfaces["Gi1/0/23"].access_vlan == 50  # the change was applied; only the read-back failed
    assert (incidents / FLAGSHIP / "containment.json").exists()

    store.put_incident(result.incident)
    store.put_action(action.to_dict())
    store.put_timeline(FLAGSHIP, result.timeline)
    store.save_twin(twin)
    run = engine.run("post-failure")
    # Two new FAILs: the unverified containment itself, and Gi1/0/23 sitting in VLAN 50 without a
    # *verified* workflow to authorize the deviation from its intended VLAN.
    assert run["counts"]["FAIL"] == BASELINE_COUNTS["FAIL"] + 2 and run["findings_open"] == BASELINE_FINDINGS + 2
    a = store.assessment(f"ASM-QUARANTINE-VERIFIED-{FLAGSHIP}")
    assert a["status"] == "FAIL" and a["severity"] == "high" and a["related_incidents"] == [FLAGSHIP]
    assert "read-back verification failed" in a["explanation"] and a["scope"]["interface"] == "Gi1/0/23"
    assert any(e["source"] == "containment-action" and "read-back FAILED" in e["detail"] for e in a["evidence"])
    f = store.finding(f"FND-QUARANTINE-VERIFIED-{FLAGSHIP}")
    assert f is not None and f["status"] == "open" and f["severity"] == "high" and f["result"] == "FAIL"
    assert f["remediation"]["action"] is None and f["remediation"]["commands"] == action.commands
    # Authorization preceded execution, so the authorization control still passes for the failed workflow.
    assert store.assessment(f"ASM-RESPONSE-AUTHORIZED-{FLAGSHIP}")["status"] == "PASS"
    assert store.assessment(f"ASM-EVIDENCE-COMPLETE-{FLAGSHIP}")["status"] == "PASS"
    assert store.assessment("ASM-VLAN-INTENT-Gi1-0-23")["status"] == "FAIL"  # no *verified* workflow explains VLAN 50
    posture = summary(store, env)
    assert posture["incidents"] == {"total": 4, "open": 1, "resolved": 3}
    assert next(c for c in posture["by_control"] if c["control_id"] == "CTL-QUARANTINE-VERIFIED")["status"] == "FAIL"
    assert posture["assets_with_open_findings"][0]["worst"] == "high"


# -------------------------------------------------------------------------------------------------
# 6. Posture summary math
# -------------------------------------------------------------------------------------------------
def test_posture_summary_math(env, seeded):
    store, _, run = seeded
    p = summary(store, env)
    rows = store.assessments()
    counts = Counter(a["status"] for a in rows)
    t = p["totals"]
    assert t["assessments"] == len(rows) == BASELINE_TOTAL and t["controls"] == len(CONTROLS)
    assert t["retired"] == 0
    assert (t["pass"], t["fail"], t["unknown"], t["stale"]) == (
        counts["PASS"],
        counts["FAIL"],
        counts["UNKNOWN"],
        counts["STALE"],
    )
    assert t["determinate"] == t["pass"] + t["fail"] == t["assessments"] - t["unknown"] - t["stale"] == 204
    assert t["coverage_pct"] == round(100 * t["determinate"] / t["assessments"], 1) == 99.0
    assert t["pass_rate_of_determinate_pct"] == round(100 * t["pass"] / t["determinate"], 1) == 98.0
    assert t["pass_rate_of_all_pct"] == round(100 * t["pass"] / t["assessments"], 1) == 97.1
    assert t["pass_rate_of_determinate_pct"] > t["pass_rate_of_all_pct"]
    assert p["runs"] == 1 and p["last_run"]["run_id"] == run["run_id"] and p["clock"] == run["assessed_at"]
    assert p["generated_for"] == env.dataset["day"]

    by_control = {c["control_id"]: c for c in p["by_control"]}
    assert list(by_control) == [c.id for c in CONTROLS]
    for c in by_control.values():
        assert c["pass"] + c["fail"] + c["unknown"] + c["stale"] == c["assessments"]
        assert c["csf"] == [{"id": x, "text": CSF[x]} for x in CONTROLS_BY_ID[c["control_id"]].csf]
    assert sum(c["assessments"] for c in by_control.values()) == t["assessments"]
    cb = by_control["CTL-CONFIG-BASELINE"]
    assert cb["status"] == "FAIL" and cb["fail"] == 2 and cb["pass"] == 48 and cb["open_findings"] == 2
    up = by_control["CTL-UNUSED-PORTS"]
    assert up["status"] == "FAIL" and up["assessments"] == 12 and up["fail"] == 1 and up["open_findings"] == 1
    assert by_control["CTL-SENSOR-COVERAGE"]["status"] == "FAIL" and by_control["CTL-SENSOR-COVERAGE"]["pass"] == 3
    ei = by_control["CTL-ENDPOINT-IDENTITY"]
    assert ei["status"] == "STALE" and ei["stale"] == 1 and ei["fail"] == 0 and ei["open_findings"] == 1
    tf = by_control["CTL-TELEMETRY-FRESH"]
    assert tf["status"] == "UNKNOWN" and tf["unknown"] == 1 and tf["pass"] == 3 and tf["open_findings"] == 0
    qv = by_control["CTL-QUARANTINE-VERIFIED"]
    assert qv["status"] == "NOT_ASSESSED" and qv["assessments"] == 0
    for cid in (
        "CTL-VLAN-INTENT",
        "CTL-DOT1X-ENFORCED",
        "CTL-PORT-SECURITY",
        "CTL-TRUST-BOUNDARY",
        "CTL-RESPONSE-AUTHORIZED",
        "CTL-RECOVERY-VERIFIED",
        "CTL-EVIDENCE-COMPLETE",
    ):
        c = by_control[cid]
        assert c["status"] == "PASS" and c["pass"] == c["assessments"] > 0 and c["open_findings"] == 0

    assert {c["category"] for c in p["by_category"]} == {c.category for c in CONTROLS}
    assert sum(c["pass"] + c["fail"] + c["unknown"] + c["stale"] for c in p["by_category"]) == t["assessments"]
    assert [c["category"] for c in p["by_category"]] == sorted(c["category"] for c in p["by_category"])

    fs = p["findings"]
    assert fs["open"] == BASELINE_FINDINGS and fs["closed"] == 0 and fs["by_status"] == {"open": BASELINE_FINDINGS}
    assert fs["by_severity"] == {"high": 0, "medium": 2, "low": 3} and fs["by_result"] == {"FAIL": 4, "STALE": 1}
    sev = [SEVERITY_ORDER.index(f["severity"]) for f in fs["open_items"]]
    assert sev == sorted(sev) and len(fs["open_items"]) == BASELINE_FINDINGS and fs["recently_closed"] == []

    assets = p["assets_with_open_findings"]
    ranks = [SEVERITY_ORDER.index(a["worst"]) for a in assets]
    assert ranks == sorted(ranks) and ranks[0] == SEVERITY_ORDER.index("medium")
    assert {a["asset"] for a in assets if a["worst"] == "medium"} == {"Gi1/0/41", "VLAN 50 QUARANTINE"}
    assert {a["asset"] for a in assets if a["worst"] == "low"} == {"MKT-WS-022", "ENG-LT-035", "CONF-A-TV01"}
    assert sum(a["findings"] for a in assets) == fs["open"]
    assert next(a for a in assets if a["asset"] == "Gi1/0/41")["controls"] == ["CTL-UNUSED-PORTS"]

    assert {(u["id"], u["status"]) for u in p["unverified"]} == {
        ("ASM-ENDPOINT-IDENTITY-Gi1-0-30", "STALE"),
        ("ASM-TELEMETRY-FRESH-suricata", "UNKNOWN"),
    }
    assert {u["id"] for u in p["unverified"]} == {a["id"] for a in rows if a["status"] in {"UNKNOWN", "STALE"}}

    expected = Counter()
    for a in rows:
        for sub in CONTROLS_BY_ID[a["control_id"]].csf:
            expected[(sub, a["status"].lower())] += 1
    assert [r["id"] for r in p["csf"]] == sorted({sub for a in rows for sub in CONTROLS_BY_ID[a["control_id"]].csf})
    assert "RS.MI-01" not in {r["id"] for r in p["csf"]}  # only referenced by the not-yet-assessed control
    for r in p["csf"]:
        assert r["function"] == r["id"].split(".")[0] and r["text"] == CSF[r["id"]]
        for s in ("pass", "fail", "unknown", "stale"):
            assert r[s] == expected[(r["id"], s)]
        assert r["controls"] == sorted(
            {a["control_id"] for a in rows if r["id"] in CONTROLS_BY_ID[a["control_id"]].csf}
        )
    assert p["incidents"] == {"total": 3, "open": 0, "resolved": 3}


# -------------------------------------------------------------------------------------------------
# 7. Export
# -------------------------------------------------------------------------------------------------
def test_export_document_html_and_files(env, seeded, tmp_path):
    store, incidents, run = seeded
    doc = build_export(store, env, incidents)
    assert json.loads(json.dumps(doc)) == doc
    required = {
        "schema_version",
        "generator",
        "generated_at",
        "clock_basis",
        "simulation_notice",
        "scope",
        "methodology",
        "posture",
        "controls",
        "assessments",
        "findings",
        "assets_with_open_findings",
        "unverified",
        "assessment_runs",
        "incidents",
        "manual_reviews",
        "containment_actions",
        "validation",
        "framework_mapping",
        "limitations",
        "reproducibility",
    }
    assert required <= set(doc)
    assert doc["schema_version"] == "2.0" and doc["generator"]["name"] == "SentinelSwitch"
    assert doc["generated_at"] == ts_iso(store.load_twin().now) == run["assessed_at"]
    assert doc["scope"]["switch"]["hostname"] == "SW01" and doc["scope"]["controls_in_scope"] == 13
    assert doc["scope"]["assets_in_scope"] == len(store.devices()) == 36
    assert 999 not in {v["id"] for v in doc["scope"]["vlans"]}
    assert set(doc["methodology"]["states"]) == {"PASS", "FAIL", "UNKNOWN", "STALE"}
    assert len(doc["controls"]) == 13 and len(doc["assessments"]) == run["assessments"]
    for a in doc["assessments"]:
        assert isinstance(a["evidence"], list) and a["evidence"]
        assert all({"source", "ref", "collected_at", "detail"} <= set(e) for e in a["evidence"])
        mapping = a["framework"]["nist_csf_2_0"]
        assert [m["id"] for m in mapping] == CONTROLS_BY_ID[a["control_id"]].csf
        assert all(m["text"] == CSF[m["id"]] for m in mapping)
    post = doc["posture"]
    assert post["totals"] == summary(store, env)["totals"]
    assert post["findings_open"] == BASELINE_FINDINGS and post["findings_closed"] == 0
    assert post["findings_by_status"] == {"open": BASELINE_FINDINGS}
    assert not {"findings", "assets_with_open_findings", "unverified", "recent_runs", "last_run"} & set(post)
    assert len(doc["findings"]) == BASELINE_FINDINGS and all(
        f["events"][0]["event"] == "opened" for f in doc["findings"]
    )
    assert {u["id"] for u in doc["unverified"]} == {"ASM-ENDPOINT-IDENTITY-Gi1-0-30", "ASM-TELEMETRY-FRESH-suricata"}
    assert [r["run_id"] for r in doc["assessment_runs"]] == [run["run_id"]]
    assert {i["incident"]["id"] for i in doc["incidents"]} == set(HISTORICAL)
    for item in doc["incidents"]:
        assert set(BUNDLE_FILES) <= set(item["evidence_bundle"]["present"]) and item["timeline"] and item["actions"]
    assert len(doc["manual_reviews"]) == 5
    assert all("attribution" not in r and "timeline" not in r for r in doc["manual_reviews"])
    assert len(doc["containment_actions"]) == 3 and all(a["authorization"] for a in doc["containment_actions"])
    assert doc["framework_mapping"]["framework"] == "NIST CSF 2.0"
    assert doc["framework_mapping"]["subcategories"] == summary(store, env)["csf"]
    assert doc["reproducibility"]["deterministic"] is True and len(doc["limitations"]) >= 4

    html = render_html(doc)
    for heading in HTML_SECTIONS:
        assert f"<h2>{heading}</h2>" in html
    assert html.count("<h2>") == 10
    assert "Scope and simulation disclaimer" in html and "No real network was assessed." in html
    assert "FND-UNUSED-PORTS-Gi1-0-41" in html and "ASM-TELEMETRY-FRESH-suricata" in html
    assert "wall clock" not in html  # exports carry only simulated-clock timestamps and are byte-reproducible
    assert "MKT-WS-022 loaner" in html and "<h3>Verified / closed findings</h3>" not in html
    for inc in HISTORICAL:
        assert inc in html

    j = write_json(doc, tmp_path / "out" / "security-posture-report.json")
    h = write_html(doc, tmp_path / "out" / "security-posture-report.html")
    assert j.exists() and h.exists() and j.parent == h.parent == tmp_path / "out"
    assert json.loads(j.read_text(encoding="utf-8")) == doc
    assert h.read_text(encoding="utf-8").startswith("<!doctype html>")


# -------------------------------------------------------------------------------------------------
# 10. Deterministic end-to-end workflow
# -------------------------------------------------------------------------------------------------
def _workflow(env, root: Path) -> tuple[Store, dict, dict]:
    store, incidents, baseline = _seed(env, root)
    settings = Settings(
        db_path=root / "t.db",
        data_dir=ROOT / "data",
        incidents_dir=incidents,
        artifacts_dir=root / "artifacts",
        frontend_dist=Path("/nonexistent"),
    )
    flag = demo_service.run_flagship(store, env, settings)
    assert flag.passed and flag.incident["id"] == FLAGSHIP and flag.incident["status"] == "contained"
    assert flag.incident["authorization"]["mode"] == "automatic"
    post = store.assessment_run(flag.metrics["assessment_run"])
    # Three incident-scoped PASS rows join the baseline: authorization, verified quarantine, evidence bundle.
    assert post["trigger"] == "post-containment"
    assert post["counts"] == {**BASELINE_COUNTS, "PASS": BASELINE_COUNTS["PASS"] + 3}
    assert post["assessments"] == BASELINE_TOTAL + 3 and post["retired"] == 0
    assert store.assessment(f"ASM-QUARANTINE-VERIFIED-{FLAGSHIP}")["status"] == "PASS"
    assert store.assessment(f"ASM-RESPONSE-AUTHORIZED-{FLAGSHIP}")["status"] == "PASS"
    assert store.assessment(f"ASM-EVIDENCE-COMPLETE-{FLAGSHIP}")["status"] == "PASS"
    vlan_intent = store.assessment("ASM-VLAN-INTENT-Gi1-0-23")
    assert vlan_intent["status"] == "PASS" and "quarantined by WF-2026-0042" in vlan_intent["observed"]
    assert vlan_intent["related_incidents"] == [FLAGSHIP]

    engine = AssessmentEngine(env, store, incidents)
    svc = RemediationService(env, store, engine)
    queue = [
        f["id"]
        for f in store.findings()
        if f["status"] in FINDING_OPEN_STATES and (f.get("remediation") or {}).get("action")
    ]
    assert len(queue) == BASELINE_FINDINGS
    outcomes: dict[str, str] = {}
    for fid in queue:
        current = store.finding(fid)
        if current["status"] not in FINDING_OPEN_STATES:
            outcomes[fid] = f"already {current['status']}"
            continue
        outcomes[fid] = svc.remediate(fid, actor="tlee", note="workflow remediation")["finding"]["status"]
    assert outcomes == {
        "FND-CONFIG-BASELINE-Gi1-0-22": "verified",
        "FND-CONFIG-BASELINE-Gi1-0-35": "verified",
        "FND-ENDPOINT-IDENTITY-Gi1-0-30": "verified",
        "FND-SENSOR-COVERAGE-vlan-50": "verified",
        "FND-UNUSED-PORTS-Gi1-0-41": "verified",
    }

    restored = demo_service.restore_incident(
        store, env, FLAGSHIP, actor="tlee", note="Endpoint re-imaged", settings=settings
    )
    assert restored["incident"]["status"] == "resolved" and restored["action"]["status"] == "restored"
    assert restored["assessment_run"]["trigger"] == f"recovery-{FLAGSHIP}"
    # The quarantine-verification row of the now-resolved incident is retired, never silently kept as a PASS.
    assert restored["assessment_run"]["retired"] == 1
    retired = store.assessment(f"ASM-QUARANTINE-VERIFIED-{FLAGSHIP}")
    assert retired["status"] == "RETIRED" and retired["retired_by_run"] == restored["assessment_run"]["run_id"]
    assert store.assessment_history(assessment_id=retired["id"])[-1]["status"] == "RETIRED"
    twin = store.load_twin()
    gi23 = twin.interfaces["Gi1/0/23"]
    assert gi23.access_vlan == 20 and not gi23.quarantined and not gi23.hold
    assert store.assessment(f"ASM-RECOVERY-VERIFIED-{FLAGSHIP}")["status"] == "PASS"
    assert demo_service.demo_status(store)["stage"] == "restored"
    return store, build_export(store, env, incidents), summary(store, env)


def _fingerprint(doc: dict) -> dict:
    return {
        "assessments": [
            (a["id"], a["status"], a["severity"], a["assessed_at"], a["run_id"]) for a in doc["assessments"]
        ],
        "findings": [
            (f["id"], f["status"], f["occurrences"], f["resolved_at"], [(e["ts"], e["event"]) for e in f["events"]])
            for f in doc["findings"]
        ],
        "runs": [(r["run_id"], r["counts"]) for r in doc["assessment_runs"]],
        "actions": [
            (a["workflow_id"], a["status"], a["applied_at"], a["restored_at"]) for a in doc["containment_actions"]
        ],
        "totals": doc["posture"]["totals"],
        "generated_at": doc["generated_at"],
    }


def test_deterministic_workflow_reaches_zero_fail_zero_stale(env, tmp_path, seed_ready):
    store, doc, posture = _workflow(env, tmp_path / "a")
    t = posture["totals"]
    assert t["fail"] == 0 and t["stale"] == 0 and t["unknown"] == 1 and t["retired"] == 1
    assert t["assessments"] == BASELINE_TOTAL + 3  # retired rows are excluded from every total
    assert t["determinate"] == t["pass"] and t["pass_rate_of_determinate_pct"] == 100.0
    assert t["coverage_pct"] == round(100 * t["determinate"] / t["assessments"], 1) < 100.0
    assert posture["findings"]["by_status"] == {"verified": BASELINE_FINDINGS}
    assert posture["findings"]["open"] == 0 and posture["findings"]["closed"] == BASELINE_FINDINGS
    assert posture["assets_with_open_findings"] == []
    assert {u["id"] for u in posture["unverified"]} == {"ASM-TELEMETRY-FRESH-suricata"}
    assert posture["incidents"] == {"total": 4, "open": 0, "resolved": 4}
    assert posture["runs"] == 8  # baseline + post-containment + 5 remediations + recovery
    statuses = {c["control_id"]: c["status"] for c in posture["by_control"]}
    assert set(statuses.values()) == {"PASS", "UNKNOWN", "NOT_ASSESSED"}
    assert statuses["CTL-QUARANTINE-VERIFIED"] == "NOT_ASSESSED"  # nothing is contained once the incident is resolved
    assert statuses["CTL-TELEMETRY-FRESH"] == "UNKNOWN"
    assert all(f["verification"]["outcome"] == "PASS" for f in store.findings())
    assert sum(1 for f in store.findings() if f["verification"]["after_remediation"]) == BASELINE_FINDINGS
    assert doc["posture"]["findings_by_status"] == {"verified": BASELINE_FINDINGS}
    assert sum(1 for a in doc["assessments"] if a["status"] == "RETIRED") == 1  # exported with its status, not hidden
    html = render_html(doc)
    assert "<p>No open findings.</p>" in html and "<h3>Verified / closed findings</h3>" in html
    assert "<p>No outstanding remediation.</p>" in html

    # The same workflow in a second isolated store produces identical records on the simulated clock.
    _, doc_b, _ = _workflow(env, tmp_path / "b")
    assert _fingerprint(doc_b) == _fingerprint(doc)


# -------------------------------------------------------------------------------------------------
# 11. Lifecycle edges: verification failure, scope retirement, trust-boundary remediation
# -------------------------------------------------------------------------------------------------
def test_remediation_that_does_not_hold_is_recorded_as_verification_failed(seeded, engine, remediation):
    store, _, _ = seeded
    fid = "FND-CONFIG-BASELINE-Gi1-0-22"
    res = remediation.remediate(fid, actor="tlee", note="re-apply the template", reassess=False)
    assert res["executed"] is True and store.finding(fid)["status"] == "remediated"
    # An executed remediation that has not been verified yet cannot be requested again.
    with pytest.raises(RemediationError, match="in progress"):
        remediation.remediate(fid, actor="tlee")
    # The drift comes back before the next assessment run.
    twin = store.load_twin()
    twin.apply_drift([{"interface": "Gi1/0/22", "setting": "description", "observed": "MKT-WS-022 loaner"}])
    store.save_twin(twin)
    run = engine.run("drift-returned", at=add_seconds(twin.now, 30))
    f = store.finding(fid)
    assert f["status"] == "remediation_failed"
    assert f["verification"] == {
        "outcome": "FAIL",
        "at": run["assessed_at"],
        "run_id": run["run_id"],
        "after_remediation": True,
    }
    assert _events(store, fid)[-1] == "verification_failed"
    assert store.finding_events(fid)[-1]["actor"] == "sentinel-assurance"
    assert fid in {x["id"] for x in store.findings() if x["status"] in FINDING_OPEN_STATES}


def test_retired_scope_closes_its_open_finding_and_leaves_the_totals(env, seeded, engine, monkeypatch):
    store, incidents, _ = seeded
    monkeypatch.setattr(
        SimulatedCisco2960XAdapter,
        "verify_vlan",
        lambda self, interface, vlan: (False, "simulated read-back mismatch"),
    )
    twin = SwitchTwin.baseline(env)
    result = ScenarioRunner(env, twin, evidence_root=incidents, incident_seq=41).run(env.flagship(), "day")
    store.put_incident(result.incident)
    store.put_action(result.action.to_dict())
    store.put_timeline(FLAGSHIP, result.timeline)
    store.save_twin(twin)
    engine.run("post-failure")
    fid = f"FND-QUARANTINE-VERIFIED-{FLAGSHIP}"
    assert store.finding(fid)["status"] == "open"

    # The incident is closed out, so the quarantine-verification scope no longer exists.
    inc = store.incident(FLAGSHIP)
    inc["status"] = "resolved"
    store.put_incident(inc)
    run = engine.run("incident-closed")
    assert run["retired"] == 1
    a = store.assessment(f"ASM-QUARANTINE-VERIFIED-{FLAGSHIP}")
    assert a["status"] == "RETIRED" and a["retired_by_run"] == run["run_id"]
    assert store.assessment_history(assessment_id=a["id"])[-1]["status"] == "RETIRED"
    f = store.finding(fid)
    assert f["status"] == "closed" and f["resolved_at"] == run["assessed_at"]
    assert f["verification"]["outcome"] is None  # closed, never verified
    assert _events(store, fid) == ["opened", "scope_retired"]
    assert fid not in {x["id"] for x in store.findings() if x["status"] in FINDING_OPEN_STATES}
    with pytest.raises(RemediationError, match="already closed"):
        RemediationService(env, store, engine).remediate(fid, actor="tlee")
    t = summary(store, env)["totals"]
    assert t["retired"] == 1 and t["assessments"] == run["assessments"]
    assert t["pass"] + t["fail"] + t["unknown"] + t["stale"] == t["assessments"]


def test_trust_boundary_violation_is_remediated_through_the_adapter(seeded, engine, remediation):
    store, _, _ = seeded
    twin = store.load_twin()
    twin.interfaces["Gi1/0/22"].settings["dai_trust"] = True
    store.save_twin(twin)
    engine.run("trust-drift", at=add_seconds(twin.now, 30))
    a = store.assessment("ASM-TRUST-BOUNDARY-trust-boundary")
    assert a["status"] == "FAIL"
    assert a["remediation"]["action"] == {"type": "fix_trust", "extra": ["Gi1/0/22"], "missing": []}
    # One deviation, one finding: the configuration-baseline row for Gi1/0/22 does not also claim it.
    assert "dai_trust" not in (store.assessment("ASM-CONFIG-BASELINE-Gi1-0-22")["observed"] or {})
    res = remediation.remediate("FND-TRUST-BOUNDARY-trust-boundary", actor="tlee")
    assert res["executed"] is True and res["finding"]["status"] == "verified"
    assert not store.load_twin().interfaces["Gi1/0/22"].settings.get("dai_trust")
    assert store.assessment("ASM-TRUST-BOUNDARY-trust-boundary")["status"] == "PASS"
