import json

from sentinelswitch.simulator.scenario import ScenarioRunner
from sentinelswitch.simulator.twin import SwitchTwin
from sentinelswitch.validation.harness import run_validation


def test_validation_all_pass(env):
    report = run_validation(env)
    assert report.all_passed
    assert report.metrics["scenarios"] == 9 and report.metrics["passed"] == 9
    assert 0 < report.metrics["mtta"] < report.metrics["mttc"] < report.metrics["mttd"]
    names = [r["name"] for r in report.results]
    assert names == [
        "Unauthorized Endpoint",
        "ARP Spoofing Attempt",
        "Rogue DHCP",
        "MAC Address Change",
        "Port Scan",
        "DNS Anomaly",
        "Lateral Reconnaissance",
        "STP/BPDU Violation",
        "Critical Asset Scan",
    ]
    mechanisms = {r["scenario_id"]: r["mechanism"] for r in report.results}
    assert "BPDU Guard" in mechanisms["bpdu-violation"]
    assert mechanisms["lateral-reconnaissance"].startswith("SentinelSwitch VLAN reassignment")
    # The negative path: high confidence on a critical asset is withheld from automation by the guard.
    negative = next(r for r in report.results if r["scenario_id"] == "critical-asset-scan")
    assert negative["expected"]["disposition"] == "manual_review" and negative["action"] == "none"
    assert negative["ttc"] is None
    assert "critical_assets" in negative["guards"]
    # A validated safety decision is reported as withheld, never as a containment.
    assert negative["response"] == "withheld" and negative["post_state"]["access_vlan"] == 30
    assert {r["response"] for r in report.results if r["scenario_id"] != "critical-asset-scan"} == {"contained"}
    assert report.metrics["contained"] == 8 and report.metrics["withheld"] == 1


def test_flagship_evidence_bundle(env, tmp_path):
    twin = SwitchTwin.baseline(env)
    runner = ScenarioRunner(env, twin, evidence_root=tmp_path, incident_seq=41)
    result = runner.run(env.flagship(), "day")
    assert result.passed and result.incident["id"] == "INC-2026-0042"
    d = tmp_path / "INC-2026-0042"
    expected = {
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
    }
    assert expected <= {p.name for p in d.iterdir()}
    inc = json.loads((d / "incident.json").read_text())
    assert inc["original_vlan"] == 20 and inc["current_vlan"] == 50 and inc["interface"] == "Gi1/0/23"
    assert inc["chain"] == ["10.20.0.47", "A4:83:E7:12:34:56", "SW01", "Gi1/0/23", "VLAN 20", "VLAN 50"]
    port = json.loads((d / "switch-port.json").read_text())
    assert "Access Mode VLAN: 50 (QUARANTINE)" in port["after"]["show_switchport"]
    cont = json.loads((d / "containment.json").read_text())
    assert cont["action"]["status"] == "verified" and cont["decision"]["disposition"] == "automatic_containment"
    tl = json.loads((d / "timeline.json").read_text())
    assert [t["ts"] for t in tl] == sorted(t["ts"] for t in tl)
    assert any(t["phase"] == "containment" for t in tl) and any(t["phase"] == "verification" for t in tl)
    readme = (d / "README.md").read_text()
    assert "INC-2026-0042" in readme and "Simulated lab telemetry" in readme
    assert result.metrics["ttd"] == 8.583 and result.metrics["tta"] == 0.572 and result.metrics["ttc"] == 1.258


def test_flagship_is_deterministic(env):
    a = ScenarioRunner(env, SwitchTwin.baseline(env), incident_seq=41).run(env.flagship(), "day", write_evidence=False)
    b = ScenarioRunner(env, SwitchTwin.baseline(env), incident_seq=41).run(env.flagship(), "day", write_evidence=False)
    assert a.timeline == b.timeline and a.metrics == b.metrics


def test_manual_review_instances_do_not_change_switch(env):
    twin = SwitchTwin.baseline(env)
    keys = ("access_vlan", "oper_vlan", "admin_status", "oper_status", "quarantined", "hold", "auth_state")
    before = {k: getattr(twin.interfaces["Gi1/0/14"], k) for k in keys}
    r = ScenarioRunner(env, twin).run(env.scenarios["dns-anomaly"], "day", write_evidence=False)
    assert r.decision.disposition == "manual_review" and r.review is not None and r.incident is None
    assert {k: getattr(twin.interfaces["Gi1/0/14"], k) for k in keys} == before
    assert not twin.config_changes
    assert r.checks["contain"]


def test_bpdu_native_errdisable_then_hold(env):
    twin = SwitchTwin.baseline(env)
    r = ScenarioRunner(env, twin).run(env.scenarios["bpdu-violation"], "validation", write_evidence=False)
    i = twin.interfaces["Gi1/0/30"]
    assert i.errdisable_reason == "bpduguard" and i.admin_status == "down" and i.hold
    assert "err-disable" in r.action.mechanism
