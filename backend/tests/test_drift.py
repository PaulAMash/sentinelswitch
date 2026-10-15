from sentinelswitch.drift.engine import DriftEngine
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import parse_ts


def test_drift_findings(env, twin):
    report = DriftEngine(env).evaluate(twin)
    found = {(f["interface"], f["setting"]): f for f in report["findings"]}
    assert ("Gi1/0/41", "admin_status") in found and found[("Gi1/0/41", "admin_status")]["severity"] == "medium"
    assert ("Gi1/0/35", "storm_control") in found and found[("Gi1/0/35", "storm_control")]["severity"] == "low"
    assert ("Gi1/0/22", "description") in found and found[("Gi1/0/22", "description")]["severity"] == "info"
    # The fourth deviation is global: VLAN 50 is missing from the SPAN session the intent declares.
    assert (None, "span_session") in found and found[(None, "span_session")]["severity"] == "high"
    assert found[(None, "span_session")]["observed"]["source_vlans"] == [20, 30, 40]
    assert found[(None, "span_session")]["expected"]["source_vlans"] == [20, 30, 40, 50]
    assert report["open"] == 4 and report["approved"] == 0
    assert "shutdown" in found[("Gi1/0/41", "admin_status")]["recommendation"]


def test_no_drift_on_pristine_twin(env):
    clean = SwitchTwin.baseline(env, apply_drift=False)
    report = DriftEngine(env).evaluate(clean)
    assert report["findings"] == [] and report["compliant_interfaces"] == 50


def test_quarantine_is_an_approved_deviation(env, twin):
    twin.quarantine("Gi1/0/23", 50, reason="x", workflow="WF-1", at=parse_ts("2026-03-17T21:14:41Z"))
    report = DriftEngine(env).evaluate(twin)
    f = next(f for f in report["findings"] if f["interface"] == "Gi1/0/23")
    assert f["status"] == "approved" and f["setting"] == "access_vlan" and f["observed"] == 50
    assert report["approved"] == 1 and report["open"] == 4
