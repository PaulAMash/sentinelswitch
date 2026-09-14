import pytest

from sentinelswitch.containment.adapters import ProtectedInterfaceError, SimulatedCisco2960XAdapter
from sentinelswitch.containment.controller import ContainmentController
from sentinelswitch.containment.policy import PolicyEngine
from sentinelswitch.correlation.engine import Clock, CorrelationEngine
from simulator.canonical import parse_ts

TIMING = {"apply": 0.415, "verify": 0.125}


def test_quarantine_action_changes_twin_and_verifies(env, twin):
    adapter = SimulatedCisco2960XAdapter(twin)
    ctl = ContainmentController(adapter)
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    d = PolicyEngine().decide(severity="high", confidence=0.97, klass="compromised_host", attribution=a)
    clock = Clock(parse_ts("2026-03-17T21:14:40.585Z"))
    act = ctl.contain(
        decision=d,
        attribution=a,
        detection_id="DET-1",
        summary="test",
        incident_id="INC-2026-0042",
        clock=clock,
        timing=TIMING,
    )
    assert act.status == "verified" and act.verification["ok"]
    assert act.from_vlan == 20 and act.to_vlan == 50
    assert act.applied_at == "2026-03-17T21:14:41.000Z" and act.verified_at == "2026-03-17T21:14:41.125Z"
    assert twin.interfaces["Gi1/0/23"].access_vlan == 50
    assert "switchport access vlan 50" in act.transcript
    assert act.workflow_id.startswith("WF-2026-0042")


def test_rollback(env, twin):
    adapter = SimulatedCisco2960XAdapter(twin)
    ctl = ContainmentController(adapter)
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    d = PolicyEngine().decide(severity="high", confidence=0.97, klass="compromised_host", attribution=a)
    act = ctl.contain(
        decision=d,
        attribution=a,
        detection_id="DET-1",
        summary="test",
        incident_id="INC-X",
        clock=Clock(twin.now),
        timing=TIMING,
    )
    ctl.restore(act, actor="tlee", note="remediated", at=parse_ts("2026-03-17T22:00:00Z"))
    assert act.status == "restored" and act.restored_by == "tlee"
    assert twin.interfaces["Gi1/0/23"].access_vlan == 20 and not twin.interfaces["Gi1/0/23"].quarantined
    assert "switchport access vlan 20" in act.restore_transcript


@pytest.mark.parametrize("iface", ["Gi1/0/1", "Gi1/0/48", "Gi1/0/47"])
def test_adapter_refuses_protected_interfaces(env, twin, iface):
    adapter = SimulatedCisco2960XAdapter(twin)
    with pytest.raises(ProtectedInterfaceError):
        adapter.set_access_vlan(iface, 50, reason="x", workflow="WF", at=twin.now)
    with pytest.raises(ProtectedInterfaceError):
        adapter.shutdown(iface, reason="x", workflow="WF", at=twin.now)
    assert twin.interfaces[iface].oper_status in {"connected", "monitoring"}


def test_controller_never_quarantines_protected_even_if_forced(env, twin):
    """Even with a hand-built automatic decision the adapter guard refuses infrastructure ports."""
    from sentinelswitch.containment.policy import Decision

    adapter = SimulatedCisco2960XAdapter(twin)
    ctl = ContainmentController(adapter)
    a = CorrelationEngine(env, twin).resolve(ip="10.10.10.1")
    forced = Decision(
        disposition="automatic_containment", action="quarantine_vlan", reason="forced", quarantine_vlan=50
    )
    act = ctl.contain(
        decision=forced,
        attribution=a,
        detection_id="DET-1",
        summary="x",
        incident_id=None,
        clock=Clock(twin.now),
        timing=TIMING,
    )
    assert act.status == "refused"
    assert twin.interfaces["Gi1/0/1"].is_trunk and twin.interfaces["Gi1/0/1"].oper_status == "connected"


def test_shutdown_action(env, twin):
    twin.attach("DC:A6:32:19:77:C1", "Gi1/0/17", 20, auth_state="unauthorized")
    adapter = SimulatedCisco2960XAdapter(twin)
    ctl = ContainmentController(adapter)
    a = CorrelationEngine(env, twin).resolve(mac="DC:A6:32:19:77:C1", interface="Gi1/0/17")
    d = PolicyEngine().decide(severity="high", confidence=0.96, klass="rogue_device", attribution=a)
    act = ctl.contain(
        decision=d,
        attribution=a,
        detection_id="DET-2",
        summary="rogue",
        incident_id="INC-Y",
        clock=Clock(twin.now),
        timing=TIMING,
    )
    assert act.action == "port_shutdown" and act.status == "verified"
    assert twin.interfaces["Gi1/0/17"].admin_status == "down" and twin.interfaces["Gi1/0/17"].hold


def test_manual_review_does_not_touch_switch(env, twin):
    adapter = SimulatedCisco2960XAdapter(twin)
    ctl = ContainmentController(adapter)
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    d = PolicyEngine().decide(severity="medium", confidence=0.80, klass="compromised_host", attribution=a)
    before = twin.to_dict()
    act = ctl.contain(
        decision=d,
        attribution=a,
        detection_id="DET-3",
        summary="x",
        incident_id=None,
        clock=Clock(twin.now),
        timing=TIMING,
    )
    assert act.status == "not_applicable"
    assert twin.to_dict() == before
