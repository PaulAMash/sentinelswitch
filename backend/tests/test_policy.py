import pytest

from sentinelswitch.containment.policy import PolicyEngine
from sentinelswitch.correlation.engine import CorrelationEngine


@pytest.fixture()
def policy():
    return PolicyEngine()


def test_thresholds(env, twin, policy):
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    assert (
        policy.decide(severity="high", confidence=0.97, klass="compromised_host", attribution=a).disposition
        == "automatic_containment"
    )
    assert (
        policy.decide(severity="high", confidence=0.95, klass="compromised_host", attribution=a).disposition
        == "automatic_containment"
    )
    assert (
        policy.decide(severity="medium", confidence=0.97, klass="compromised_host", attribution=a).disposition
        == "manual_review"
    )
    assert (
        policy.decide(severity="high", confidence=0.80, klass="compromised_host", attribution=a).disposition
        == "manual_review"
    )
    assert (
        policy.decide(severity="high", confidence=0.75, klass="compromised_host", attribution=a).disposition
        == "manual_review"
    )
    assert (
        policy.decide(severity="high", confidence=0.61, klass="compromised_host", attribution=a).disposition
        == "monitor"
    )


def test_action_by_class(env, twin, policy):
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    d = policy.decide(severity="high", confidence=0.97, klass="compromised_host", attribution=a)
    assert d.action == "quarantine_vlan" and d.quarantine_vlan == 50
    d = policy.decide(severity="high", confidence=0.97, klass="rogue_device", attribution=a)
    assert d.action == "port_shutdown"
    d = policy.decide(severity="high", confidence=0.97, klass="identity", attribution=a)
    assert d.disposition == "manual_review" and d.action == "none"


def test_protected_and_trunk_guard(env, twin, policy):
    a = CorrelationEngine(env, twin).resolve(ip="10.10.10.1")
    d = policy.decide(severity="high", confidence=0.99, klass="compromised_host", attribution=a)
    assert d.disposition == "manual_review" and d.action == "none"
    assert "protected_ports" in d.guards_triggered and "trunk_ports" in d.guards_triggered


def test_critical_asset_guard(env, twin, policy):
    a = CorrelationEngine(env, twin).resolve(ip="10.30.0.20")
    assert a.interface == "Gi1/0/9" and a.criticality == "critical"
    d = policy.decide(severity="high", confidence=0.99, klass="compromised_host", attribution=a)
    assert d.disposition == "manual_review" and "critical_assets" in d.guards_triggered


def test_unresolved_guard(env, twin, policy):
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.199")
    d = policy.decide(severity="high", confidence=0.99, klass="compromised_host", attribution=a)
    assert d.disposition == "manual_review" and "unresolved_attribution" in d.guards_triggered
    d = policy.decide(severity="high", confidence=0.99, klass="compromised_host", attribution=None)
    assert d.disposition == "manual_review"
