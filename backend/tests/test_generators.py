import json

from simulator.generators.scenarios import emit
from simulator.generators.traffic import TrafficModel


def test_scenario_emitters_are_deterministic(env):
    for sid, sc in env.scenarios.items():
        a = emit(env, sc, "validation")
        b = emit(env, sc, "validation")
        assert json.dumps(a.records, sort_keys=True) == json.dumps(b.records, sort_keys=True), sid
        assert [f.__dict__ for f in a.flows] == [f.__dict__ for f in b.flows], sid


def test_flagship_alert_timing_is_derived_from_traffic(env):
    out = emit(env, env.flagship(), "day")
    d = out.derived
    assert (
        d["icmp_sweep_alert"]
        < d["ptr_burst_alert"]
        < d["smb_fanout_alert"]
        < d["rdp_fanout_alert"]
        < d["zeek_address_scan"]
    )
    sids = [raw["alert"]["signature_id"] for src, raw in out.records if src == "suricata"]
    assert sids.count(1000021) == 1 and 1000010 in sids and 1000022 in sids
    assert all(f.orig_h == "10.20.0.47" for f in out.flows)


def test_background_traffic_uses_private_and_documentation_ranges_only(env):
    model = TrafficModel(env)
    model.generate_all([])
    for f in model.flows[:3000]:
        for ip in (f.orig_h, f.resp_h):
            assert ip.startswith(("10.", "192.0.2.", "198.51.100.", "203.0.113.", "0.0.0.0", "255.")), ip
    assert len(model.flows) > 3000
