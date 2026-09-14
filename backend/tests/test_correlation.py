from sentinelswitch.correlation.engine import Clock, CorrelationEngine
from sentinelswitch.simulator.twin import DhcpBinding, MacObservation
from simulator.canonical import add_seconds, parse_ts, ts_iso


def test_ip_to_mac_to_port_chain(env, twin):
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    assert a.mac == "A4:83:E7:12:34:56"
    assert a.interface == "Gi1/0/23" and a.vlan == 20 and a.switch == "SW01"
    assert a.device == "ENG-LT-047" and a.user == "jchen" and a.department == "Engineering"
    assert a.resolved and a.confidence == 1.0 and a.flags == []
    assert a.chain == ["10.20.0.47", "A4:83:E7:12:34:56", "SW01", "Gi1/0/23", "VLAN 20"]
    assert [s.status for s in a.steps] == ["resolved", "resolved", "resolved", "resolved"]


def test_mac_to_interface(env, twin):
    a = CorrelationEngine(env, twin).resolve(mac="3c:d9:2b:8e:16:26")
    assert a.interface == "Gi1/0/16" and a.ip == "10.20.0.26" and a.device == "HR-WS-016"


def test_unknown_mac_with_aaa_interface_hint(env, twin):
    twin.attach("DC:A6:32:19:77:C1", "Gi1/0/17", 20, auth_state="unauthorized")
    a = CorrelationEngine(env, twin).resolve(
        mac="DC:A6:32:19:77:C1", interface="Gi1/0/17", hints={"interface_source": "RADIUS NAS-Port-Id"}
    )
    assert a.interface == "Gi1/0/17" and a.device is None
    assert "unknown_device" in a.flags and "mac_not_learned" in a.flags and "no_binding" in a.flags
    assert a.resolved  # a physical port was still identified
    assert a.vendor == "Raspberry Pi Foundation"


def test_expired_binding_is_flagged(env, twin):
    b = twin.find_binding_by_ip("10.20.0.47")
    b.lease_expires = ts_iso(add_seconds(twin.now, -60))
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.47")
    assert "expired_binding" in a.flags and a.confidence < 1.0
    assert a.interface == "Gi1/0/23"


def test_missing_data(env, twin):
    a = CorrelationEngine(env, twin).resolve(ip="10.20.0.199")
    assert not a.resolved and a.interface is None and "unresolved" in a.flags
    assert any(s.status == "missing" for s in a.steps)


def test_static_host_inventory_fallback_and_protected_trunk(env, twin):
    a = CorrelationEngine(env, twin).resolve(ip="10.10.10.1")
    assert a.mac == "AC:1F:6B:0A:11:01" and "static_inventory_fallback" in a.flags
    assert a.interface == "Gi1/0/1" and a.trunk and a.protected
    assert "protected_port" in a.flags and "trunk_interface" in a.flags
    assert not a.resolved  # trunks never resolve to a single endpoint


def test_multiple_observations_and_mac_movement(env, twin):
    mac = "A4:83:E7:2B:35:45"
    now = twin.now
    twin.mac_table = [e for e in twin.mac_table if e.mac != mac]
    twin._learn(mac, 20, "Gi1/0/35", at=add_seconds(now, -3000))
    twin._learn(mac, 20, "Gi1/0/29", at=add_seconds(now, -600))
    twin.mac_table.append(type(twin.mac_table[0])(mac, 20, "Gi1/0/35", "DYNAMIC", ts_iso(add_seconds(now, -3000))))
    twin.mac_history.append(
        MacObservation(mac, "Gi1/0/29", 20, ts_iso(add_seconds(now, -700)), ts_iso(add_seconds(now, -600)))
    )
    a = CorrelationEngine(env, twin).resolve(mac=mac)
    assert "multiple_observations" in a.flags and "mac_moved" in a.flags
    assert a.interface == "Gi1/0/29"  # most recent entry wins


def test_impersonation_of_server_mac(env, twin):
    server_mac = "AC:1F:6B:3B:09:20"
    twin.attach(server_mac, "Gi1/0/16", 20, auth_state="unauthorized")
    a = CorrelationEngine(env, twin).resolve(mac=server_mac, interface="Gi1/0/16")
    assert a.interface == "Gi1/0/16"
    assert "mac_impersonation" in a.flags and a.impersonated_device == "SRV-FILE01"
    assert a.device is None and a.criticality == "standard"  # port owner's criticality, not the server's


def test_simulated_clock_timestamps_are_monotonic(env, twin):
    clock = Clock(parse_ts("2026-03-17T21:14:39.867Z"))
    a = CorrelationEngine(env, twin, timing={"open": 0.083, "dhcp": 0.142, "mac": 0.254, "identity": 0.093}).resolve(
        ip="10.20.0.47", clock=clock
    )
    stamps = [s.ts for s in a.steps]
    assert stamps == sorted(stamps)
    assert a.completed_at == "2026-03-17T21:14:40.439Z"


def test_bindings_by_mac_static(env, twin):
    b = twin.find_bindings_by_mac("AC:1F:6B:3B:08:10")
    assert b and b[0].binding_type == "static"
    assert isinstance(b[0], DhcpBinding)
