from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import parse_ts


def test_baseline_shape(env, twin):
    assert len(twin.interfaces) == 50
    assert twin.interfaces["Gi1/0/1"].is_trunk and twin.interfaces["Gi1/0/1"].protected
    assert twin.interfaces["Gi1/0/48"].is_trunk and twin.interfaces["Gi1/0/48"].protected
    assert twin.interfaces["Gi1/0/47"].span_destination
    assert twin.interfaces["Gi1/0/23"].access_vlan == 20
    assert twin.interfaces["Gi1/0/23"].oper_status == "connected"
    assert twin.find_binding_by_ip("10.20.0.47").mac == "A4:83:E7:12:34:56"
    # Laptops that left earlier keep an unexpired lease but no MAC-table entry
    assert twin.find_mac("A4:83:E7:2B:07:17") == []
    assert twin.find_bindings_by_mac("A4:83:E7:2B:07:17")


def test_quarantine_changes_state_and_restore_reverts(env, twin):
    at = parse_ts("2026-03-17T21:14:41.000Z")
    res = twin.quarantine("Gi1/0/23", 50, reason="test", workflow="WF-TEST", at=at)
    i = twin.interfaces["Gi1/0/23"]
    assert res["from_vlan"] == 20 and res["to_vlan"] == 50
    assert i.access_vlan == 50 and i.oper_vlan == 50 and i.quarantined and i.original_vlan == 20
    assert all(e.vlan == 50 for e in twin.macs_on_interface("Gi1/0/23"))
    assert twin.find_binding_by_ip("10.20.0.47") is None  # bindings flushed on VLAN change
    assert "Access Mode VLAN: 50 (QUARANTINE)" in cli_render.show_interface_switchport(twin, "Gi1/0/23")
    assert any(c.actor == "sentinel" for c in twin.config_changes)
    assert any(line.mnemonic == "CONFIG_I" for line in twin.log)
    twin.restore("Gi1/0/23", actor="tlee", reason="remediated", at=parse_ts("2026-03-17T22:00:00Z"))
    assert i.access_vlan == 20 and not i.quarantined and i.original_vlan is None


def test_shutdown_hold_and_release(env, twin):
    at = parse_ts("2026-03-17T21:00:00Z")
    twin.shutdown("Gi1/0/17", actor="sentinel", reason="rogue", at=at, hold=True, workflow="WF-X")
    i = twin.interfaces["Gi1/0/17"]
    assert i.admin_status == "down" and i.oper_status == "disabled" and i.hold
    twin.restore("Gi1/0/17", actor="tlee", reason="removed", at=at)
    assert i.admin_status == "up" and not i.hold


def test_serialization_roundtrip(env, twin):
    data = twin.to_dict()
    clone = SwitchTwin.from_dict(env, data)
    assert clone.to_dict() == data
    assert clone.copy().to_dict() == data


def test_lease_renewal_on_advance(env):
    twin = SwitchTwin.baseline(env, now=env.day_start)
    dev = env.device_by_hostname("ENG-LT-047")
    twin.attach(
        dev.mac, dev.interface, dev.vlan, ip=dev.ip, auth=dev.auth, user=dev.user, at=parse_ts("2026-03-17T07:52:00Z")
    )
    b = twin.find_binding_by_ip(dev.ip)
    first_expiry = parse_ts(b.lease_expires)
    twin.advance_to(parse_ts("2026-03-17T21:14:00Z"))
    b = twin.find_binding_by_ip(dev.ip)
    assert parse_ts(b.lease_expires) > first_expiry
    assert parse_ts(b.lease_expires) > twin.now


def test_show_commands_render(env, twin):
    for cmd in cli_render.SHOW_COMMANDS:
        out = cli_render.run_show(twin, cmd)
        assert out and "unsupported" not in out, cmd
    assert "Gi1/0/23" in cli_render.run_show(twin, "show mac address-table address a483.e712.3456")
    assert "Ambiguous" in cli_render.run_show(twin, "show bogus")
    cfg = cli_render.render_running_config(twin)
    assert "hostname SW01" in cfg and "<REDACTED" in cfg and "ip dhcp snooping" in cfg and "monitor session 1" in cfg
    assert "password" not in cfg.lower().replace("service password-encryption", "").replace("password-recovery", "")
