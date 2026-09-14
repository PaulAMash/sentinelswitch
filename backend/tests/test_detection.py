from sentinelswitch.detection.engine import DetectionEngine, load_rules
from sentinelswitch.detection.normalize import normalize
from sentinelswitch.detection.suricata_rules import load_rules as load_suricata
from simulator.canonical import load_environment


def _alert(ts, sid, src="10.20.0.31", dest="10.30.0.10", port=445):
    rule = load_suricata()[sid]
    return normalize(
        load_environment(),
        "suricata",
        {
            "timestamp": ts,
            "_ts_iso": ts,
            "src_ip": src,
            "src_port": 51000,
            "dest_ip": dest,
            "dest_port": port,
            "proto": "TCP",
            "alert": {"signature_id": sid, "signature": rule.msg, "category": rule.category, "severity": rule.severity},
        },
    )


def test_rules_load():
    rules = load_rules()
    assert {
        "lateral-reconnaissance",
        "port-scan",
        "dns-anomaly",
        "arp-spoofing",
        "rogue-dhcp",
        "mac-address-change",
        "unauthorized-endpoint",
        "bpdu-violation",
    } <= set(rules)
    for r in rules.values():
        assert 0 < r.base_confidence < 1
        assert r.actor_key in {"actor_ip", "src_ip", "mac", "interface"}


def test_suricata_rules_parse():
    rules = load_suricata()
    assert rules[1000021].severity == 1 and rules[1000021].sentinel_class == "lateral"
    assert rules[1000031].track == "by_dst"
    assert rules[1000050].sentinel_severity == "low"


def test_lateral_scoring_and_window(env):
    engine = DetectionEngine(env, latency_by_rule={"lateral-reconnaissance": 0.169})
    events = [
        _alert("2026-03-17T21:14:33.507Z", 1000010),
        _alert("2026-03-17T21:14:36.108Z", 1000014, port=53),
        _alert("2026-03-17T21:14:38.198Z", 1000021),
        normalize(
            env,
            "zeek",
            {
                "ts": 0,
                "_ts_iso": "2026-03-17T21:14:39.649Z",
                "note": "Scan::Address_Scan",
                "msg": "10.20.0.31 scanned at least 15 unique hosts on port 445/tcp in 0m2s",
                "sub": "",
                "src": "10.20.0.31",
                "p": 445,
            },
        ),
    ]
    dets = [d for d in engine.evaluate(events) if d.rule.id == "lateral-reconnaissance"]
    assert len(dets) == 1
    d = dets[0]
    assert d.confidence == 0.97 and d.severity == "high"
    assert d.ts == "2026-03-17T21:14:39.867Z"  # trigger 38.198 + 1.5 s window + 0.169 s latency
    assert {f.id for f in d.features if f.matched} == {"zeek_address_scan", "prior_icmp_sweep", "ptr_burst"}


def test_authorized_scanner_reduces_confidence(env):
    engine = DetectionEngine(env)
    events = [
        _alert("2026-03-17T13:05:12.955Z", 1000011, src="10.20.0.48", dest="10.30.0.30", port=80),
        normalize(
            env,
            "zeek",
            {
                "ts": 0,
                "_ts_iso": "2026-03-17T13:05:11.009Z",
                "note": "Scan::Port_Scan",
                "msg": "10.20.0.48 scanned at least 100 unique ports of host 10.30.0.10 in 0m0s",
                "sub": "",
                "src": "10.20.0.48",
                "dst": "10.30.0.10",
            },
        ),
    ]
    d = [d for d in engine.evaluate(events) if d.rule.id == "port-scan"][0]
    assert d.confidence == 0.61 and d.severity == "medium"
    assert any(f.id == "authorized_scanner" and f.matched for f in d.features)
    # Same evidence from a non-scanner host
    events2 = [
        _alert("2026-03-17T13:05:12.955Z", 1000011, src="10.20.0.31", dest="10.30.0.30", port=80),
        normalize(
            env,
            "zeek",
            {
                "ts": 0,
                "_ts_iso": "2026-03-17T13:05:11.009Z",
                "note": "Scan::Port_Scan",
                "msg": "10.20.0.31 scanned at least 100 unique ports of host 10.30.0.10 in 0m0s",
                "sub": "",
                "src": "10.20.0.31",
                "dst": "10.30.0.10",
            },
        ),
    ]
    d2 = [d for d in engine.evaluate(events2) if d.rule.id == "port-scan"][0]
    assert d2.confidence == 0.96 and d2.severity == "high"


def test_confidence_is_clamped_and_deduplicated(env):
    engine = DetectionEngine(env)
    events = []
    for i in range(30):
        events.append(
            normalize(
                env,
                "syslog",
                {
                    "ts": f"2026-03-17T10:27:{18 + i // 5:02d}.{(i % 5) * 200:03d}Z",
                    "facility": "SW_DAI",
                    "severity": 4,
                    "mnemonic": "DHCP_SNOOPING_DENY",
                    "message": "1 Invalid ARPs (Res) on Gi1/0/29, vlan 40.([f018.98c4.2901/10.40.0.1/0000.0000.0000/0.0.0.0/10:27:18 UTC Tue Mar 17 2026])",
                },
            )
        )
    dets = [d for d in engine.evaluate(events) if d.rule.id == "arp-spoofing"]
    assert len(dets) == 1 and dets[0].confidence == 0.99 and dets[0].severity == "high"
    assert dets[0].actor_value == "F0:18:98:C4:29:01"
    assert events[0]["claims_gateway"] is True


def test_emit_threshold_filters_low_value_detections(env):
    engine = DetectionEngine(env)
    ev = normalize(
        env,
        "radius",
        {
            "timestamp": "2026-03-17T08:03:41.207Z",
            "username": "hlindqvist",
            "identity": "x",
            "calling_station_id": "B4-B5-2F-1C-22-32",
            "nas_port_id": "GigabitEthernet1/0/22",
            "result": "Access-Reject",
            "method": "EAP-TLS",
            "reason": "certificate expired",
        },
    )
    ids = [d.rule.id for d in engine.evaluate([ev])]
    assert "certificate-failure" in ids and "auth-failure-burst" not in ids
