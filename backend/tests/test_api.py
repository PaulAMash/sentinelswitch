def test_meta_and_overview(api_client):
    meta = api_client.get("/api/meta").json()
    assert meta["simulation"] is True and meta["switch"]["hostname"] == "SW01"
    kpis = api_client.get("/api/overview").json()["kpis"]
    assert kpis["devices_total"] == 36 and kpis["quarantined_hosts"] == 0
    assert kpis["validation_passed"] == 8


def test_alerts_incidents_devices(api_client):
    alerts = api_client.get("/api/alerts?severity=high").json()
    assert alerts and all(a["severity"] == "high" for a in alerts)
    incidents = api_client.get("/api/incidents").json()
    assert {i["id"] for i in incidents} == {"INC-2026-0039", "INC-2026-0040", "INC-2026-0041"}
    detail = api_client.get("/api/incidents/INC-2026-0040").json()
    assert detail["incident"]["interface"] == "Gi1/0/17" and detail["timeline"]
    assert api_client.get("/api/incidents/NOPE").status_code == 404
    dev = api_client.get("/api/devices/ENG-LT-047").json()
    assert dev["device"]["ip"] == "10.20.0.47" and dev["interface"]["name"] == "Gi1/0/23"
    devices = api_client.get("/api/devices").json()["devices"]
    assert sum(1 for d in devices if d["online"]) >= 25


def test_switch_endpoints(api_client):
    sw = api_client.get("/api/switch").json()
    assert len(sw["interfaces"]) == 50
    gi23 = next(i for i in sw["interfaces"] if i["name"] == "Gi1/0/23")
    assert gi23["state"] == "connected" and gi23["access_vlan"] == 20
    out = api_client.get("/api/switch/show", params={"cmd": "show interfaces Gi1/0/23 switchport"}).text
    assert "Access Mode VLAN: 20 (USERS)" in out
    assert api_client.get("/api/switch/show", params={"cmd": "configure terminal"}).status_code == 400
    one = api_client.get("/api/switch/interfaces/Gi1/0/1").json()
    assert one["interface"]["protected"] and one["interface"]["state"] == "trunk"


def test_demo_run_restore_reset(api_client):
    assert api_client.get("/api/demo/status").json()["stage"] == "baseline"
    r = api_client.post("/api/demo/run")
    assert r.status_code == 200
    body = r.json()
    assert body["incident"]["id"] == "INC-2026-0042" and body["checks"] == {
        "detect": True,
        "attribute": True,
        "contain": True,
    }
    sw = api_client.get("/api/switch").json()
    gi23 = next(i for i in sw["interfaces"] if i["name"] == "Gi1/0/23")
    assert gi23["state"] == "quarantined" and gi23["access_vlan"] == 50
    assert api_client.get("/api/overview").json()["kpis"]["quarantined_hosts"] == 1
    assert api_client.post("/api/demo/run").status_code == 409
    detail = api_client.get("/api/incidents/INC-2026-0042").json()
    assert detail["incident"]["chain"][-1] == "VLAN 50" and len(detail["evidence"]["files"]) == 11
    assert "Access Mode VLAN: 50 (QUARANTINE)" in detail["verification"]["switchport"]
    ev = api_client.get("/api/incidents/INC-2026-0042/evidence/containment.json").json()
    assert ev["action"]["status"] == "verified"
    drift = api_client.get("/api/drift").json()
    assert drift["approved"] == 1
    r = api_client.post("/api/incidents/INC-2026-0042/restore", json={"actor": "tlee", "note": "re-imaged"})
    assert r.status_code == 200 and r.json()["incident"]["status"] == "resolved"
    assert api_client.get("/api/overview").json()["kpis"]["quarantined_hosts"] == 0
    assert api_client.post("/api/demo/reset").status_code == 200
    assert api_client.get("/api/demo/status").json()["stage"] == "baseline"
    assert api_client.get("/api/incidents/INC-2026-0042").status_code == 404


def test_validation_and_rules(api_client):
    v = api_client.get("/api/validation").json()
    assert len(v["results"]) == 8 and all(r["passed"] for r in v["results"])
    assert v["metrics"]["mttd"] > 0
    rules = api_client.get("/api/rules").json()
    assert len(rules["correlation"]) >= 8 and len(rules["suricata"]) >= 10
    assert api_client.post("/api/validation/run").json()["metrics"]["passed"] == 8
