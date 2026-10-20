import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from sentinelswitch.app.config import Settings
from sentinelswitch.app.main import create_app
from simulator.canonical import ROOT


def _pending(client):
    return [r for r in client.get("/api/reviews").json() if r["status"] == "review"]


def test_demo_run_plays_the_analyst_through_the_approval_workflow(api_client):
    (pending,) = _pending(api_client)
    guards = pending["decision"]["guards_triggered"]
    assert guards, "the review exists because a policy guard withheld automation"
    body = api_client.post("/api/demo/run").json()
    (d,) = body["analyst_decisions"]
    assert d["review"] == pending["detection_id"] and d["action"] == "verified"
    auth = d["authorization"]
    assert auth["mode"] == "analyst" and auth["status"] == "authorized" and auth["authorized_by"] == "tlee"
    assert auth["channel"] == "scripted-demo" and auth["guards"] == guards and "acknowledged" in auth["note"]
    review = api_client.get(f"/api/reviews/{d['review']}").json()
    assert review["status"] == "approved" and review["incident_id"] == d["incident"]
    incident = api_client.get(f"/api/incidents/{d['incident']}").json()["incident"]
    assert incident["status"] == "contained" and incident["disposition"] == "analyst_approved"
    assert incident["authorization"]["channel"] == "scripted-demo"
    port = next(i for i in api_client.get("/api/switch").json()["interfaces"] if i["name"] == incident["interface"])
    assert port["state"] == "quarantined" and port["access_vlan"] == 50
    assert api_client.get("/api/overview").json()["kpis"]["quarantined_hosts"] == 2
    status = api_client.get("/api/demo/status").json()
    assert status["scripted_decisions"] == [{"review": d["review"], "incident": d["incident"], "actor": "tlee"}]
    # the flagship stays a policy (automatic) authorization; only the reviewed detection carries the analyst
    flagship = api_client.get("/api/incidents/INC-2026-0042").json()["incident"]["authorization"]
    assert flagship["mode"] == "automatic" and "channel" not in flagship
    assert _pending(api_client) == []


def test_the_live_site_startup_replays_with_the_scripted_analyst(tmp_path, baseline_db):
    db = tmp_path / "start.db"
    shutil.copyfile(baseline_db, db)
    (tmp_path / "incidents").mkdir()
    settings = Settings(
        db_path=db,
        data_dir=ROOT / "data",
        incidents_dir=tmp_path / "incidents",
        artifacts_dir=tmp_path / "artifacts",
        frontend_dist=Path("/nonexistent"),
        auto_seed=False,
        auto_demo=True,
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/demo/status").json()["stage"] == "contained"
        assert _pending(client) == []
        decided = [
            r
            for r in client.get("/api/reviews").json()
            if (r.get("authorization") or {}).get("channel") == "scripted-demo"
        ]
        assert len(decided) == 1 and decided[0]["status"] == "approved"


def test_the_scripted_analyst_can_be_switched_off(tmp_path, baseline_db):
    db = tmp_path / "off.db"
    shutil.copyfile(baseline_db, db)
    (tmp_path / "incidents").mkdir()
    settings = Settings(
        db_path=db,
        data_dir=ROOT / "data",
        incidents_dir=tmp_path / "incidents",
        artifacts_dir=tmp_path / "artifacts",
        frontend_dist=Path("/nonexistent"),
        auto_seed=False,
        auto_demo=True,
        demo_analyst=False,
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/demo/status").json()["stage"] == "contained"
        assert len(_pending(client)) == 1
