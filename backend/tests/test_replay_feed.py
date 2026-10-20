import gzip
import json

from sentinelswitch.app.config import get_settings


def _count(name: str) -> int:
    with (get_settings().data_dir / name).open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def test_telemetry_feed_mirrors_the_dataset_files(api_client):
    r = api_client.get("/api/telemetry")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    feed = r.json()
    assert feed["day"] == "2026-03-17" and feed["start"] == "2026-03-17T00:00:00Z"
    # one row per recorded line: nothing generated, nothing dropped
    assert feed["counts"]["conn"] == _count("zeek/conn.log")
    assert len(feed["auth"]) == _count("radius/auth-events.jsonl")
    assert len(feed["syslog"]) == _count("cisco/SW01-syslog.jsonl")
    conn = feed["conn"]
    n = feed["counts"]["conn"]
    assert all(len(col) == n for col in conn.values())
    assert conn["t"] == sorted(conn["t"]) and 0 <= conn["t"][0] and conn["t"][-1] < 86_400_000
    assert max(conn["o"] + conn["r"]) < len(feed["hosts"]) and min(conn["o"] + conn["r"]) >= 0
    assert max(conn["s"]) < len(feed["services"]) and max(conn["d"]) < len(feed["details"])
    assert {"dns", "ssl", "smb"} <= set(feed["services"])
    assert any(d.endswith(" A NOERROR") for d in feed["details"])  # DNS query joined by uid
    assert all(a["port"] is None or a["port"].startswith("Gi") for a in feed["auth"])


def test_telemetry_feed_is_compressed_and_cacheable(api_client):
    first = api_client.get("/api/telemetry", headers={"Accept-Encoding": "identity"})
    etag = first.headers["etag"]
    assert "content-encoding" not in first.headers and first.headers["cache-control"].startswith("public")
    packed = api_client.get("/api/telemetry", headers={"Accept-Encoding": "gzip"})
    assert packed.headers["content-encoding"] == "gzip" and packed.json() == first.json()
    assert len(gzip.compress(first.content)) < len(first.content) / 2
    assert api_client.get("/api/telemetry", headers={"If-None-Match": etag}).status_code == 304
    assert json.loads(first.content)["counts"] == packed.json()["counts"]


def test_telemetry_feed_is_read_only(api_client):
    for method in ("post", "put", "delete"):
        assert getattr(api_client, method)("/api/telemetry").status_code == 405
