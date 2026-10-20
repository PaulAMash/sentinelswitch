"""Recorded network telemetry of the dataset day, shaped for the dashboard replay.

Every row comes from a committed dataset file: Zeek connections (data/zeek/conn.log) with the DNS query,
TLS server name or HTTP request of the same connection joined by uid, RADIUS results
(data/radius/auth-events.jsonl) and the switch's syslog (data/cisco/SW01-syslog.jsonl). Nothing is
generated, sampled or rewritten here; the feed is a compact, read-only projection of those files.

Connections are columnar to keep the payload small: times are milliseconds after the dataset day's UTC
midnight, hosts, services and details are indexes into string tables (-1 when absent).
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from simulator.canonical import short_ifname

FILES = {
    "conn": "zeek/conn.log",
    "dns": "zeek/dns.log",
    "ssl": "zeek/ssl.log",
    "http": "zeek/http.log",
    "auth": "radius/auth-events.jsonl",
    "syslog": "cisco/SW01-syslog.jsonl",
}


def _lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _iso_ms(ts: str) -> int:
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


class _Table:
    """String table: the index of each distinct value, in first-seen order."""

    def __init__(self) -> None:
        self.values: list[str] = []
        self._index: dict[str, int] = {}

    def __call__(self, value: str | None) -> int:
        if not value:
            return -1
        i = self._index.get(value)
        if i is None:
            i = self._index[value] = len(self.values)
            self.values.append(value)
        return i


def build_feed(data_dir: Path, day: str) -> dict[str, Any]:
    start = int(datetime.fromisoformat(f"{day}T00:00:00+00:00").timestamp() * 1000)
    hosts, services, details = _Table(), _Table(), _Table()

    detail_by_uid: dict[str, str] = {}
    for d in _lines(data_dir / FILES["dns"]):
        q = d.get("query")
        if q:
            detail_by_uid[d["uid"]] = " ".join(x for x in (q, d.get("qtype_name"), d.get("rcode_name")) if x)
    for s in _lines(data_dir / FILES["ssl"]):
        if s.get("server_name"):
            detail_by_uid[s["uid"]] = s["server_name"]
    for h in _lines(data_dir / FILES["http"]):
        if h.get("host"):
            detail_by_uid[h["uid"]] = " ".join(
                str(x) for x in (h.get("method"), f"{h['host']}{h.get('uri') or ''}", h.get("status_code")) if x
            )

    conn: dict[str, list[int]] = {k: [] for k in ("t", "o", "r", "p", "s", "b", "d")}
    rows = sorted(_lines(data_dir / FILES["conn"]), key=lambda c: c["ts"])
    for c in rows:
        conn["t"].append(round(c["ts"] * 1000) - start)
        conn["o"].append(hosts(c["id.orig_h"]))
        conn["r"].append(hosts(c["id.resp_h"]))
        conn["p"].append(int(c.get("id.resp_p") or 0))
        conn["s"].append(services(c.get("service") or c.get("proto")))
        conn["b"].append(int(c.get("orig_bytes") or 0) + int(c.get("resp_bytes") or 0))
        conn["d"].append(details(detail_by_uid.get(c["uid"])))

    auth = [
        {
            "t": _iso_ms(a["timestamp"]) - start,
            "result": a.get("result"),
            "user": a.get("username"),
            "device": a.get("device"),
            "port": short_ifname(a["nas_port_id"]) if a.get("nas_port_id") else None,
            "method": a.get("method"),
            "vlan": a.get("assigned_vlan"),
        }
        for a in sorted(_lines(data_dir / FILES["auth"]), key=lambda a: a["timestamp"])
    ]
    syslog = [
        {
            "t": _iso_ms(s["ts"]) - start,
            "severity": s.get("severity"),
            "mnemonic": f"%{s.get('facility')}-{s.get('severity')}-{s.get('mnemonic')}",
            "port": short_ifname(s["interface"]) if s.get("interface") else None,
            "message": s.get("message"),
        }
        for s in sorted(_lines(data_dir / FILES["syslog"]), key=lambda s: s["ts"])
    ]
    return {
        "day": day,
        "start": f"{day}T00:00:00Z",
        "files": {k: f"data/{v}" for k, v in FILES.items()},
        "counts": {
            "conn": len(rows),
            "auth": len(auth),
            "syslog": len(syslog),
            "with_detail": sum(1 for d in conn["d"] if d >= 0),
        },
        "hosts": hosts.values,
        "services": services.values,
        "details": details.values,
        "conn": conn,
        "auth": auth,
        "syslog": syslog,
    }


@lru_cache(maxsize=2)
def _encoded(data_dir: str, day: str, stamp: tuple[float, ...]) -> tuple[bytes, bytes, str]:
    raw = json.dumps(build_feed(Path(data_dir), day), separators=(",", ":")).encode()
    return raw, gzip.compress(raw, compresslevel=6), hashlib.sha1(raw).hexdigest()[:16]


def encoded_feed(data_dir: Path, day: str) -> tuple[bytes, bytes, str]:
    """(json, gzip(json), etag), rebuilt only when a source file changes."""
    stamp = tuple((data_dir / f).stat().st_mtime if (data_dir / f).exists() else 0.0 for f in FILES.values())
    return _encoded(str(data_dir), day, stamp)
