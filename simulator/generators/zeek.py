"""Write Zeek-style JSON logs (conn, dns, http, ssl, notice, weird)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from simulator.canonical import Environment, add_seconds

from .base import DnsRecord, Flow, HttpRecord, SslRecord, stable_rng, zeek_uid

WEIRD_NAMES = [
    "bad_TCP_checksum",
    "dns_unmatched_msg",
    "possible_split_routing",
    "active_connection_reuse",
    "data_before_established",
    "DNS_RR_unknown_type",
    "TCP_ack_underflow_or_misorder",
    "inappropriate_FIN",
    "connection_originator_SYN_ack",
]


def _epoch(dt) -> float:
    return round(dt.timestamp(), 6)


def assign_uids(
    env: Environment, flows: list[Flow], dns: list[DnsRecord], http: list[HttpRecord], ssl: list[SslRecord]
) -> None:
    rng = stable_rng(env, "zeek-uids")
    flows.sort(key=lambda f: (f.ts, f.orig_h, f.resp_h, f.resp_p, f.orig_p))
    for f in flows:
        f.uid = zeek_uid(rng)
    index = {(f.ts, f.orig_h, f.orig_p, f.resp_h, f.resp_p): f.uid for f in flows}
    for d in dns:
        d.uid = index.get((d.ts, d.orig_h, d.orig_p, d.resp_h, 53), zeek_uid(rng))
    for h in http:
        h.uid = index.get((h.ts, h.orig_h, h.orig_p, h.resp_h, h.resp_p), zeek_uid(rng))
    for s in ssl:
        s.uid = index.get((s.ts, s.orig_h, s.orig_p, s.resp_h, s.resp_p), zeek_uid(rng))


def conn_record(f: Flow) -> dict[str, Any]:
    rec = {
        "ts": _epoch(f.ts),
        "uid": f.uid,
        "id.orig_h": f.orig_h,
        "id.orig_p": f.orig_p,
        "id.resp_h": f.resp_h,
        "id.resp_p": f.resp_p,
        "proto": f.proto,
    }
    if f.service:
        rec["service"] = f.service
    rec.update(
        {
            "duration": round(f.duration, 6),
            "orig_bytes": f.orig_bytes,
            "resp_bytes": f.resp_bytes,
            "conn_state": f.conn_state,
            "local_orig": f.local_orig,
            "local_resp": f.local_resp,
            "missed_bytes": 0,
            "history": f.history,
            "orig_pkts": f.orig_pkts,
            "orig_ip_bytes": f.orig_bytes + 40 * f.orig_pkts,
            "resp_pkts": f.resp_pkts,
            "resp_ip_bytes": f.resp_bytes + 40 * f.resp_pkts,
        }
    )
    if f.proto == "icmp":
        rec["history"] = ""
    return rec


def dns_record(d: DnsRecord) -> dict[str, Any]:
    return {
        "ts": _epoch(d.ts),
        "uid": d.uid,
        "id.orig_h": d.orig_h,
        "id.orig_p": d.orig_p,
        "id.resp_h": d.resp_h,
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": d.trans_id,
        "rtt": d.rtt,
        "query": d.query,
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": {"A": 1, "PTR": 12, "AAAA": 28}.get(d.qtype_name, 1),
        "qtype_name": d.qtype_name,
        "rcode": {"NOERROR": 0, "NXDOMAIN": 3}.get(d.rcode_name, 0),
        "rcode_name": d.rcode_name,
        "AA": d.resp_h == "10.30.0.10" and d.query.endswith("corp.example.com"),
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": d.answers,
        "TTLs": [float(t) for t in d.ttls],
        "rejected": False,
    }


def http_record(h: HttpRecord) -> dict[str, Any]:
    return {
        "ts": _epoch(h.ts),
        "uid": h.uid,
        "id.orig_h": h.orig_h,
        "id.orig_p": h.orig_p,
        "id.resp_h": h.resp_h,
        "id.resp_p": h.resp_p,
        "trans_depth": 1,
        "method": h.method,
        "host": h.host,
        "uri": h.uri,
        "version": "1.1",
        "user_agent": h.user_agent,
        "request_body_len": h.request_body_len,
        "response_body_len": h.response_body_len,
        "status_code": h.status_code,
        "status_msg": h.status_msg,
        "tags": [],
        "resp_fuids": [],
        "resp_mime_types": [h.resp_mime],
    }


def ssl_record(s: SslRecord) -> dict[str, Any]:
    return {
        "ts": _epoch(s.ts),
        "uid": s.uid,
        "id.orig_h": s.orig_h,
        "id.orig_p": s.orig_p,
        "id.resp_h": s.resp_h,
        "id.resp_p": s.resp_p,
        "version": s.version,
        "cipher": s.cipher,
        "curve": s.curve,
        "server_name": s.server_name,
        "resumed": s.resumed,
        "established": s.established,
        "ssl_history": "CsxkrsC" if not s.resumed else "Csr",
        "validation_status": s.validation_status,
    }


def weird_records(env: Environment, flows: list[Flow]) -> list[dict[str, Any]]:
    rng = stable_rng(env, "zeek-weird")
    out = []
    candidates = [f for f in flows if f.proto == "tcp" and f.scenario is None]
    for _ in range(26):
        f = rng.choice(candidates)
        out.append(
            {
                "ts": _epoch(add_seconds(f.ts, rng.uniform(0.001, 0.4))),
                "uid": f.uid,
                "id.orig_h": f.orig_h,
                "id.orig_p": f.orig_p,
                "id.resp_h": f.resp_h,
                "id.resp_p": f.resp_p,
                "name": rng.choice(WEIRD_NAMES),
                "addl": "",
                "notice": False,
                "peer": "zeek",
                "source": "TCP",
            }
        )
    out.sort(key=lambda r: r["ts"])
    return out


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


def write_all(
    env: Environment,
    out_dir: Path,
    flows: list[Flow],
    dns: list[DnsRecord],
    http: list[HttpRecord],
    ssl: list[SslRecord],
    notices: list[dict[str, Any]],
) -> dict[str, int]:
    assign_uids(env, flows, dns, http, ssl)
    dns.sort(key=lambda d: (d.ts, d.orig_h, d.query))
    http.sort(key=lambda h: h.ts)
    ssl.sort(key=lambda s: s.ts)
    notices = sorted(notices, key=lambda n: n["ts"])
    weird = weird_records(env, flows)
    write_jsonl(out_dir / "conn.log", [conn_record(f) for f in flows])
    write_jsonl(out_dir / "dns.log", [dns_record(d) for d in dns])
    write_jsonl(out_dir / "http.log", [http_record(h) for h in http])
    write_jsonl(out_dir / "ssl.log", [ssl_record(s) for s in ssl])
    write_jsonl(out_dir / "notice.log", notices)
    write_jsonl(out_dir / "weird.log", weird)
    return {
        "conn": len(flows),
        "dns": len(dns),
        "http": len(http),
        "ssl": len(ssl),
        "notice": len(notices),
        "weird": len(weird),
    }
