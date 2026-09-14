"""Write the Suricata EVE JSON dataset (alerts plus flow records for scenario traffic)."""

from __future__ import annotations

import json
import zlib
from pathlib import Path
from typing import Any

from simulator.canonical import Environment, add_seconds

from .base import Flow, stable_rng
from .events import suricata_ts


def flow_event(env: Environment, f: Flow, rng) -> dict[str, Any]:
    start = f.ts
    end = add_seconds(f.ts, f.duration)
    state = {"SF": "closed", "REJ": "closed", "RSTO": "closed", "S0": "new", "OTH": "established"}.get(
        f.conn_state, "closed"
    )
    rec = {
        "timestamp": suricata_ts(end),
        "flow_id": rng.randint(10**15, 2 * 10**15),
        "in_iface": "eth1",
        "event_type": "flow",
        "src_ip": f.orig_h,
        "src_port": f.orig_p,
        "dest_ip": f.resp_h,
        "dest_port": f.resp_p,
        "proto": f.proto.upper(),
        "flow": {
            "pkts_toserver": f.orig_pkts,
            "pkts_toclient": f.resp_pkts,
            "bytes_toserver": f.orig_bytes + 40 * f.orig_pkts,
            "bytes_toclient": f.resp_bytes + 40 * f.resp_pkts,
            "start": suricata_ts(start),
            "end": suricata_ts(end),
            "age": int(f.duration),
            "state": state,
            "reason": "timeout" if f.conn_state in {"S0", "OTH"} else "shutdown",
            "alerted": False,
        },
        "community_id": f"1:{zlib.crc32(f'{f.orig_h}|{f.resp_h}|{f.resp_p}|{f.orig_p}'.encode()):010d}",
    }
    if f.service:
        rec["app_proto"] = {
            "dns": "dns",
            "ssl": "tls",
            "smb": "smb",
            "http": "http",
            "ssh": "ssh",
            "rdp": "rdp",
            "dhcp": "dhcp",
        }.get(f.service, "failed")
    if f.proto == "tcp":
        rec["tcp"] = {
            "tcp_flags": "1b" if f.conn_state == "SF" else "02",
            "syn": True,
            "fin": f.conn_state == "SF",
            "rst": f.conn_state in {"REJ", "RSTO"},
            "state": "closed" if f.conn_state != "S0" else "syn_sent",
        }
    if f.proto == "icmp":
        rec["icmp_type"], rec["icmp_code"] = 8, 0
        del rec["src_port"], rec["dest_port"]
    return rec


def write_eve(env: Environment, path: Path, alerts: list[dict[str, Any]], scenario_flows: list[Flow]) -> dict[str, int]:
    rng = stable_rng(env, "eve-flows")
    records: list[dict[str, Any]] = []
    for a in alerts:
        rec = {k: v for k, v in a.items() if not k.startswith("_")}
        records.append(rec)
    n_flows = 0
    for f in scenario_flows:
        if f.proto == "icmp" and rng.random() > 0.15:
            continue  # sample ICMP echo flows; Suricata flow logging of a full sweep is noisy
        records.append(flow_event(env, f, rng))
        n_flows += 1
    records.sort(key=lambda r: r["timestamp"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    return {"alerts": len(alerts), "flows": n_flows, "total": len(records)}
