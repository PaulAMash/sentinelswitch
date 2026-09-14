"""Overview KPIs and chart series, all derived from the seeded dataset and the current twin state."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from simulator.canonical import Environment, parse_ts

from .store import Store


def _fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} B"
        v /= 1024
    return f"{v:.1f} TB"


def overview(store: Store, env: Environment) -> dict[str, Any]:
    twin = store.load_twin()
    alerts = store.alerts(limit=100000)
    incidents = store.incidents()
    auth = store.auth_events(limit=100000)
    buckets = store.buckets()
    vmetrics = store.kv_get("validation_metrics", {}) or {}
    demo = store.kv_get("demo", {})

    online = [i for i in twin.interfaces.values() if i.oper_status == "connected" and not i.is_trunk]
    trunk_hosts = len({e.mac for e in twin.mac_table if twin.interfaces[e.interface].is_trunk})
    devices_online = len(online) + trunk_hosts
    quarantined = [i for i in twin.interfaces.values() if i.quarantined or i.hold]
    accepts = sum(1 for a in auth if a["result"] == "Access-Accept")
    rejects = sum(1 for a in auth if a["result"] == "Access-Reject")
    success_rate = round(100.0 * accepts / max(1, accepts + rejects), 1)
    total_bytes = sum(b["bytes"] for b in buckets)
    total_conns = sum(b["connections"] for b in buckets)
    active_vlans = sorted(
        {i.oper_vlan for i in twin.interfaces.values() if i.oper_status == "connected" and i.oper_vlan}
        | {
            v
            for i in twin.interfaces.values()
            if i.is_trunk and i.oper_status == "connected"
            for v in i.allowed_vlans
            if any(e.vlan == v for e in twin.mac_table if e.interface == i.name)
        }
    )

    by_hour: dict[str, Counter] = defaultdict(Counter)
    for a in alerts:
        by_hour[a["ts"][11:13]][a["severity"]] += 1
    timeline = [
        {
            "hour": f"{h:02d}:00",
            "high": by_hour[f"{h:02d}"]["high"],
            "medium": by_hour[f"{h:02d}"]["medium"],
            "low": by_hour[f"{h:02d}"]["low"] + by_hour[f"{h:02d}"]["info"],
        }
        for h in range(24)
    ]
    by_category = Counter(_category(a) for a in alerts)
    devices = store.devices()
    by_vlan = Counter()
    for d in devices:
        by_vlan[d["vlan"]] += 1
    for i in twin.interfaces.values():
        if i.quarantined:
            by_vlan[50] += 1
            dev = env.device_by_interface(i.name)
            if dev:
                by_vlan[dev["vlan"] if isinstance(dev, dict) else dev.vlan] -= 1
    devices_by_vlan = [
        {"vlan": v.id, "name": v.name, "devices": by_vlan.get(v.id, 0)} for v in env.vlans.values() if v.id != 999
    ]

    return {
        "kpis": {
            "devices_online": devices_online,
            "devices_total": len(devices),
            "alerts": len(alerts),
            "high_alerts": sum(1 for a in alerts if a["severity"] == "high"),
            "incidents": len(incidents),
            "open_incidents": sum(1 for i in incidents if i["status"] in {"contained", "open"}),
            "quarantined_hosts": len(quarantined),
            "auth_success_rate": success_rate,
            "auth_accepts": accepts,
            "auth_rejects": rejects,
            "traffic_bytes": total_bytes,
            "traffic_human": _fmt_bytes(total_bytes),
            "connections": total_conns,
            "active_vlans": len(active_vlans),
            "active_vlan_ids": active_vlans,
            "mttd": vmetrics.get("mttd"),
            "mtta": vmetrics.get("mtta"),
            "mttc": vmetrics.get("mttc"),
            "validation_passed": vmetrics.get("passed"),
            "validation_total": vmetrics.get("scenarios"),
        },
        "alert_timeline": timeline,
        "traffic": [
            {
                "ts": b["ts"],
                "connections": b["connections"],
                "bytes": b["bytes"],
                "dns": b["dns_queries"],
                "alerts": b["alerts"],
                "hosts": b["hosts"],
            }
            for b in buckets
        ],
        "alerts_by_category": [
            {"category": k, "count": v} for k, v in sorted(by_category.items(), key=lambda kv: -kv[1])
        ],
        "devices_by_vlan": devices_by_vlan,
        "recent_alerts": alerts[:8],
        "recent_auth": auth[:8],
        "containment_activity": store.actions()[:6],
        "incidents": incidents[:5],
        "switch": twin.summary() | {"hostname": twin.hostname, "model": twin.model},
        "demo": demo,
        "dataset": env.dataset,
    }


def _category(a: dict[str, Any]) -> str:
    src = a["source"]
    if src == "suricata":
        return {
            "recon": "Reconnaissance",
            "lateral": "Lateral movement",
            "dns": "DNS anomaly",
            "rogue": "Rogue infrastructure",
            "policy": "Policy",
        }.get(a.get("category", ""), a.get("category") or "Suricata")
    if src == "zeek":
        return "Scan detection (Zeek)"
    if src == "radius":
        return "Authentication"
    sig = a.get("signature", "")
    if "DAI" in sig:
        return "ARP inspection"
    if "DHCP_SNOOPING" in sig:
        return "DHCP snooping"
    if "PORT_SECURITY" in sig:
        return "Port security"
    if "SPANTREE" in sig or "PM-4" in sig:
        return "BPDU Guard"
    if "MAB" in sig or "DOT1X" in sig:
        return "Authentication"
    return "Switch security"


def auth_summary(store: Store) -> dict[str, Any]:
    events = store.auth_events(limit=100000)
    by_hour: dict[int, Counter] = defaultdict(Counter)
    methods: Counter = Counter()
    vlans: Counter = Counter()
    users: Counter = Counter()
    for e in events:
        h = int(e["timestamp"][11:13])
        by_hour[h][e["result"]] += 1
        methods[e.get("method") or "unknown"] += 1
        if e["result"] in {"Access-Accept", "Guest-VLAN"}:
            vlans[str(e.get("assigned_vlan") or "n/a")] += 1
        if e["result"] == "Access-Reject":
            users[e.get("username") or "?"] += 1
    series = [
        {
            "hour": f"{h:02d}:00",
            "accept": by_hour[h]["Access-Accept"],
            "reject": by_hour[h]["Access-Reject"],
            "guest": by_hour[h]["Guest-VLAN"],
        }
        for h in range(24)
    ]
    accepts = sum(1 for e in events if e["result"] == "Access-Accept")
    rejects = sum(1 for e in events if e["result"] == "Access-Reject")
    return {
        "series": series,
        "methods": [{"method": k, "count": v} for k, v in methods.most_common()],
        "vlans": [{"vlan": k, "count": v} for k, v in sorted(vlans.items())],
        "top_rejected": [{"username": k, "count": v} for k, v in users.most_common(6)],
        "totals": {
            "events": len(events),
            "accepts": accepts,
            "rejects": rejects,
            "guest": sum(1 for e in events if e["result"] == "Guest-VLAN"),
            "success_rate": round(100.0 * accepts / max(1, accepts + rejects), 1),
        },
        "recent": events[:200],
    }


def hour_label(ts: str) -> str:
    return parse_ts(ts).strftime("%H:%M")
