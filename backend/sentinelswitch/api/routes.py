"""REST + SSE API for the SentinelSwitch dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from sentinelswitch import __version__
from sentinelswitch.app.events import bus
from sentinelswitch.containment.policy import load_policy
from sentinelswitch.detection.engine import load_rules
from sentinelswitch.detection.suricata_rules import load_rules as load_suricata_rules
from sentinelswitch.drift.engine import DriftEngine
from sentinelswitch.evidence.bundle import BUNDLE_FILES
from sentinelswitch.services import demo as demo_service
from sentinelswitch.services import metrics
from sentinelswitch.services.seed import seed_database
from sentinelswitch.simulator import cli_render
from sentinelswitch.validation.harness import run_validation
from simulator.canonical import ROOT, short_ifname

router = APIRouter(prefix="/api")


def _ctx(request: Request):
    return request.app.state.store, request.app.state.env, request.app.state.settings


# ---------------------------------------------------------------------------------------------
@router.get("/meta")
def meta(request: Request) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    twin = store.load_twin()
    return {
        "name": "SentinelSwitch",
        "tagline": "Autonomous Network Detection & Response Lab",
        "version": __version__,
        "simulation": True,
        "dataset": env.dataset,
        "organization": env.organization,
        "switch": {
            "hostname": twin.hostname,
            "model": twin.model,
            "ios_version": twin.ios_version,
            "management_ip": twin.management_ip,
            "now": twin.to_dict()["now"],
            "summary": twin.summary(),
        },
        "demo": demo_service.demo_status(store),
        "counts": store.counts(),
        "flagship_incident": env.flagship().instances["day"].incident_id,
    }


@router.get("/overview")
def overview(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    return metrics.overview(store, env)


@router.get("/traffic")
def traffic(request: Request) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    return store.buckets()


# ---- alerts / detections --------------------------------------------------------------------
@router.get("/alerts")
def alerts(
    request: Request,
    severity: str | None = None,
    source: str | None = None,
    status: str | None = None,
    limit: int = Query(500, le=5000),
) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    rows = store.alerts(severity=severity, source=source, status=status, limit=limit)
    return [{k: v for k, v in r.items() if k != "raw"} for r in rows]


@router.get("/alerts/{alert_id}")
def alert(request: Request, alert_id: str) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    row = store.alert(alert_id)
    if not row:
        raise HTTPException(404, "alert not found")
    det = store.detection(row["detection_id"]) if row.get("detection_id") else None
    return {"alert": row, "detection": det}


@router.get("/detections")
def detections(request: Request) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    return store.detections()


@router.get("/reviews")
def reviews(request: Request) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    return store.reviews()


@router.get("/rules")
def rules(request: Request) -> dict[str, Any]:
    correlation = [
        {
            "id": r.id,
            "name": r.name,
            "class": r.klass,
            "description": r.description,
            "mitre": r.mitre,
            "actor_key": r.actor_key,
            "trigger": r.trigger,
            "aggregate_window": r.aggregate_window,
            "base_confidence": r.base_confidence,
            "severity": r.severity,
            "features": r.features,
            "path": r.path,
        }
        for r in load_rules().values()
    ]
    suricata = [
        {
            "sid": r.sid,
            "rev": r.rev,
            "msg": r.msg,
            "classtype": r.classtype,
            "category": r.category,
            "class": r.sentinel_class,
            "severity": r.sentinel_severity,
            "proto": r.proto,
            "rule": r.raw,
        }
        for r in load_suricata_rules().values()
    ]
    zeek = [
        {"note": "Scan::Address_Scan", "script": "policy/misc/scan (thresholds in detections/zeek/sentinel-scan.zeek)"},
        {"note": "Scan::Port_Scan", "script": "policy/misc/scan"},
        {"note": "SentinelDNS::NXDomain_Burst", "script": "detections/zeek/sentinel-dns.zeek"},
        {"note": "SentinelDNS::High_Query_Rate", "script": "detections/zeek/sentinel-dns.zeek"},
    ]
    return {"correlation": correlation, "suricata": suricata, "zeek": zeek, "policy": load_policy()}


# ---- incidents --------------------------------------------------------------------------------
@router.get("/incidents")
def incidents(request: Request) -> list[dict[str, Any]]:
    store, _, _ = _ctx(request)
    return store.incidents()


@router.get("/incidents/{incident_id}")
def incident(request: Request, incident_id: str) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    inc = store.incident(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    det = store.detection(inc["detection_id"]) if inc.get("detection_id") else None
    actions = store.actions_for_incident(incident_id)
    alerts_ = [a for a in store.alerts(limit=100000) if a.get("incident_id") == incident_id]
    evidence_dir = settings.incidents_dir / incident_id
    files = []
    if evidence_dir.exists():
        for name in BUNDLE_FILES:
            p = evidence_dir / name
            if p.exists():
                files.append({"name": name, "bytes": p.stat().st_size})
    attribution = None
    if evidence_dir.exists() and (evidence_dir / "network-context.json").exists():
        attribution = json.loads((evidence_dir / "network-context.json").read_text(encoding="utf-8")).get("attribution")
    twin = store.load_twin()
    iface = inc.get("interface")
    port = twin.interfaces.get(iface) if iface else None
    return {
        "incident": inc,
        "detection": det,
        "attribution": attribution,
        "actions": actions,
        "alerts": [{k: v for k, v in a.items() if k != "raw"} for a in sorted(alerts_, key=lambda a: a["ts"])],
        "timeline": store.timeline(incident_id),
        "evidence": {"path": f"data/incidents/{incident_id}", "files": files},
        "port": port.__dict__ if port else None,
        "verification": {
            "switchport": cli_render.show_interface_switchport(twin, iface) if port else None,
            "status": cli_render.show_interface_status_single(twin, iface) if port else None,
            "mac_table": cli_render.show_mac_address_table(twin, interface=iface) if port else None,
            "running_config": cli_render.show_running_config_interface(twin, iface) if port else None,
        },
        "scenario": next((s for s in store.scenarios() if s["id"] == inc.get("scenario")), None),
    }


@router.get("/incidents/{incident_id}/evidence/{name}")
def evidence_file(request: Request, incident_id: str, name: str):
    _, _, settings = _ctx(request)
    if name not in BUNDLE_FILES:
        raise HTTPException(404, "unknown artifact")
    path = settings.incidents_dir / incident_id / name
    if not path.exists():
        raise HTTPException(404, "artifact not found")
    text = path.read_text(encoding="utf-8")
    if name.endswith(".json"):
        return json.loads(text)
    return PlainTextResponse(text)


class RestoreBody(BaseModel):
    actor: str = Field(default="tlee", max_length=64)
    note: str = Field(default="Endpoint remediated and re-imaged; returning to production VLAN.", max_length=500)


@router.post("/incidents/{incident_id}/restore")
def restore(request: Request, incident_id: str, body: RestoreBody) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    try:
        result = demo_service.restore_incident(store, env, incident_id, actor=body.actor, note=body.note)
    except KeyError:
        raise HTTPException(404, "incident not found") from None
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None
    bus.publish("incident", {"id": incident_id, "status": "resolved"})
    bus.publish("state", {"reason": "restore"})
    return result


@router.get("/evidence")
def evidence_index(request: Request) -> list[dict[str, Any]]:
    store, _, settings = _ctx(request)
    out = []
    for inc in store.incidents():
        d = settings.incidents_dir / inc["id"]
        files = (
            [{"name": n, "bytes": (d / n).stat().st_size} for n in BUNDLE_FILES if (d / n).exists()]
            if d.exists()
            else []
        )
        out.append(
            {
                "incident": inc,
                "path": f"data/incidents/{inc['id']}",
                "files": files,
                "complete": len(files) == len(BUNDLE_FILES),
            }
        )
    return out


# ---- devices ----------------------------------------------------------------------------------
@router.get("/devices")
def devices(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    twin = store.load_twin()
    rows = []
    for d in store.devices():
        iface = twin.interfaces.get(d["interface"])
        macs = twin.find_mac(d["mac"])
        binding = next((b for b in twin.dhcp_bindings if b.mac == d["mac"]), None)
        online = bool(macs)
        current_vlan = macs[0].vlan if macs else d["vlan"]
        rows.append(
            d
            | {
                "online": online,
                "current_vlan": current_vlan,
                "quarantined": bool(iface and iface.quarantined and online),
                "port_status": iface.oper_status if iface else None,
                "port_hold": bool(iface and iface.hold),
                "binding": binding.__dict__ if binding else None,
                "auth_state": iface.auth_state if iface and not d.get("via_trunk") else None,
                "user_display": env.users[d["user"]].display_name if d.get("user") in env.users else None,
                "department": env.users[d["user"]].department if d.get("user") in env.users else None,
            }
        )
    return {"devices": rows, "unknown": store.unknown_devices(), "users": store.users()}


@router.get("/devices/{hostname}")
def device(request: Request, hostname: str) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    d = store.device(hostname)
    if not d:
        raise HTTPException(404, "device not found")
    twin = store.load_twin()
    iface = twin.interfaces.get(d["interface"])
    alerts_ = [
        a
        for a in store.alerts(limit=100000)
        if a.get("device") == hostname or a.get("src_ip") == d.get("ip") or (a.get("mac") == d.get("mac"))
    ]
    auth = [
        e
        for e in store.auth_events(limit=100000)
        if e.get("device") == hostname or e.get("calling_station_id", "").replace("-", ":") == d["mac"]
    ]
    incidents_ = [i for i in store.incidents() if i.get("device") == hostname]
    user = env.users.get(d["user"]) if d.get("user") else None
    return {
        "device": d,
        "user": user.__dict__ if user else None,
        "interface": iface.__dict__ if iface else None,
        "mac_entries": [e.__dict__ for e in twin.find_mac(d["mac"])],
        "bindings": [b.__dict__ for b in twin.dhcp_bindings if b.mac == d["mac"]],
        "observations": [o.__dict__ for o in twin.observations_for_mac(d["mac"])],
        "alerts": [{k: v for k, v in a.items() if k != "raw"} for a in alerts_[:50]],
        "auth": auth[:30],
        "incidents": incidents_,
    }


# ---- switch -----------------------------------------------------------------------------------
@router.get("/switch")
def switch(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    twin = store.load_twin()
    data = twin.to_dict()
    ifaces = []
    for name, i in twin.interfaces.items():
        macs = twin.macs_on_interface(name)
        dev = env.device_by_interface(name)
        ifaces.append(
            i.__dict__
            | {
                "macs": [e.__dict__ for e in macs],
                "device": dev.hostname if dev else None,
                "device_user": dev.user if dev else None,
                "bindings": [b.__dict__ for b in twin.dhcp_bindings if b.interface == name],
                "state": _port_state(i),
            }
        )
    return {
        "hostname": twin.hostname,
        "model": twin.model,
        "ios_version": twin.ios_version,
        "serial": twin.serial,
        "management_ip": twin.management_ip,
        "now": data["now"],
        "uptime": cli_render._uptime(twin),
        "summary": twin.summary(),
        "vlans": data["vlans"],
        "span": data["span"],
        "dhcp_snooping_vlans": data["dhcp_snooping_vlans"],
        "dai_vlans": data["dai_vlans"],
        "interfaces": ifaces,
        "mac_table": data["mac_table"],
        "dhcp_bindings": data["dhcp_bindings"],
        "config_changes": data["config_changes"][-25:],
        "audit": data.get("audit", []),
        "log_tail": [line.render() for line in twin.log[-40:]],
        "commands": cli_render.SHOW_COMMANDS,
    }


def _port_state(i) -> str:
    if i.quarantined:
        return "quarantined"
    if i.hold:
        return "held"
    if i.span_destination:
        return "monitor"
    if i.is_trunk:
        return "trunk"
    if i.oper_status == "err-disabled":
        return "err-disabled"
    if i.oper_status == "connected":
        return "connected"
    if i.admin_status == "down":
        return "disabled"
    return "notconnect"


@router.get("/switch/interfaces/{name:path}")
def switch_interface(request: Request, name: str) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    twin = store.load_twin()
    n = short_ifname(name)
    if n not in twin.interfaces:
        raise HTTPException(404, "interface not found")
    i = twin.interfaces[n]
    dev = env.device_by_interface(n)
    return {
        "interface": i.__dict__ | {"state": _port_state(i)},
        "intent": {
            "description": env.ports[n].description,
            "profile": env.ports[n].profile,
            "class": env.ports[n].port_class,
            "protected": env.ports[n].protected,
            "settings": env.ports[n].settings,
        },
        "device": dev.hostname if dev else None,
        "macs": [e.__dict__ for e in twin.macs_on_interface(n)],
        "bindings": [b.__dict__ for b in twin.dhcp_bindings if b.interface == n],
        "show": {
            "status": cli_render.show_interface_status_single(twin, n),
            "switchport": cli_render.show_interface_switchport(twin, n),
            "running_config": cli_render.show_running_config_interface(twin, n),
            "port_security": cli_render.show_port_security_interface(twin, n),
            "authentication": cli_render.show_authentication_sessions(twin, n),
        },
        "changes": [c for c in twin.to_dict()["config_changes"] if c.get("interface") == n],
    }


@router.get("/switch/show", response_class=PlainTextResponse)
def switch_show(request: Request, cmd: str = Query(..., max_length=120)) -> str:
    store, _, _ = _ctx(request)
    if not cmd.strip().lower().startswith("show"):
        raise HTTPException(400, "only show commands are supported")
    twin = store.load_twin()
    return f"{twin.hostname}#{cmd}\n{cli_render.run_show(twin, cmd)}\n{twin.hostname}#"


# ---- authentication ---------------------------------------------------------------------------
@router.get("/auth")
def auth(request: Request) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    return metrics.auth_summary(store)


# ---- validation / drift -----------------------------------------------------------------------
@router.get("/validation")
def validation(request: Request) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    rows = store.validation()
    order = [
        "unauthorized-endpoint",
        "arp-spoofing",
        "rogue-dhcp",
        "mac-address-change",
        "port-scan",
        "dns-anomaly",
        "lateral-reconnaissance",
        "bpdu-violation",
    ]
    rows.sort(key=lambda r: order.index(r["scenario_id"]) if r["scenario_id"] in order else 99)
    return {"results": rows, "metrics": store.kv_get("validation_metrics", {}), "scenarios": store.scenarios()}


@router.post("/validation/run")
def validation_run(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    report = run_validation(env, store.load_baseline_twin())
    for row in report.results:
        store.put_validation(row)
    store.kv_set("validation_metrics", report.metrics | {"all_passed": report.all_passed})
    bus.publish("validation", {"passed": report.metrics["passed"]})
    return {"results": report.results, "metrics": report.metrics | {"all_passed": report.all_passed}}


@router.get("/drift")
def drift(request: Request) -> dict[str, Any]:
    store, env, _ = _ctx(request)
    twin = store.load_twin()
    report = DriftEngine(env).evaluate(twin)
    report["desired_source"] = "simulator/fixtures/environment.yaml"
    report["observed_source"] = "digital twin running state (show running-config)"
    return report


# ---- demo -------------------------------------------------------------------------------------
@router.get("/demo/status")
def demo_status(request: Request) -> dict[str, Any]:
    store, _, _ = _ctx(request)
    return demo_service.demo_status(store)


@router.post("/demo/run")
def demo_run(request: Request) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    try:
        result = demo_service.run_flagship(
            store, env, settings, on_event=lambda e: bus.publish(e["type"], e["payload"])
        )
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None
    bus.publish("state", {"reason": "demo"})
    return {
        "incident": result.incident,
        "metrics": result.metrics,
        "checks": result.checks,
        "timeline": result.timeline,
    }


@router.post("/demo/reset")
def demo_reset(request: Request) -> dict[str, Any]:
    store, env, settings = _ctx(request)
    summary = seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    bus.publish("state", {"reason": "reset"})
    return summary


# ---- about ------------------------------------------------------------------------------------
@router.get("/about")
def about(request: Request) -> dict[str, Any]:
    _, env, _ = _ctx(request)
    diagrams = (
        sorted(p.name for p in (ROOT / "diagrams" / "svg").glob("*.svg"))
        if (ROOT / "diagrams" / "svg").exists()
        else []
    )
    return {
        "name": "SentinelSwitch",
        "tagline": "Autonomous Network Detection & Response Lab",
        "version": __version__,
        "organization": env.organization,
        "switch": env.switch,
        "vlans": [v.__dict__ for v in env.vlans.values()],
        "diagrams": diagrams,
        "components": [
            {
                "name": "Simulated endpoints",
                "role": "Workstations, servers, guests and rogue devices modelled from simulator/fixtures/inventory.yaml",
                "layer": "access",
            },
            {
                "name": "Catalyst 2960-X digital twin",
                "role": "Interfaces, VLANs, MAC table, DHCP snooping bindings, port security, logging buffer (backend/sentinelswitch/simulator/twin.py)",
                "layer": "access",
            },
            {
                "name": "SPAN / syslog / AAA",
                "role": "VLAN SPAN to the sensor, syslog to the collector, RADIUS to FreeRADIUS",
                "layer": "telemetry",
            },
            {
                "name": "Zeek + Suricata-style telemetry",
                "role": "conn/dns/ssl/http/notice logs and EVE alerts generated deterministically",
                "layer": "telemetry",
            },
            {
                "name": "Normalization",
                "role": "One event schema across Suricata, Zeek, RADIUS and IOS syslog",
                "layer": "detection",
            },
            {
                "name": "Detection + correlation",
                "role": "Declarative rules with evidence features and confidence scoring; IP → MAC → port attribution",
                "layer": "detection",
            },
            {
                "name": "Policy engine",
                "role": "Confidence/severity tiers with protected-port, trunk, SPAN and critical-asset guards",
                "layer": "response",
            },
            {
                "name": "Containment controller",
                "role": "Executes quarantine VLAN moves or administrative shutdowns through the switch adapter and verifies them",
                "layer": "response",
            },
            {
                "name": "Switch adapter",
                "role": "SwitchAdapter abstraction; SimulatedCisco2960XAdapter ships, IOSSSHAdapter documented",
                "layer": "response",
            },
            {
                "name": "SQLite evidence store",
                "role": "Operational state plus per-incident evidence bundles under data/incidents/",
                "layer": "platform",
            },
            {
                "name": "Dashboard / API",
                "role": "FastAPI + React SOC console with Server-Sent Events",
                "layer": "platform",
            },
        ],
        "stack": [
            "Python 3.11+",
            "FastAPI",
            "Pydantic",
            "SQLite",
            "React 19",
            "TypeScript",
            "Vite",
            "Recharts",
            "Playwright",
        ],
    }


# ---- SSE --------------------------------------------------------------------------------------
@router.get("/events/stream")
async def stream(request: Request):
    return StreamingResponse(
        bus.subscribe(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _safe_relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)
