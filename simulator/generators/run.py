"""Simulate the dataset day and write every artifact the repository ships with.

    python -m simulator.generators.run          (or: make seed / sentinelswitch generate)

The day is simulated once, in order: routine link events and authentications, the security scenarios
that occur before the baseline instant (each replayed through the real SentinelSwitch pipeline against
the twin), analyst resolutions, the deliberate configuration drift, and finally a dry run of the
flagship scenario on a copy of the twin so the post-quarantine Cisco transcripts and the SPAN feed
truncation are consistent with what `make demo` will produce.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelswitch.detection.engine import DetectionEngine
from sentinelswitch.detection.normalize import normalize
from sentinelswitch.simulator.scenario import (
    SECURITY_SYSLOG_PREFIXES,
    InMemoryTelemetry,
    RunResult,
    ScenarioRunner,
    _dns_dict,
    _flow_dict,
)
from sentinelswitch.simulator.twin import LogLine, SwitchTwin
from simulator.canonical import ROOT, Environment, add_seconds, load_environment, parse_ts, ts_iso

from . import cisco as cisco_writer
from . import suricata as suricata_writer
from . import zeek as zeek_writer
from .base import Flow, stable_rng
from .events import RecordFactory
from .radius import RadiusGenerator, link_events_for_day
from .syslog import baseline_syslog
from .traffic import TrafficModel

DATA = ROOT / "data"


@dataclass
class DayOutput:
    env: Environment
    twin: SwitchTwin
    post_twin: SwitchTwin
    auth_events: list[dict[str, Any]]
    syslog: list[dict[str, Any]]
    events: list[dict[str, Any]]
    flagship_events: list[dict[str, Any]]
    detections: list[dict[str, Any]]
    incidents: list[dict[str, Any]]
    reviews: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    timelines: dict[str, list[dict[str, Any]]]
    results: dict[str, RunResult]
    flagship: RunResult
    flows: list[Flow]
    dns: list
    http: list
    ssl: list
    notices: list[dict[str, Any]]
    suricata_alerts: list[dict[str, Any]]
    manifest: dict[str, Any] = field(default_factory=dict)


class DaySimulation:
    def __init__(self, env: Environment | None = None, root: Path = ROOT):
        self.env = env or load_environment()
        self.root = root

    # ---------------------------------------------------------------------------------------
    def run(self) -> DayOutput:
        env = self.env
        twin = SwitchTwin.baseline(env, now=env.day_start, apply_drift=False)
        auth_events = RadiusGenerator(env).generate()
        sys_lines = baseline_syslog(env, auth_events)
        traffic = TrafficModel(env)
        traffic.generate_all(auth_events)
        background = self._background_alerts(traffic)
        telemetry = InMemoryTelemetry(
            flows=[_flow_dict(f) for f in traffic.flows], dns=[_dns_dict(d) for d in traffic.dns]
        )

        evidence_root = self.root / "data" / "incidents"
        for stale in evidence_root.glob("INC-*"):
            shutil.rmtree(stale)
        runner = ScenarioRunner(env, twin, evidence_root=evidence_root, telemetry=telemetry, incident_seq=37)

        items: list[tuple[datetime, int, str, Any]] = []
        for ts, iface, state, host in link_events_for_day(env):
            items.append((ts, 0, "link", (iface, state, host)))
        for sid, sc in env.scenarios.items():
            inst = sc.instances.get("day")
            if not inst or inst.start >= env.baseline_now:
                continue
            items.append((inst.start, 1, "scenario", sid))
            res = inst.resolution or {}
            when = res.get("restored_at") or res.get("reviewed_at")
            if when:
                items.append((parse_ts(when), 2, "resolve", sid))
        for inj in env.drift_injections:
            items.append((parse_ts(inj["at"]), 3, "drift", inj))
        items.sort(key=lambda x: (x[0], x[1]))

        results: dict[str, RunResult] = {}
        for ts, _prio, kind, payload in items:
            if kind == "link":
                iface, state, host = payload
                twin.advance_to(ts)
                dev = env.device_by_hostname(host)
                if state == "up":
                    twin.attach(
                        dev.mac,
                        iface,
                        dev.vlan,
                        ip=dev.ip,
                        auth=dev.auth,
                        user=dev.user,
                        at=ts,
                        auth_state="guest" if dev.vlan == 40 else None,
                    )
                else:
                    twin.detach(iface, at=ts)
            elif kind == "scenario":
                results[payload] = runner.run(env.scenarios[payload], "day", write_evidence=True)
            elif kind == "resolve":
                runner.resolve(results[payload])
            elif kind == "drift":
                twin.advance_to(ts)
                twin.apply_drift([payload])
        twin.advance_to(env.baseline_now)

        # Flagship dry run on a copy: gives the post-quarantine transcripts and truncates the SPAN feed.
        post_twin = twin.copy()
        flag_runner = ScenarioRunner(env, post_twin, evidence_root=None, telemetry=telemetry, incident_seq=41)
        flagship = flag_runner.run(env.flagship(), "day", write_evidence=False)
        assert flagship.passed, f"flagship dry run failed: {flagship.checks}"

        # ---- assemble telemetry ---------------------------------------------------------
        flows = list(traffic.flows)
        dns = list(traffic.dns)
        for r in list(results.values()) + [flagship]:
            flows.extend(r.flows)
            dns.extend(r.dns)
        notices = [e["raw"] for r in list(results.values()) + [flagship] for e in r.events if e["source"] == "zeek"]
        suricata_alerts = [
            e["raw"] for r in list(results.values()) + [flagship] for e in r.events if e["source"] == "suricata"
        ]
        suricata_alerts += [raw for src, raw in background if src == "suricata"]

        # ---- syslog: baseline lines + scenario lines + lines the twin generated ----------
        syslog: list[dict[str, Any]] = []
        for ln in sys_lines:
            syslog.append(
                {
                    "ts": ts_iso(ln["ts"]),
                    "facility": ln["facility"],
                    "severity": ln["severity"],
                    "mnemonic": ln["mnemonic"],
                    "message": ln["message"],
                    "interface": ln.get("interface"),
                    "mac": ln.get("mac"),
                    "origin": "baseline",
                }
            )
        for r in list(results.values()) + [flagship]:
            for e in r.events:
                if e["source"] == "syslog":
                    raw = e["raw"]
                    syslog.append(
                        {
                            "ts": raw["ts"],
                            "facility": raw["facility"],
                            "severity": raw["severity"],
                            "mnemonic": raw["mnemonic"],
                            "message": raw["message"],
                            "interface": raw.get("interface"),
                            "mac": raw.get("mac"),
                            "origin": r.scenario.id,
                        }
                    )
        for line in post_twin.log:
            if line.ts >= ts_iso(env.day_start):
                syslog.append(
                    {
                        "ts": line.ts,
                        "facility": line.facility,
                        "severity": line.severity,
                        "mnemonic": line.mnemonic,
                        "message": line.message,
                        "interface": None,
                        "mac": None,
                        "origin": "switch",
                    }
                )
        syslog.sort(key=lambda x: x["ts"])
        seq0 = 1817
        for i, ln in enumerate(syslog):
            ln["seq"] = seq0 + i
        # the baseline twin keeps everything up to the baseline instant in its buffer
        twin.log = [
            LogLine(ln["ts"], ln["seq"], ln["facility"], int(ln["severity"]), ln["mnemonic"], ln["message"])
            for ln in syslog
            if ln["ts"] <= ts_iso(env.baseline_now)
        ]
        twin.log_seq = twin.log[-1].seq if twin.log else seq0
        post_twin.log = [
            LogLine(ln["ts"], ln["seq"], ln["facility"], int(ln["severity"]), ln["mnemonic"], ln["message"])
            for ln in syslog
        ]
        post_twin.log_seq = post_twin.log[-1].seq

        # ---- normalized event stream --------------------------------------------------------
        events: list[dict[str, Any]] = []
        for ev in auth_events:
            events.append(normalize(env, "radius", ev))
        for ln in syslog:
            if ln["origin"] in {"baseline", "switch"}:
                events.append(normalize(env, "syslog", {k: v for k, v in ln.items() if k not in {"origin", "seq"}}))
        for src, raw in background:
            events.append(normalize(env, src, raw))
        background_events = list(events)
        for r in results.values():
            events.extend(r.events)
        flagship_events = list(flagship.events)
        events.sort(key=lambda e: e["ts"])

        # Background detections (identity / policy rules over routine telemetry)
        engine = DetectionEngine(env)
        bg_detections = [
            d
            for d in engine.evaluate(background_events)
            if d.rule.id not in {s.rule for s in env.scenarios.values()} or d.confidence < 0.75
        ]
        detections: list[dict[str, Any]] = []
        for d in bg_detections:
            rec = d.to_dict()
            rec.update(
                {"scenario": None, "instance": None, "disposition": "monitor", "incident_id": None, "review": None}
            )
            detections.append(rec)
        incidents, reviews, actions = [], [], []
        timelines: dict[str, list[dict[str, Any]]] = {}
        for sid, r in results.items():
            for d in r.detections:
                rec = d.to_dict()
                is_primary = r.detection is not None and d.id == r.detection.id
                rec.update(
                    {
                        "scenario": sid,
                        "instance": "day",
                        "disposition": r.decision.disposition if is_primary and r.decision else "monitor",
                        "incident_id": r.incident["id"] if is_primary and r.incident else None,
                        "review": r.review if is_primary else None,
                    }
                )
                detections.append(rec)
            if r.incident:
                incidents.append(r.incident)
                timelines[r.incident["id"]] = r.timeline
            if r.review:
                rv = dict(r.review)
                rv.update(
                    {
                        "scenario": sid,
                        "rule": r.scenario.rule,
                        "actor": r.actor,
                        "attribution": r.attribution.to_dict() if r.attribution else None,
                        "decision": r.decision.to_dict() if r.decision else None,
                        "timeline": r.timeline,
                        "severity": r.detection.severity,
                        "confidence": r.detection.confidence,
                        "title": f"{r.scenario.name} — {r.attribution.device or r.actor.get('device')}",
                    }
                )
                reviews.append(rv)
                timelines[r.review["detection_id"]] = r.timeline
            if r.action and r.action.status in {"verified", "restored", "failed", "refused"}:
                actions.append(r.action.to_dict())
        detections.sort(key=lambda d: d["ts"])
        incidents.sort(key=lambda i: i["opened_at"])

        out = DayOutput(
            env,
            twin,
            post_twin,
            auth_events,
            syslog,
            events,
            flagship_events,
            detections,
            incidents,
            reviews,
            actions,
            timelines,
            results,
            flagship,
            flows,
            dns,
            traffic.http,
            traffic.ssl,
            notices,
            suricata_alerts,
        )
        out.manifest = {
            "flagship": {
                "derived": flagship.derived,
                "metrics": flagship.metrics,
                "incident": flagship.incident,
                "checks": flagship.checks,
            }
        }
        return out

    def _background_alerts(self, traffic: TrafficModel) -> list[tuple[str, dict[str, Any]]]:
        env = self.env
        rf = RecordFactory(env)
        ntp = next(f for f in traffic.flows if f.tags.get("policy") == "ntp")
        rf.suricata_alert(
            add_seconds(ntp.ts, 0.012), 1000050, ntp.orig_h, ntp.orig_p, ntp.resp_h, 123, "udp", app_proto="ntp"
        )
        # rahmed manages SRV-DC01 over WinRM from the IT laptop: the low-severity WinRM signature fires once.
        rng = stable_rng(env, "background-winrm")
        it = env.device_by_hostname("IT-LT-037")
        ts = parse_ts("2026-03-17T10:12:33.618Z")
        traffic.flows.append(
            Flow(
                ts, it.ip, 52114, "10.30.0.10", 5985, "tcp", "http", 184.2, 48_211, 120_944, "SF", "ShADadFf", 212, 240
            )
        )
        rf.suricata_alert(add_seconds(ts, 0.014), 1000024, it.ip, 52114, "10.30.0.10", 5985, "tcp", app_proto="http")
        rng.random()
        return rf.records


# -------------------------------------------------------------------------------------------------
# Writers
# -------------------------------------------------------------------------------------------------
def _pri(severity: int) -> int:
    return 23 * 8 + int(severity)


def _syslog_line(hostname: str, ln: dict[str, Any]) -> str:
    dt = parse_ts(ln["ts"])
    stamp = dt.strftime("%b %d %H:%M:%S.") + f"{dt.microsecond // 1000:03d} UTC"
    return f"<{_pri(ln['severity'])}>{ln['seq']}: {hostname}: {stamp}: %{ln['facility']}-{ln['severity']}-{ln['mnemonic']}: {ln['message']}"


def _radius_line(ev: dict[str, Any]) -> str:
    dt = parse_ts(ev["timestamp"])
    stamp = dt.strftime("%a %b %d %H:%M:%S %Y")
    n = int(ev["event_id"].split("-")[-1]) if ev["event_id"].split("-")[-1].isdigit() else 0
    port = ev["nas_port"]
    cli = ev["calling_station_id"]
    if ev["result"] == "Access-Accept":
        return (
            f"{stamp} : Auth: ({n}) Login OK: [{ev['identity']}] (from client {ev['nas_identifier']} port {port} cli {cli} via TLS tunnel)"
            if ev["method"] != "MAB"
            else f"{stamp} : Auth: ({n}) Login OK: [{ev['identity']}] (from client {ev['nas_identifier']} port {port} cli {cli})"
        )
    if ev["result"] == "Access-Reject":
        return f"{stamp} : Auth: ({n}) Login incorrect ({ev['reason']}): [{ev['identity']}] (from client {ev['nas_identifier']} port {port} cli {cli})"
    return f"{stamp} : Info: ({n}) {ev['result']}: [{ev['identity']}] (from client {ev['nas_identifier']} port {port} cli {cli}) {ev.get('reason', '')}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def derive_alerts(
    env: Environment,
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Rows for the Alerts view: every alert-worthy raw event, linked to the detection/incident that consumed it."""
    ref_index: dict[tuple[str, str], dict[str, Any]] = {}
    for d in detections:
        for ref in d["event_refs"]:
            ref_index.setdefault((ref["ts"], ref["source"]), d)
    inc_status = {i["id"]: i["status"] for i in incidents}
    inc_by_scenario = {i["scenario"]: i for i in incidents}
    review_by_scenario = {r["scenario"]: r for r in reviews}
    review_status = {r["detection_id"]: r["status"] for r in reviews}
    rows = []
    n = 0
    for e in sorted(events, key=lambda x: x["ts"]):
        src = e["source"]
        worthy = (
            src in {"suricata", "zeek"}
            or (src == "radius" and e["result"] == "Access-Reject")
            or (src == "syslog" and e["mnemonic"].startswith(SECURITY_SYSLOG_PREFIXES))
        )
        if not worthy:
            continue
        n += 1
        det = ref_index.get((e["ts"], src))
        status = "informational"
        incident_id = det["incident_id"] if det else None
        if det:
            if incident_id:
                status = inc_status.get(incident_id, "open")
            elif det.get("review"):
                status = review_status.get(det["id"], det["review"]["status"])
            else:
                status = det.get("disposition", "monitor")
        elif e.get("scenario") in inc_by_scenario:
            inc = inc_by_scenario[e["scenario"]]
            incident_id, status = inc["id"], inc["status"]
            det = {"id": inc["detection_id"]}
        elif e.get("scenario") in review_by_scenario:
            rv = review_by_scenario[e["scenario"]]
            status = rv["status"]
            det = {"id": rv["detection_id"]}
        elif src == "radius":
            status = "closed"
        rows.append(
            {
                "id": f"ALT-{n:05d}",
                "ts": e["ts"],
                "source": src,
                "severity": e.get("severity", "info"),
                "signature": e.get("signature")
                or e.get("note")
                or (f"%{e['mnemonic']}" if src == "syslog" else f"RADIUS {e['result']} ({e.get('method')})"),
                "signature_id": e.get("signature_id"),
                "category": e.get("category")
                or e.get("sentinel_class")
                or ("aaa" if src == "radius" else "switch-security" if src == "syslog" else "zeek"),
                "src_ip": e.get("src_ip"),
                "src_port": e.get("src_port"),
                "dest_ip": e.get("dest_ip"),
                "dest_port": e.get("dest_port"),
                "proto": e.get("proto"),
                "mac": e.get("mac"),
                "interface": e.get("interface"),
                "device": e.get("device"),
                "summary": e.get("summary"),
                "status": status,
                "detection_id": det["id"] if det else None,
                "incident_id": incident_id,
                "scenario": e.get("scenario"),
                "raw": e.get("raw"),
            }
        )
    return rows


def traffic_buckets(
    env: Environment,
    flows: list[Flow],
    dns_count_by_bucket: dict[int, int],
    alerts: list[dict[str, Any]],
    minutes: int = 15,
) -> list[dict[str, Any]]:
    start = env.day_start
    n = int(24 * 60 / minutes)
    buckets = [
        {
            "ts": ts_iso(start + timedelta(minutes=i * minutes)),
            "connections": 0,
            "bytes": 0,
            "dns_queries": 0,
            "alerts": 0,
            "hosts": set(),
        }
        for i in range(n)
    ]
    for f in flows:
        i = int((f.ts - start).total_seconds() // (minutes * 60))
        if 0 <= i < n:
            b = buckets[i]
            b["connections"] += 1
            b["bytes"] += f.orig_bytes + f.resp_bytes
            b["hosts"].add(f.orig_h)
            if f.service == "dns":
                b["dns_queries"] += 1
    for a in alerts:
        i = int((parse_ts(a["ts"]) - start).total_seconds() // (minutes * 60))
        if 0 <= i < n:
            buckets[i]["alerts"] += 1
    for b in buckets:
        b["hosts"] = len(b["hosts"])
    return buckets


def write_all(out: DayOutput, root: Path = ROOT) -> dict[str, Any]:
    env = out.env
    data = root / "data"
    for sub in ("zeek", "suricata", "radius", "cisco", "seed", "generated"):
        (data / sub).mkdir(parents=True, exist_ok=True)

    counts: dict[str, Any] = {}
    counts["zeek"] = zeek_writer.write_all(env, data / "zeek", out.flows, out.dns, out.http, out.ssl, out.notices)
    scenario_flows = [f for f in out.flows if f.scenario]
    counts["suricata"] = suricata_writer.write_eve(
        env, data / "suricata" / "eve.json", out.suricata_alerts, scenario_flows
    )

    # RADIUS
    zeek_writer.write_jsonl(
        data / "radius" / "auth-events.jsonl",
        out.auth_events + [e["raw"] for e in out.events if e["source"] == "radius" and e.get("scenario")],
    )
    radius_all = sorted(
        out.auth_events + [e["raw"] for e in out.events if e["source"] == "radius" and e.get("scenario")],
        key=lambda e: e["timestamp"],
    )
    (data / "radius" / "radius.log").write_text("\n".join(_radius_line(e) for e in radius_all) + "\n", encoding="utf-8")
    counts["radius"] = {
        "events": len(radius_all),
        "accepts": sum(1 for e in radius_all if e["result"] == "Access-Accept"),
        "rejects": sum(1 for e in radius_all if e["result"] == "Access-Reject"),
    }

    # Syslog
    (data / "cisco" / "SW01-syslog.log").write_text(
        "\n".join(_syslog_line(env.hostname, ln) for ln in out.syslog) + "\n", encoding="utf-8"
    )
    zeek_writer.write_jsonl(data / "cisco" / "SW01-syslog.jsonl", out.syslog)
    counts["syslog"] = len(out.syslog)

    # Cisco artifacts
    cisco_dir = root / "cisco"
    if (cisco_dir / "show-output").exists():
        shutil.rmtree(cisco_dir / "show-output")
    cisco_writer.write_show_outputs(
        out.twin, cisco_dir / "show-output" / "pre-quarantine", "baseline, before INC-2026-0042"
    )
    cisco_writer.write_show_outputs(
        out.post_twin, cisco_dir / "show-output" / "post-quarantine", "after INC-2026-0042 automated containment"
    )
    cisco_writer.write_configs(env, out.twin, cisco_dir / "configs")

    # Normalized events and seeds
    events_sorted = sorted(out.events, key=lambda e: e["ts"])
    zeek_writer.write_jsonl(data / "generated" / "events.jsonl", events_sorted)
    zeek_writer.write_jsonl(data / "generated" / "flagship-events.jsonl", out.flagship_events)
    alerts = derive_alerts(env, events_sorted, out.detections, out.incidents, out.reviews)
    buckets = traffic_buckets(
        env,
        out.flows,
        {},
        alerts + [{"ts": e["ts"]} for e in out.flagship_events if e["source"] in {"suricata", "zeek"}],
    )

    seed = data / "seed"
    _json(
        seed / "environment.json",
        {
            "organization": env.organization,
            "dataset": env.dataset,
            "switch": env.switch,
            "vlans": [v.__dict__ for v in env.vlans.values()],
            "dhcp": env.dhcp,
            "approved_ntp": env.approved_ntp,
            "approved_dns": env.approved_dns,
            "external_services": [e.__dict__ for e in env.external_services],
        },
    )
    _json(
        seed / "inventory.json",
        [_device_dict(env, d) for d in env.devices]
        + [
            {
                "hostname": None,
                "label": u.label,
                "description": u.description,
                "mac": u.mac,
                "interface": u.interface,
                "schedule": [ts_iso(u.schedule[0]), ts_iso(u.schedule[1])],
                "known": False,
                "vendor": env.vendor_for_mac(u.mac),
            }
            for u in env.unknown_devices
        ],
    )
    _json(seed / "users.json", [u.__dict__ for u in env.users.values()])
    _json(seed / "switch-state.json", out.twin.to_dict())
    _json(seed / "switch-state-post-flagship.json", out.post_twin.to_dict())
    _json(seed / "detections.json", out.detections)
    _json(seed / "incidents.json", out.incidents)
    _json(seed / "reviews.json", out.reviews)
    _json(seed / "containment-actions.json", out.actions)
    _json(seed / "timelines.json", out.timelines)
    _json(seed / "alerts.json", alerts)
    _json(seed / "traffic-buckets.json", buckets)
    _json(seed / "scenarios.json", [_scenario_dict(s) for s in env.scenarios.values()])
    counts["alerts"] = len(alerts)
    counts["detections"] = len(out.detections)
    counts["incidents"] = len(out.incidents)
    counts["reviews"] = len(out.reviews)
    counts["events"] = len(events_sorted)
    counts["flagship_events"] = len(out.flagship_events)
    counts["devices"] = len(env.devices)

    files = sorted(p for p in (data / "zeek").glob("*")) + [
        data / "suricata" / "eve.json",
        data / "radius" / "auth-events.jsonl",
        data / "radius" / "radius.log",
        data / "cisco" / "SW01-syslog.log",
        data / "generated" / "events.jsonl",
        data / "generated" / "flagship-events.jsonl",
    ]
    manifest = {
        "generated_for": env.dataset,
        "seed": env.seed,
        "counts": counts,
        "flagship": out.manifest.get("flagship"),
        "files": {
            str(p.relative_to(root)): {"sha256": _sha256(p), "bytes": p.stat().st_size} for p in files if p.is_file()
        },
        "note": "Synthetic dataset produced by simulator/generators/run.py; regenerate with `make seed`.",
    }
    _json(data / "generated" / "manifest.json", manifest)
    return manifest


def _device_dict(env: Environment, d) -> dict[str, Any]:
    return {
        "hostname": d.hostname,
        "role": d.role,
        "vendor": d.vendor,
        "os": d.os,
        "mac": d.mac,
        "ip": d.ip,
        "vlan": d.vlan,
        "interface": d.interface,
        "criticality": d.criticality,
        "auth": d.auth,
        "user": d.user,
        "tags": d.tags,
        "services": d.services,
        "via_trunk": d.via_trunk,
        "secondary_ips": {str(k): v for k, v in d.secondary_ips.items()},
        "schedule": [ts_iso(d.schedule[0]), ts_iso(d.schedule[1])] if d.schedule else None,
        "online_at_baseline": d.present_at(env.baseline_now),
        "dhcp_reservation": d.dhcp_reservation,
        "asset_tag": d.asset_tag,
        "notes": d.notes,
        "known": True,
    }


def _scenario_dict(s) -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "short": s.short,
        "class": s.klass,
        "rule": s.rule,
        "mitre": s.mitre,
        "description": s.description,
        "flagship": s.flagship,
        "actor": s.actor,
        "timing": s.timing,
        "instances": {
            k: {
                "start": ts_iso(v.start),
                "incident_id": v.incident_id,
                "expected": v.expected,
                "parameters": v.parameters,
                "resolution": v.resolution,
                "actor_override": v.actor_override,
            }
            for k, v in s.instances.items()
        },
    }


def generate(root: Path = ROOT, quiet: bool = False) -> dict[str, Any]:
    env = load_environment()
    sim = DaySimulation(env, root)
    out = sim.run()
    manifest = write_all(out, root)
    if not quiet:
        print(json.dumps(manifest["counts"], indent=2))
    return manifest


if __name__ == "__main__":
    generate()
