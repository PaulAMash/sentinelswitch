"""Scenario runner: replays a scenario instance through the complete SentinelSwitch pipeline.

    telemetry -> normalization -> correlation rules -> attribution -> policy -> containment -> verification -> evidence

The runner drives a simulated clock so every phase gets a deterministic timestamp derived from the
scenario's traffic model and its declared engine latencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from sentinelswitch.containment.adapters import SimulatedCisco2960XAdapter
from sentinelswitch.containment.controller import ContainmentAction, ContainmentController
from sentinelswitch.containment.policy import Decision, PolicyEngine
from sentinelswitch.correlation.engine import Attribution, Clock, CorrelationEngine
from sentinelswitch.detection.engine import Detection, DetectionEngine, load_rules
from sentinelswitch.detection.normalize import normalize
from sentinelswitch.evidence.bundle import write_bundle
from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import (
    Environment,
    Scenario,
    ScenarioInstance,
    add_seconds,
    mac_norm,
    parse_ts,
    short_ifname,
    ts_iso,
)
from simulator.generators.base import DnsRecord, Flow
from simulator.generators.scenarios import ScenarioOutput, emit

SECURITY_SYSLOG_PREFIXES = (
    "SW_DAI",
    "DHCP_SNOOPING",
    "PORT_SECURITY",
    "SPANTREE-2",
    "PM-4-ERR",
    "MAB-5-FAIL",
    "DOT1X-5-FAIL",
)


class TelemetryStore(Protocol):
    def flows_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]: ...

    def dns_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]: ...


class InMemoryTelemetry:
    def __init__(self, flows: list[dict[str, Any]] | None = None, dns: list[dict[str, Any]] | None = None):
        self.flows = flows or []
        self.dns = dns or []

    def flows_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        lo, hi = start.timestamp(), end.timestamp()
        return [
            f
            for f in self.flows
            if (f.get("id.orig_h") == ip or f.get("id.resp_h") == ip) and lo <= float(f["ts"]) <= hi
        ]

    def dns_for(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        lo, hi = start.timestamp(), end.timestamp()
        return [d for d in self.dns if d.get("id.orig_h") == ip and lo <= float(d["ts"]) <= hi]


@dataclass
class RunResult:
    scenario: Scenario
    instance: ScenarioInstance
    actor: dict[str, Any]
    events: list[dict[str, Any]]
    detections: list[Detection]
    detection: Detection | None
    attribution: Attribution | None
    decision: Decision | None
    action: ContainmentAction | None
    incident: dict[str, Any] | None
    review: dict[str, Any] | None
    timeline: list[dict[str, Any]]
    metrics: dict[str, Any]
    checks: dict[str, bool]
    narrative: list[dict[str, Any]]
    flows: list[Flow]
    dns: list[DnsRecord]
    evidence_dir: str | None = None
    applied_at: datetime | None = None
    derived: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(self.checks.values())


class ScenarioRunner:
    def __init__(
        self,
        env: Environment,
        twin: SwitchTwin,
        *,
        evidence_root: Path | None = None,
        telemetry: TelemetryStore | None = None,
        incident_seq: int = 38,
        policy: PolicyEngine | None = None,
    ):
        self.env = env
        self.twin = twin
        self.evidence_root = evidence_root
        self.telemetry = telemetry or InMemoryTelemetry()
        self.policy = policy or PolicyEngine()
        self.adapter = SimulatedCisco2960XAdapter(twin)
        self.controller = ContainmentController(
            self.adapter, quarantine_vlan=int(self.policy.policy["quarantine_vlan"])
        )
        self.rules = load_rules()
        self._incident_seq = incident_seq

    # ---------------------------------------------------------------------------------------
    # Twin fixtures
    # ---------------------------------------------------------------------------------------
    def apply_ops(
        self, ops: list[dict[str, Any]], base: datetime, params: dict[str, Any], default_at: datetime | None = None
    ) -> None:
        for op in ops:
            at = (
                parse_ts(op["at"])
                if op.get("at")
                else add_seconds(base, float(op.get("offset", 0.0)))
                if "offset" in op
                else (default_at or base)
            )
            kind = op["op"]
            if kind == "link_up":
                mac = str(op["mac"]).format(**params)
                dev = self.env.device_by_mac(mac)
                self.twin.attach(
                    mac,
                    op["interface"],
                    int(op.get("vlan", self.env.ports[op["interface"]].access_vlan or 20)),
                    ip=op.get("ip") or (dev.ip if dev else None),
                    auth=(dev.auth if dev else "none"),
                    user=(dev.user if dev else None),
                    at=at,
                    auth_state=op.get("auth_state"),
                )
            elif kind == "link_down":
                self.twin.detach(op["interface"], at=at)
            elif kind == "reattach":
                dev = self.env.device_by_hostname(op["device"])
                self.twin.attach(
                    dev.mac,
                    dev.interface,
                    dev.vlan,
                    ip=dev.ip,
                    auth=dev.auth,
                    user=dev.user,
                    at=at,
                    auth_state="guest" if dev.vlan == 40 else None,
                )
            else:
                raise ValueError(f"unknown op {kind}")

    def _apply_switch_effects(self, out: ScenarioOutput) -> str | None:
        native = None
        for eff in out.switch_effects:
            at = parse_ts(eff["ts"])
            if eff["op"] == "errdisable":
                self.twin.errdisable(eff["interface"], eff["reason"], at)
                native = "err-disabled"
            elif eff["op"] == "psecure_violation":
                self.twin.port_security_violation(eff["interface"], eff["mac"], at)
        return native

    # ---------------------------------------------------------------------------------------
    # Main pipeline
    # ---------------------------------------------------------------------------------------
    def run(
        self, scenario: Scenario, instance_name: str, *, write_evidence: bool = True, apply_setup: bool = True
    ) -> RunResult:
        inst = scenario.instances[instance_name]
        out = emit(self.env, scenario, instance_name)
        events = [normalize(self.env, src, raw) for src, raw in out.records]
        params = inst.parameters
        t0 = inst.start
        if apply_setup:
            self.apply_ops(scenario.setup, t0, params, default_at=add_seconds(t0, -1.0))
        self.twin.advance_to(t0)
        native_state = self._apply_switch_effects(out)

        timeline: list[dict[str, Any]] = []

        def tl(ts: str, phase: str, message: str, actor: str = "sensor", **details: Any) -> None:
            timeline.append({"ts": ts, "phase": phase, "actor": actor, "message": message, "details": details or None})

        for n in out.narrative:
            tl(n["ts"], n["phase"], n["message"], actor="telemetry")
        for e in events:
            if e["source"] == "suricata":
                tl(
                    e["ts"],
                    "alert",
                    f"Suricata sid {e['signature_id']} ({e['severity']}): {e['signature']}",
                    actor="suricata",
                    src=e.get("src_ip"),
                    dest=e.get("dest_ip"),
                    dest_port=e.get("dest_port"),
                )
            elif e["source"] == "zeek":
                tl(e["ts"], "alert", f"Zeek notice {e['note']}: {e['msg']}", actor="zeek")
            elif e["source"] == "radius" and e["result"] != "Access-Accept":
                tl(
                    e["ts"],
                    "aaa",
                    f"RADIUS {e['result']} ({e['method']}) for {e['mac']} on {e['interface']}: {e.get('reason')}",
                    actor="freeradius",
                )
            elif e["source"] == "syslog" and e["mnemonic"].startswith(SECURITY_SYSLOG_PREFIXES):
                tl(e["ts"], "switch", f"SW01 %{e['mnemonic']}: {e['message']}", actor="SW01")

        engine = DetectionEngine(
            self.env, self.rules, latency_by_rule={scenario.rule: float(params.get("detect_latency", 0.05))}
        )
        detections = engine.evaluate(events)
        primary = next((d for d in detections if d.rule.id == scenario.rule), None)
        expected = inst.expected
        actor = out.actor
        metrics: dict[str, Any] = {"t0": ts_iso(t0)}
        alert_ts = [
            e["ts"]
            for e in events
            if e["source"] in {"suricata", "zeek"}
            or (e["source"] == "radius" and e["result"] == "Access-Reject")
            or (e["source"] == "syslog" and e["mnemonic"].startswith(SECURITY_SYSLOG_PREFIXES))
        ]
        metrics["first_alert"] = min(alert_ts) if alert_ts else None

        result = RunResult(
            scenario,
            inst,
            actor,
            events,
            detections,
            primary,
            None,
            None,
            None,
            None,
            None,
            timeline,
            metrics,
            {"detect": False, "attribute": False, "contain": False},
            out.narrative,
            out.flows,
            out.dns,
            derived=out.derived,
        )
        if primary is None:
            tl(
                ts_iso(add_seconds(t0, 1)),
                "detection",
                f"No detection produced by rule {scenario.rule}",
                actor="sentinel",
            )
            return result

        # ---- detection ----------------------------------------------------------------------
        feats = ", ".join(f"{f.id}{'+' if f.weight > 0 else ''}{f.weight:.2f}" for f in primary.features if f.matched)
        tl(
            primary.ts,
            "detection",
            f"Rule {primary.rule.id} matched: severity {primary.severity}, confidence {primary.confidence:.2f} (base {primary.rule.base_confidence:.2f}; {feats or 'no features'})",
            actor="sentinel",
            detection_id=primary.id,
            sources=sorted({e["source"] for e in primary.events}),
        )
        metrics["detection"] = primary.ts
        metrics["ttd"] = round((parse_ts(primary.ts) - t0).total_seconds(), 3)
        result.checks["detect"] = (
            primary.severity == expected.get("severity", primary.severity)
            and abs(primary.confidence - float(expected.get("confidence", primary.confidence))) < 0.006
        )

        # ---- attribution --------------------------------------------------------------------
        clock = Clock(parse_ts(primary.ts))
        trigger = primary.events[0] if primary.events else {}
        trig_event = next((e for e in primary.events if e["ts"] == primary.trigger_ts), trigger)
        ip = primary.actor_value if primary.actor_key in {"src_ip", "actor_ip"} else None
        mac = None
        iface_hint = None
        if primary.actor_key == "mac":
            mac = primary.actor_value
            iface_hint = trig_event.get("interface")
        elif primary.actor_key == "interface":
            iface_hint = primary.actor_value
            mac = trig_event.get("new_mac") or trig_event.get("mac")
        hints = {
            "interface_source": "RADIUS NAS-Port-Id"
            if trig_event.get("source") == "radius"
            else "syslog interface field"
        }
        correlator = CorrelationEngine(self.env, self.twin, timing=scenario.timing)
        tl(
            ts_iso(add_seconds(clock.now, scenario.timing.get("open", 0.08))),
            "correlation",
            f"Resolving actor {ip or mac or iface_hint} through DHCP snooping, MAC table and inventory",
            actor="sentinel",
        )
        attribution = correlator.resolve(ip=ip, mac=mac, interface=iface_hint, hints=hints, clock=clock)
        for step in attribution.steps:
            tl(
                step.ts,
                "correlation",
                f"{step.name} [{step.status}] {step.detail}",
                actor="sentinel",
                source=step.source,
            )
        result.attribution = attribution
        metrics["attribution_complete"] = attribution.completed_at
        metrics["tta"] = round((parse_ts(attribution.completed_at) - parse_ts(primary.ts)).total_seconds(), 3)
        result.checks["attribute"] = (
            bool(attribution.interface)
            and short_ifname(attribution.interface) == short_ifname(actor["interface"])
            and (
                attribution.mac is None
                or actor.get("mac") is None
                or mac_norm(attribution.mac) == mac_norm(actor["mac"])
                or scenario.id == "mac-address-change"
            )
        )

        # ---- policy -------------------------------------------------------------------------
        decision_at = clock.advance(scenario.timing.get("policy", 0.15))
        sources = len({e["source"] for e in primary.events})
        decision = self.policy.decide(
            severity=primary.severity,
            confidence=primary.confidence,
            klass=primary.rule.klass,
            attribution=attribution,
            corroborating_sources=sources,
        )
        result.decision = decision
        tl(
            ts_iso(decision_at),
            "policy",
            f"Disposition {decision.disposition}: {decision.reason}",
            actor="sentinel",
            action=decision.action,
            guards=decision.guards_triggered,
        )
        metrics["decision"] = ts_iso(decision_at)

        # ---- authorization ------------------------------------------------------------------
        from sentinelswitch.containment.controller import authorization_record

        authorization = authorization_record(decision, at=clock.now)
        if authorization["status"] == "authorized":
            tl(
                ts_iso(add_seconds(decision_at, 0.002)),
                "authorization",
                f"Containment authorized by {authorization['authorized_by']} ({authorization['basis']}); action {authorization['action']}",
                actor="sentinel",
                mode=authorization["mode"],
            )
        elif decision.disposition == "manual_review":
            tl(
                ts_iso(add_seconds(decision_at, 0.002)),
                "authorization",
                "Automatic containment NOT authorized: "
                + (
                    f"guard(s) {', '.join(decision.guards_triggered)} require analyst approval"
                    if decision.guards_triggered
                    else "confidence below the automatic tier; analyst approval required"
                ),
                actor="sentinel",
                mode="pending",
                guards=decision.guards_triggered,
            )
        # ---- incident / review --------------------------------------------------------------
        incident: dict[str, Any] | None = None
        if decision.disposition == "automatic_containment":
            incident_id = inst.incident_id or self._next_incident_id(instance_name)
            incident = self._incident_record(incident_id, scenario, primary, attribution, decision, instance_name)
            incident["authorization"] = authorization
            tl(
                ts_iso(add_seconds(decision_at, 0.004)),
                "incident",
                f"Incident {incident_id} opened",
                actor="sentinel",
                incident_id=incident_id,
            )
        else:
            result.review = {
                "authorization": authorization,
                "detection_id": primary.id,
                "status": "review" if decision.disposition == "manual_review" else "monitor",
                "opened_at": ts_iso(decision_at),
                "closed_at": None,
                "closed_by": None,
                "note": None,
            }

        # ---- containment --------------------------------------------------------------------
        action = self.controller.contain(
            decision=decision,
            attribution=attribution,
            detection_id=primary.id,
            summary=primary.summary,
            incident_id=incident["id"] if incident else None,
            clock=clock,
            timing=scenario.timing,
            native_state=native_state,
            authorization=authorization,
        )
        result.action = action
        if action.status in {"applied", "verified", "failed"}:
            if action.action == "quarantine_vlan":
                tl(
                    action.applied_at,
                    "containment",
                    f"{action.switch} {action.interface}: switchport access vlan {action.from_vlan} → {action.to_vlan} (workflow {action.workflow_id})",
                    actor="sentinel",
                    workflow=action.workflow_id,
                    commands=action.commands,
                )
            else:
                tl(
                    action.applied_at,
                    "containment",
                    f"{action.switch} {action.interface}: administrative shutdown (workflow {action.workflow_id}) — {action.mechanism}",
                    actor="sentinel",
                    workflow=action.workflow_id,
                    commands=action.commands,
                )
            ok = action.verification.get("ok")
            tl(
                action.verified_at,
                "verification",
                f"Verification {'succeeded' if ok else 'FAILED'}: {action.verification.get('expected')}",
                actor="sentinel",
            )
            result.applied_at = parse_ts(action.applied_at)
            metrics["applied"] = action.applied_at
            metrics["verified"] = action.verified_at
            metrics["ttc"] = round((parse_ts(action.verified_at) - parse_ts(primary.ts)).total_seconds(), 3)
            metrics["end_to_end"] = round((parse_ts(action.verified_at) - t0).total_seconds(), 3)
            # Traffic after containment is no longer on the SPAN feed.
            result.flows = [f for f in out.flows if f.ts <= result.applied_at]
            result.dns = [d for d in out.dns if d.ts <= result.applied_at]
            if len(result.flows) != len(out.flows):
                tl(
                    ts_iso(add_seconds(result.applied_at, 0.05)),
                    "telemetry",
                    f"Telemetry from {actor.get('ip') or actor.get('mac')} no longer observed on monitored VLANs ({len(out.flows) - len(result.flows)} further probe flows not seen)",
                    actor="telemetry",
                )
        elif action.status == "refused":
            tl(
                ts_iso(clock.now),
                "containment",
                f"Adapter refused action on {attribution.interface}: {'; '.join(action.notes)}",
                actor="sentinel",
            )

        # ---- checks -------------------------------------------------------------------------
        exp_disp = expected.get("disposition")
        exp_action = expected.get("action", "none")
        if exp_disp == "automatic_containment":
            result.checks["contain"] = (
                decision.disposition == exp_disp
                and action.action == exp_action
                and action.status == "verified"
                and bool(action.verification.get("ok"))
            )
        else:
            guard_ok = not expected.get("guard") or expected["guard"] in decision.guards_triggered
            result.checks["contain"] = (
                decision.disposition == exp_disp and action.status == "not_applicable" and guard_ok
            )

        if incident:
            incident["workflow_id"] = action.workflow_id
            incident["mechanism"] = action.mechanism
            incident["current_vlan"] = (
                self.twin.interfaces[attribution.interface].oper_vlan if attribution.interface else None
            )
            incident["status"] = "contained" if action.status == "verified" else "containment_failed"
            incident["contained_at"] = action.verified_at
            result.incident = incident
            evidence_at = clock.advance(scenario.timing.get("evidence", 0.33))
            metrics["evidence"] = ts_iso(evidence_at)
            incident["evidence_finalized_at"] = ts_iso(evidence_at)
            result.timeline.sort(key=lambda t: t["ts"])
            if write_evidence and self.evidence_root is not None:
                path = self._write_evidence(result, evidence_at)
                result.evidence_dir = str(path)
                incident["evidence_path"] = (
                    str(path.relative_to(self.evidence_root.parent.parent))
                    if self.evidence_root.parent.parent in path.parents
                    else str(path)
                )
            tl(
                ts_iso(evidence_at),
                "evidence",
                f"Evidence bundle {incident['id']} finalized ({len(result.flows)} related connections, {len(result.dns)} DNS records)",
                actor="sentinel",
            )
        result.timeline.sort(key=lambda t: t["ts"])
        return result

    # ---------------------------------------------------------------------------------------
    def resolve(self, result: RunResult) -> None:
        """Apply the instance's resolution block: analyst restore or review closure, then teardown."""
        inst = result.instance
        res = inst.resolution or {}
        scenario = result.scenario
        removed_at = parse_ts(res["device_removed"]) if res.get("device_removed") else None
        if result.action and result.action.status == "verified" and res.get("restored_at"):
            at = parse_ts(res["restored_at"])
            if removed_at:
                self.twin.advance_to(removed_at)
                self.apply_ops(
                    [op for op in scenario.teardown if op["op"] != "reattach"],
                    removed_at,
                    inst.parameters,
                    default_at=removed_at,
                )
                result.timeline.append(
                    {
                        "ts": ts_iso(removed_at),
                        "phase": "resolution",
                        "actor": "analyst",
                        "message": "Offending device physically removed after inspection",
                        "details": None,
                    }
                )
            self.twin.advance_to(at)
            self.controller.restore(result.action, actor=res["restored_by"], note=res["note"], at=at)
            result.timeline.append(
                {
                    "ts": ts_iso(at),
                    "phase": "resolution",
                    "actor": res["restored_by"],
                    "message": f"Containment released by {res['restored_by']}: {res['note']}",
                    "details": {"transcript": result.action.restore_transcript},
                }
            )
            if result.incident:
                result.incident["status"] = "resolved"
                result.incident["closed_at"] = ts_iso(at)
                result.incident["closed_by"] = res["restored_by"]
                result.incident["resolution_note"] = res["note"]
                result.incident["current_vlan"] = (
                    self.twin.interfaces[result.incident["interface"]].oper_vlan
                    if result.incident.get("interface")
                    else None
                )
            self.apply_ops(
                [op for op in scenario.teardown if op["op"] == "reattach"],
                at,
                inst.parameters,
                default_at=add_seconds(at, 30),
            )
        elif result.review and res.get("reviewed_at"):
            at = parse_ts(res["reviewed_at"])
            self.twin.advance_to(at)
            result.review.update(
                {"closed_at": ts_iso(at), "closed_by": res["reviewed_by"], "note": res["note"], "status": "closed"}
            )
            result.review["authorization"] = dict(
                result.review.get("authorization") or {},
                status="rejected",
                mode="analyst",
                authorized_by=res["reviewed_by"],
                authorized_at=ts_iso(at),
                note=f"Containment declined after review: {res['note']}",
            )
            result.timeline.append(
                {
                    "ts": ts_iso(at),
                    "phase": "resolution",
                    "actor": res["reviewed_by"],
                    "message": f"Review closed by {res['reviewed_by']}: {res['note']}",
                    "details": None,
                }
            )
            # Only explicitly timed teardown steps apply here; scheduled devices leave on their own schedule.
            self.apply_ops([op for op in scenario.teardown if op.get("at")], at, inst.parameters, default_at=at)
        result.timeline.sort(key=lambda t: t["ts"])

    # ---------------------------------------------------------------------------------------
    def _next_incident_id(self, instance_name: str) -> str:
        self._incident_seq += 1
        prefix = "INC-2026" if instance_name == "day" else "VAL-2026"
        return f"{prefix}-{self._incident_seq:04d}"

    def _incident_record(
        self,
        incident_id: str,
        scenario: Scenario,
        det: Detection,
        attribution: Attribution,
        decision: Decision,
        instance_name: str,
    ) -> dict[str, Any]:
        endpoint = attribution.device or (f"unknown device {attribution.mac}" if attribution.mac else "unknown device")
        if attribution.impersonated_device:
            endpoint = f"unknown device impersonating {attribution.impersonated_device}"
        return {
            "id": incident_id,
            "title": f"{det.rule.name} — {endpoint}",
            "severity": det.severity,
            "confidence": det.confidence,
            "status": "open",
            "opened_at": det.ts,
            "closed_at": None,
            "rule": det.rule.id,
            "rule_name": det.rule.name,
            "class": det.rule.klass,
            "mitre": det.rule.mitre,
            "scenario": scenario.id,
            "instance": instance_name,
            "detection_id": det.id,
            "device": attribution.device,
            "user": attribution.user,
            "department": attribution.department,
            "ip": attribution.ip,
            "mac": attribution.mac,
            "vendor": attribution.vendor,
            "switch": attribution.switch,
            "interface": attribution.interface,
            "original_vlan": attribution.vlan,
            "current_vlan": attribution.vlan,
            "port_class": attribution.port_class,
            "chain": attribution.chain
            + (
                [f"VLAN {decision.quarantine_vlan}"]
                if decision.action == "quarantine_vlan"
                else ["shutdown"]
                if decision.action == "port_shutdown"
                else []
            ),
            "summary": scenario.description,
            "disposition": decision.disposition,
            "action": decision.action,
            "attribution_confidence": attribution.confidence,
            "flags": attribution.flags,
            "impersonated_device": attribution.impersonated_device,
        }

    def _write_evidence(self, result: RunResult, evidence_at: datetime) -> Path:
        inc = result.incident
        attribution = result.attribution
        iface = attribution.interface
        twin = self.twin
        actor_ip = attribution.ip or result.actor.get("ip")
        start = add_seconds(result.instance.start, -120)
        end = evidence_at
        flows = [_flow_dict(f) for f in result.flows]
        dns = [_dns_dict(d) for d in result.dns]
        if actor_ip and self.telemetry:
            flows = _merge(
                self.telemetry.flows_for(actor_ip, start, end),
                flows,
                ("ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"),
            )
            dns = _merge(self.telemetry.dns_for(actor_ip, start, end), dns, ("ts", "id.orig_h", "id.orig_p", "query"))
        flows.sort(key=lambda f: (f["ts"], f["id.orig_h"], f["id.resp_h"], f["id.resp_p"]))
        dns.sort(key=lambda d: (d["ts"], d["query"]))
        port_after = {
            "interface": iface,
            "state": twin.interfaces[iface].__dict__ if iface else None,
            "show_switchport": cli_render.show_interface_switchport(twin, iface) if iface else "",
            "show_status": cli_render.show_interface_status_single(twin, iface) if iface else "",
            "show_mac_table": cli_render.show_mac_address_table(twin, interface=iface) if iface else "",
            "show_running_config": cli_render.show_running_config_interface(twin, iface) if iface else "",
            "show_port_security": cli_render.show_port_security_interface(twin, iface) if iface else "",
        }
        network_context = {
            "actor": result.actor,
            "attribution": attribution.to_dict(),
            "vlans": {str(k): v for k, v in twin.vlans.items()},
            "interface_intent": {
                "description": self.env.ports[iface].description,
                "class": self.env.ports[iface].port_class,
                "profile": self.env.ports[iface].profile,
                "protected": self.env.ports[iface].protected,
            }
            if iface
            else None,
            "span_session": twin.span,
            "sensor": "SEC-TP01 eth1 (SPAN destination Gi1/0/47), Zeek + Suricata",
            "simulation_notice": "Synthetic telemetry generated by the SentinelSwitch digital twin.",
        }
        alerts = [
            e
            for e in result.events
            if e["source"] in {"suricata", "zeek"}
            or (e["source"] == "radius" and e["result"] != "Access-Accept")
            or (e["source"] == "syslog" and e["mnemonic"].startswith(SECURITY_SYSLOG_PREFIXES))
        ]
        inc = dict(inc)
        inc["evidence_finalized_at"] = ts_iso(evidence_at)
        inc["detection"] = result.detection.to_dict()
        inc["metrics"] = result.metrics
        return write_bundle(
            self.evidence_root,
            inc,
            timeline=result.timeline,
            alerts=[{k: v for k, v in a.items() if k != "raw"} | {"raw": a["raw"]} for a in alerts],
            attribution=attribution.to_dict(),
            decision=result.decision.to_dict(),
            action=result.action.to_dict() if result.action else None,
            network_context=network_context,
            switch_port={
                "before": {
                    "access_vlan": inc["original_vlan"],
                    "oper_vlan": inc["original_vlan"],
                    "oper_status": "connected",
                },
                "after": port_after,
            },
            flows=flows,
            dns=dns,
        )


def _flow_dict(f: Flow) -> dict[str, Any]:
    return {
        "ts": round(f.ts.timestamp(), 6),
        "uid": f.uid,
        "id.orig_h": f.orig_h,
        "id.orig_p": f.orig_p,
        "id.resp_h": f.resp_h,
        "id.resp_p": f.resp_p,
        "proto": f.proto,
        "service": f.service,
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
        **({"scenario": f.scenario} if f.scenario else {}),
    }


def _dns_dict(d: DnsRecord) -> dict[str, Any]:
    return {
        "ts": round(d.ts.timestamp(), 6),
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
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": d.answers,
        "TTLs": [float(t) for t in d.ttls],
        "rejected": False,
        **({"scenario": d.scenario} if d.scenario else {}),
    }


def _merge(
    primary: list[dict[str, Any]], extra: list[dict[str, Any]], key_fields: tuple[str, ...]
) -> list[dict[str, Any]]:
    seen = {tuple(round(r[k], 3) if isinstance(r.get(k), float) else r.get(k) for k in key_fields) for r in primary}
    out = list(primary)
    for r in extra:
        key = tuple(round(r[k], 3) if isinstance(r.get(k), float) else r.get(k) for k in key_fields)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out
