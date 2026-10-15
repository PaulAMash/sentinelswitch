"""Assessment engine.

`AssessmentEngine.run()` evaluates every control in the catalog against the current switch twin and
application store, records one assessment per (control, scope), appends the full result set to the
history table, and reconciles findings:

    FAIL / STALE  -> a finding is opened (or re-opened) with a stable id FND-<control>-<scope>
    PASS          -> an open finding is marked verified (remediated findings) or resolved
    UNKNOWN       -> no finding; the assessment is listed as unverified

Nothing is ever deleted: previous assessment results stay in `assessment_history`, finding state
changes are appended to `finding_events`.

All timestamps are taken from the simulated clock (the twin's `now`) so runs are reproducible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelswitch.drift.engine import DriftEngine
from sentinelswitch.evidence.bundle import BUNDLE_FILES
from sentinelswitch.services.store import Store
from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment, add_seconds, parse_ts, ts_iso

from .controls import CONTROLS, CONTROLS_BY_ID, Control

ENDPOINT_VLANS = [20, 30, 40, 50]
TELEMETRY_WINDOWS = {"zeek-conn": 900, "radius": 14400 + 900, "syslog": 7200 + 900}
FINDING_OPEN_STATES = {"open", "remediation_requested", "remediated", "remediation_failed", "reopened"}
# Closed states the engine writes: verified by a passing run, or closed because the scope was retired.
FINDING_TERMINAL_STATES = {"verified", "closed"}
# Drift settings that a dedicated control owns. CTL-CONFIG-BASELINE leaves them out so that one deviation
# yields exactly one finding (and one remediation verifies exactly one finding).
OWNED_DRIFT_SETTINGS = {"access_vlan", "dot1x", "mab", "port_security", "dhcp_snooping_trust", "dai_trust"}


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-")


@dataclass
class Evidence:
    source: str
    ref: str
    collected_at: str
    detail: str
    freshness_relevant: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "ref": self.ref, "collected_at": self.collected_at, "detail": self.detail}


@dataclass
class Draft:
    control: Control
    scope: dict[str, Any]
    expected: Any
    observed: Any
    status: str
    explanation: str
    evidence: list[Evidence] = field(default_factory=list)
    severity: str | None = None
    related_incidents: list[str] = field(default_factory=list)
    remediation_commands: list[str] = field(default_factory=list)
    remediation_action: dict[str, Any] | None = None  # executable by RemediationService


class AssessmentEngine:
    def __init__(self, env: Environment, store: Store, incidents_dir: Path):
        self.env = env
        self.store = store
        self.incidents_dir = incidents_dir

    # ---------------------------------------------------------------------------------------
    def run(self, trigger: str, *, at: datetime | None = None, actor: str = "sentinel-assurance") -> dict[str, Any]:
        twin = self.store.load_twin()
        at = at or twin.now
        drafts: list[Draft] = []
        for control in CONTROLS:
            evaluator = getattr(self, "_eval_" + control.id.replace("CTL-", "").replace("-", "_").lower())
            drafts.extend(evaluator(twin, at))
        run_id = self._unique_run_id(f"ASR-{at.strftime('%Y%m%dT%H%M%S')}-{slug(trigger)}")
        assessments = [self._finalize(d, run_id, at) for d in drafts]
        self._reconcile(assessments, run_id, at, actor, trigger)
        retired = self._retire(assessments, run_id, at, actor)
        counts = {s: sum(1 for a in assessments if a["status"] == s) for s in ("PASS", "FAIL", "UNKNOWN", "STALE")}
        run = {
            "run_id": run_id,
            "assessed_at": ts_iso(at),
            "trigger": trigger,
            "actor": actor,
            "controls": len(CONTROLS),
            "assessments": len(assessments),
            "counts": counts,
            "retired": retired,
            "findings_open": len([f for f in self.store.findings() if f["status"] in FINDING_OPEN_STATES]),
            "clock": "simulated (switch twin)",
        }
        self.store.put_assessment_run(run)
        self.store.kv_set("last_assessment_run", run_id)
        return run

    # ---------------------------------------------------------------------------------------
    def _unique_run_id(self, base: str) -> str:
        """Two runs can share a simulated second (API re-runs); a run record is never overwritten."""
        run_id, n = base, 1
        while self.store.assessment_run(run_id) is not None:
            n += 1
            run_id = f"{base}-{n}"
        return run_id

    def _retire(self, assessments: list[dict[str, Any]], run_id: str, at: datetime, actor: str) -> int:
        """Latest-result rows whose scope no longer exists (a resolved incident, a MAC that left the port)
        are marked RETIRED so they stop counting toward the posture totals. History keeps every result."""
        current = {a["id"] for a in assessments}
        now = ts_iso(at)
        retired = 0
        for old in self.store.assessments():
            if old["id"] in current or old["status"] == "RETIRED":
                continue
            old["status"] = "RETIRED"
            old["retired_at"] = now
            old["retired_by_run"] = run_id
            old["explanation"] = (
                f"{old['explanation']} Scope no longer existed at {now}; the result was retired by run {run_id} "
                "and is excluded from the posture totals."
            )
            self.store.put_assessment(old)
            self.store.put_assessment_history(run_id, old)
            retired += 1
            fid = old.get("finding_id")
            finding = self.store.finding(fid) if fid else None
            if finding is not None and finding["status"] in FINDING_OPEN_STATES:
                finding.update({"status": "closed", "updated_at": now, "resolved_at": now, "last_run_id": run_id})
                self.store.put_finding(finding)
                self.store.put_finding_event(
                    fid,
                    {
                        "ts": now,
                        "event": "scope_retired",
                        "actor": actor,
                        "detail": f"scope no longer exists; closed without verification by run {run_id}",
                    },
                )
        return retired

    # ---------------------------------------------------------------------------------------
    def _finalize(self, d: Draft, run_id: str, at: datetime) -> dict[str, Any]:
        control = d.control
        status = d.status
        freshness: dict[str, Any] = {"window_seconds": control.freshness_window, "applied": False}
        if control.freshness_window and status in {"PASS", "FAIL"}:
            relevant = [e for e in d.evidence if e.freshness_relevant]
            if relevant:
                oldest = min(parse_ts(e.collected_at) for e in relevant)
                age = int((at - oldest).total_seconds())
                freshness.update(
                    {
                        "applied": True,
                        "oldest_evidence_at": ts_iso(oldest),
                        "age_seconds": age,
                        "fresh": age <= control.freshness_window,
                    }
                )
                if age > control.freshness_window:
                    status = "STALE"
                    d.explanation = f"{d.explanation} Evidence is {age // 3600}h {age % 3600 // 60}m old, older than the {control.freshness_window // 60}-minute freshness window; result is not current."
        collected = max((parse_ts(e.collected_at) for e in d.evidence), default=at)
        severity = d.severity or control.severity
        if status == "STALE":
            severity = "low" if control.severity != "high" else "medium"
        scope_id = d.scope["id"]
        return {
            "id": f"ASM-{control.id.replace('CTL-', '')}-{slug(scope_id)}",
            "run_id": run_id,
            "control_id": control.id,
            "control_name": control.name,
            "category": control.category,
            "framework": {
                "nist_csf_2_0": [
                    {"id": c, "text": __import__("sentinelswitch.assurance.controls", fromlist=["CSF"]).CSF[c]}
                    for c in control.csf
                ]
            },
            "scope": d.scope,
            "assessed_at": ts_iso(at),
            "expected": d.expected,
            "observed": d.observed,
            "status": status,
            "severity": severity,
            "explanation": d.explanation,
            "evidence": [e.to_dict() for e in d.evidence],
            "evidence_collected_at": ts_iso(collected),
            "freshness": freshness,
            "related_incidents": d.related_incidents,
            "detector": "sentinelswitch-assurance",
            "source_of_truth": control.source_of_truth,
            "remediation": {
                "guidance": control.remediation,
                "commands": d.remediation_commands,
                "action": d.remediation_action,
            },
            "finding_id": None,
            "limitations": control.limitations or None,
        }

    def _reconcile(
        self, assessments: list[dict[str, Any]], run_id: str, at: datetime, actor: str, trigger: str
    ) -> None:
        now = ts_iso(at)
        for a in assessments:
            fid = f"FND-{a['control_id'].replace('CTL-', '')}-{slug(a['scope']['id'])}"
            existing = self.store.finding(fid)
            if a["status"] in {"FAIL", "STALE"}:
                if existing is None:
                    finding = {
                        "id": fid,
                        "control_id": a["control_id"],
                        "control_name": a["control_name"],
                        "category": a["category"],
                        "scope": a["scope"],
                        "asset": a["scope"].get("asset"),
                        "severity": a["severity"],
                        "status": "open",
                        "result": a["status"],
                        "opened_at": now,
                        "updated_at": now,
                        "first_run_id": run_id,
                        "last_run_id": run_id,
                        "occurrences": 1,
                        "assessment_id": a["id"],
                        "expected": a["expected"],
                        "observed": a["observed"],
                        "explanation": a["explanation"],
                        "related_incidents": a["related_incidents"],
                        "remediation": {
                            "guidance": a["remediation"]["guidance"],
                            "commands": a["remediation"]["commands"],
                            "action": a["remediation"]["action"],
                            "status": "not_started",
                            "requested_at": None,
                            "requested_by": None,
                            "executed_at": None,
                            "transcript": None,
                        },
                        "verification": {"outcome": None, "at": None, "run_id": None},
                        "resolved_at": None,
                    }
                    self.store.put_finding(finding)
                    self.store.put_finding_event(
                        fid,
                        {
                            "ts": now,
                            "event": "opened",
                            "actor": actor,
                            "detail": f"{a['status']} in run {run_id} ({trigger})",
                        },
                    )
                else:
                    existing.update(
                        {
                            "updated_at": now,
                            "last_run_id": run_id,
                            "occurrences": int(existing.get("occurrences", 1)) + 1,
                            "assessment_id": a["id"],
                            "observed": a["observed"],
                            "explanation": a["explanation"],
                            "result": a["status"],
                            "severity": a["severity"],
                        }
                    )
                    existing["remediation"]["commands"] = a["remediation"]["commands"]
                    existing["remediation"]["action"] = a["remediation"]["action"]
                    if existing["status"] in FINDING_TERMINAL_STATES:
                        existing["status"] = "reopened"
                        existing["resolved_at"] = None
                        self.store.put_finding_event(
                            fid,
                            {
                                "ts": now,
                                "event": "reopened",
                                "actor": actor,
                                "detail": f"{a['status']} again in run {run_id}",
                            },
                        )
                    elif existing["status"] == "remediated":
                        existing["status"] = "remediation_failed"
                        existing["verification"] = {
                            "outcome": "FAIL",
                            "at": now,
                            "run_id": run_id,
                            "after_remediation": True,
                        }
                        self.store.put_finding_event(
                            fid,
                            {
                                "ts": now,
                                "event": "verification_failed",
                                "actor": actor,
                                "detail": f"still {a['status']} after remediation (run {run_id})",
                            },
                        )
                    self.store.put_finding(existing)
                a["finding_id"] = fid
            else:
                if existing is not None and existing["status"] in FINDING_OPEN_STATES:
                    verified_after_remediation = existing["status"] in {"remediated"}
                    existing.update(
                        {
                            "status": "verified",
                            "updated_at": now,
                            "last_run_id": run_id,
                            "resolved_at": now,
                            "assessment_id": a["id"],
                            "verification": {
                                "outcome": "PASS",
                                "at": now,
                                "run_id": run_id,
                                "after_remediation": verified_after_remediation,
                            },
                        }
                    )
                    self.store.put_finding(existing)
                    self.store.put_finding_event(
                        fid,
                        {
                            "ts": now,
                            "event": "verified",
                            "actor": actor,
                            "detail": ("remediation verified" if verified_after_remediation else "condition satisfied")
                            + f" by run {run_id}",
                        },
                    )
                    a["finding_id"] = fid
                elif existing is not None:
                    a["finding_id"] = fid
            self.store.put_assessment(a)
            self.store.put_assessment_history(run_id, a)

    # ---------------------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------------------
    def _iface_scope(self, twin: SwitchTwin, name: str) -> dict[str, Any]:
        dev = self.env.device_by_interface(name)
        i = twin.interfaces[name]
        return {
            "type": "interface",
            "id": name,
            "asset": dev.hostname if dev else None,
            "interface": name,
            "vlan": i.oper_vlan or i.access_vlan,
            "switch": twin.hostname,
            "description": i.description,
        }

    def _twin_evidence(self, twin: SwitchTwin, name: str, at: datetime, what: str = "switchport") -> Evidence:
        if what == "switchport":
            text = cli_render.show_interface_switchport(twin, name)
            line = next(
                (
                    ln
                    for ln in text.splitlines()
                    if ln.startswith("Access Mode VLAN") or ln.startswith("Administrative Mode")
                ),
                text[:80],
            )
            return Evidence("switch-twin", f"show interfaces {name} switchport", ts_iso(at), line)
        if what == "running-config":
            text = cli_render.show_running_config_interface(twin, name)
            return Evidence(
                "switch-twin", f"show running-config interface {name}", ts_iso(at), "\n".join(text.splitlines()[4:])
            )
        if what == "status":
            return Evidence(
                "switch-twin",
                f"show interfaces {name} status",
                ts_iso(at),
                cli_render.show_interface_status_single(twin, name).splitlines()[-1],
            )
        raise ValueError(what)

    def _actions(self) -> list[dict[str, Any]]:
        return self.store.actions()

    # ---------------------------------------------------------------------------------------
    # Evaluators
    # ---------------------------------------------------------------------------------------
    def _eval_vlan_intent(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-VLAN-INTENT"]
        out = []
        actions_by_iface: dict[str, dict[str, Any]] = {}
        for a in self._actions():
            if a.get("interface") and a.get("status") == "verified":
                actions_by_iface[a["interface"]] = a
        for name, intent in self.env.ports.items():
            if intent.mode != "access" or intent.port_class == "unused":
                continue
            i = twin.interfaces[name]
            expected = intent.access_vlan
            observed = i.access_vlan
            scope = self._iface_scope(twin, name)
            ev = [self._twin_evidence(twin, name, at, "switchport")]
            if observed == expected:
                out.append(
                    Draft(
                        c,
                        scope,
                        f"access VLAN {expected}",
                        f"access VLAN {observed}",
                        "PASS",
                        f"{name} is in its intended VLAN {expected}.",
                        ev,
                    )
                )
            elif (
                i.quarantined
                and i.quarantine_workflow
                and actions_by_iface.get(name, {}).get("workflow_id") == i.quarantine_workflow
            ):
                act = actions_by_iface[name]
                ev.append(
                    Evidence(
                        "containment-action",
                        act["workflow_id"],
                        act["verified_at"] or act["applied_at"],
                        f"{act['mechanism']} · verified={act.get('verification', {}).get('ok')}",
                    )
                )
                out.append(
                    Draft(
                        c,
                        scope,
                        f"access VLAN {expected} (or quarantine VLAN under an authorized workflow)",
                        f"access VLAN {observed} · quarantined by {i.quarantine_workflow}",
                        "PASS",
                        f"{name} is in quarantine VLAN {observed} under verified containment workflow {i.quarantine_workflow}; the deviation from VLAN {expected} is authorized.",
                        ev,
                        related_incidents=[act["incident_id"]] if act.get("incident_id") else [],
                    )
                )
            else:
                out.append(
                    Draft(
                        c,
                        scope,
                        f"access VLAN {expected}",
                        f"access VLAN {observed}",
                        "FAIL",
                        f"{name} is configured for VLAN {observed} but the port intent requires VLAN {expected} and no authorized containment workflow explains the change.",
                        ev,
                        remediation_commands=[f"interface {i.long_name}", f" switchport access vlan {expected}"],
                        remediation_action={
                            "type": "apply_config",
                            "interface": name,
                            "lines": [f"switchport access vlan {expected}"],
                        },
                    )
                )
        return out

    def _eval_dot1x_enforced(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-DOT1X-ENFORCED"]
        out = []
        for name, intent in self.env.ports.items():
            if not intent.settings.get("dot1x"):
                continue
            i = twin.interfaces[name]
            observed = {"dot1x": bool(i.settings.get("dot1x")), "mab": bool(i.settings.get("mab"))}
            expected = {"dot1x": True, "mab": bool(intent.settings.get("mab"))}
            ev = [self._twin_evidence(twin, name, at, "running-config")]
            if observed == expected:
                out.append(
                    Draft(
                        c,
                        self._iface_scope(twin, name),
                        expected,
                        observed,
                        "PASS",
                        f"{name} runs 802.1X with MAB fallback (authentication port-control auto, mab).",
                        ev,
                    )
                )
            else:
                out.append(
                    Draft(
                        c,
                        self._iface_scope(twin, name),
                        expected,
                        observed,
                        "FAIL",
                        f"{name} is missing the 802.1X/MAB configuration required by its profile.",
                        ev,
                        remediation_commands=[
                            f"interface {i.long_name}",
                            " authentication port-control auto",
                            " mab",
                            " dot1x pae authenticator",
                        ],
                        remediation_action={"type": "apply_config", "interface": name, "lines": ["dot1x", "mab"]},
                    )
                )
        return out

    def _eval_endpoint_identity(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-ENDPOINT-IDENTITY"]
        out = []
        auth = sorted(self.store.auth_events(limit=100000), key=lambda e: e["timestamp"])
        last_auth: dict[str, dict[str, Any]] = {}
        for e in auth:
            if parse_ts(e["timestamp"]) <= at:
                last_auth[e["calling_station_id"].replace("-", ":").upper()] = e
        static_bindings = {(b.mac.upper(), b.interface) for b in twin.dhcp_bindings if b.binding_type == "static"}
        rank = {"PASS": 0, "UNKNOWN": 1, "FAIL": 2}
        for name, i in twin.interfaces.items():
            if i.is_trunk or i.span_destination or i.oper_status != "connected":
                continue
            macs = twin.macs_on_interface(name)
            if not macs:
                continue
            scope = self._iface_scope(twin, name)
            ev = [
                Evidence(
                    "switch-twin",
                    f"show mac address-table interface {name}",
                    ts_iso(at),
                    "; ".join(f"{m.mac} VLAN {m.vlan} {m.entry_type}" for m in macs),
                )
            ]
            status = "PASS"
            observed: list[str] = []
            notes: list[str] = []
            has_radius = False
            for m in macs:
                dev = self.env.device_by_mac(m.mac)
                if dev is None:
                    status = max(status, "UNKNOWN", key=rank.get)
                    observed.append(f"{m.mac}: not in inventory")
                    notes.append(f"{m.mac} is not in the asset inventory; its identity cannot be established.")
                    continue
                ev.append(
                    Evidence(
                        "inventory",
                        dev.hostname,
                        ts_iso(at),
                        f"{dev.hostname} · {dev.role} · {dev.vendor} · auth {dev.auth} · owner {dev.user or '-'}",
                    )
                )
                la = last_auth.get(m.mac.upper())
                if la is None:
                    if dev.auth == "static":
                        bound = (m.mac.upper(), name) in static_bindings
                        if bound:
                            ev.append(
                                Evidence(
                                    "switch-twin",
                                    "show ip source binding",
                                    ts_iso(at),
                                    f"static binding {m.mac} on {name}",
                                )
                            )
                        observed.append(
                            f"{m.mac}: {dev.hostname} (static, {'source binding' if bound else 'inventory only'})"
                        )
                        notes.append(
                            f"{dev.hostname} is a statically addressed asset; no 802.1X session is expected"
                            + (
                                " and its static ip source binding is present."
                                if bound
                                else "; identity rests on the inventory record."
                            )
                        )
                    else:
                        status = max(status, "UNKNOWN", key=rank.get)
                        observed.append(f"{m.mac}: {dev.hostname}, no RADIUS result")
                        notes.append(f"{dev.hostname} is inventoried but no RADIUS result exists for {m.mac}.")
                    continue
                has_radius = True
                ev.append(
                    Evidence(
                        "radius",
                        la["event_id"],
                        la["timestamp"],
                        f"{la['result']} {la['method']} {la.get('username')} on {la['nas_port_id']}",
                        freshness_relevant=True,
                    )
                )
                if la["result"] not in {"Access-Accept", "Guest-VLAN"}:
                    status = "FAIL"
                    observed.append(f"{m.mac}: {dev.hostname}, last result {la['result']}")
                    notes.append(
                        f"{m.mac} ({dev.hostname}) is forwarding on {name} although its latest RADIUS result was "
                        f"{la['result']} at {la['timestamp'][11:19]} UTC."
                    )
                else:
                    observed.append(f"{m.mac}: {dev.hostname}, {la['result']} at {la['timestamp'][11:19]}Z")
                    notes.append(
                        f"{m.mac} is {dev.hostname}; last authentication {la['result']} ({la['method']}) at "
                        f"{la['timestamp'][11:19]} UTC."
                    )
            out.append(
                Draft(
                    c,
                    scope,
                    "every learned MAC is an inventoried asset with an authentication result inside the re-authentication period",
                    observed if len(observed) > 1 else observed[0],
                    status,
                    " ".join(notes),
                    ev,
                    remediation_action={"type": "reauthenticate", "interface": name} if has_radius else None,
                    remediation_commands=[f"clear authentication sessions interface {i.long_name}"]
                    if has_radius
                    else [],
                )
            )
        return out

    def _eval_port_security(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-PORT-SECURITY"]
        out = []
        for name, intent in self.env.ports.items():
            ps = intent.settings.get("port_security", {})
            if not ps.get("enabled"):
                continue
            i = twin.interfaces[name]
            expected = {k: ps.get(k) for k in ("enabled", "maximum", "violation", "sticky")}
            obs = i.settings.get("port_security", {}) or {}
            observed = {k: obs.get(k) for k in ("enabled", "maximum", "violation", "sticky")}
            ev = [self._twin_evidence(twin, name, at, "running-config")]
            if observed == expected:
                out.append(
                    Draft(
                        c,
                        self._iface_scope(twin, name),
                        expected,
                        observed,
                        "PASS",
                        f"{name} port security matches the {intent.profile} profile (max {expected['maximum']}, {expected['violation']}{', sticky' if expected['sticky'] else ''}).",
                        ev,
                    )
                )
            else:
                out.append(
                    Draft(
                        c,
                        self._iface_scope(twin, name),
                        expected,
                        observed,
                        "FAIL",
                        f"{name} port security differs from the {intent.profile} profile.",
                        ev,
                        remediation_action={"type": "apply_config", "interface": name, "lines": ["port_security"]},
                        remediation_commands=[
                            f"interface {i.long_name}",
                            " switchport port-security",
                            f" switchport port-security maximum {expected['maximum']}",
                            f" switchport port-security violation {expected['violation']}",
                        ]
                        + ([" switchport port-security mac-address sticky"] if expected["sticky"] else []),
                    )
                )
        return out

    def _eval_config_baseline(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-CONFIG-BASELINE"]
        report = DriftEngine(self.env).evaluate(twin)
        by_iface: dict[str, list[dict[str, Any]]] = {}
        for f in report["findings"]:
            if f["interface"]:
                by_iface.setdefault(f["interface"], []).append(f)
        out = []
        sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
        for name in self.env.ports:
            owned = OWNED_DRIFT_SETTINGS | (
                {"admin_status"} if self.env.ports[name].port_class == "unused" else set()
            )  # CTL-UNUSED-PORTS owns the administrative state of unused ports
            items = [f for f in by_iface.get(name, []) if f["setting"] not in owned]
            open_items = [f for f in items if f["status"] == "open"]
            approved = [f for f in items if f["status"] == "approved"]
            scope = self._iface_scope(twin, name)
            ev = [
                Evidence(
                    "drift-engine",
                    f"{name}",
                    ts_iso(at),
                    f"{len(items)} deviation(s): "
                    + "; ".join(
                        f"{f['setting']} expected {f['expected']} observed {f['observed']} [{f['status']}]"
                        for f in items
                    )
                    if items
                    else "no deviation from baseline",
                ),
                self._twin_evidence(twin, name, at, "running-config"),
            ]
            if not open_items:
                note = "" if not approved else " Deviation is approved: " + "; ".join(f["note"] or "" for f in approved)
                out.append(
                    Draft(
                        c,
                        scope,
                        "running configuration equals the rendered baseline",
                        "no open drift" if not approved else "approved deviation only",
                        "PASS",
                        f"{name} matches cisco/configs/SW01-baseline.cfg.{note}",
                        ev,
                    )
                )
            else:
                worst = max(open_items, key=lambda f: sev_rank.get(f["severity"], 0))
                severity = {"high": "high", "medium": "medium", "low": "low", "info": "low"}[worst["severity"]]
                cmds = []
                for f in open_items:
                    cmds.extend(f["recommendation"].splitlines())
                out.append(
                    Draft(
                        c,
                        scope,
                        {f["setting"]: f["expected"] for f in open_items},
                        {f["setting"]: f["observed"] for f in open_items},
                        "FAIL",
                        f"{name} drifted from the baseline: "
                        + "; ".join(
                            f"{f['setting']} is {f['observed']!r}, expected {f['expected']!r}" for f in open_items
                        )
                        + ".",
                        ev,
                        severity=severity,
                        remediation_commands=cmds,
                        remediation_action={
                            "type": "apply_config",
                            "interface": name,
                            "lines": [f["setting"] for f in open_items],
                        },
                    )
                )
        return out

    def _eval_unused_ports(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-UNUSED-PORTS"]
        out = []
        for name, p in self.env.ports.items():
            if p.port_class != "unused":
                continue
            i = twin.interfaces[name]
            ok = i.admin_status == "down" and i.access_vlan == 999
            scope = self._iface_scope(twin, name)
            ev = [self._twin_evidence(twin, name, at, "status"), self._twin_evidence(twin, name, at, "switchport")]
            observed = f"admin {i.admin_status}, access VLAN {i.access_vlan}"
            if ok:
                out.append(
                    Draft(
                        c,
                        scope,
                        "administratively down, access VLAN 999",
                        observed,
                        "PASS",
                        f"{name} is shut down and parked in VLAN 999.",
                        ev,
                    )
                )
            else:
                why = "is enabled" if i.admin_status != "down" else "is not parked in VLAN 999"
                out.append(
                    Draft(
                        c,
                        scope,
                        "administratively down, access VLAN 999",
                        observed,
                        "FAIL",
                        f"{name} has no assigned asset but {why} ({observed}).",
                        ev,
                        remediation_commands=[f"interface {i.long_name}", " switchport access vlan 999", " shutdown"],
                        remediation_action={"type": "shutdown_unused", "interfaces": [name]},
                    )
                )
        return out

    def _eval_trust_boundary(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-TRUST-BOUNDARY"]
        trusted = [
            n
            for n, i in twin.interfaces.items()
            if i.settings.get("dhcp_snooping_trust") or i.settings.get("dai_trust")
        ]
        expected_trusted = sorted(n for n, p in self.env.ports.items() if p.protected and p.mode == "trunk")
        scope = {
            "type": "global",
            "id": "trust-boundary",
            "asset": twin.hostname,
            "switch": twin.hostname,
            "interface": None,
            "vlan": None,
        }
        ev = [
            Evidence(
                "switch-twin",
                "show ip dhcp snooping",
                ts_iso(at),
                f"trusted interfaces: {', '.join(trusted) or 'none'}",
            )
        ]
        if sorted(trusted) == expected_trusted:
            return [
                Draft(
                    c,
                    scope,
                    expected_trusted,
                    sorted(trusted),
                    "PASS",
                    f"Only the protected infrastructure trunks ({', '.join(expected_trusted)}) are DHCP-snooping and DAI trusted.",
                    ev,
                )
            ]
        extra = sorted(set(trusted) - set(expected_trusted))
        missing = sorted(set(expected_trusted) - set(trusted))
        return [
            Draft(
                c,
                scope,
                expected_trusted,
                sorted(trusted),
                "FAIL",
                f"Trust boundary violated: unexpected trusted ports {extra or 'none'}; untrusted trunks {missing or 'none'}.",
                ev,
                remediation_action={"type": "fix_trust", "extra": extra, "missing": missing},
            )
        ]

    def _eval_telemetry_fresh(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-TELEMETRY-FRESH"]
        out = []

        def scope(src: str) -> dict[str, Any]:
            return {
                "type": "source",
                "id": src,
                "asset": "SEC-TP01",
                "switch": twin.hostname,
                "interface": None,
                "vlan": None,
            }

        buckets = [b for b in self.store.buckets() if parse_ts(b["ts"]) <= at and b["connections"] > 0]
        if buckets:
            last = buckets[-1]
            end = add_seconds(parse_ts(last["ts"]), 900)
            end = min(end, at)
            age = int((at - end).total_seconds())
            ok = age <= TELEMETRY_WINDOWS["zeek-conn"]
            out.append(
                Draft(
                    c,
                    scope("zeek-conn"),
                    "connection records within the last 15 minutes",
                    f"last bucket {last['ts'][11:16]}Z with {last['connections']} connections",
                    "PASS" if ok else "STALE",
                    f"Zeek conn feed: last populated 15-minute bucket starts {last['ts'][11:16]}Z ({age // 60} min ago).",
                    [
                        Evidence(
                            "zeek",
                            "traffic_buckets",
                            ts_iso(end),
                            f"{last['connections']} connections, {last['bytes']} bytes",
                        )
                    ],
                )
            )
        else:
            out.append(
                Draft(
                    c,
                    scope("zeek-conn"),
                    "connection records within the last 15 minutes",
                    "no records",
                    "UNKNOWN",
                    "No Zeek connection records are available before the assessment time.",
                    [],
                )
            )

        auth = [e for e in self.store.auth_events(limit=100000) if parse_ts(e["timestamp"]) <= at]
        if auth:
            last = max(auth, key=lambda e: e["timestamp"])
            age = int((at - parse_ts(last["timestamp"])).total_seconds())
            ok = age <= TELEMETRY_WINDOWS["radius"]
            out.append(
                Draft(
                    c,
                    scope("radius"),
                    "a RADIUS result within one re-authentication period (4h15m)",
                    f"last result {last['timestamp'][11:19]}Z",
                    "PASS" if ok else "STALE",
                    f"RADIUS: last result {last['result']} for {last.get('username')} at {last['timestamp'][11:19]}Z ({age // 60} min ago).",
                    [
                        Evidence(
                            "radius",
                            last["event_id"],
                            last["timestamp"],
                            f"{last['result']} {last['method']} {last['nas_port_id']}",
                        )
                    ],
                )
            )
        else:
            out.append(
                Draft(
                    c,
                    scope("radius"),
                    "a RADIUS result within one re-authentication period",
                    "no records",
                    "UNKNOWN",
                    "No RADIUS results available.",
                    [],
                )
            )

        logs = [ln for ln in twin.log if parse_ts(ln.ts) <= at]
        if logs:
            last = logs[-1]
            age = int((at - parse_ts(last.ts)).total_seconds())
            ok = age <= TELEMETRY_WINDOWS["syslog"]
            out.append(
                Draft(
                    c,
                    scope("syslog"),
                    "a syslog message within 2h15m (controller health-check cadence)",
                    f"last message {last.ts[11:19]}Z",
                    "PASS" if ok else "STALE",
                    f"IOS syslog: last message %{last.facility}-{last.severity}-{last.mnemonic} at {last.ts[11:19]}Z ({age // 60} min ago).",
                    [Evidence("syslog", f"seq {last.seq}", last.ts, last.message[:120])],
                )
            )
        else:
            out.append(
                Draft(
                    c,
                    scope("syslog"),
                    "a syslog message within 2h15m",
                    "no records",
                    "UNKNOWN",
                    "No syslog messages available.",
                    [],
                )
            )

        out.append(
            Draft(
                c,
                scope("suricata"),
                "EVE stats heartbeat within 60 s",
                "no liveness signal",
                "UNKNOWN",
                "The dataset contains Suricata alerts and flow records but no periodic `stats` events, so sensor liveness cannot be determined from available evidence. Alert absence is not evidence of health.",
                [Evidence("suricata", "data/suricata/eve.json", ts_iso(at), "event types present: alert, flow")],
            )
        )
        return out

    def _eval_sensor_coverage(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-SENSOR-COVERAGE"]
        out = []
        sources = list(twin.span.get("source_vlans", []))
        ev_txt = cli_render.show_monitor_session(twin)
        for vlan in ENDPOINT_VLANS:
            name = twin.vlans.get(vlan, {}).get("name", str(vlan))
            scope = {
                "type": "vlan",
                "id": f"vlan-{vlan}",
                "asset": f"VLAN {vlan} {name}",
                "switch": twin.hostname,
                "interface": None,
                "vlan": vlan,
            }
            ev = [Evidence("switch-twin", "show monitor session 1", ts_iso(at), ev_txt.splitlines()[4].strip())]
            if vlan in sources:
                out.append(
                    Draft(
                        c,
                        scope,
                        f"VLAN {vlan} in SPAN session 1 sources",
                        f"sources {sources}",
                        "PASS",
                        f"VLAN {vlan} ({name}) is mirrored to the sensor on {twin.span['destination']}.",
                        ev,
                    )
                )
            else:
                out.append(
                    Draft(
                        c,
                        scope,
                        f"VLAN {vlan} in SPAN session 1 sources",
                        f"sources {sources}",
                        "FAIL",
                        f"VLAN {vlan} ({name}) is not a SPAN source: traffic in it is invisible to Zeek and Suricata.",
                        ev,
                        remediation_commands=[
                            f"monitor session 1 source vlan {', '.join(str(v) for v in sources + [vlan])} both"
                        ],
                        remediation_action={"type": "add_span_source", "vlan": vlan},
                    )
                )
        return out

    def _eval_response_authorized(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-RESPONSE-AUTHORIZED"]
        out = []
        for a in self._actions():
            if a.get("status") not in {"verified", "restored", "failed"} or not a.get("applied_at"):
                continue
            scope = {
                "type": "incident",
                "id": a.get("incident_id") or a["workflow_id"],
                "asset": a.get("interface"),
                "switch": a.get("switch"),
                "interface": a.get("interface"),
                "vlan": a.get("from_vlan"),
            }
            auth = a.get("authorization")
            ev = [
                Evidence(
                    "containment-action",
                    a["workflow_id"],
                    a["applied_at"],
                    f"{a['action']} on {a['interface']} applied {a['applied_at'][11:23]}Z",
                )
            ]
            if not auth:
                out.append(
                    Draft(
                        c,
                        scope,
                        "authorization recorded before execution",
                        "no authorization record",
                        "UNKNOWN",
                        f"Workflow {a['workflow_id']} has no authorization record; authorization cannot be established from available evidence.",
                        ev,
                        related_incidents=[a["incident_id"]] if a.get("incident_id") else [],
                    )
                )
                continue
            ev.append(
                Evidence(
                    "policy-decision",
                    auth.get("basis", ""),
                    auth.get("authorized_at", a["requested_at"]),
                    f"mode={auth.get('mode')} by {auth.get('authorized_by')} · {auth.get('reason', '')}",
                )
            )
            ok = (
                auth.get("status") == "authorized"
                and auth.get("authorized_at")
                and auth["authorized_at"] <= a["applied_at"]
            )
            out.append(
                Draft(
                    c,
                    scope,
                    "authorization recorded before execution",
                    f"{auth.get('mode')} authorization at {auth.get('authorized_at', '')[11:23]}Z, executed {a['applied_at'][11:23]}Z",
                    "PASS" if ok else "FAIL",
                    (
                        f"Workflow {a['workflow_id']} was authorized ({auth.get('mode')}, {auth.get('authorized_by')}) before execution."
                        if ok
                        else f"Workflow {a['workflow_id']} executed without a valid prior authorization."
                    ),
                    ev,
                    related_incidents=[a["incident_id"]] if a.get("incident_id") else [],
                )
            )
        return out

    def _eval_quarantine_verified(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-QUARANTINE-VERIFIED"]
        out = []
        for inc in self.store.incidents():
            if inc.get("status") not in {"contained", "containment_failed"}:
                continue
            actions = [
                a
                for a in self.store.actions_for_incident(inc["id"])
                if a.get("status") in {"verified", "failed", "applied"}
            ]
            scope = {
                "type": "incident",
                "id": inc["id"],
                "asset": inc.get("device") or inc.get("mac"),
                "switch": inc["switch"],
                "interface": inc.get("interface"),
                "vlan": inc.get("current_vlan"),
            }
            if not actions:
                out.append(
                    Draft(
                        c,
                        scope,
                        "verified containment action",
                        "no action record",
                        "UNKNOWN",
                        f"{inc['id']} is marked contained but has no containment action record.",
                        [],
                        related_incidents=[inc["id"]],
                    )
                )
                continue
            a = actions[-1]
            iface = twin.interfaces.get(a["interface"]) if a.get("interface") else None
            ver = a.get("verification") or {}
            ev = [
                Evidence(
                    "containment-action",
                    a["workflow_id"],
                    a.get("verified_at") or a.get("applied_at"),
                    f"read-back {'ok' if ver.get('ok') else 'FAILED'}: {ver.get('expected')}",
                )
            ]
            if iface is None:
                out.append(
                    Draft(
                        c,
                        scope,
                        "interface in containment state",
                        "interface unknown",
                        "UNKNOWN",
                        "No interface recorded for the containment action.",
                        ev,
                        related_incidents=[inc["id"]],
                    )
                )
                continue
            if a["action"] == "quarantine_vlan":
                live_ok = iface.access_vlan == a["to_vlan"] and all(
                    m.vlan == a["to_vlan"] for m in twin.macs_on_interface(iface.name)
                )
                observed = f"access VLAN {iface.access_vlan}; MACs in VLAN {sorted({m.vlan for m in twin.macs_on_interface(iface.name)}) or 'none'}"
                expected = f"access VLAN {a['to_vlan']} with all learned MACs in VLAN {a['to_vlan']}"
            else:
                live_ok = iface.admin_status == "down" and not twin.macs_on_interface(iface.name)
                observed = (
                    f"admin {iface.admin_status}, {iface.oper_status}, {len(twin.macs_on_interface(iface.name))} MAC(s)"
                )
                expected = "administratively down with no learned MACs"
            ev.append(
                self._twin_evidence(
                    twin, iface.name, at, "switchport" if a["action"] == "quarantine_vlan" else "status"
                )
            )
            if ver.get("ok") and live_ok:
                out.append(
                    Draft(
                        c,
                        scope,
                        expected,
                        observed,
                        "PASS",
                        f"{inc['id']}: controller read-back succeeded at {a['verified_at'][11:23]}Z and the twin still reports the containment state on {iface.name}.",
                        ev,
                        related_incidents=[inc["id"]],
                    )
                )
            else:
                why = (
                    "read-back verification failed"
                    if not ver.get("ok")
                    else "the twin no longer reports the containment state"
                )
                out.append(
                    Draft(
                        c,
                        scope,
                        expected,
                        observed,
                        "FAIL",
                        f"{inc['id']}: {why} on {iface.name}.",
                        ev,
                        related_incidents=[inc["id"]],
                        remediation_commands=a.get("commands", []),
                    )
                )
        return out

    def _eval_recovery_verified(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-RECOVERY-VERIFIED"]
        out = []
        for inc in self.store.incidents():
            if inc.get("status") != "resolved":
                continue
            actions = [a for a in self.store.actions_for_incident(inc["id"]) if a.get("status") == "restored"]
            if not actions or not inc.get("interface"):
                continue
            a = actions[-1]
            name = inc["interface"]
            iface = twin.interfaces[name]
            intent = self.env.ports[name]
            expected_vlan = intent.access_vlan
            ok = (
                iface.access_vlan == expected_vlan
                and iface.admin_status == "up"
                and not iface.quarantined
                and not iface.hold
            )
            scope = {
                "type": "incident",
                "id": inc["id"],
                "asset": inc.get("device") or inc.get("mac"),
                "switch": inc["switch"],
                "interface": name,
                "vlan": iface.access_vlan,
            }
            ev = [
                Evidence(
                    "containment-action",
                    a["workflow_id"],
                    a["restored_at"],
                    f"restored by {a['restored_by']}: {a['restore_note']}",
                ),
                self._twin_evidence(twin, name, at, "switchport"),
                self._twin_evidence(twin, name, at, "status"),
            ]
            out.append(
                Draft(
                    c,
                    scope,
                    f"access VLAN {expected_vlan}, admin up, no quarantine/hold flags",
                    f"access VLAN {iface.access_vlan}, admin {iface.admin_status}, quarantined={iface.quarantined}, hold={iface.hold}",
                    "PASS" if ok else "FAIL",
                    (
                        f"{inc['id']}: {name} returned to VLAN {expected_vlan} and normal administrative state after containment was released at {a['restored_at'][11:19]}Z."
                        if ok
                        else f"{inc['id']}: {name} has not returned to its expected state after restore."
                    ),
                    ev,
                    related_incidents=[inc["id"]],
                )
            )
        return out

    def _eval_evidence_complete(self, twin: SwitchTwin, at: datetime) -> list[Draft]:
        c = CONTROLS_BY_ID["CTL-EVIDENCE-COMPLETE"]
        out = []
        for inc in self.store.incidents():
            d = self.incidents_dir / inc["id"]
            scope = {
                "type": "incident",
                "id": inc["id"],
                "asset": inc.get("device") or inc.get("mac"),
                "switch": inc["switch"],
                "interface": inc.get("interface"),
                "vlan": inc.get("original_vlan"),
            }
            if not d.exists():
                out.append(
                    Draft(
                        c,
                        scope,
                        f"{len(BUNDLE_FILES)} artifacts in data/incidents/{inc['id']}/",
                        "bundle directory missing",
                        "FAIL",
                        f"No evidence bundle directory exists for {inc['id']}; the bundle must be (re)generated.",
                        [],
                        related_incidents=[inc["id"]],
                    )
                )
                continue
            present = [n for n in BUNDLE_FILES if (d / n).exists()]
            missing = [n for n in BUNDLE_FILES if n not in present]
            ev = [
                Evidence(
                    "evidence-bundle",
                    f"data/incidents/{inc['id']}",
                    ts_iso(at),
                    f"{len(present)}/{len(BUNDLE_FILES)} artifacts present"
                    + (f"; missing {missing}" if missing else ""),
                )
            ]
            out.append(
                Draft(
                    c,
                    scope,
                    f"{len(BUNDLE_FILES)} artifacts",
                    f"{len(present)} present",
                    "PASS" if not missing else "FAIL",
                    (
                        f"{inc['id']}: all {len(BUNDLE_FILES)} evidence artifacts are present."
                        if not missing
                        else f"{inc['id']}: missing artifacts {missing}."
                    ),
                    ev,
                    related_incidents=[inc["id"]],
                )
            )
        return out
