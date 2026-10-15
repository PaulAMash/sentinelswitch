"""Remediation service.

A finding's remediation goes through four distinct, separately recorded steps so the history shows
what was asked for, what was done, and whether it worked:

    requested  -> an analyst asks for the remediation (authorization is recorded with the actor)
    executed   -> the action is applied to the switch twin through the adapter (IOS command transcript)
    assessed   -> the control is re-run
    verified   -> the re-assessment reports PASS; the finding is marked verified (never deleted)

If the re-assessment still fails, the finding becomes `remediation_failed` and keeps its history.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinelswitch.containment.adapters import ProtectedInterfaceError, SimulatedCisco2960XAdapter
from sentinelswitch.services.store import Store
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment, add_seconds, ts_iso

from .engine import FINDING_TERMINAL_STATES, AssessmentEngine


class RemediationError(RuntimeError):
    pass


class RemediationService:
    def __init__(self, env: Environment, store: Store, engine: AssessmentEngine):
        self.env = env
        self.store = store
        self.engine = engine

    # ---------------------------------------------------------------------------------------
    def remediate(
        self, finding_id: str, *, actor: str, note: str = "", at: datetime | None = None, reassess: bool = True
    ) -> dict[str, Any]:
        finding = self.store.finding(finding_id)
        if finding is None:
            raise KeyError(finding_id)
        if finding["status"] in FINDING_TERMINAL_STATES:
            raise RemediationError(f"{finding_id} is already {finding['status']}")
        if finding["status"] in {"remediation_requested", "remediated"}:
            raise RemediationError(f"{finding_id} already has a remediation in progress (awaiting verification)")
        action = (finding.get("remediation") or {}).get("action")
        if not action:
            raise RemediationError(f"{finding_id} has no executable remediation; manual follow-up required")
        twin = self.store.load_twin()
        at = at or add_seconds(twin.now, 60.0)
        twin.advance_to(at)
        # 1. request
        finding["status"] = "remediation_requested"
        finding["updated_at"] = ts_iso(at)
        finding["remediation"].update(
            {"status": "requested", "requested_at": ts_iso(at), "requested_by": actor, "note": note or None}
        )
        self.store.put_finding(finding)
        self.store.put_finding_event(
            finding_id,
            {"ts": ts_iso(at), "event": "remediation_requested", "actor": actor, "detail": note or action["type"]},
        )
        # 2. execute
        exec_at = add_seconds(at, 4.2)
        try:
            transcript, commands = self._execute(
                twin, action, actor=actor, at=exec_at, reason=f"remediation of {finding_id}"
            )
        except ProtectedInterfaceError as exc:
            finding["status"] = "remediation_failed"
            finding["remediation"].update({"status": "refused", "executed_at": ts_iso(exec_at), "transcript": str(exc)})
            self.store.put_finding(finding)
            self.store.put_finding_event(
                finding_id,
                {"ts": ts_iso(exec_at), "event": "remediation_refused", "actor": "switch-adapter", "detail": str(exc)},
            )
            self.store.save_twin(twin)
            return {"finding": finding, "executed": False, "refused": str(exc)}
        finding["status"] = "remediated"
        finding["updated_at"] = ts_iso(exec_at)
        finding["remediation"].update(
            {
                "status": "executed",
                "executed_at": ts_iso(exec_at),
                "executed_by": "sentinel",
                "commands": commands,
                "transcript": transcript,
            }
        )
        self.store.put_finding(finding)
        self.store.put_finding_event(
            finding_id,
            {
                "ts": ts_iso(exec_at),
                "event": "remediation_executed",
                "actor": "sentinel",
                "detail": " / ".join(c.strip() for c in commands) if commands else action["type"],
                "transcript": transcript,
            },
        )
        self.store.save_twin(twin)
        result: dict[str, Any] = {"finding": finding, "executed": True, "transcript": transcript, "commands": commands}
        # 3 + 4. re-assess and verify
        if reassess:
            # Re-assess after the switch has had time to converge (guest-VLAN fallback needs ~7 s).
            # The verification run is attributed to the assurance engine, not to the analyst who asked for
            # the remediation: the analyst requests, the switch executes, the engine verifies.
            run = self.engine.run(
                f"remediation-{finding_id}", at=add_seconds(exec_at, 12.0), actor="sentinel-assurance"
            )
            result["run"] = run
            result["finding"] = self.store.finding(finding_id)
        return result

    # ---------------------------------------------------------------------------------------
    def _execute(
        self, twin: SwitchTwin, action: dict[str, Any], *, actor: str, at: datetime, reason: str
    ) -> tuple[str, list[str]]:
        adapter = SimulatedCisco2960XAdapter(twin)
        kind = action["type"]
        if kind == "apply_config":
            return adapter.apply_baseline(
                action["interface"],
                action.get("lines", []),
                intent=self.env.ports[action["interface"]],
                reason=reason,
                actor=actor,
                at=at,
            )
        if kind == "shutdown_unused":
            transcripts, commands = [], []
            for name in action["interfaces"]:
                t, c = adapter.apply_baseline(
                    name,
                    ["admin_status", "access_vlan"],
                    intent=self.env.ports[name],
                    reason=reason,
                    actor=actor,
                    at=at,
                )
                transcripts.append(t)
                commands.extend(c)
            return "\n".join(transcripts), commands
        if kind == "add_span_source":
            return adapter.add_span_source(int(action["vlan"]), reason=reason, actor=actor, at=at)
        if kind == "reauthenticate":
            res = adapter.reauthenticate(action["interface"], reason=reason, actor=actor, at=at)
            # The twin records the fresh RADIUS result; persist it alongside the historical events.
            for ev in res.get("auth_events", []):
                self.store.put_auth_event(ev)
            return res["transcript"], res["commands"]
        if kind == "fix_trust":
            transcripts, commands = [], []
            for name in action.get("extra", []):
                t, c = adapter.apply_baseline(
                    name,
                    ["dhcp_snooping_trust", "dai_trust"],
                    intent=self.env.ports[name],
                    reason=reason,
                    actor=actor,
                    at=at,
                )
                transcripts.append(t)
                commands.extend(c)
            return "\n".join(transcripts), commands
        raise RemediationError(f"unsupported remediation action {kind}")
