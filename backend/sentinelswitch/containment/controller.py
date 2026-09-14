"""Containment controller: executes policy decisions through a SwitchAdapter and verifies them."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sentinelswitch.correlation.engine import Attribution, Clock
from simulator.canonical import ts_iso

from .adapters import ProtectedInterfaceError, SwitchAdapter
from .policy import Decision

MECHANISMS = {
    "quarantine_vlan": "SentinelSwitch VLAN reassignment (quarantine VLAN)",
    "port_shutdown": "SentinelSwitch administrative shutdown",
}


@dataclass
class ContainmentAction:
    workflow_id: str
    incident_id: str | None
    action: str
    mechanism: str
    interface: str | None
    switch: str
    from_vlan: int | None
    to_vlan: int | None
    reason: str
    initiating_detection: str
    actor: str
    requested_at: str
    applied_at: str | None
    verified_at: str | None
    status: str  # applied | verified | failed | refused | restored
    commands: list[str] = field(default_factory=list)
    transcript: str = ""
    verification: dict[str, Any] = field(default_factory=dict)
    restored_at: str | None = None
    restored_by: str | None = None
    restore_note: str | None = None
    restore_transcript: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContainmentController:
    def __init__(self, adapter: SwitchAdapter, quarantine_vlan: int = 50):
        self.adapter = adapter
        self.quarantine_vlan = quarantine_vlan
        self._n = 0

    def _workflow_id(self, incident_id: str | None, at: datetime) -> str:
        self._n += 1
        stem = incident_id or at.strftime("%Y%m%d%H%M%S")
        return f"WF-{stem.replace('INC-', '')}-{self._n:02d}"

    def contain(
        self,
        *,
        decision: Decision,
        attribution: Attribution,
        detection_id: str,
        summary: str,
        incident_id: str | None,
        clock: Clock,
        timing: dict[str, float],
        native_state: str | None = None,
    ) -> ContainmentAction:
        requested = clock.now
        wf = self._workflow_id(incident_id, requested)
        iface = attribution.interface
        mechanism = MECHANISMS.get(decision.action, decision.action)
        action = ContainmentAction(
            workflow_id=wf,
            incident_id=incident_id,
            action=decision.action,
            mechanism=mechanism,
            interface=iface,
            switch=attribution.switch,
            from_vlan=attribution.vlan,
            to_vlan=self.quarantine_vlan if decision.action == "quarantine_vlan" else None,
            reason=summary,
            initiating_detection=detection_id,
            actor="sentinel",
            requested_at=ts_iso(requested),
            applied_at=None,
            verified_at=None,
            status="pending",
        )
        if decision.disposition != "automatic_containment" or decision.action == "none":
            action.status = "not_applicable"
            action.notes.append(f"Disposition {decision.disposition}; no automatic action")
            return action
        if iface is None:
            action.status = "failed"
            action.notes.append("No interface to act on")
            return action
        applied_at = clock.advance(timing.get("apply", 0.4))
        try:
            if decision.action == "quarantine_vlan":
                res = self.adapter.set_access_vlan(
                    iface, self.quarantine_vlan, reason=summary, workflow=wf, at=applied_at
                )
            elif decision.action == "port_shutdown":
                res = self.adapter.shutdown(iface, reason=summary, workflow=wf, at=applied_at)
                if native_state == "err-disabled":
                    action.mechanism = "BPDU Guard err-disable (switch-native) + SentinelSwitch administrative hold"
                    action.notes.append(
                        "Port was already err-disabled by the switch; hold prevents errdisable recovery from re-enabling it"
                    )
            else:
                action.status = "failed"
                action.notes.append(f"Unknown action {decision.action}")
                return action
        except ProtectedInterfaceError as exc:
            action.status = "refused"
            action.notes.append(str(exc))
            return action
        action.applied_at = ts_iso(applied_at)
        action.commands = res.commands
        action.transcript = res.transcript
        action.status = "applied"
        if res.before.get("access_vlan") is not None:
            action.from_vlan = res.before.get("oper_vlan") or res.before.get("access_vlan")
        verified_at = clock.advance(timing.get("verify", 0.12))
        if decision.action == "quarantine_vlan":
            ok, transcript = self.adapter.verify_vlan(iface, self.quarantine_vlan)
            expect = f"Access Mode VLAN: {self.quarantine_vlan}"
        else:
            ok, transcript = self.adapter.verify_shutdown(iface)
            expect = "admin down, no MAC addresses learned"
        action.verified_at = ts_iso(verified_at)
        action.verification = {
            "ok": ok,
            "expected": expect,
            "transcript": transcript,
            "checked_at": ts_iso(verified_at),
        }
        action.status = "verified" if ok else "failed"
        return action

    def restore(self, action: ContainmentAction, *, actor: str, note: str, at: datetime) -> ContainmentAction:
        if action.interface is None:
            return action
        res = self.adapter.restore(action.interface, actor=actor, reason=note, at=at)
        action.restored_at = ts_iso(at)
        action.restored_by = actor
        action.restore_note = note
        action.restore_transcript = res.transcript
        action.status = "restored"
        return action
