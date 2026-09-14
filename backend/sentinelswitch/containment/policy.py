"""Containment policy engine (automation/policies/containment-policy.yaml)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from sentinelswitch.correlation.engine import Attribution
from sentinelswitch.detection.engine import SEVERITY_RANK
from simulator.canonical import ROOT

POLICY_PATH = ROOT / "automation" / "policies" / "containment-policy.yaml"


@dataclass
class Decision:
    disposition: str  # automatic_containment | manual_review | monitor
    action: str  # quarantine_vlan | port_shutdown | none
    reason: str
    factors: list[dict[str, Any]] = field(default_factory=list)
    guards_triggered: list[str] = field(default_factory=list)
    quarantine_vlan: int | None = None
    tier_before_guards: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@lru_cache(maxsize=1)
def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class PolicyEngine:
    def __init__(self, policy: dict[str, Any] | None = None):
        self.policy = policy or load_policy()

    def decide(
        self,
        *,
        severity: str,
        confidence: float,
        klass: str,
        attribution: Attribution | None,
        corroborating_sources: int = 1,
    ) -> Decision:
        p = self.policy
        factors: list[dict[str, Any]] = [
            {"factor": "severity", "value": severity},
            {"factor": "confidence", "value": confidence},
            {"factor": "corroborating_sources", "value": corroborating_sources},
            {"factor": "actor_class", "value": klass},
        ]
        tier = "monitor"
        for t in p["tiers"]:
            cond = t.get("when", {})
            ok = True
            if "min_confidence" in cond and confidence < float(cond["min_confidence"]):
                ok = False
            if "severities" in cond and severity not in cond["severities"]:
                ok = False
            if ok:
                tier = t["name"]
                break
        tier_before = tier
        guards: list[str] = []
        action = p["actions"].get(klass, "none")
        if attribution is not None:
            factors.append({"factor": "interface", "value": attribution.interface})
            factors.append({"factor": "port_class", "value": attribution.port_class})
            factors.append({"factor": "asset_criticality", "value": attribution.criticality or "unknown"})
            factors.append({"factor": "protected", "value": attribution.protected})
            g = p["guards"]
            if tier == "automatic_containment":
                if attribution.interface in g["protected_ports"]["interfaces"] or attribution.protected:
                    guards.append("protected_ports")
                    tier = g["protected_ports"]["downgrade_to"]
                if attribution.trunk:
                    guards.append("trunk_ports")
                    tier = g["trunk_ports"]["downgrade_to"]
                if attribution.span_destination:
                    guards.append("span_destination")
                    tier = g["span_destination"]["downgrade_to"]
                if attribution.criticality in g["critical_assets"]["criticalities"]:
                    guards.append("critical_assets")
                    tier = g["critical_assets"]["downgrade_to"]
                if not attribution.resolved or attribution.interface is None:
                    guards.append("unresolved_attribution")
                    tier = g["unresolved_attribution"]["downgrade_to"]
        else:
            factors.append({"factor": "attribution", "value": "not available"})
            if tier == "automatic_containment":
                guards.append("unresolved_attribution")
                tier = "manual_review"
        if tier != "automatic_containment":
            action = "none"
        if action == "none" and tier == "automatic_containment":
            tier = "manual_review"
            guards.append("no_action_for_class")
        reason = self._reason(tier, tier_before, severity, confidence, guards, action)
        return Decision(
            disposition=tier,
            action=action,
            reason=reason,
            factors=factors,
            guards_triggered=guards,
            quarantine_vlan=int(p["quarantine_vlan"]) if action == "quarantine_vlan" else None,
            tier_before_guards=tier_before,
        )

    @staticmethod
    def _reason(tier: str, before: str, severity: str, confidence: float, guards: list[str], action: str) -> str:
        base = f"severity={severity} confidence={confidence:.2f}"
        if tier == "automatic_containment":
            return f"Automatic containment approved ({base}); action={action}"
        if guards:
            return f"Tier '{before}' downgraded to '{tier}' by guard(s): {', '.join(guards)} ({base})"
        if tier == "manual_review":
            return f"Manual review required ({base}); below the automatic-containment threshold"
        return f"Monitor only ({base})"

    def is_high(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]
