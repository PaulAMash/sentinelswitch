"""Correlation-rule engine.

Rules (detections/correlation/*.yaml) are evaluated over the normalized event stream. When a trigger
event is seen for an actor, the engine schedules an evaluation at `trigger.ts + aggregate_window`,
collects the corroborating evidence available by then, scores the features and emits a Detection.
The engine is deterministic: given the same events it always produces the same detections with the
same timestamps, which is what makes the validation metrics reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from simulator.canonical import ROOT, Environment, add_seconds, mac_norm, parse_ts, ts_iso

RULES_DIR = ROOT / "detections" / "correlation"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Rule:
    id: str
    name: str
    klass: str
    description: str
    mitre: list[str]
    actor_key: str
    trigger: dict[str, Any]
    aggregate_window: float
    base_confidence: float
    severity: Any
    features: list[dict[str, Any]]
    path: str
    emit_threshold: float = 0.0


@dataclass
class FeatureResult:
    id: str
    label: str
    weight: float
    matched: bool
    evidence: str | None = None


@dataclass
class Detection:
    id: str
    rule: Rule
    actor_key: str
    actor_value: str
    ts: str
    trigger_ts: str
    severity: str
    confidence: float
    features: list[FeatureResult]
    events: list[dict[str, Any]]
    summary: str
    actor: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule.id,
            "rule_name": self.rule.name,
            "class": self.rule.klass,
            "mitre": self.rule.mitre,
            "actor_key": self.actor_key,
            "actor_value": self.actor_value,
            "actor": self.actor,
            "ts": self.ts,
            "trigger_ts": self.trigger_ts,
            "severity": self.severity,
            "confidence": self.confidence,
            "base_confidence": self.rule.base_confidence,
            "features": [f.__dict__ for f in self.features],
            "summary": self.summary,
            "event_refs": [{"ts": e["ts"], "source": e["source"], "summary": e.get("summary")} for e in self.events],
        }


@lru_cache(maxsize=1)
def load_rules(path: Path = RULES_DIR) -> dict[str, Rule]:
    rules: dict[str, Rule] = {}
    for p in sorted(path.glob("*.yaml")):
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        rules[raw["id"]] = Rule(
            id=raw["id"],
            name=raw["name"],
            klass=raw["class"],
            description=" ".join(str(raw.get("description", "")).split()),
            mitre=list(raw.get("mitre", [])),
            actor_key=raw["actor_key"],
            trigger=dict(raw["trigger"]),
            aggregate_window=float(raw.get("aggregate_window", 0)),
            base_confidence=float(raw["base_confidence"]),
            severity=raw.get("severity", "medium"),
            features=list(raw.get("features", [])),
            path=str(p.relative_to(ROOT)),
            emit_threshold=float(raw.get("emit_threshold", 0.0)),
        )
    return rules


def _matches(event: dict[str, Any], flt: dict[str, Any]) -> bool:
    for key, want in flt.items():
        if key == "reason_contains":
            if want.lower() not in str(event.get("reason", "")).lower():
                return False
            continue
        have = event.get(key)
        if isinstance(want, list):
            if have not in want:
                return False
        elif have != want:
            return False
    return True


def _cmp(have: Any, op: str, want: Any) -> bool:
    if have is None:
        return False
    try:
        if op == "ge":
            return float(have) >= float(want)
        if op == "le":
            return float(have) <= float(want)
        if op == "gt":
            return float(have) > float(want)
        if op == "lt":
            return float(have) < float(want)
    except (TypeError, ValueError):
        return False
    if op == "eq":
        return have == want
    if op == "ne":
        return have != want
    return False


class DetectionEngine:
    def __init__(
        self,
        env: Environment,
        rules: dict[str, Rule] | None = None,
        detect_latency: float = 0.05,
        latency_by_rule: dict[str, float] | None = None,
    ):
        self.env = env
        self.rules = rules or load_rules()
        self.default_latency = detect_latency
        self.latency_by_rule = latency_by_rule or {}
        self._seq = 0

    # ---- asset context ---------------------------------------------------------------------
    def _device_for_actor(self, key: str, value: str):
        if key in {"src_ip", "actor_ip"}:
            return self.env.device_by_ip(value)
        if key == "mac":
            return self.env.device_by_mac(value)
        if key == "interface":
            return self.env.device_by_interface(value)
        return None

    def _actor_events(self, events: list[dict[str, Any]], key: str, value: str) -> list[dict[str, Any]]:
        out = []
        for e in events:
            v = e.get(key)
            if key == "mac" and v:
                v = mac_norm(v)
            if v == value:
                out.append(e)
        return out

    # ---- evaluation ------------------------------------------------------------------------
    def evaluate(self, events: list[dict[str, Any]]) -> list[Detection]:
        """Run every rule over the events (any order) and return detections sorted by time."""
        events = sorted(events, key=lambda e: e["ts"])
        detections: list[Detection] = []
        for rule in self.rules.values():
            seen: set[tuple[str, str]] = set()
            for ev in events:
                if not _matches(ev, rule.trigger):
                    continue
                actor_value = ev.get(rule.actor_key)
                if not actor_value:
                    continue
                if rule.actor_key == "mac":
                    actor_value = mac_norm(actor_value)
                bucket = (rule.id, actor_value)
                if bucket in seen:
                    continue
                seen.add(bucket)
                det = self._score(rule, ev, actor_value, events)
                if det.confidence >= rule.emit_threshold:
                    detections.append(det)
        detections.sort(key=lambda d: d.ts)
        return detections

    def _score(self, rule: Rule, trigger: dict[str, Any], actor_value: str, events: list[dict[str, Any]]) -> Detection:
        trigger_ts = parse_ts(trigger["ts"])
        eval_ts = add_seconds(trigger_ts, rule.aggregate_window)
        latency = self.latency_by_rule.get(rule.id, self.default_latency)
        detect_ts = add_seconds(eval_ts, latency)
        actor_events = [
            e for e in self._actor_events(events, rule.actor_key, actor_value) if parse_ts(e["ts"]) <= eval_ts
        ]
        device = self._device_for_actor(rule.actor_key, actor_value)
        confidence = rule.base_confidence
        results: list[FeatureResult] = []
        matched_ids: set[str] = set()
        for f in rule.features:
            matched, evidence = self._feature(f, trigger, actor_events, eval_ts, device, actor_value)
            results.append(FeatureResult(f["id"], f.get("label", f["id"]), float(f["weight"]), matched, evidence))
            if matched:
                confidence += float(f["weight"])
                matched_ids.add(f["id"])
        confidence = round(max(0.05, min(0.99, confidence)), 2)
        severity = self._severity(rule, matched_ids)
        self._seq += 1
        used = sorted({id(e): e for e in actor_events}.values(), key=lambda e: e["ts"])
        actor = {"key": rule.actor_key, "value": actor_value}
        if device:
            actor.update(
                {
                    "device": device.hostname,
                    "ip": device.ip,
                    "mac": device.mac,
                    "interface": device.interface,
                    "vlan": device.vlan,
                    "user": device.user,
                }
            )
        if rule.actor_key in {"src_ip", "actor_ip"}:
            actor.setdefault("ip", actor_value)
        if rule.actor_key == "mac":
            actor.setdefault("mac", actor_value)
            actor.setdefault("interface", trigger.get("interface"))
        if rule.actor_key == "interface":
            actor.setdefault("interface", actor_value)
            actor.setdefault("mac", trigger.get("new_mac") or trigger.get("mac"))
        summary = f"{rule.name}: {trigger.get('summary', '')}"
        det = Detection(
            id=f"DET-{ts_iso(detect_ts).replace('-', '').replace(':', '').replace('.', '')[:17]}-{rule.id[:4].upper()}",
            rule=rule,
            actor_key=rule.actor_key,
            actor_value=actor_value,
            ts=ts_iso(detect_ts),
            trigger_ts=ts_iso(trigger_ts),
            severity=severity,
            confidence=confidence,
            features=results,
            events=used,
            summary=summary,
            actor=actor,
        )
        return det

    def _severity(self, rule: Rule, matched: set[str]) -> str:
        sev = rule.severity
        if isinstance(sev, str):
            return sev
        default = "medium"
        for entry in sev:
            if "default" in entry:
                default = entry["default"]
                continue
            if entry.get("when") in matched:
                return entry["severity"]
        return default

    def _feature(
        self,
        f: dict[str, Any],
        trigger: dict[str, Any],
        actor_events: list[dict[str, Any]],
        eval_ts: datetime,
        device,
        actor_value: str,
    ) -> tuple[bool, str | None]:
        ftype = f["type"]
        if ftype in {"event_match", "event_count"}:
            window = float(f.get("window", 60))
            lo = add_seconds(eval_ts, -abs(window))
            hits = [
                e
                for e in actor_events
                if _matches(e, f["match"])
                and lo <= parse_ts(e["ts"]) <= eval_ts
                and e is not trigger
                or (_matches(e, f["match"]) and e is trigger and ftype == "event_count")
            ]
            if ftype == "event_match":
                if hits:
                    return True, f"{len(hits)} matching event(s): {hits[0].get('summary', '')[:120]}"
                return False, None
            n = len(hits)
            ok = n >= int(f["min"])
            return ok, f"{n} event(s) in {int(window)}s window (min {f['min']})"
        if ftype == "event_field":
            src = None
            if "from" in f:
                cands = [e for e in actor_events if _matches(e, f["from"])]
                src = cands[-1] if cands else None
            else:
                src = trigger
            if src is None:
                return False, None
            have = src.get(f["field"])
            ok = _cmp(have, f.get("op", "eq"), f.get("value"))
            return ok, f"{f['field']}={have}"
        if ftype == "asset_tag":
            if device and f["tag"] in device.tags:
                return True, f"{device.hostname} tagged {f['tag']}"
            return False, None
        if ftype == "asset_unknown":
            mac = trigger.get(f.get("mac_field", "mac")) or actor_value
            known = self.env.device_by_mac(mac) if mac else None
            if known is None:
                return True, f"{mac} not in inventory"
            return False, f"{mac} is {known.hostname}"
        if ftype == "asset_mac_belongs_elsewhere":
            mac = trigger.get(f.get("mac_field", "mac"))
            known = self.env.device_by_mac(mac) if mac else None
            iface = trigger.get("interface")
            if known and iface and known.interface != iface:
                return True, f"{mac} belongs to {known.hostname} on {known.interface}"
            return False, None
        if ftype == "asset_in_vlan":
            vlan = device.vlan if device else trigger.get("vlan")
            if vlan is not None and int(vlan) == int(f["vlan"]):
                return True, f"VLAN {vlan}"
            return False, None
        if ftype == "outside_business_hours":
            ts = parse_ts(trigger["ts"])
            outside = ts.hour < 7 or ts.hour >= 19 or ts.weekday() >= 5
            return outside, ts.strftime("%H:%M UTC")
        raise ValueError(f"unknown feature type {ftype}")
