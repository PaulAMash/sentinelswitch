"""Run every scenario's validation instance against an isolated twin and summarise the results."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any

from sentinelswitch.simulator.scenario import RunResult, ScenarioRunner
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment

SCENARIO_ORDER = [
    "unauthorized-endpoint",
    "arp-spoofing",
    "rogue-dhcp",
    "mac-address-change",
    "port-scan",
    "dns-anomaly",
    "lateral-reconnaissance",
    "bpdu-violation",
]


@dataclass
class ValidationReport:
    results: list[dict[str, Any]]
    metrics: dict[str, Any]
    all_passed: bool
    runs: list[RunResult] = field(default_factory=list)


def run_validation(env: Environment, baseline: SwitchTwin | None = None) -> ValidationReport:
    baseline = baseline or SwitchTwin.baseline(env)
    rows: list[dict[str, Any]] = []
    runs: list[RunResult] = []
    for sid in SCENARIO_ORDER:
        scenario = env.scenarios[sid]
        twin = baseline.copy()
        runner = ScenarioRunner(env, twin, evidence_root=None, incident_seq=900)
        result = runner.run(scenario, "validation", write_evidence=False)
        runs.append(result)
        iface = result.attribution.interface if result.attribution else None
        port = twin.interfaces.get(iface) if iface else None
        rows.append(
            {
                "scenario_id": sid,
                "name": scenario.name,
                "class": scenario.klass,
                "rule": scenario.rule,
                "mitre": scenario.mitre,
                "detect": result.checks["detect"],
                "attribute": result.checks["attribute"],
                "contain": result.checks["contain"],
                "passed": result.passed,
                "severity": result.detection.severity if result.detection else None,
                "confidence": result.detection.confidence if result.detection else None,
                "expected": result.instance.expected,
                "action": result.action.action if result.action else None,
                "mechanism": result.action.mechanism if result.action else None,
                "interface": iface,
                "from_vlan": result.action.from_vlan if result.action else None,
                "to_vlan": result.action.to_vlan if result.action else None,
                "post_state": {
                    "oper_status": port.oper_status,
                    "access_vlan": port.access_vlan,
                    "admin_status": port.admin_status,
                }
                if port
                else None,
                "t0": result.metrics.get("t0"),
                "first_alert": result.metrics.get("first_alert"),
                "detection_ts": result.metrics.get("detection"),
                "verified_ts": result.metrics.get("verified"),
                "ttd": result.metrics.get("ttd"),
                "tta": result.metrics.get("tta"),
                "ttc": result.metrics.get("ttc"),
                "end_to_end": result.metrics.get("end_to_end"),
                "attribution_flags": result.attribution.flags if result.attribution else [],
                "chain": result.attribution.chain if result.attribution else [],
                "timeline": result.timeline,
                "features": [f.__dict__ for f in result.detection.features] if result.detection else [],
                "derived": result.derived,
            }
        )
    ttd = [r["ttd"] for r in rows if r["ttd"] is not None]
    tta = [r["tta"] for r in rows if r["tta"] is not None]
    ttc = [r["ttc"] for r in rows if r["ttc"] is not None]
    e2e = [r["end_to_end"] for r in rows if r["end_to_end"] is not None]
    metrics = {
        "scenarios": len(rows),
        "passed": sum(1 for r in rows if r["passed"]),
        "mttd": round(mean(ttd), 3) if ttd else None,
        "mtta": round(mean(tta), 3) if tta else None,
        "mttc": round(mean(ttc), 3) if ttc else None,
        "mean_end_to_end": round(mean(e2e), 3) if e2e else None,
        "max_ttd": max(ttd) if ttd else None,
        "min_ttd": min(ttd) if ttd else None,
        "median_ttc": sorted(ttc)[len(ttc) // 2] if ttc else None,
    }
    return ValidationReport(rows, metrics, all(r["passed"] for r in rows), runs)
