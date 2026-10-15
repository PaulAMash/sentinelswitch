"""Security posture summary derived from persisted assessment and finding records.

Every number is a count over records in SQLite with an explicit denominator. There is no composite
risk score: coverage, determinate pass rate and open findings are reported separately so that
UNKNOWN and STALE results can never masquerade as passes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from sentinelswitch.services.store import Store
from simulator.canonical import Environment

from .controls import CONTROLS, CSF
from .engine import FINDING_OPEN_STATES

SEVERITY_ORDER = ["high", "medium", "low"]


def summary(store: Store, env: Environment) -> dict[str, Any]:
    all_rows = store.assessments()
    assessments = [a for a in all_rows if a["status"] != "RETIRED"]  # retired scopes never count
    retired = len(all_rows) - len(assessments)
    findings = store.findings()
    runs = store.assessment_runs()
    last_run = runs[0] if runs else None
    counts = Counter(a["status"] for a in assessments)
    total = len(assessments)
    determinate = counts["PASS"] + counts["FAIL"]
    open_findings = [f for f in findings if f["status"] in FINDING_OPEN_STATES]
    closed_findings = [f for f in findings if f["status"] not in FINDING_OPEN_STATES]

    by_control: dict[str, dict[str, Any]] = {}
    for c in CONTROLS:
        rows = [a for a in assessments if a["control_id"] == c.id]
        cc = Counter(a["status"] for a in rows)
        by_control[c.id] = {
            "control_id": c.id,
            "name": c.name,
            "category": c.category,
            "severity": c.severity,
            "scope_type": c.scope_type,
            "csf": [{"id": x, "text": CSF[x]} for x in c.csf],
            "assessments": len(rows),
            "pass": cc["PASS"],
            "fail": cc["FAIL"],
            "unknown": cc["UNKNOWN"],
            "stale": cc["STALE"],
            "open_findings": sum(1 for f in open_findings if f["control_id"] == c.id),
            "status": "FAIL"
            if cc["FAIL"]
            else "STALE"
            if cc["STALE"]
            else "UNKNOWN"
            if cc["UNKNOWN"]
            else ("PASS" if rows else "NOT_ASSESSED"),
        }

    by_category: dict[str, Counter] = defaultdict(Counter)
    for a in assessments:
        by_category[a["category"]][a["status"]] += 1

    assets: dict[str, dict[str, Any]] = {}
    for f in open_findings:
        key = f.get("asset") or f["scope"].get("asset") or f["scope"]["id"]
        entry = assets.setdefault(
            key, {"asset": key, "interface": f["scope"].get("interface"), "findings": 0, "worst": "low", "controls": []}
        )
        entry["findings"] += 1
        entry["controls"].append(f["control_id"])
        if SEVERITY_ORDER.index(f["severity"]) < SEVERITY_ORDER.index(entry["worst"]):
            entry["worst"] = f["severity"]

    unverified = [a for a in assessments if a["status"] in {"UNKNOWN", "STALE"}]
    csf_rollup: dict[str, dict[str, Any]] = {}
    for a in assessments:
        for m in a["framework"]["nist_csf_2_0"]:
            r = csf_rollup.setdefault(
                m["id"],
                {
                    "id": m["id"],
                    "text": m["text"],
                    "function": m["id"].split(".")[0],
                    "controls": set(),
                    "pass": 0,
                    "fail": 0,
                    "unknown": 0,
                    "stale": 0,
                },
            )
            r["controls"].add(a["control_id"])
            r[a["status"].lower()] += 1
    for r in csf_rollup.values():
        r["controls"] = sorted(r["controls"])

    remediation = Counter(f["status"] for f in findings)
    incidents = store.incidents()
    recent_runs = runs[:8]
    return {
        "generated_for": env.dataset["day"],
        "clock": last_run["assessed_at"] if last_run else None,
        "last_run": last_run,
        "runs": len(runs),
        "totals": {
            "assessments": total,
            "controls": len(CONTROLS),
            "pass": counts["PASS"],
            "fail": counts["FAIL"],
            "unknown": counts["UNKNOWN"],
            "stale": counts["STALE"],
            "determinate": determinate,
            "retired": retired,
            "coverage_pct": round(100.0 * determinate / total, 1) if total else None,
            "pass_rate_of_determinate_pct": round(100.0 * counts["PASS"] / determinate, 1) if determinate else None,
            "pass_rate_of_all_pct": round(100.0 * counts["PASS"] / total, 1) if total else None,
        },
        "definitions": {
            "coverage_pct": "share of assessments with a determinate result (PASS or FAIL); UNKNOWN and STALE are excluded from the numerator",
            "pass_rate_of_determinate_pct": "PASS divided by (PASS + FAIL); this is control effectiveness among determinate results, not overall compliance",
            "pass_rate_of_all_pct": "PASS divided by all assessments; UNKNOWN and STALE count against it",
            "open_findings": "findings whose status is open, reopened, remediation_requested, remediated (awaiting verification) or remediation_failed",
            "retired": "latest results whose scope no longer exists (for example a resolved incident); kept in history, excluded from every total above",
        },
        "findings": {
            "open": len(open_findings),
            "closed": len(closed_findings),
            "by_severity": {s: sum(1 for f in open_findings if f["severity"] == s) for s in SEVERITY_ORDER},
            "by_status": dict(remediation),
            "by_result": dict(Counter(f.get("result", "FAIL") for f in open_findings)),
            "open_items": sorted(open_findings, key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"])),
            "recently_closed": sorted(closed_findings, key=lambda f: f.get("resolved_at") or "", reverse=True)[:8],
        },
        "assets_with_open_findings": sorted(
            assets.values(), key=lambda x: (SEVERITY_ORDER.index(x["worst"]), -x["findings"])
        ),
        "unverified": [
            {
                "id": a["id"],
                "control_id": a["control_id"],
                "scope": a["scope"],
                "status": a["status"],
                "explanation": a["explanation"],
            }
            for a in unverified
        ],
        "by_control": list(by_control.values()),
        "by_category": [
            {"category": k, **{s.lower(): v[s] for s in ("PASS", "FAIL", "UNKNOWN", "STALE")}}
            for k, v in sorted(by_category.items())
        ],
        "csf": sorted(csf_rollup.values(), key=lambda r: r["id"]),
        "incidents": {
            "total": len(incidents),
            "open": sum(1 for i in incidents if i["status"] in {"contained", "open", "containment_failed"}),
            "resolved": sum(1 for i in incidents if i["status"] == "resolved"),
        },
        "recent_runs": recent_runs,
        "scope_note": "Simulated assessments of the SentinelSwitch digital twin. Results describe the twin's state at the simulated clock, not a real network.",
    }
