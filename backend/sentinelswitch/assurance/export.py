"""Machine-readable (JSON) and human-readable (HTML, optional PDF) posture and incident reports.

The JSON document follows the schema in docs/export-schema.md (`schema_version` 2.0). Everything in
both reports is read from SQLite and the evidence bundles at export time; nothing is computed only
for the export.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelswitch import __version__
from sentinelswitch.services.store import Store
from simulator.canonical import Environment, ts_iso

from .controls import catalog
from .engine import FINDING_OPEN_STATES
from .posture import summary

SCHEMA_VERSION = "2.0"


def build_export(
    store: Store, env: Environment, incidents_dir: Path, *, generated_at: datetime | None = None
) -> dict[str, Any]:
    post = summary(store, env)
    runs = store.assessment_runs()
    incidents = store.incidents()
    actions = store.actions()
    reviews = store.reviews()
    findings = store.findings()
    generated_at = generated_at or (store.load_twin().now)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "SentinelSwitch", "version": __version__, "component": "assurance.export"},
        "generated_at": ts_iso(generated_at),
        "clock_basis": "simulated switch-twin clock (dataset day " + env.dataset["day"] + ")",
        "simulation_notice": "All assets, telemetry, incidents and assessments are synthetic and produced by the SentinelSwitch digital twin. No real network was assessed.",
        "scope": {
            "organization": env.organization,
            "switch": {k: env.switch[k] for k in ("hostname", "model", "ios_version", "management_ip")},
            "vlans": [
                {"id": v.id, "name": v.name, "subnet": v.subnet, "purpose": v.purpose}
                for v in env.vlans.values()
                if v.id != 999
            ],
            "assets_in_scope": len(store.devices()),
            "controls_in_scope": len(catalog()),
        },
        "methodology": {
            "states": {
                "PASS": "available evidence demonstrates the condition is satisfied",
                "FAIL": "available evidence demonstrates the condition is not satisfied",
                "UNKNOWN": "evidence is insufficient to decide; never counted as a pass",
                "STALE": "evidence is older than the control's freshness window at the assessment clock; never counted as a pass",
            },
            "freshness": "per-control windows measured against the simulated clock; state-based evidence is read live from the twin and has no window",
            "metrics": post["definitions"],
        },
        "posture": {
            k: v
            for k, v in post.items()
            if k not in {"findings", "assets_with_open_findings", "unverified", "recent_runs", "last_run"}
        }
        | {
            "findings_open": post["findings"]["open"],
            "findings_closed": post["findings"]["closed"],
            "findings_by_severity": post["findings"]["by_severity"],
            "findings_by_status": post["findings"]["by_status"],
        },
        "controls": catalog(),
        "assessments": store.assessments(),
        "findings": [dict(f, events=store.finding_events(f["id"])) for f in findings],
        "assets_with_open_findings": post["assets_with_open_findings"],
        "unverified": post["unverified"],
        "assessment_runs": runs,
        "incidents": [
            {
                "incident": inc,
                "timeline": store.timeline(inc["id"]),
                "actions": store.actions_for_incident(inc["id"]),
                "evidence_bundle": {
                    "path": f"data/incidents/{inc['id']}",
                    "present": sorted(p.name for p in (incidents_dir / inc["id"]).iterdir())
                    if (incidents_dir / inc["id"]).exists()
                    else [],
                },
            }
            for inc in incidents
        ],
        "manual_reviews": [
            {k: v for k, v in r.items() if k not in {"timeline", "attribution"}}
            | {"attribution_chain": (r.get("attribution") or {}).get("flags")}
            for r in reviews
        ],
        "containment_actions": actions,
        "validation": {
            "metrics": store.kv_get("validation_metrics", {}),
            "results": [
                {k: v for k, v in r.items() if k not in {"timeline", "features", "derived"}} for r in store.validation()
            ],
        },
        "framework_mapping": {
            "framework": "NIST CSF 2.0",
            "note": "Limited mapping of simulated checks to CSF 2.0 subcategories for orientation only; not a framework assessment or certification.",
            "subcategories": post["csf"],
        },
        "limitations": [
            "The switch is a digital twin; no commands were sent to physical hardware.",
            "Telemetry is synthesized from a deterministic traffic model; Zeek and Suricata were not executed.",
            "Suricata liveness cannot be assessed because the dataset has no EVE stats events.",
            "Timestamps are simulated-clock values, not wall-clock execution times.",
        ],
        "reproducibility": {
            "commands": ["make seed", "make demo-2", "make report"],
            "dataset_manifest": "data/generated/manifest.json",
            "deterministic": True,
        },
    }
    return doc


def write_json(doc: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


# -------------------------------------------------------------------------------------------------
# HTML report
# -------------------------------------------------------------------------------------------------
_CSS = """
:root{color-scheme:light}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;margin:0;color:#1b2430;background:#f5f7fa;font-size:13px;line-height:1.45}
.page{max-width:1120px;margin:0 auto;padding:36px 40px 60px;background:#fff}
h1{font-size:26px;margin:0 0 4px}h2{font-size:17px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid #e3e8ee}h3{font-size:13.5px;margin:18px 0 6px}
.muted{color:#5b6b7c}.small{font-size:11.5px}.brand{display:flex;align-items:center;gap:10px;margin-bottom:22px}.brand b{font-size:15px}
.notice{border:1px solid #bfe3ea;background:#eefafc;padding:10px 14px;border-radius:6px;margin:14px 0}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0}.kpi{border:1px solid #e3e8ee;border-radius:6px;padding:10px 12px}.kpi .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:#5b6b7c}.kpi .v{font-size:22px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:12.5px}th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:#5b6b7c;border-bottom:1px solid #e3e8ee;padding:6px 8px}td{padding:6px 8px;border-bottom:1px solid #eef2f6;vertical-align:top}
.chip{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:600}.PASS{background:#e3f6e8;color:#1b6b34}.FAIL{background:#fde8e6;color:#9b1c1c}.UNKNOWN{background:#eef0f3;color:#4b5563}.status{background:#fff;color:#374151;border:1px solid #cbd2db}.STALE{background:#fff3d6;color:#8a5a00}
.high{background:#fde8e6;color:#9b1c1c}.medium{background:#fff3d6;color:#8a5a00}.low{background:#e8eefc;color:#1e40af}
pre{background:#0f1720;color:#dbe4ee;padding:10px 12px;border-radius:6px;font-size:11px;overflow:auto;white-space:pre-wrap}
.mono{font-family:'SF Mono',Menlo,Consolas,monospace;font-size:11.5px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media print{body{background:#fff}.page{padding:12mm}h2{page-break-after:avoid}table{page-break-inside:auto}tr{page-break-inside:avoid}}
"""


def _e(v: Any) -> str:
    return html.escape(str(v) if v is not None else "—")


def _dt(ts: str | None) -> str | None:
    """Simulated-clock ISO timestamp as 'YYYY-MM-DD HH:MM:SS.mmm' (UTC)."""
    return f"{ts[:10]} {ts[11:23]}" if ts else None


def _chip(status: str) -> str:
    return f'<span class="chip {html.escape(status)}">{html.escape(status)}</span>'


def render_html(doc: dict[str, Any]) -> str:
    p = doc["posture"]
    t = p["totals"]
    findings = doc["findings"]
    open_f = [f for f in findings if f["status"] in FINDING_OPEN_STATES]
    closed_f = [f for f in findings if f["status"] not in FINDING_OPEN_STATES]
    assessments = doc["assessments"]
    out: list[str] = []
    out.append(
        f"<!doctype html><html><head><meta charset='utf-8'><title>SentinelSwitch 2.0 — Security posture report</title><style>{_CSS}</style></head><body><div class='page'>"
    )
    out.append(
        "<div class='brand'><svg width='28' height='28' viewBox='0 0 64 64'><rect x='4' y='4' width='56' height='56' rx='12' fill='#131a22' stroke='#39c5d6' stroke-width='3'/><path d='M32 14 L48 21 V34 C48 43 41 49 32 52 C23 49 16 43 16 34 V21 Z' fill='none' stroke='#e6edf3' stroke-width='3'/><rect x='24' y='30' width='16' height='7' rx='1.5' fill='#39c5d6'/></svg><b>SentinelSwitch 2.0</b><span class='muted'>Evidence-Driven Network Security &amp; Response Lab</span></div>"
    )
    out.append(
        f"<h1>Security posture report</h1><div class='muted'>Generated {_e(doc['generated_at'])} · {_e(doc['clock_basis'])} · schema {_e(doc['schema_version'])} · SentinelSwitch {_e(doc['generator']['version'])}</div>"
    )
    out.append(
        f"<div class='notice'><b>Scope and simulation disclaimer.</b> {_e(doc['simulation_notice'])} Scope: {_e(doc['scope']['switch']['hostname'])} ({_e(doc['scope']['switch']['model'])}), {_e(doc['scope']['assets_in_scope'])} inventoried assets, {_e(doc['scope']['controls_in_scope'])} controls, {len(doc['scope']['vlans'])} VLANs.</div>"
    )

    # Executive summary
    out.append("<h2>1. Executive summary</h2>")
    worst = sorted(open_f, key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]], f["id"]))
    inc = doc["posture"]["incidents"]
    recovered = sum(
        1 for a in doc["assessments"] if a["control_id"] == "CTL-RECOVERY-VERIFIED" and a["status"] == "PASS"
    )
    out.append(
        "<p>"
        f"{t['assessments']} control assessments were evaluated across {t['controls']} controls at the simulated clock. "
        f"{t['pass']} passed, {t['fail']} failed, {t['unknown']} could not be determined and {t['stale']} rest on stale evidence. "
        f"{len(open_f)} finding(s) remain open ({p['findings_by_severity']['high']} high, {p['findings_by_severity']['medium']} medium, {p['findings_by_severity']['low']} low); {len(closed_f)} finding(s) were verified closed. "
        f"{inc['open']} incident(s) are open (contained or containment failed); {inc['resolved']} resolved, "
        f"{recovered} of them with recovery verified by CTL-RECOVERY-VERIFIED."
        "</p>"
    )
    if worst:
        out.append(
            "<p><b>Most significant open findings:</b></p><ul>"
            + "".join(
                f"<li>{_e(f['id'])} — {_e(f['control_name'])} on {_e(f.get('asset') or f['scope']['id'])}: {_e(f['explanation'])}</li>"
                for f in worst[:5]
            )
            + "</ul>"
        )
    out.append(
        "<div class='kpis'>"
        + "".join(
            f"<div class='kpi'><div class='l'>{_e(label)}</div><div class='v'>{_e(v)}</div></div>"
            for label, v in [
                ("Assessments", t["assessments"]),
                ("Pass", t["pass"]),
                ("Fail", t["fail"]),
                ("Unknown", t["unknown"]),
                ("Stale", t["stale"]),
                ("Open findings", len(open_f)),
            ]
        )
        + "</div>"
    )

    # Methodology
    out.append("<h2>2. Assessment counts and methodology</h2>")
    out.append("<table><tr><th>metric</th><th>value</th><th>definition</th></tr>")
    out.append(
        f"<tr><td>coverage</td><td>{_e(t['coverage_pct'])}%</td><td>{_e(doc['methodology']['metrics']['coverage_pct'])}</td></tr>"
    )
    out.append(
        f"<tr><td>pass rate (determinate)</td><td>{_e(t['pass_rate_of_determinate_pct'])}%</td><td>{_e(doc['methodology']['metrics']['pass_rate_of_determinate_pct'])}</td></tr>"
    )
    out.append(
        f"<tr><td>pass rate (all)</td><td>{_e(t['pass_rate_of_all_pct'])}%</td><td>{_e(doc['methodology']['metrics']['pass_rate_of_all_pct'])}</td></tr></table>"
    )
    out.append(
        "<table><tr><th>state</th><th>meaning</th></tr>"
        + "".join(f"<tr><td>{_chip(k)}</td><td>{_e(v)}</td></tr>" for k, v in doc["methodology"]["states"].items())
        + "</table>"
    )
    out.append(f"<p class='small muted'>Freshness: {_e(doc['methodology']['freshness'])}</p>")
    out.append(
        "<h3>Results by control</h3><table><tr><th>control</th><th>category</th><th>assessed</th><th>pass</th><th>fail</th><th>unknown</th><th>stale</th><th>status</th><th>NIST CSF 2.0</th></tr>"
    )
    for c in p["by_control"]:
        out.append(
            f"<tr><td><b>{_e(c['name'])}</b><div class='mono muted'>{_e(c['control_id'])}</div></td><td>{_e(c['category'])}</td><td>{c['assessments']}</td><td>{c['pass']}</td><td>{c['fail']}</td><td>{c['unknown']}</td><td>{c['stale']}</td><td>{_chip(c['status'])}</td><td class='mono'>{_e(', '.join(x['id'] for x in c['csf']))}</td></tr>"
        )
    out.append("</table>")

    # Findings
    out.append("<h2>3. Control findings</h2>")
    if not open_f:
        out.append("<p>No open findings.</p>")
    for f in worst:
        rem = f.get("remediation") or {}
        out.append(
            f"<h3>{_e(f['id'])} · {_e(f['control_name'])} <span class='chip {html.escape(f['severity'])}'>{_e(f['severity'])}</span> <span class='chip {html.escape(f.get('result', 'FAIL'))}'>{_e(f.get('result', 'FAIL'))}</span> <span class='chip status'>{_e(f['status'])}</span></h3>"
        )
        out.append(
            f"<table><tr><th>affected asset</th><td>{_e(f.get('asset') or f['scope']['id'])} {('· ' + _e(f['scope'].get('interface'))) if f['scope'].get('interface') else ''}</td></tr>"
            f"<tr><th>expected</th><td class='mono'>{_e(json.dumps(f['expected']) if not isinstance(f['expected'], str) else f['expected'])}</td></tr>"
            f"<tr><th>observed</th><td class='mono'>{_e(json.dumps(f['observed']) if not isinstance(f['observed'], str) else f['observed'])}</td></tr>"
            f"<tr><th>explanation</th><td>{_e(f['explanation'])}</td></tr>"
            f"<tr><th>opened</th><td>{_e(f['opened_at'])} (run {_e(f['first_run_id'])}, {f.get('occurrences', 1)} occurrence(s))</td></tr>"
            f"<tr><th>remediation</th><td>{_e(rem.get('guidance'))}{('<pre>' + _e(chr(10).join(rem.get('commands') or [])) + '</pre>') if rem.get('commands') else ''}</td></tr></table>"
        )
    if closed_f:
        out.append(
            "<h3>Verified / closed findings</h3><table><tr><th>finding</th><th>control</th><th>asset</th><th>opened</th><th>closed</th><th>verification</th></tr>"
        )
        for f in sorted(closed_f, key=lambda x: x.get("resolved_at") or ""):
            v = f.get("verification") or {}
            out.append(
                f"<tr><td class='mono'>{_e(f['id'])}</td><td>{_e(f['control_name'])}</td><td>{_e(f.get('asset') or f['scope']['id'])}</td><td>{_e(f['opened_at'])}</td><td>{_e(f.get('resolved_at'))}</td><td>{_chip(v.get('outcome') or 'UNKNOWN')} {('after remediation' if v.get('after_remediation') else '')} · run {_e(v.get('run_id'))}</td></tr>"
            )
        out.append("</table>")

    # Affected assets
    out.append("<h2>4. Affected assets</h2>")
    if doc["assets_with_open_findings"]:
        out.append(
            "<table><tr><th>asset</th><th>interface</th><th>open findings</th><th>worst severity</th><th>controls</th></tr>"
            + "".join(
                f"<tr><td>{_e(a['asset'])}</td><td class='mono'>{_e(a.get('interface'))}</td><td>{a['findings']}</td><td><span class='chip {html.escape(a['worst'])}'>{_e(a['worst'])}</span></td><td class='mono'>{_e(', '.join(a['controls']))}</td></tr>"
                for a in doc["assets_with_open_findings"]
            )
            + "</table>"
        )
    else:
        out.append("<p>No assets currently have open findings.</p>")
    if doc["unverified"]:
        out.append(
            "<h3>Unverified assessments (UNKNOWN / STALE)</h3><table><tr><th>assessment</th><th>status</th><th>scope</th><th>explanation</th></tr>"
            + "".join(
                f"<tr><td class='mono'>{_e(u['id'])}</td><td>{_chip(u['status'])}</td><td>{_e(u['scope'].get('asset') or u['scope']['id'])}</td><td>{_e(u['explanation'])}</td></tr>"
                for u in doc["unverified"]
            )
            + "</table>"
        )

    # Supporting evidence
    out.append(
        "<h2>5. Supporting evidence</h2><p class='small muted'>Evidence rows for every non-passing assessment and for the incident-related controls. Every assessment in the JSON export carries its full evidence list.</p>"
    )
    out.append(
        "<table><tr><th>assessment</th><th>status</th><th>evidence source</th><th>reference</th><th>collected</th><th>detail</th></tr>"
    )
    for a in assessments:
        if a["status"] == "PASS" and a["scope"]["type"] != "incident":
            continue
        for ev in a["evidence"]:
            out.append(
                f"<tr><td class='mono'>{_e(a['id'])}</td><td>{_chip(a['status'])}</td><td>{_e(ev['source'])}</td><td class='mono'>{_e(ev['ref'])}</td><td class='mono'>{_e(ev['collected_at'])}</td><td class='small'>{_e(ev['detail'][:220])}</td></tr>"
            )
    out.append("</table>")

    # Incident timeline
    out.append("<h2>6. Incident timeline</h2>")
    for item in doc["incidents"]:
        inc = item["incident"]
        out.append(
            f"<h3>{_e(inc['id'])} · {_e(inc['title'])} <span class='chip {html.escape(inc['severity'])}'>{_e(inc['severity'])}</span> <span class='chip status'>{_e(inc['status'])}</span></h3>"
        )
        out.append(
            f"<p class='small'>Chain: <span class='mono'>{_e(' → '.join(inc.get('chain', [])))}</span> · opened {_e(inc['opened_at'])}"
            + (f" · closed {_e(inc['closed_at'])} by {_e(inc.get('closed_by'))}" if inc.get("closed_at") else "")
            + "</p>"
        )
        out.append(
            "<table><tr><th>time (UTC)</th><th>phase</th><th>actor</th><th>event</th></tr>"
            + "".join(
                f"<tr><td class='mono'>{_e(_dt(e['ts']))}</td><td>{_e(e['phase'])}</td><td>{_e(e['actor'])}</td><td>{_e(e['message'])}</td></tr>"
                for e in item["timeline"]
            )
            + "</table>"
        )

    # Authorization and verification
    out.append(
        "<h2>7. Containment authorization and verification</h2><table><tr><th>workflow</th><th>incident</th><th>action</th><th>authorization</th><th>authorized at</th><th>applied</th><th>verified</th><th>read-back</th><th>status</th></tr>"
    )
    for a in doc["containment_actions"]:
        auth = a.get("authorization") or {}
        ver = a.get("verification") or {}
        out.append(
            f"<tr><td class='mono'>{_e(a['workflow_id'])}</td><td class='mono'>{_e(a.get('incident_id'))}</td><td>{_e(a['action'])} {_e(a.get('interface'))}</td><td>{_e(auth.get('mode'))} · {_e(auth.get('authorized_by'))}<div class='small muted'>{_e(auth.get('basis'))}</div></td><td class='mono'>{_e(_dt(auth.get('authorized_at')))}</td><td class='mono'>{_e(_dt(a.get('applied_at')))}</td><td class='mono'>{_e(_dt(a.get('verified_at')))}</td><td>{_chip('PASS' if ver.get('ok') else 'FAIL')}</td><td>{_e(a['status'])}</td></tr>"
        )
    out.append("</table>")
    if doc["manual_reviews"]:
        out.append(
            "<h3>Detections routed to manual review</h3><table><tr><th>detection</th><th>title</th><th>confidence</th><th>policy disposition</th><th>guards</th><th>authorization</th><th>outcome</th></tr>"
        )
        for r in doc["manual_reviews"]:
            auth = r.get("authorization") or {}
            d = r.get("decision") or {}
            out.append(
                f"<tr><td class='mono'>{_e(r['detection_id'])}</td><td>{_e(r['title'])}</td><td>{_e(r['confidence'])}</td><td>{_e(d.get('disposition'))}</td><td class='mono'>{_e(', '.join(d.get('guards_triggered') or []) or '—')}</td><td>{_e(auth.get('status'))} · {_e(auth.get('authorized_by'))}</td><td>{_e(r['status'])}: {_e(r.get('note'))}</td></tr>"
            )
        out.append("</table>")

    # Outstanding remediation
    out.append("<h2>8. Outstanding remediation</h2>")
    pending = [f for f in open_f]
    if pending:
        out.append(
            "<table><tr><th>finding</th><th>status</th><th>asset</th><th>remediation</th><th>requested</th><th>executed</th></tr>"
            + "".join(
                f"<tr><td class='mono'>{_e(f['id'])}</td><td>{_e(f['status'])}</td><td>{_e(f.get('asset') or f['scope']['id'])}</td><td>{_e((f.get('remediation') or {}).get('guidance'))}</td><td class='mono'>{_e((f.get('remediation') or {}).get('requested_at'))}</td><td class='mono'>{_e((f.get('remediation') or {}).get('executed_at'))}</td></tr>"
                for f in pending
            )
            + "</table>"
        )
    else:
        out.append("<p>No outstanding remediation.</p>")
    out.append(
        "<h3>Remediation history</h3><table><tr><th>finding</th><th>time</th><th>event</th><th>actor</th><th>detail</th></tr>"
    )
    for f in findings:
        for e in f.get("events", []):
            out.append(
                f"<tr><td class='mono'>{_e(f['id'])}</td><td class='mono'>{_e(e['ts'])}</td><td>{_e(e['event'])}</td><td>{_e(e.get('actor'))}</td><td class='small'>{_e(e.get('detail'))}</td></tr>"
            )
    out.append("</table>")

    # Framework mapping
    out.append("<h2>9. Framework mapping (NIST CSF 2.0)</h2>")
    out.append(
        f"<p class='small muted'>{_e(doc['framework_mapping']['note'])}</p><table><tr><th>subcategory</th><th>text</th><th>controls</th><th>pass</th><th>fail</th><th>unknown</th><th>stale</th></tr>"
    )
    for r in doc["framework_mapping"]["subcategories"]:
        out.append(
            f"<tr><td class='mono'>{_e(r['id'])}</td><td>{_e(r['text'])}</td><td class='mono small'>{_e(', '.join(r['controls']))}</td><td>{r['pass']}</td><td>{r['fail']}</td><td>{r['unknown']}</td><td>{r['stale']}</td></tr>"
        )
    out.append("</table>")

    # Limitations
    out.append(
        "<h2>10. Limitations and reproducibility</h2><ul>"
        + "".join(f"<li>{_e(x)}</li>" for x in doc["limitations"])
        + "</ul>"
    )
    out.append(
        f"<p class='small'>Reproduce: <span class='mono'>{_e(' ; '.join(doc['reproducibility']['commands']))}</span>. Dataset manifest: <span class='mono'>{_e(doc['reproducibility']['dataset_manifest'])}</span>. Validation harness: {_e(doc['validation']['metrics'].get('passed'))}/{_e(doc['validation']['metrics'].get('scenarios'))} scenarios, MTTD {_e(doc['validation']['metrics'].get('mttd'))} s, MTTC {_e(doc['validation']['metrics'].get('mttc'))} s (simulated clock).</p>"
    )
    out.append(
        f"<p class='small muted'>Report rendered from persisted records at simulated clock {_e(doc['generated_at'])}; no wall-clock timestamps are embedded so repeated exports of the same state are identical.</p>"
    )
    out.append("</div></body></html>")
    return "".join(out)


def write_html(doc: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(doc), encoding="utf-8")
    return path


def write_pdf(html_path: Path, pdf_path: Path) -> Path | None:
    """Render the HTML report to PDF with headless Chromium if Playwright is installed."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_path.resolve().as_uri(), wait_until="load")
            page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
            )
            browser.close()
    except Exception:  # noqa: BLE001 - Chromium missing or not launchable
        return None
    return pdf_path
