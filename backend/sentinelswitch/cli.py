"""SentinelSwitch command line: generate, seed, demo, validate, reset, serve, drift, show."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinelswitch import __version__
from sentinelswitch.app.config import get_settings
from sentinelswitch.services import demo as demo_service
from sentinelswitch.services.seed import seed_database
from sentinelswitch.services.store import Store
from simulator.canonical import load_environment, parse_ts

console = Console(highlight=False, width=None if sys.stdout.isatty() else 150)

PHASE_STYLE = {
    "telemetry": "cyan",
    "alert": "yellow",
    "switch": "blue",
    "aaa": "blue",
    "detection": "bold red",
    "incident": "bold red",
    "correlation": "magenta",
    "policy": "bold yellow",
    "containment": "bold green",
    "verification": "green",
    "evidence": "bold white",
    "resolution": "white",
}
PHASE_LABEL = {
    "telemetry": "telemetry",
    "alert": "detect",
    "switch": "switch",
    "aaa": "aaa",
    "detection": "detection",
    "incident": "incident",
    "correlation": "correlate",
    "policy": "policy",
    "containment": "contain",
    "verification": "verify",
    "evidence": "evidence",
    "resolution": "restore",
}


def _rel(path: Path, root: Path) -> str:
    """Repository-relative path for records that are shared (no local home-directory paths)."""
    return str(path.relative_to(root)) if path.is_relative_to(root) else path.name


def _store():
    settings = get_settings()
    env = load_environment()
    return Store(env, settings.db_path), env, settings


def banner(subtitle: str) -> None:
    console.print(
        Panel.fit(
            Text.assemble(
                ("SentinelSwitch ", "bold cyan"),
                ("· ", "dim"),
                ("Evidence-Driven Network Security & Response Lab", "white"),
                ("\n" + subtitle, "dim"),
            ),
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------------------------
def cmd_generate(args) -> int:
    from simulator.generators.run import generate

    banner("Generating the deterministic synthetic dataset")
    manifest = generate(quiet=True)
    c = manifest["counts"]
    table = Table(title="Dataset", show_header=True, header_style="bold")
    table.add_column("artifact")
    table.add_column("records", justify="right")
    table.add_row("Zeek conn.log", str(c["zeek"]["conn"]))
    table.add_row("Zeek dns.log", str(c["zeek"]["dns"]))
    table.add_row("Zeek ssl.log / http.log", f"{c['zeek']['ssl']} / {c['zeek']['http']}")
    table.add_row("Zeek notice.log / weird.log", f"{c['zeek']['notice']} / {c['zeek']['weird']}")
    table.add_row("Suricata eve.json (alerts / flows)", f"{c['suricata']['alerts']} / {c['suricata']['flows']}")
    table.add_row(
        "RADIUS events (accept / reject)",
        f"{c['radius']['events']} ({c['radius']['accepts']} / {c['radius']['rejects']})",
    )
    table.add_row("IOS syslog lines", str(c["syslog"]))
    table.add_row("Alerts / detections / incidents", f"{c['alerts']} / {c['detections']} / {c['incidents']}")
    console.print(table)
    console.print(
        f"[green]✓[/] wrote data/, cisco/show-output/ and data/incidents/ ({len(manifest['files'])} hashed files)"
    )
    return 0


def cmd_seed(args) -> int:
    store, env, settings = _store()
    banner("Loading the dataset into SQLite and running the validation harness")
    if not settings.seed_dir.exists() or args.regenerate:
        cmd_generate(args)
    summary = seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    counts = summary["counts"]
    console.print(
        f"[green]✓[/] seeded {settings.db_path.relative_to(settings.root) if settings.db_path.is_relative_to(settings.root) else settings.db_path}: {counts['devices']} devices, {counts['alerts']} alerts, {counts['incidents']} incidents, {counts['auth_events']} auth events"
    )
    v = summary.get("validation") or {}
    if v:
        console.print(
            f"[green]✓[/] validation: {v['passed']}/{v['scenarios']} scenarios met their expected outcome ({v.get('contained')} contained, {v.get('withheld')} withheld by policy)  MTTD {v['mttd']}s  MTTA {v['mtta']}s  MTTC {v['mttc']}s"
        )
    console.print("[dim]baseline state: Gi1/0/23 in VLAN 20, flagship incident not yet replayed[/]")
    return 0


def cmd_reset(args) -> int:
    store, env, settings = _store()
    banner("Resetting to the deterministic baseline")
    seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    console.print("[green]✓[/] baseline restored (flagship evidence bundle removed, Gi1/0/23 back in VLAN 20)")
    return 0


def _print_line(ts: str, phase: str, message: str) -> None:
    stamp = ts[11:23]
    label = PHASE_LABEL.get(phase, phase)
    console.print(
        Text.assemble((f"[{stamp}] ", "dim"), (f"{label:<11}", PHASE_STYLE.get(phase, "white")), (message, "white"))
    )


def cmd_demo(args) -> int:
    store, env, settings = _store()
    banner("Replaying the flagship incident: lateral reconnaissance from ENG-LT-047")
    if store.kv_get("twin") is None or args.reset:
        console.print("[dim]→ resetting the deterministic environment[/]")
        seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    elif demo_service.demo_status(store).get("stage") == "contained":
        console.print("[yellow]flagship incident already applied; resetting first[/]")
        seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    twin_before = store.load_twin()
    console.print(
        f"[dim]→ baseline loaded: {twin_before.hostname} {twin_before.model}, Gi1/0/23 access VLAN {twin_before.interfaces['Gi1/0/23'].access_vlan}[/]"
    )
    console.print()
    result = demo_service.run_flagship(store, env, settings)
    prev = None
    for entry in result.timeline:
        if entry["phase"] in {"resolution"}:
            continue
        if not args.fast and prev is not None:
            gap = (parse_ts(entry["ts"]) - parse_ts(prev)).total_seconds()
            time.sleep(min(max(gap * args.speed, 0.0), 1.2))
        prev = entry["ts"]
        _print_line(entry["ts"], entry["phase"], entry["message"])
    console.print()
    inc = result.incident
    twin_after = store.load_twin()
    m = result.metrics
    table = Table(show_header=False, box=None)
    table.add_row("incident", f"[bold]{inc['id']}[/] — {inc['title']}")
    table.add_row("endpoint", f"{inc['device']} ({inc['user']}) {inc['ip']} {inc['mac']}")
    table.add_row(
        "switch port",
        f"{inc['switch']} {inc['interface']}  VLAN {inc['original_vlan']} → VLAN {inc['current_vlan']}  ({twin_after.interfaces[inc['interface']].oper_status})",
    )
    table.add_row("time to detect", f"{m['ttd']:.3f} s   (first anomalous flow → incident detection)")
    table.add_row("time to attribute", f"{m['tta']:.3f} s   (detection → IP/MAC/port/identity resolved)")
    table.add_row("time to contain", f"{m['ttc']:.3f} s   (detection → quarantine verified)")
    table.add_row(
        "evidence",
        f"data/incidents/{inc['id']}/  ({len(result.flows)} related connections, {len(result.dns)} DNS records)",
    )
    console.print(
        Panel(
            table,
            title="[bold green]containment verified[/]"
            if inc["status"] == "contained"
            else "[red]containment failed[/]",
            border_style="green" if inc["status"] == "contained" else "red",
        )
    )
    console.print('[dim]verify on the twin:  sentinelswitch show "show interfaces Gi1/0/23 switchport"[/]')
    return 0 if result.passed else 1


def cmd_validate(args) -> int:
    from sentinelswitch.validation.harness import run_validation

    store, env, settings = _store()
    if store.kv_get("twin") is None:
        seed_database(store, env, settings.seed_dir, settings.incidents_dir, run_validation_suite=False)
    report = run_validation(env, store.load_baseline_twin())
    for row in report.results:
        store.put_validation(row)
    store.kv_set("validation_metrics", report.metrics | {"all_passed": report.all_passed})
    if args.json:
        print(
            json.dumps(
                {
                    "results": [
                        {k: v for k, v in r.items() if k not in {"timeline", "features", "derived"}}
                        for r in report.results
                    ],
                    "metrics": report.metrics,
                },
                indent=2,
            )
        )
        return 0 if report.all_passed else 1
    banner(f"Security validation: {len(report.results)} adversary scenarios replayed against an isolated twin")
    table = Table(title="SENTINELSWITCH SECURITY VALIDATION", header_style="bold", title_style="bold cyan")
    table.add_column("Scenario")
    table.add_column("Detect", justify="center")
    table.add_column("Attribute", justify="center")
    table.add_column("Response", justify="center")
    table.add_column("Conf", justify="right")
    table.add_column("TTD", justify="right")
    table.add_column("TTA", justify="right")
    table.add_column("TTC", justify="right")
    table.add_column("Mechanism")

    def pf(ok: bool) -> str:
        return "[bold green]PASS[/]" if ok else "[bold red]FAIL[/]"

    def response(r: dict) -> str:
        return {"contained": "[bold green]CONTAINED[/]", "withheld": "[bold cyan]WITHHELD[/]"}.get(
            r.get("response", ""), "[bold red]FAIL[/]"
        )

    for r in report.results:
        table.add_row(
            r["name"],
            pf(r["detect"]),
            pf(r["attribute"]),
            response(r),
            f"{r['confidence']:.2f}",
            f"{r['ttd']:.3f}s",
            f"{r['tta']:.3f}s",
            f"{r['ttc']:.3f}s" if r["ttc"] is not None else "-",
            r["mechanism"] or "-",
        )
    console.print(table)
    m = report.metrics
    console.print(
        f"  Mean Time To Detect     [bold]{m['mttd']:.3f} s[/]   (range {m['min_ttd']:.3f}–{m['max_ttd']:.3f} s; DNS anomalies need a minute of volume)"
    )
    console.print(f"  Mean Time To Attribute  [bold]{m['mtta']:.3f} s[/]")
    console.print(f"  Mean Time To Contain    [bold]{m['mttc']:.3f} s[/]   (detection → switch state verified)")
    console.print(
        f"  {m['passed']}/{m['scenarios']} scenarios met their expected outcome"
        f" ({m['contained']} contained and verified, {m['withheld']} withheld by policy for analyst review)"
        + ("  [green]✓ all controls validated[/]" if report.all_passed else "  [red]✗ failures present[/]")
    )
    return 0 if report.all_passed else 1


def cmd_drift(args) -> int:
    from sentinelswitch.drift.engine import DriftEngine

    store, env, settings = _store()
    twin = store.load_twin()
    report = DriftEngine(env).evaluate(twin)
    banner("Configuration drift: desired intent vs observed switch state")
    table = Table(header_style="bold")
    for col in ("id", "interface", "setting", "expected", "observed", "severity", "status"):
        table.add_column(col)
    for f in report["findings"]:
        table.add_row(
            f["id"],
            f["interface"] or "-",
            f["setting"],
            str(f["expected"]),
            str(f["observed"]),
            f["severity"],
            f["status"],
        )
    console.print(table)
    console.print(
        f"{report['checks']} checks on {report['checked_interfaces']} interfaces: {report['open']} open, {report['approved']} approved deviations"
    )
    return 0


def cmd_show(args) -> int:
    from sentinelswitch.simulator import cli_render

    store, env, settings = _store()
    twin = store.load_twin()
    print(f"{twin.hostname}#{args.command}")
    print(cli_render.run_show(twin, args.command))
    print(f"{twin.hostname}#")
    return 0


def cmd_status(args) -> int:
    store, env, settings = _store()
    if store.kv_get("twin") is None:
        console.print("[yellow]database not seeded[/]")
        return 1
    twin = store.load_twin()
    print(
        json.dumps(
            {
                "db": str(settings.db_path),
                "demo": demo_service.demo_status(store),
                "switch": twin.summary(),
                "counts": store.counts(),
                "gi1/0/23": {
                    "access_vlan": twin.interfaces["Gi1/0/23"].access_vlan,
                    "quarantined": twin.interfaces["Gi1/0/23"].quarantined,
                },
            },
            indent=2,
        )
    )
    return 0


def _assurance(store, env, settings):
    from sentinelswitch.assurance.engine import AssessmentEngine

    return AssessmentEngine(env, store, settings.incidents_dir)


def _print_run(run: dict) -> None:
    c = run["counts"]
    console.print(
        f"[green]✓[/] {run['run_id']}: {run['assessments']} assessments over {run['controls']} controls at {run['assessed_at'][11:23]}Z — "
        f"[green]{c['PASS']} pass[/] · [red]{c['FAIL']} fail[/] · [yellow]{c['STALE']} stale[/] · [dim]{c['UNKNOWN']} unknown[/] · {run['findings_open']} open findings"
    )


def cmd_assess(args) -> int:
    store, env, settings = _store()
    if store.kv_get("twin") is None:
        seed_database(store, env, settings.seed_dir, settings.incidents_dir, run_validation_suite=False)
    run = _assurance(store, env, settings).run(args.trigger, actor=args.actor)
    if args.json:
        print(json.dumps(run, indent=2))
        return 0
    banner("Control assessment against the current twin state")
    _print_run(run)
    for a in store.assessments():
        if a["status"] != "PASS":
            console.print(
                f"  [{'red' if a['status'] == 'FAIL' else 'yellow' if a['status'] == 'STALE' else 'dim'}]{a['status']:<7}[/] {a['id']:<44} {a['explanation'][:110]}"
            )
    return 0


def cmd_findings(args) -> int:
    from sentinelswitch.assurance.engine import FINDING_OPEN_STATES

    store, env, settings = _store()
    rows = store.findings()
    if not args.all:
        rows = [f for f in rows if f["status"] in FINDING_OPEN_STATES]
    table = Table(title="Findings", header_style="bold")
    for col in ("id", "severity", "result", "status", "asset", "control", "opened"):
        table.add_column(col)
    for f in rows:
        table.add_row(
            f["id"],
            f["severity"],
            f.get("result", "FAIL"),
            f["status"],
            str(f.get("asset") or f["scope"]["id"]),
            f["control_name"],
            f["opened_at"][11:19],
        )
    console.print(table)
    return 0


def cmd_remediate(args) -> int:
    from sentinelswitch.assurance.engine import FINDING_OPEN_STATES
    from sentinelswitch.assurance.remediation import RemediationError, RemediationService

    store, env, settings = _store()
    svc = RemediationService(env, store, _assurance(store, env, settings))
    ids = args.finding_ids or []
    if args.all:
        ids = [
            f["id"]
            for f in store.findings()
            if f["status"] in FINDING_OPEN_STATES and (f.get("remediation") or {}).get("action")
        ]
    if not ids:
        console.print("[yellow]nothing to remediate[/]")
        return 0
    rc = 0
    for fid in ids:
        try:
            res = svc.remediate(fid, actor=args.actor, note=args.note or "", reassess=not args.no_reassess)
        except (KeyError, RemediationError) as exc:
            console.print(f"[red]✗[/] {fid}: {exc}")
            rc = 1
            continue
        f = res["finding"]
        if not res.get("executed"):
            console.print(f"[red]✗[/] {fid} → {f['status']}: {res.get('refused')}")
            rc = 1
            continue
        console.print(
            f"[green]✓[/] {fid} → {f['status']}"
            + (f"  (verified by {f['verification']['run_id']})" if f.get("verification", {}).get("run_id") else "")
        )
        if res.get("transcript"):
            console.print(Text(res["transcript"], style="dim"))
    return rc


def cmd_report(args) -> int:
    from sentinelswitch.assurance.export import build_export, write_html, write_json, write_pdf

    store, env, settings = _store()
    out_dir = Path(args.out) if args.out else settings.artifacts_dir / "reports"
    doc = build_export(store, env, settings.incidents_dir)
    j = write_json(doc, out_dir / "security-posture-report.json")
    h = write_html(doc, out_dir / "security-posture-report.html")
    console.print(f"[green]✓[/] {j}")
    console.print(f"[green]✓[/] {h}")
    if not args.no_pdf:
        pdf = write_pdf(h, out_dir / "security-posture-report.pdf")
        console.print(f"[green]✓[/] {pdf}" if pdf else "[yellow]PDF skipped (Playwright Chromium not available)[/]")
    # validate the JSON round-trips and carries the required top-level keys
    required = {
        "schema_version",
        "generated_at",
        "posture",
        "controls",
        "assessments",
        "findings",
        "incidents",
        "containment_actions",
        "framework_mapping",
        "limitations",
    }
    loaded = json.loads(j.read_text(encoding="utf-8"))
    missing = required - set(loaded)
    if missing:
        console.print(f"[red]export missing keys: {sorted(missing)}[/]")
        return 1
    console.print(
        f"[dim]{len(loaded['assessments'])} assessments · {len(loaded['findings'])} findings · {len(loaded['incidents'])} incidents · schema {loaded['schema_version']}[/]"
    )
    return 0


def cmd_demo2(args) -> int:
    """SentinelSwitch 2.0 end-to-end workflow: reset → baseline assessment → flagship incident → post-containment
    assessment → remediation of open findings → reassessment → restore → recovery assessment → report."""
    from sentinelswitch.assurance.engine import FINDING_OPEN_STATES
    from sentinelswitch.assurance.export import build_export, write_html, write_json, write_pdf
    from sentinelswitch.assurance.remediation import RemediationService

    store, env, settings = _store()
    banner(
        "SentinelSwitch 2.0 — evidence-driven workflow: assess → detect → attribute → authorize → contain → verify → remediate → report"
    )
    results: dict = {"steps": []}

    def step(name: str, detail: str, **data):
        console.print(
            Text.assemble((f"{len(results['steps']) + 1:>2}. ", "dim"), (f"{name:<22}", "bold cyan"), (detail, "white"))
        )
        results["steps"].append({"step": name, "detail": detail, **data})

    seed_summary = seed_database(store, env, settings.seed_dir, settings.incidents_dir)
    step(
        "reset + baseline",
        f"seeded {seed_summary['counts']['devices']} devices; baseline assessment {seed_summary['assessment']['run_id']}: {seed_summary['assessment']['counts']}",
        assessment=seed_summary["assessment"],
    )
    flag = demo_service.run_flagship(store, env, settings)
    inc = flag.incident
    step(
        "flagship incident",
        f"{inc['id']} detected {flag.metrics['detection'][11:23]}Z conf {flag.detection.confidence} → {inc['interface']} VLAN {inc['original_vlan']}→{inc['current_vlan']} verified {flag.metrics['verified'][11:23]}Z (TTD {flag.metrics['ttd']}s, TTC {flag.metrics['ttc']}s)",
        incident=inc["id"],
        metrics=flag.metrics,
        authorization=inc.get("authorization"),
    )
    post_run = store.assessment_run(flag.metrics["assessment_run"])
    step("post-containment", f"{post_run['run_id']}: {post_run['counts']}", assessment=post_run)
    reviews = [r for r in store.reviews() if r["status"] == "review"]
    step(
        "negative path",
        f"{len([r for r in store.reviews() if (r.get('decision') or {}).get('guards_triggered')])} detection(s) withheld from automation by policy guards; {len(reviews)} awaiting analyst decision",
        withheld=[r["detection_id"] for r in store.reviews() if (r.get("decision") or {}).get("guards_triggered")],
    )
    from sentinelswitch.services import response as response_service

    for r in [r for r in store.reviews() if r["status"] == "review"]:
        guards = (r.get("decision") or {}).get("guards_triggered") or []
        res = response_service.reject_review(
            store,
            env,
            r["detection_id"],
            actor="tlee",
            note=f"Containment declined: {', '.join(guards) or 'confidence below the automatic tier'}; investigated and closed as benign after review.",
        )
        step(
            "analyst decision",
            f"{r['detection_id']} ({r['title']}): containment rejected by tlee",
            review=r["detection_id"],
            authorization=res["review"]["authorization"],
        )
    svc = RemediationService(env, store, _assurance(store, env, settings))
    remediated = []
    for fid in [
        f["id"]
        for f in store.findings()
        if f["status"] in FINDING_OPEN_STATES and (f.get("remediation") or {}).get("action")
    ]:
        current = store.finding(fid)
        if current is None or current["status"] not in FINDING_OPEN_STATES:
            step(
                "remediate",
                f"{fid} already {current['status'] if current else 'gone'} (verified by an earlier reassessment)",
                finding=fid,
                status=current["status"] if current else None,
            )
            continue
        res = svc.remediate(fid, actor="tlee", note="SentinelSwitch 2.0 demo remediation")
        remediated.append({"finding": fid, "status": res["finding"]["status"], "run": res.get("run", {}).get("run_id")})
        step("remediate", f"{fid} → {res['finding']['status']}", **remediated[-1])
    restore = demo_service.restore_incident(
        store,
        env,
        inc["id"],
        actor="tlee",
        note="Endpoint re-imaged and cleared by IT; returning to production VLAN.",
        settings=settings,
    )
    step(
        "restore + recovery",
        f"{inc['id']} resolved; recovery assessment {restore['assessment_run']['run_id']}: {restore['assessment_run']['counts']}",
        assessment=restore["assessment_run"],
    )
    out_dir = settings.artifacts_dir / "reports"
    doc = build_export(store, env, settings.incidents_dir)
    j = write_json(doc, out_dir / "security-posture-report.json")
    h = write_html(doc, out_dir / "security-posture-report.html")
    pdf = None if args.no_pdf else write_pdf(h, out_dir / "security-posture-report.pdf")
    step(
        "export",
        f"{j.name}, {h.name}" + (f", {pdf.name}" if pdf else " (PDF skipped)"),
        json=_rel(j, settings.root),
        html=_rel(h, settings.root),
        pdf=_rel(pdf, settings.root) if pdf else None,
    )
    final = store.kv_get("validation_metrics", {})
    post = doc["posture"]["totals"]
    results.update(
        {
            "final_posture": post,
            "findings": doc["posture"]["findings_by_status"],
            "validation": final,
            "incident": inc["id"],
            "generated_at": doc["generated_at"],
            "remediated": remediated,
        }
    )
    vdir = settings.artifacts_dir / "validation"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / "demo-results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    console.print(
        Panel(
            Text.assemble(
                ("final posture  ", "dim"),
                (
                    f"{post['assessments']} assessments · {post['pass']} pass · {post['fail']} fail · {post['unknown']} unknown · {post['stale']} stale · coverage {post['coverage_pct']}% · determinate pass rate {post['pass_rate_of_determinate_pct']}%\n",
                    "white",
                ),
                ("findings       ", "dim"),
                (json.dumps(doc["posture"]["findings_by_status"]) + "\n", "white"),
                ("artifacts      ", "dim"),
                (
                    f"{out_dir.relative_to(settings.root) if out_dir.is_relative_to(settings.root) else out_dir}  ·  {vdir / 'demo-results.json'}",
                    "white",
                ),
            ),
            title="[bold green]workflow complete[/]",
            border_style="green",
        )
    )
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    settings = get_settings()
    console.print(
        f"[cyan]SentinelSwitch[/] serving on http://{args.host or settings.host}:{args.port or settings.port}  (API docs at /docs)"
    )
    uvicorn.run(
        "sentinelswitch.app.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=args.reload,
        log_level="info" if args.reload else "warning",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinelswitch", description="SentinelSwitch — Evidence-Driven Network Security & Response Lab"
    )
    parser.add_argument("--version", action="version", version=f"sentinelswitch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate", help="regenerate the synthetic dataset from the canonical fixtures").set_defaults(
        fn=cmd_generate
    )
    p = sub.add_parser("seed", help="load the dataset into SQLite (generates first if needed)")
    p.add_argument("--regenerate", action="store_true")
    p.set_defaults(fn=cmd_seed)
    sub.add_parser("reset", help="restore the deterministic baseline").set_defaults(fn=cmd_reset)
    p = sub.add_parser("demo", help="replay the flagship incident end to end")
    p.add_argument("--fast", action="store_true", help="no pacing delays")
    p.add_argument("--reset", action="store_true", help="reset before replaying")
    p.add_argument("--speed", type=float, default=0.6, help="pacing multiplier for simulated gaps")
    p.set_defaults(fn=cmd_demo)
    p = sub.add_parser("validate", help="run the security validation harness")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_validate)
    sub.add_parser("drift", help="report configuration drift").set_defaults(fn=cmd_drift)
    p = sub.add_parser("show", help="run an IOS show command against the twin")
    p.add_argument("command")
    p.set_defaults(fn=cmd_show)
    sub.add_parser("status", help="print database / demo state").set_defaults(fn=cmd_status)
    p = sub.add_parser("assess", help="run the control assessment engine against the current twin state")
    p.add_argument("--trigger", default="cli")
    p.add_argument("--actor", default="tlee")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_assess)
    p = sub.add_parser("findings", help="list findings")
    p.add_argument("--all", action="store_true", help="include verified / closed findings")
    p.set_defaults(fn=cmd_findings)
    p = sub.add_parser("remediate", help="request, execute and verify remediation for findings")
    p.add_argument("finding_ids", nargs="*")
    p.add_argument("--all", action="store_true", help="remediate every open finding with an executable action")
    p.add_argument("--actor", default="tlee")
    p.add_argument("--note", default="")
    p.add_argument("--no-reassess", action="store_true")
    p.set_defaults(fn=cmd_remediate)
    p = sub.add_parser("report", help="export the posture + incident report (JSON, HTML, PDF)")
    p.add_argument("--out")
    p.add_argument("--no-pdf", action="store_true")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("demo2", help="SentinelSwitch 2.0 end-to-end workflow with exports (deterministic)")
    p.add_argument("--no-pdf", action="store_true")
    p.set_defaults(fn=cmd_demo2)
    p = sub.add_parser("serve", help="start the API + dashboard server")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(fn=cmd_serve)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
