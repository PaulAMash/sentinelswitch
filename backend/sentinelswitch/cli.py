"""SentinelSwitch command line: generate, seed, demo, validate, reset, serve, drift, show."""

from __future__ import annotations

import argparse
import json
import sys
import time

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
                ("Autonomous Network Detection & Response Lab", "white"),
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
            f"[green]✓[/] validation: {v['passed']}/{v['scenarios']} scenarios passed  MTTD {v['mttd']}s  MTTA {v['mtta']}s  MTTC {v['mttc']}s"
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
    banner("Security validation: 8 adversary scenarios replayed against an isolated twin")
    table = Table(title="SENTINELSWITCH SECURITY VALIDATION", header_style="bold", title_style="bold cyan")
    table.add_column("Scenario")
    table.add_column("Detect", justify="center")
    table.add_column("Attribute", justify="center")
    table.add_column("Contain", justify="center")
    table.add_column("Conf", justify="right")
    table.add_column("TTD", justify="right")
    table.add_column("TTA", justify="right")
    table.add_column("TTC", justify="right")
    table.add_column("Mechanism")

    def pf(ok: bool) -> str:
        return "[bold green]PASS[/]" if ok else "[bold red]FAIL[/]"

    for r in report.results:
        table.add_row(
            r["name"],
            pf(r["detect"]),
            pf(r["attribute"]),
            pf(r["contain"]),
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
        f"  {m['passed']}/{m['scenarios']} scenarios passed"
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
        prog="sentinelswitch", description="SentinelSwitch — Autonomous Network Detection & Response Lab"
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
    p = sub.add_parser("serve", help="start the API + dashboard server")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(fn=cmd_serve)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
