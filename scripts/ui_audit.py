"""Render every dashboard route at four viewports against a temporary server and measure it.

For each route and viewport the script records horizontal overflow, elements wider than the viewport
outside scroll containers, font sizes in use, text below 11 px, border radii, inline-styled nodes,
clickable rows without keyboard access, chips without text, undersized buttons, console errors and
failed requests, and saves a viewport screenshot. It exits non-zero when any acceptance criterion of
docs/ui-redesign-plan.md (section H.4) fails, so it doubles as the visual-QA gate.

Usage:
    python scripts/ui_audit.py OUT_DIR
    UI_AUDIT_ROUTES="/,/operations,/alerts" python scripts/ui_audit.py OUT_DIR   # custom route list
    SENTINEL_AUTO_DEMO=0 python scripts/ui_audit.py OUT_DIR                      # baseline stage

The server it starts uses a temporary database, a copy of the committed evidence bundles and a
temporary artifacts directory, so the repository and the live deployment are never touched.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ROUTES = [
    "/",
    "/posture",
    "/controls",
    "/controls/CTL-ENDPOINT-IDENTITY",
    "/findings",
    "/findings/FND-SENSOR-COVERAGE-vlan-50",
    "/incidents",
    "/incidents/INC-2026-0042",
    "/reports",
    "/alerts",
    "/devices",
    "/devices/ENG-LT-047",
    "/switch",
    "/authentication",
    "/coverage",
    "/drift",
    "/evidence",
    "/evidence/INC-2026-0042",
    "/about",
]
VIEWPORTS = {"desktop": (1920, 1080), "laptop": (1440, 900), "tablet": (1024, 768), "mobile": (390, 844)}
ALLOWED_RADII = {"4px", "6px", "50%"}
MAX_FONT_SIZES = 8
HEX_EXEMPT = {"Logo.tsx", "SwitchPanel.tsx"}

METRICS_JS = """() => {
  const vw = document.documentElement.clientWidth;
  const all = [...document.querySelectorAll('body *')];
  const vis = all.filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
  const inScroller = e => !!e.closest('[style*="overflow"], .table-wrap, pre, .chain, .ledger, .trace, .tabs, .console, .md table, .scroll-x');
  const fonts = {}; let tiny = 0; const tinyEls = [];
  for (const e of vis) {
    if (![...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const fs = parseFloat(getComputedStyle(e).fontSize); fonts[fs] = (fonts[fs] || 0) + 1;
    if (fs < 11 && !e.closest('svg')) { tiny++; if (tinyEls.length < 5) tinyEls.push((e.className ? String(e.className).slice(0, 30) : e.tagName) + ':' + e.textContent.trim().slice(0, 24)); }
  }
  const radii = {};
  for (const e of vis) { const r = getComputedStyle(e).borderTopLeftRadius; if (r !== '0px') radii[r] = (radii[r] || 0) + 1; }
  const minBtn = vw < 600 ? 40 : 32;
  return {
    hOverflow: document.documentElement.scrollWidth - vw,
    wide: vis.filter(e => e.getBoundingClientRect().right > vw + 1 && !inScroller(e)).length,
    fonts, tiny, tinyEls, radii,
    inlineStyled: document.querySelectorAll('[style]').length,
    rowsNotFocusable: document.querySelectorAll('tr.clickable:not([tabindex])').length,
    chipsWithoutText: [...document.querySelectorAll('.chip')].filter(c => !c.textContent.trim()).length,
    smallButtons: [...document.querySelectorAll('button,a.btn')].filter(b => { const r = b.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.height < minBtn; }).length,
    docHeight: document.documentElement.scrollHeight,
  };
}"""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(tmp: Path, port: int) -> subprocess.Popen:
    incidents = tmp / "incidents"
    shutil.copytree(ROOT / "data" / "incidents", incidents)
    env = dict(
        os.environ,
        SENTINEL_DB=str(tmp / "audit.db"),
        SENTINEL_INCIDENTS_DIR=str(incidents),
        SENTINEL_ARTIFACTS_DIR=str(tmp / "artifacts"),
        SENTINEL_AUTO_SEED="1",
        SENTINEL_AUTO_DEMO=os.environ.get("SENTINEL_AUTO_DEMO", "1"),
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "sentinelswitch", "serve", "--port", str(port)],
        env=env,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(base + "/api/meta", timeout=2)
            return proc
        except Exception:  # noqa: BLE001 - server still starting
            time.sleep(1)
    proc.terminate()
    raise SystemExit("server did not start")


def audit(out: Path, routes: list[str]) -> dict[str, dict]:
    report: dict[str, dict] = {}
    tmp = Path(tempfile.mkdtemp(prefix="ui-audit-"))
    port = free_port()
    proc = start_server(tmp, port)
    base = f"http://127.0.0.1:{port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for vname, (w, h) in VIEWPORTS.items():
                ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme="dark")
                page = ctx.new_page()
                errors: list[str] = []
                failed: list[str] = []

                def on_console(msg, errors=errors):
                    if msg.type in ("error", "warning"):
                        errors.append(msg.text)

                def on_failed(req, failed=failed):
                    failed.append(req.url)

                def on_response(res, failed=failed):
                    if res.status >= 400:
                        failed.append(f"{res.status} {res.url}")

                page.on("console", on_console)
                page.on("requestfailed", on_failed)
                page.on("response", on_response)
                for route in routes:
                    errors.clear()
                    failed.clear()
                    page.goto(base + route, wait_until="networkidle")
                    page.wait_for_timeout(600)
                    m = page.evaluate(METRICS_JS)
                    m["console"] = list(errors)
                    m["failed"] = list(failed)
                    name = (route.strip("/") or "home").replace("/", "_").replace("?", "_")
                    page.screenshot(path=str(out / f"{vname}__{name}.png"))
                    report[f"{vname} {route}"] = m
                ctx.close()
            browser.close()
    finally:
        proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    return report


def failing(report: dict[str, dict]) -> list[str]:
    bad = []
    for key, m in report.items():
        reasons = []
        if m["hOverflow"] > 0:
            reasons.append(f"overflow {m['hOverflow']}px")
        if m["wide"]:
            reasons.append(f"{m['wide']} elements past the viewport")
        if m["console"]:
            reasons.append(f"{len(m['console'])} console messages")
        if m["failed"]:
            reasons.append(f"{len(m['failed'])} failed requests")
        if m["tiny"]:
            reasons.append(f"{m['tiny']} text nodes below 11px")
        if m["rowsNotFocusable"]:
            reasons.append(f"{m['rowsNotFocusable']} rows not focusable")
        if m["chipsWithoutText"]:
            reasons.append(f"{m['chipsWithoutText']} chips without text")
        if len({float(x) for x in m["fonts"]}) > MAX_FONT_SIZES:
            reasons.append(f"{len(m['fonts'])} font sizes")
        extra = set(m["radii"]) - ALLOWED_RADII
        if extra:
            reasons.append(f"radii {sorted(extra)}")
        if reasons:
            bad.append(f"{key}: " + "; ".join(reasons))
    return bad


def hex_literals() -> list[str]:
    hits = []
    for f in (ROOT / "frontend" / "src").rglob("*.tsx"):
        if f.name in HEX_EXEMPT:
            continue
        if re.search(r"#[0-9a-fA-F]{6}\b", f.read_text(encoding="utf-8")):
            hits.append(str(f.relative_to(ROOT)))
    return sorted(hits)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    routes = [r for r in os.environ.get("UI_AUDIT_ROUTES", ",".join(DEFAULT_ROUTES)).split(",") if r]
    report = audit(out, routes)
    (out / "metrics.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    bad = failing(report)
    hexes = hex_literals()
    print(f"{len(report)} route/viewport combinations measured; screenshots in {out}")
    print(f"routes failing a criterion: {len(bad)}")
    for b in bad:
        print("  ", b)
    print("tsx files with hex colour literals:", hexes or "none")
    return 1 if bad or hexes else 0


if __name__ == "__main__":
    sys.exit(main())
