#!/usr/bin/env python3
"""Regenerate every screenshot and media asset from live application state.

    python scripts/screenshots.py [--port 8765] [--keep-state]

The script starts a dedicated API server on a temporary database, seeds it, applies the flagship
incident, and captures:

    assets/screenshots/*.png   every dashboard page (1440×900 @2x)
    assets/github/*.png        hero, architecture, dashboard, incident, validation images for the README
    assets/linkedin/0N-*.png   seven portrait carousel cards (1080×1350 @2x) rendered by /media/<slug>
    assets/branding/*.png      logo / social card rasterised from the SVG sources

Nothing here is hand-edited: every number in every image comes from the API.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
PAGES = [
    ("overview", "/", "01-overview"),
    ("alerts", "/alerts", "02-alerts"),
    ("incidents", "/incidents", "03-incidents"),
    ("incident-detail", "/incidents/INC-2026-0042", "04-incident-detail"),
    ("devices", "/devices", "05-devices"),
    ("switch", "/switch", "06-switch"),
    ("authentication", "/authentication", "07-authentication"),
    ("coverage", "/coverage", "08-detection-coverage"),
    ("drift", "/drift", "09-configuration-drift"),
    ("evidence", "/evidence/INC-2026-0042", "10-evidence"),
    ("about", "/about", "11-architecture"),
]
LINKEDIN = [
    "01-architecture",
    "02-soc-overview",
    "03-incident-detected",
    "04-correlation",
    "05-auto-quarantine",
    "06-cisco-verification",
    "07-validation-results",
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    raise RuntimeError(f"server at {url} did not come up")


def start_server(port: int, db: Path) -> subprocess.Popen:
    env = dict(os.environ, SENTINEL_DB=str(db), SENTINEL_AUTO_SEED="1", SENTINEL_AUTO_DEMO="1", SENTINEL_PORT=str(port))
    proc = subprocess.Popen(
        [sys.executable, "-m", "sentinelswitch", "serve", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for(f"http://127.0.0.1:{port}/api/meta")
    return proc


def _media(page, url: str, console: list[str]) -> None:
    """Load a /media/<slug> card; retry once and dump console output if the bundle never renders."""
    for attempt in range(2):
        page.goto(url, wait_until="domcontentloaded")
        try:
            page.wait_for_selector("#media-root:not([data-loading])", timeout=25000)
            if page.query_selector("#media-root[data-error]"):
                raise RuntimeError(page.get_attribute("#media-root", "data-error"))
            page.wait_for_timeout(1200)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"media {url} attempt {attempt + 1} failed: {exc}", file=sys.stderr)
            for line in console[-10:]:
                print("  console:", line, file=sys.stderr)
            if attempt == 1:
                raise


def capture(base: str) -> None:
    from playwright.sync_api import sync_playwright

    for d in ("screenshots", "github", "linkedin", "branding"):
        (ASSETS / d).mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # ---- dashboard pages -------------------------------------------------------------------
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2, color_scheme="dark")
        page = ctx.new_page()
        for _name, path, fname in PAGES:
            page.goto(f"{base}{path}", wait_until="networkidle")
            page.wait_for_selector(".content", timeout=15000)
            page.wait_for_timeout(700)
            page.screenshot(
                path=str(ASSETS / "screenshots" / f"{fname}.png"),
                full_page=path in {"/", "/incidents/INC-2026-0042", "/switch"},
            )
            print("screenshot", fname)
        # GitHub images (viewport-sized crops for the README)
        for path, fname in [
            ("/", "dashboard-overview"),
            ("/incidents/INC-2026-0042", "incident-detail"),
            ("/coverage", "validation-results"),
            ("/switch", "switch-panel"),
        ]:
            page.goto(f"{base}{path}", wait_until="networkidle")
            page.wait_for_timeout(700)
            page.screenshot(path=str(ASSETS / "github" / f"{fname}.png"), full_page=False)
            print("github", fname)
        ctx.close()
        # ---- LinkedIn portrait cards -----------------------------------------------------------
        ctx = browser.new_context(viewport={"width": 1080, "height": 1350}, device_scale_factor=2, color_scheme="dark")
        page = ctx.new_page()
        console: list[str] = []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
        page.on("requestfailed", lambda r: console.append(f"requestfailed: {r.url} {r.failure}"))
        for slug in LINKEDIN:
            _media(page, f"{base}/media/{slug}", console)
            page.screenshot(
                path=str(ASSETS / "linkedin" / f"{slug}.png"), clip={"x": 0, "y": 0, "width": 1080, "height": 1350}
            )
            print("linkedin", slug)
        ctx.close()
        # ---- hero / social card ----------------------------------------------------------------
        ctx = browser.new_context(viewport={"width": 1600, "height": 800}, device_scale_factor=2, color_scheme="dark")
        page = ctx.new_page()
        _media(page, f"{base}/media/hero", [])
        page.screenshot(path=str(ASSETS / "github" / "hero.png"), clip={"x": 0, "y": 0, "width": 1600, "height": 800})
        shutil.copy(ASSETS / "github" / "hero.png", ASSETS / "branding" / "social-card.png")
        print("github hero")
        ctx.close()
        # ---- branding PNGs from SVG ------------------------------------------------------------
        for svg, size in (("logo.svg", 512), ("wordmark.svg", None)):
            src = ASSETS / "branding" / svg
            if not src.exists():
                continue
            text = src.read_text(encoding="utf-8")
            if size:
                ctx = browser.new_context(viewport={"width": size, "height": size}, device_scale_factor=1)
                page = ctx.new_page()
                scaled = text.replace('width="64" height="64"', f'width="{size}" height="{size}"')
                page.set_content(f"<html><body style='margin:0;background:transparent'>{scaled}</body></html>")
                page.screenshot(path=str(ASSETS / "branding" / svg.replace(".svg", ".png")), omit_background=True)
                ctx.close()
            else:
                ctx = browser.new_context(viewport={"width": 640, "height": 160}, device_scale_factor=2)
                page = ctx.new_page()
                page.set_content(f"<html><body style='margin:0;background:#0e1218'>{text}</body></html>")
                page.screenshot(path=str(ASSETS / "branding" / svg.replace(".svg", ".png")))
                ctx.close()
            print("branding", svg)
        browser.close()
    # architecture diagram copies for GitHub / LinkedIn landscape
    png = ROOT / "diagrams" / "png"
    if (png / "architecture.png").exists():
        shutil.copy(png / "architecture.png", ASSETS / "github" / "architecture.png")
        shutil.copy(png / "architecture.png", ASSETS / "linkedin" / "01-architecture-landscape.png")
        print("copied architecture diagram")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--base", default=None, help="use an already running server instead of starting one")
    args = ap.parse_args()
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        print("frontend/dist missing — run `make build` first", file=sys.stderr)
        return 1
    if args.base:
        capture(args.base.rstrip("/"))
        return 0
    port = args.port or free_port()
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-shots-"))
    proc = start_server(port, tmp / "shots.db")
    try:
        capture(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
