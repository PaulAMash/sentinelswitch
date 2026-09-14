#!/usr/bin/env python3
"""Render the diagrams: SVG + Mermaid via diagrams/source/render.py, PNG via headless Chromium.

python scripts/diagrams.py            # everything
python scripts/diagrams.py --no-png   # vector only (no browser needed)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "diagrams" / "source"))

from render import render_all  # noqa: E402

PNG_DIR = ROOT / "diagrams" / "png"


def rasterize(svgs: list[Path], scale: int = 2) -> list[Path]:
    from playwright.sync_api import sync_playwright

    PNG_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for svg in svgs:
            text = svg.read_text(encoding="utf-8")
            import re

            m = re.search(r'width="(\d+)" height="(\d+)"', text)
            w, h = (int(m.group(1)), int(m.group(2))) if m else (1600, 900)
            page = browser.new_page(viewport={"width": w, "height": h}, device_scale_factor=scale)
            page.set_content(f"<html><body style='margin:0;background:#0e1218'>{text}</body></html>")
            page.wait_for_timeout(150)
            target = PNG_DIR / f"{svg.stem}.png"
            page.screenshot(path=str(target), full_page=False)
            page.close()
            out.append(target)
        browser.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-png", action="store_true")
    args = ap.parse_args()
    svgs = render_all()
    for s in svgs:
        print("svg ", s.relative_to(ROOT))
    if not args.no_png:
        try:
            for p in rasterize(svgs):
                print("png ", p.relative_to(ROOT))
        except Exception as exc:  # noqa: BLE001
            print(f"PNG rasterisation skipped ({exc}); run `python -m playwright install chromium`", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
