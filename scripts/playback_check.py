"""Browser check of the Overview playback against a temporary server.

Checks autoplay, the recorded-traffic canvas and console, auto pace (fast through quiet stretches, slow
motion at a containment), then with auto pace off: the 1x rate, pause, click and drag seeking, resume,
speed, window presets, looping, navigation away and back, a hidden tab, reload, reduced motion, and that
a full replay pass issues no data request and no write: historical replay must never become an
execution mechanism.

    python scripts/playback_check.py

It starts the same temporary server as scripts/ui_audit.py (temporary database, a copy of the committed
evidence bundles), so neither the repository data nor the live deployment is touched. Requires a built
frontend (make build). Exits non-zero when any check fails.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_audit import ROOT, free_port, start_server  # noqa: E402

PLAYBACK_TS = (ROOT / "frontend" / "src" / "lib" / "playback.ts").read_text(encoding="utf-8")
WINDOW_SECONDS = int(re.search(r"WINDOW_SECONDS:\s*(\d+)", PLAYBACK_TS).group(1))

results: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((ok, name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")


def secs(hms: str) -> int:
    h, m, s = map(int, hms.split(":"))
    return h * 3600 + m * 60 + s


def window_minutes(text: str) -> int:
    (h1, m1), (h2, m2) = re.findall(r"(\d\d):(\d\d)", text)[:2]
    return (int(h2) * 60 + int(m2)) - (int(h1) * 60 + int(m1))


def run(base: str) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="dark")
        errors: list[str] = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        def clock() -> str:
            return page.evaluate("document.querySelector('.pb-time').textContent")

        def state() -> str:
            return page.evaluate("document.querySelector('.pb-state').textContent")

        def loops() -> str:
            return page.evaluate("document.querySelector('.pb-loop').textContent.trim()")

        def window_text() -> str:
            return page.evaluate("document.querySelector('.pb-meta .mono').textContent")

        def rate(seconds: float = 2.0) -> float:
            a = secs(clock())
            page.wait_for_timeout(int(seconds * 1000))
            return (secs(clock()) - a) / seconds / 60  # simulated minutes per real second

        def sub() -> str:
            return page.evaluate("document.querySelector('.pb-sub').textContent")

        def from_end(steps_back: int) -> None:
            page.evaluate("document.querySelector('.scrub-track').focus({ preventScroll: true })")
            page.keyboard.press("End")
            for _ in range(steps_back):
                page.keyboard.press("ArrowLeft")

        page.goto(f"{base}/", wait_until="networkidle")
        page.wait_for_function("document.querySelector('.pb-state')?.textContent === 'playing'", timeout=15000)
        check("autoplay", state() == "playing", f"state {state()} at {clock()}")
        page.wait_for_selector(".sf-flowcanvas", timeout=15000)
        page.wait_for_timeout(1200)
        lines = page.evaluate("document.querySelectorAll('.wire-lines .wl:not(.is-blank)').length")
        check(
            "recorded traffic: particle canvas and wire console",
            page.locator(".sf-flowcanvas").count() == 1 and lines > 0,
            f"{lines} console lines",
        )

        expected = window_minutes(window_text()) / WINDOW_SECONDS
        from_end(73)  # 03:00, a quiet night hour
        page.keyboard.press(" ")
        page.wait_for_timeout(400)
        rq = rate(1.0)
        check(
            "auto pace fast-forwards a quiet stretch",
            rq > expected * 2 and "quiet" in sub(),
            f"{rq:.0f} sim-min/s ({sub()})",
        )
        from_end(1)  # 21:00, before the flagship containment at 21:14:41
        page.keyboard.press(" ")
        page.wait_for_function("document.querySelector('.pb-time').textContent >= '21:14:30'", timeout=20000)
        a = secs(clock())
        page.wait_for_timeout(1000)
        slow_s = secs(clock()) - a
        check(
            "auto pace slows to the containment",
            0 <= slow_s <= 12 and "slow" in sub(),
            f"{slow_s} simulated s in 1 s ({sub()})",
        )
        burst = page.evaluate("document.querySelector('.wire-lines').textContent")
        check("wire console shows the recorded burst", "ENG-LT-047" in burst, "ENG-LT-047 connections listed at 21:14")
        page.get_by_role("button", name="auto pace").click()
        check(
            "auto pace can be switched off",
            page.get_by_role("button", name="auto pace").get_attribute("aria-pressed") == "false",
            "the rest runs at the plain rate",
        )
        page.evaluate("document.querySelector('.scrub-track').focus({ preventScroll: true })")
        page.keyboard.press("Home")
        page.keyboard.press(" ")
        page.wait_for_timeout(300)
        r1 = rate()
        check("1x rate", abs(r1 - expected) / expected < 0.15, f"{r1:.1f} sim-min/s, expected {expected:.1f}")

        page.get_by_role("button", name="Pause playback").first.click()
        held = clock()
        page.wait_for_timeout(1500)
        check("pause freezes", state() == "paused" and clock() == held, f"{held} -> {clock()} ({state()})")

        track = page.locator(".scrub-track").first
        box = track.bounding_box()
        track.click(position={"x": box["width"] * 0.5, "y": box["height"] / 2})
        page.wait_for_timeout(300)
        seek = clock()
        page.wait_for_timeout(1200)
        check("click seeks and pauses", seek != held and clock() == seek and state() == "paused", f"{held} -> {seek}")

        track.hover(position={"x": box["width"] * 0.3, "y": box["height"] / 2})
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.42, box["y"] + box["height"] / 2, steps=8)
        page.mouse.up()
        drag = clock()
        page.wait_for_timeout(1200)
        check("drag scrubs and pauses", drag != seek and clock() == drag and state() == "paused", f"{seek} -> {drag}")

        page.get_by_role("button", name="Play", exact=True).first.click()
        page.wait_for_timeout(1000)
        ahead = secs(clock()) - secs(drag)
        check(
            "play resumes from the playhead", state() == "playing" and 0 < ahead < r1 * 60 * 2.5, f"{drag} -> {clock()}"
        )

        page.get_by_role("button", name="4×").click()
        r4 = rate()
        page.get_by_role("button", name="1×").click()
        check("4x speed", 3.4 < r4 / r1 < 4.6, f"{r4:.1f} sim-min/s ({r4 / r1:.2f}x)")

        page.get_by_role("button", name="4 h").click()
        page.wait_for_timeout(300)
        w4 = window_text()
        r4h = rate()
        check(
            "4 h window",
            window_minutes(w4) == 240 and abs(r4h - 240 / WINDOW_SECONDS) < 0.6,
            f"{w4}, {r4h:.1f} sim-min/s",
        )
        page.get_by_role("button", name="Day").click()
        page.wait_for_timeout(300)

        page.evaluate("document.querySelector('.scrub-track').focus({ preventScroll: true })")
        page.keyboard.press("End")
        page.keyboard.press("ArrowLeft")
        before, loops_before = clock(), loops()
        page.keyboard.press(" ")
        page.wait_for_timeout(2500)
        wrapped = secs(clock()) < secs(before)
        check(
            "loops to the window start",
            wrapped and loops() != loops_before and state() == "playing",
            f"{before} -> {clock()}, {loops_before} -> {loops()}",
        )

        requests: list[tuple[str, str]] = []
        page.on("request", lambda r: requests.append((r.method, r.url)))
        page.get_by_role("button", name="4×").click()
        loops_mark = loops()
        page.wait_for_timeout(int(WINDOW_SECONDS / 4 * 1000) + 2500)
        page.get_by_role("button", name="1×").click()
        writes = [r for r in requests if r[0] != "GET"]
        reads = [u for m, u in requests if m == "GET" and not u.endswith("/api/meta")]
        check(
            "a full replay pass makes no write and no data request",
            loops() != loops_mark and not writes and not reads,
            f"{loops_mark} -> {loops()}, {len(writes)} non-GET, {len(reads)} data GETs, {len(requests)} requests in all",
        )

        track.click(position={"x": box["width"] * 0.25, "y": box["height"] / 2})  # well clear of a loop wrap
        page.get_by_role("button", name="Play", exact=True).first.click()
        left = clock()
        page.get_by_role("link", name="Posture").first.click()
        page.wait_for_timeout(3000)
        page.get_by_role("link", name="Overview").first.click()
        page.wait_for_selector(".pb-time")
        page.wait_for_timeout(300)
        away = secs(clock()) - secs(left)
        r_back = rate()
        check(
            "navigation keeps the playhead and one clock",
            state() == "playing" and abs(away) < r1 * 60 * 1.5 and abs(r_back - r1) / r1 < 0.15,
            f"left {left}, back {clock()}, rate {r_back:.1f}",
        )

        page.evaluate(
            "Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange'))"
        )
        hidden = clock()
        page.wait_for_timeout(2000)
        still = clock()
        page.evaluate(
            "Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange'))"
        )
        page.wait_for_timeout(1000)
        jump = secs(clock()) - secs(still)
        check(
            "hidden tab holds and resumes without a jump",
            still == hidden and 0 < jump < r1 * 60 * 2,
            f"{hidden} -> {still}, then +{jump} s simulated",
        )

        page.reload(wait_until="networkidle")
        page.wait_for_function("document.querySelector('.pb-state')?.textContent === 'playing'", timeout=15000)
        check("reload autoplays", state() == "playing", clock())
        # the Alerts page timeline is a brush: a drag anywhere on a full-day window selects a range
        page.goto(f"{base}/alerts", wait_until="networkidle")
        page.wait_for_timeout(800)
        brush = page.locator(".scrub-track").first
        bb = brush.bounding_box()
        rows_before = page.evaluate("document.querySelectorAll('table.data tbody tr').length")
        page.mouse.move(bb["x"] + bb["width"] * 0.35, bb["y"] + bb["height"] / 2)
        page.mouse.down()
        page.mouse.move(bb["x"] + bb["width"] * 0.55, bb["y"] + bb["height"] / 2, steps=10)
        page.mouse.up()
        page.wait_for_timeout(400)
        picked = page.evaluate("document.querySelector('.scrub-meta .mono').textContent")
        rows_after = page.evaluate("document.querySelectorAll('table.data tbody tr').length")
        check(
            "alerts timeline drag selects a range",
            "24 h" not in picked and rows_after < rows_before,
            f"{picked}, {rows_before} -> {rows_after} rows",
        )
        brush.focus()
        page.keyboard.press("Home")
        page.wait_for_timeout(300)
        reset = page.evaluate("document.querySelector('.scrub-meta .mono').textContent")
        check("Home restores the whole day", "24 h" in reset, reset)
        check("no console errors", not errors, "; ".join(errors[:3]) or "none")
        page.close()

        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark", reduced_motion="reduce")
        page = ctx.new_page()
        page.goto(f"{base}/", wait_until="networkidle")
        page.wait_for_function("document.querySelector('.pb-state')?.textContent === 'playing'", timeout=15000)
        r_rm = rate()
        animations = page.evaluate("document.getAnimations().length") + page.locator(".sf-flowcanvas").count()
        check(
            "reduced motion keeps playback, stops CSS motion",
            r_rm > 0 and animations == 0,
            f"{r_rm:.1f} sim-min/s, {animations} running animations",
        )
        ctx.close()
        browser.close()


def main() -> int:
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        print("frontend/dist missing — run `make build` first", file=sys.stderr)
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-playback-"))
    port = free_port()
    proc = start_server(tmp, port)
    try:
        run(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - the server may hold an open event stream
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    failed = [name for ok, name, _ in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} playback checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
