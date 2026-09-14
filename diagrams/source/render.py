"""Deterministic SVG diagram renderer for the SentinelSwitch diagrams.

Each diagram is a JSON spec in diagrams/source/*.json (nodes, groups, edges on a 20 px grid). The
renderer writes:
  diagrams/svg/<name>.svg           - the published vector diagram
  diagrams/source/mermaid/<name>.mmd - an equivalent Mermaid description generated from the same spec

PNG rasterisation is done by scripts/diagrams.py with headless Chromium so no native graphics
dependencies (Graphviz, Cairo, ImageMagick) are required.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SVG_DIR = ROOT / "diagrams" / "svg"
MMD_DIR = HERE / "mermaid"
GRID = 20

PALETTE = {
    "bg": "#0e1218",
    "panel": "#161d26",
    "panel2": "#1b242f",
    "border": "#34445a",
    "text": "#e6edf3",
    "text2": "#b3c0cf",
    "muted": "#7d8b9c",
    "faint": "#56657a",
    "blue": "#58a6ff",
    "cyan": "#39c5d6",
    "green": "#3fb950",
    "amber": "#d29922",
    "red": "#f85149",
    "purple": "#a371f7",
}
FONT = "-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
MONO = "'SF Mono', ui-monospace, Menlo, Consolas, monospace"


def px(v: float) -> float:
    return v * GRID


def color(name: str | None) -> str:
    if not name:
        return PALETTE["blue"]
    return PALETTE.get(name, name)


def _text(
    x: float,
    y: float,
    s: str,
    size: float = 13,
    fill: str = PALETTE["text"],
    weight: int = 400,
    anchor: str = "start",
    mono: bool = False,
    opacity: float = 1.0,
) -> str:
    return f'<text x="{x:.1f}" y="{y:.1f}" font-family="{MONO if mono else FONT}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}" opacity="{opacity}">{escape(s)}</text>'


def _rect(
    x: float,
    y: float,
    w: float,
    h: float,
    fill: str,
    stroke: str,
    rx: float = 8,
    sw: float = 1.2,
    dash: str | None = None,
    opacity: float = 1.0,
) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d} opacity="{opacity}"/>'


class Renderer:
    def __init__(self, spec: dict[str, Any]):
        self.spec = spec
        self.w = int(spec.get("width", 1600))
        self.h = int(spec.get("height", 900))
        self.nodes: dict[str, dict[str, Any]] = {n["id"]: n for n in spec.get("nodes", [])}
        self.parts: list[str] = []

    # ---- geometry --------------------------------------------------------------------------
    def box(self, n: dict[str, Any]) -> tuple[float, float, float, float]:
        return px(n["x"]), px(n["y"]), px(n["w"]), px(n["h"])

    def anchor(self, n: dict[str, Any], side: str) -> tuple[float, float]:
        x, y, w, h = self.box(n)
        return {
            "top": (x + w / 2, y),
            "bottom": (x + w / 2, y + h),
            "left": (x, y + h / 2),
            "right": (x + w, y + h / 2),
        }[side]

    def auto_sides(self, a: dict[str, Any], b: dict[str, Any]) -> tuple[str, str]:
        ax, ay, aw, ah = self.box(a)
        bx, by, bw, bh = self.box(b)
        acx, acy, bcx, bcy = ax + aw / 2, ay + ah / 2, bx + bw / 2, by + bh / 2
        dx, dy = bcx - acx, bcy - acy
        if abs(dx) * 1.0 > abs(dy) * 1.15:
            return ("right", "left") if dx > 0 else ("left", "right")
        return ("bottom", "top") if dy > 0 else ("top", "bottom")

    # ---- drawing ---------------------------------------------------------------------------
    def draw_group(self, g: dict[str, Any]) -> None:
        x, y, w, h = px(g["x"]), px(g["y"]), px(g["w"]), px(g["h"])
        c = color(g.get("color", "faint"))
        self.parts.append(_rect(x, y, w, h, "rgba(255,255,255,0.015)", c, rx=12, sw=1.2, dash="6 5", opacity=0.9))
        label = g.get("label", "")
        if label:
            tw = len(label) * 7.2 + 20
            self.parts.append(_rect(x + 14, y - 11, tw, 22, PALETTE["bg"], c, rx=6, sw=1))
            self.parts.append(_text(x + 24, y + 4.5, label.upper(), 10.5, c, 700))
        if g.get("note"):
            self.parts.append(_text(x + w - 14, y + h - 10, g["note"], 10.5, PALETTE["muted"], 400, anchor="end"))

    def draw_node(self, n: dict[str, Any]) -> None:
        x, y, w, h = self.box(n)
        kind = n.get("kind", "box")
        c = color(n.get("color"))
        fill = PALETTE["panel"] if kind != "note" else "rgba(57,197,214,0.06)"
        stroke = (
            c
            if kind in {"accent", "switch", "db"}
            else PALETTE["border"]
            if kind != "note"
            else "rgba(57,197,214,0.35)"
        )
        if kind == "db":
            self.parts.append(
                f'<path d="M{x:.1f},{y + 10:.1f} a{w / 2:.1f},10 0 0 1 {w:.1f},0 v{h - 20:.1f} a{w / 2:.1f},10 0 0 1 -{w:.1f},0 z" fill="{fill}" stroke="{stroke}" stroke-width="1.3"/>'
            )
            self.parts.append(
                f'<path d="M{x:.1f},{y + 10:.1f} a{w / 2:.1f},10 0 0 0 {w:.1f},0" fill="none" stroke="{stroke}" stroke-width="1.3"/>'
            )
        else:
            self.parts.append(
                _rect(
                    x,
                    y,
                    w,
                    h,
                    fill,
                    stroke,
                    rx=9 if kind != "pill" else h / 2,
                    sw=1.4 if kind in {"accent", "switch"} else 1.1,
                )
            )
        if kind in {"accent", "switch"}:
            self.parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="4" height="{h:.1f}" rx="2" fill="{c}"/>')
        if kind == "switch":
            # tiny port strip
            for i in range(12):
                self.parts.append(
                    f'<rect x="{x + w - 118 + i * 9:.1f}" y="{y + h - 16:.1f}" width="6" height="7" rx="1" fill="#0b0f14" stroke="{c}" stroke-width="0.8"/>'
                )
        lines = [n.get("label", "")] + list(n.get("sub", []))
        size = n.get("size", 13)
        sub_size = n.get("sub_size", 11)
        total = size + 4 + (len(lines) - 1) * (sub_size + 4)
        ty = y + (h - total) / 2 + size - 2
        align = n.get("align", "center")
        tx = x + w / 2 if align == "center" else x + 16
        anchor = "middle" if align == "center" else "start"
        for i, line in enumerate(lines):
            if i == 0:
                self.parts.append(_text(tx, ty, line, size, PALETTE["text"], 600, anchor))
                ty += sub_size + 6
            else:
                mono = line.startswith("`")
                self.parts.append(
                    _text(
                        tx,
                        ty,
                        line.strip("`"),
                        sub_size,
                        PALETTE["muted"] if not mono else PALETTE["text2"],
                        400,
                        anchor,
                        mono=mono,
                    )
                )
                ty += sub_size + 4
        if n.get("badge"):
            bw = len(n["badge"]) * 6.4 + 14
            self.parts.append(_rect(x + w - bw - 8, y + 8, bw, 16, "rgba(0,0,0,0.25)", c, rx=4, sw=0.8))
            self.parts.append(_text(x + w - bw / 2 - 8, y + 19.5, n["badge"], 9.5, c, 700, "middle", mono=True))

    def draw_edge(self, e: dict[str, Any]) -> None:
        a, b = self.nodes[e["from"]], self.nodes[e["to"]]
        c = color(e.get("color", "faint")) if e.get("color") else PALETTE["muted"]
        sa, sb = e.get("sides") or self.auto_sides(a, b)
        p0 = self.anchor(a, sa)
        p1 = self.anchor(b, sb)
        fo, to = e.get("from_offset", [0, 0]), e.get("to_offset", [0, 0])
        p0 = (p0[0] + px(fo[0]), p0[1] + px(fo[1]))
        p1 = (p1[0] + px(to[0]), p1[1] + px(to[1]))
        pts: list[tuple[float, float]]
        if e.get("via"):
            pts = [p0] + [(px(vx), px(vy)) for vx, vy in e["via"]] + [p1]
        elif sa in {"right", "left"} and sb in {"left", "right"} and abs(p0[1] - p1[1]) > 2:
            mx = (p0[0] + p1[0]) / 2
            pts = [p0, (mx, p0[1]), (mx, p1[1]), p1]
        elif sa in {"top", "bottom"} and sb in {"top", "bottom"} and abs(p0[0] - p1[0]) > 2:
            my = (p0[1] + p1[1]) / 2
            pts = [p0, (p0[0], my), (p1[0], my), p1]
        elif sa in {"right", "left"} and sb in {"top", "bottom"}:
            pts = [p0, (p1[0], p0[1]), p1]
        elif sa in {"top", "bottom"} and sb in {"left", "right"}:
            pts = [p0, (p0[0], p1[1]), p1]
        else:
            pts = [p0, p1]
        d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        dash = ' stroke-dasharray="5 4"' if e.get("style") == "dashed" else ""
        width = e.get("width", 1.6)
        self.parts.append(
            f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{width}"{dash} marker-end="url(#arrow-{self._marker(c)})" stroke-linejoin="round"/>'
        )
        if e.get("label"):
            # label at the midpoint of the longest segment
            best = max(range(len(pts) - 1), key=lambda i: math.dist(pts[i], pts[i + 1]))
            (x0, y0), (x1, y1) = pts[best], pts[best + 1]
            mx, my = (x0 + x1) / 2, (y0 + y1) / 2
            label = e["label"]
            tw = len(label) * 6.3 + 12
            seg_len = math.dist(pts[best], pts[best + 1])
            horizontal = abs(y1 - y0) < abs(x1 - x0)
            if horizontal and seg_len < tw + 12:
                # short connector: float the label just above the two boxes instead of covering them
                top = min(self.box(a)[1], self.box(b)[1])
                my = top - 10
            elif not horizontal and seg_len < 30:
                mx += tw / 2 + 4
            off = e.get("label_offset", [0, 0])
            mx += px(off[0])
            my += px(off[1])
            self.parts.append(_rect(mx - tw / 2, my - 9, tw, 18, PALETTE["bg"], "none", rx=4, sw=0, opacity=0.92))
            self.parts.append(
                _text(mx, my + 3.5, label, 10.5, PALETTE["text2"], 500, "middle", mono=e.get("mono", False))
            )

    _markers: dict[str, str] = {}

    def _marker(self, c: str) -> str:
        key = c.replace("#", "").replace("(", "").replace(")", "").replace(",", "").replace(".", "")
        self._markers[key] = c
        return key

    def render(self) -> str:
        s = self.spec
        self.parts = []
        for g in s.get("groups", []):
            self.draw_group(g)
        for e in s.get("edges", []):
            self.draw_edge(e)
        for n in s.get("nodes", []):
            self.draw_node(n)
        defs = "".join(
            f'<marker id="arrow-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
            for k, c in self._markers.items()
        )
        head = []
        head.append(f'<rect width="{self.w}" height="{self.h}" fill="{PALETTE["bg"]}"/>')
        title, sub = s.get("title", ""), s.get("subtitle", "")
        if s.get("brand", True):
            head.append(_brand(24, 30))
        if title:
            head.append(_text(self.w / 2, 42, title, 22, PALETTE["text"], 700, "middle"))
        if sub:
            head.append(_text(self.w / 2, 64, sub, 12.5, PALETTE["muted"], 400, "middle"))
        foot = [
            f'<line x1="24" y1="{self.h - 34}" x2="{self.w - 24}" y2="{self.h - 34}" stroke="{PALETTE["border"]}" stroke-width="1"/>',
            _text(
                24,
                self.h - 14,
                s.get(
                    "footer",
                    "SentinelSwitch · Autonomous Network Detection & Response Lab · digital twin with synthetic telemetry",
                ),
                11,
                PALETTE["muted"],
            ),
            _text(
                self.w - 24,
                self.h - 14,
                s.get("footer_right", "Detect · Attribute · Contain"),
                11,
                PALETTE["muted"],
                600,
                "end",
            ),
        ]
        body = "\n".join(head + self.parts + foot)
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" font-family="{FONT}">\n<defs>{defs}</defs>\n{body}\n</svg>\n'


def _brand(x: float, y: float) -> str:
    return (
        f'<g transform="translate({x},{y - 16})">'
        f'<rect x="0" y="0" width="22" height="22" rx="5" fill="#131a22" stroke="{PALETTE["cyan"]}" stroke-width="1.5"/>'
        f'<path d="M11 4.5 L17 7 V12 C17 15.5 14.5 17.5 11 18.6 C7.5 17.5 5 15.5 5 12 V7 Z" fill="none" stroke="#e6edf3" stroke-width="1.3" stroke-linejoin="round"/>'
        f'<rect x="8" y="10.5" width="6" height="2.6" rx="0.6" fill="{PALETTE["cyan"]}"/>'
        f"</g>" + _text(x + 30, y + 1, "SentinelSwitch", 14, PALETTE["text"], 700)
    )


def to_mermaid(spec: dict[str, Any]) -> str:
    lines = [
        f"%% Generated from diagrams/source/{spec['name']}.json by diagrams/source/render.py",
        f"flowchart {spec.get('mermaid_direction', 'TB')}",
    ]
    groups = spec.get("groups", [])
    grouped: set[str] = set()
    for g in groups:
        lines.append(f'    subgraph {g["id"]}["{g.get("label", g["id"])}"]')
        for n in spec.get("nodes", []):
            if n.get("group") == g["id"]:
                grouped.add(n["id"])
                lines.append(f'        {n["id"]}["{_mm_label(n)}"]')
        lines.append("    end")
    for n in spec.get("nodes", []):
        if n["id"] not in grouped:
            lines.append(f'    {n["id"]}["{_mm_label(n)}"]')
    for e in spec.get("edges", []):
        arrow = "-.->" if e.get("style") == "dashed" else "-->"
        label = f"|{e['label']}|" if e.get("label") else ""
        lines.append(f"    {e['from']} {arrow}{label} {e['to']}")
    return "\n".join(lines) + "\n"


def _mm_label(n: dict[str, Any]) -> str:
    parts = [n.get("label", "")] + [s.strip("`") for s in n.get("sub", [])]
    return "<br/>".join(p.replace('"', "'") for p in parts if p)


def render_all(specs_dir: Path = HERE, svg_dir: Path = SVG_DIR, mmd_dir: Path = MMD_DIR) -> list[Path]:
    svg_dir.mkdir(parents=True, exist_ok=True)
    mmd_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for path in sorted(specs_dir.glob("*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        spec.setdefault("name", path.stem)
        svg = Renderer(spec).render()
        target = svg_dir / f"{spec['name']}.svg"
        target.write_text(svg, encoding="utf-8")
        (mmd_dir / f"{spec['name']}.mmd").write_text(to_mermaid(spec), encoding="utf-8")
        out.append(target)
    return out


if __name__ == "__main__":
    for p in render_all():
        print("wrote", p.relative_to(ROOT))
