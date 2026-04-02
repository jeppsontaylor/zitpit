#!/usr/bin/env python3

import json
from pathlib import Path

from reportlab.graphics import renderPDF, renderPS
from reportlab.graphics.shapes import Drawing, Line, Rect, String, Polygon
from reportlab.lib import colors
from reportlab.lib.colors import HexColor


ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "figures"
BENCHMARK_JSON = ROOT.parent / "docs" / "benchmarks" / "latest.json"


WEB = HexColor("#b23a48")
CACHE = HexColor("#2b6cb0")
HOT = HexColor("#1f9d68")
INK = HexColor("#132238")
SUBTLE = HexColor("#516170")
GRID = HexColor("#d8dde3")
BG = HexColor("#fbfaf7")
BOX = HexColor("#ffffff")
BOX_STROKE = HexColor("#d4dbe3")


def load_benchmarks():
    payload = json.loads(BENCHMARK_JSON.read_text())
    rows = []
    for repo in payload["repos"]:
        rows.append(
            {
                "repo": repo["repo"],
                "web": repo["web"]["median_ms"],
                "cache": repo["cache"]["median_ms"],
                "hot": repo["hot_cache"]["median_ms"],
            }
        )
    return rows


def add_text(drawing, x, y, text, size=12, fill=INK, font="Helvetica"):
    drawing.add(String(x, y, text, fontName=font, fontSize=size, fillColor=fill))


def build_speedup():
    rows = load_benchmarks()
    width = 1200
    height = 760
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    add_text(drawing, 70, 712, "ZitPit speedup snapshot", 30, INK, "Helvetica-Bold")
    add_text(
        drawing,
        70,
        686,
        "Five public Git repositories, one sample per mode, measured as direct upstream web vs approved disk cache vs in-memory hot cache",
        16,
        SUBTLE,
    )

    legend_y = 710
    legend = [(WEB, "web", 820), (CACHE, "cache", 908), (HOT, "hot-cache", 1018)]
    for color, label, x in legend:
        drawing.add(Rect(x, legend_y - 12, 18, 18, rx=4, ry=4, fillColor=color, strokeColor=color))
        add_text(drawing, x + 26, legend_y - 8, label, 14, INK, "Helvetica-Bold")

    left = 100
    bottom = 200
    top = 580
    right = 1110
    max_ms = 900
    plot_h = top - bottom
    scale = plot_h / max_ms

    drawing.add(Line(left, bottom, left, top, strokeColor=SUBTLE, strokeWidth=2))
    drawing.add(Line(left, bottom, right, bottom, strokeColor=SUBTLE, strokeWidth=2))

    for tick in [0, 200, 400, 600, 800, 900]:
        y = bottom + tick * scale
        drawing.add(Line(left, y, right, y, strokeColor=GRID, strokeWidth=1))
        add_text(drawing, 56, y - 4, str(tick), 12, SUBTLE)
    add_text(drawing, 28, 355, "Latency (ms)", 12, SUBTLE)

    group_start = 148
    group_gap = 200
    bar_w = 26
    for index, row in enumerate(rows):
        base = group_start + index * group_gap
        bars = [("web", row["web"], WEB), ("cache", row["cache"], CACHE), ("hot", row["hot"], HOT)]
        for offset, (_, value, color) in enumerate(bars):
            x = base + offset * 34
            h = value * scale
            drawing.add(
                Rect(
                    x,
                    bottom,
                    bar_w,
                    h,
                    rx=5,
                    ry=5,
                    fillColor=color,
                    strokeColor=color,
                )
            )
            add_text(drawing, x + 4, bottom + h + 8, str(value), 13, INK, "Helvetica-Bold")
        add_text(drawing, base + 16, 160, row["repo"], 15, INK, "Helvetica-Bold")

    add_text(
        drawing,
        70,
        90,
        "Current public demonstration run: 5 repos, N=1 sample per repo. Source: docs/benchmarks/latest.json.",
        13,
        SUBTLE,
    )
    add_text(
        drawing,
        70,
        66,
        "web = direct upstream git ls-remote; cache = approved disk cache; hot-cache = in-memory hot cache.",
        13,
        SUBTLE,
    )
    return drawing


def arrow(drawing, x1, y1, x2, y2, dashed=False):
    drawing.add(
        Line(
            x1,
            y1,
            x2,
            y2,
            strokeColor=SUBTLE,
            strokeWidth=3,
            strokeDashArray=[8, 7] if dashed else None,
        )
    )
    dx = x2 - x1
    dy = y2 - y1
    length = (dx ** 2 + dy ** 2) ** 0.5 or 1
    ux = dx / length
    uy = dy / length
    px = -uy
    py = ux
    size = 10
    tip = (x2, y2)
    left = (x2 - ux * size - px * size * 0.5, y2 - uy * size - py * size * 0.5)
    right = (x2 - ux * size + px * size * 0.5, y2 - uy * size + py * size * 0.5)
    drawing.add(
        Polygon(
            [tip[0], tip[1], left[0], left[1], right[0], right[1]],
            fillColor=SUBTLE,
            strokeColor=SUBTLE,
        )
    )


def rounded_box(drawing, x, y, w, h, title, body):
    drawing.add(Rect(x, y, w, h, rx=16, ry=16, fillColor=BOX, strokeColor=BOX_STROKE, strokeWidth=2))
    add_text(drawing, x + 18, y + h - 30, title, 18, INK, "Helvetica-Bold")
    add_text(drawing, x + 18, y + h - 54, body, 13, SUBTLE)


def build_network():
    width = 1200
    height = 420
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    add_text(drawing, 70, 372, "ZitPit control-plane diagram", 28, INK, "Helvetica-Bold")
    add_text(
        drawing,
        70,
        346,
        "A single intake gateway fans out to a hot path for approved artifacts and a cold lane for first-seen or untrusted artifacts",
        15,
        SUBTLE,
    )

    rounded_box(drawing, 60, 160, 180, 88, "Agent / IDE / CI", "requests code, config, and tools")
    rounded_box(drawing, 320, 150, 220, 108, "ZitPit Gateway", "policy, provenance, and cache routing")
    rounded_box(drawing, 620, 270, 190, 72, "Hot Cache", "approved immutable artifacts")
    rounded_box(drawing, 620, 100, 210, 100, "Cold Lane", "Mirage Lab evidence engine")
    rounded_box(drawing, 910, 145, 220, 92, "Publish / Revocation", "release firewall and recall loop")

    arrow(drawing, 240, 204, 320, 204)
    add_text(drawing, 265, 220, "first-seen", 13, SUBTLE, "Helvetica-Bold")

    arrow(drawing, 540, 204, 620, 306)
    add_text(drawing, 560, 256, "approved hit", 13, SUBTLE, "Helvetica-Bold")

    arrow(drawing, 540, 204, 620, 150)
    add_text(drawing, 562, 186, "quarantine", 13, SUBTLE, "Helvetica-Bold")

    arrow(drawing, 620, 130, 540, 180, dashed=True)
    add_text(drawing, 566, 130, "evidence", 13, SUBTLE, "Helvetica-Bold")

    arrow(drawing, 540, 204, 910, 191)
    add_text(drawing, 720, 212, "publish", 13, SUBTLE, "Helvetica-Bold")

    arrow(drawing, 910, 170, 430, 146, dashed=True)
    add_text(drawing, 702, 154, "revocation feed", 13, SUBTLE, "Helvetica-Bold")

    add_text(
        drawing,
        70,
        36,
        "Simple enough to review, specific enough to explain: approved artifacts go fast, unknown artifacts go cold.",
        13,
        SUBTLE,
    )
    return drawing


def write_outputs(name, drawing):
    FIGURES.mkdir(parents=True, exist_ok=True)
    renderPDF.drawToFile(drawing, str(FIGURES / f"{name}.pdf"))
    renderPS.drawToFile(drawing, str(FIGURES / f"{name}.eps"))


def main():
    write_outputs("speedup", build_speedup())
    write_outputs("network", build_network())


if __name__ == "__main__":
    main()
