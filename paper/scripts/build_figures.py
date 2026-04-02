#!/usr/bin/env python3

import json
import math
from pathlib import Path

from reportlab.graphics import renderPDF, renderPS
from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, Rect, String
from reportlab.lib.colors import HexColor


ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "figures"
BENCHMARK_JSON = ROOT.parent / "docs" / "benchmarks" / "latest.json"

INK = HexColor("#1d2733")
MUTED = HexColor("#5c6a79")
GRID = HexColor("#d4dbe3")
BG = HexColor("#ffffff")
FAST = HexColor("#3a7ca5")
HOT = HexColor("#2a9d6f")
WARN = HexColor("#bc4b51")
AMBER = HexColor("#d49b32")
SOFT_FAST = HexColor("#e8f1f7")
SOFT_WARN = HexColor("#f8ecec")
SOFT_AMBER = HexColor("#fbf3df")
ZONE = HexColor("#9eabb8")
BOX_STROKE = HexColor("#c7d0d8")


def load_benchmarks():
    payload = json.loads(BENCHMARK_JSON.read_text())
    rows = []
    for repo in payload["repos"]:
        rows.append(
            {
                "repo": repo["repo"],
                "web_median": repo["web"]["median_ms"],
                "web_p95": repo["web"]["p95_ms"],
                "cache_median": repo["cache"]["median_ms"],
                "cache_p95": repo["cache"]["p95_ms"],
                "hot_median": repo["hot_cache"]["median_ms"],
                "hot_p95": repo["hot_cache"]["p95_ms"],
                "samples": len(repo["web"]["samples_ms"]),
            }
        )
    return rows


def add_text(drawing, x, y, text, size=12, fill=INK, font="Helvetica"):
    drawing.add(String(x, y, text, fontName=font, fontSize=size, fillColor=fill))


def box(drawing, x, y, w, h, title, lines, fill, stroke=BOX_STROKE, title_fill=INK):
    drawing.add(Rect(x, y, w, h, rx=14, ry=14, fillColor=fill, strokeColor=stroke, strokeWidth=1.8))
    add_text(drawing, x + 16, y + h - 24, title, 15, title_fill, "Helvetica-Bold")
    current_y = y + h - 44
    for line in lines:
        add_text(drawing, x + 16, current_y, line, 11.5, MUTED)
        current_y -= 14


def dashed_zone(drawing, x, y, w, h, label):
    drawing.add(
        Rect(
            x,
            y,
            w,
            h,
            rx=16,
            ry=16,
            fillColor=None,
            strokeColor=ZONE,
            strokeWidth=1.5,
            strokeDashArray=[6, 4],
        )
    )
    add_text(drawing, x + 14, y + h - 18, label, 12, MUTED, "Helvetica-Bold")


def arrow(drawing, x1, y1, x2, y2, color=INK, width=2.5, dashed=False):
    drawing.add(
        Line(
            x1,
            y1,
            x2,
            y2,
            strokeColor=color,
            strokeWidth=width,
            strokeDashArray=[6, 4] if dashed else None,
        )
    )
    dx = x2 - x1
    dy = y2 - y1
    length = math.hypot(dx, dy) or 1
    ux = dx / length
    uy = dy / length
    px = -uy
    py = ux
    size = 9
    drawing.add(
        Polygon(
            [
                x2,
                y2,
                x2 - ux * size - px * size * 0.55,
                y2 - uy * size - py * size * 0.55,
                x2 - ux * size + px * size * 0.55,
                y2 - uy * size + py * size * 0.55,
            ],
            fillColor=color,
            strokeColor=color,
        )
    )


def step_badge(drawing, x, y, label, fill):
    drawing.add(Rect(x, y, 20, 20, rx=10, ry=10, fillColor=fill, strokeColor=fill))
    add_text(drawing, x + 6.5, y + 5, label, 11, BG, "Helvetica-Bold")


def soft_panel(drawing, x, y, w, h, fill):
    drawing.add(Rect(x, y, w, h, rx=18, ry=18, fillColor=fill, strokeColor=BOX_STROKE, strokeWidth=1.5))


def cloud(drawing, cx, cy, title, lines, accent, fill):
    circles = [
        (cx - 70, cy + 4, 28),
        (cx - 34, cy + 26, 34),
        (cx + 8, cy + 16, 32),
        (cx + 46, cy + 3, 28),
        (cx - 6, cy - 10, 40),
    ]
    for x, y, radius in circles:
        drawing.add(Circle(x, y, radius, fillColor=fill, strokeColor=accent, strokeWidth=1.6))
    add_text(drawing, cx - 70, cy + 11, title, 13, INK, "Helvetica-Bold")
    current_y = cy - 6
    for line in lines:
        add_text(drawing, cx - 70, current_y, line, 11, MUTED)
        current_y -= 13


def exposure_halo(drawing, x, y, radius, color, dashed=False):
    drawing.add(
        Circle(
            x,
            y,
            radius,
            fillColor=None,
            strokeColor=color,
            strokeWidth=1.7,
            strokeDashArray=[6, 4] if dashed else None,
        )
    )


def person_icon(drawing, x, y, color, halo_radius):
    exposure_halo(drawing, x, y + 6, halo_radius, color, dashed=True)
    drawing.add(Circle(x, y + 28, 11, fillColor=None, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x, y + 18, x, y - 12, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x - 16, y + 6, x + 16, y + 6, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x, y - 12, x - 14, y - 34, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x, y - 12, x + 14, y - 34, strokeColor=color, strokeWidth=2))


def agent_icon(drawing, x, y, color, halo_radius):
    exposure_halo(drawing, x, y + 2, halo_radius, color, dashed=True)
    drawing.add(Rect(x - 22, y - 16, 44, 34, rx=8, ry=8, fillColor=None, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x, y + 18, x, y + 30, strokeColor=color, strokeWidth=2))
    drawing.add(Line(x - 10, y + 26, x + 10, y + 26, strokeColor=color, strokeWidth=2))
    drawing.add(Circle(x - 8, y + 2, 2.2, fillColor=color, strokeColor=color, strokeWidth=1))
    drawing.add(Circle(x + 8, y + 2, 2.2, fillColor=color, strokeColor=color, strokeWidth=1))
    drawing.add(Line(x - 8, y - 8, x + 8, y - 8, strokeColor=color, strokeWidth=1.6))


def opener_host_box(drawing, x, y, w, h, accent, fill, title, lines):
    drawing.add(Rect(x, y, w, h, rx=16, ry=16, fillColor=fill, strokeColor=accent, strokeWidth=1.8))
    add_text(drawing, x + 16, y + h - 25, title, 14, INK, "Helvetica-Bold")
    add_text(drawing, x + 16, y + h - 42, lines[0], 11, MUTED)
    add_text(drawing, x + 16, y + h - 56, lines[1], 11, MUTED)


def build_opener_comparison():
    width = 1160
    height = 352
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    def node(x, y, w, h, title, stroke, fill=BG, subtitle=None, title_size=13.5):
        drawing.add(Rect(x, y, w, h, rx=12, ry=12, fillColor=fill, strokeColor=stroke, strokeWidth=2))
        lines = title.split("\n")
        tx = x + w / 2
        if subtitle:
            start_y = y + h - 24
        else:
            start_y = y + h / 2 + (8 if len(lines) == 2 else 0)

        for idx, line in enumerate(lines):
            drawing.add(
                String(
                    tx,
                    start_y - idx * 16,
                    line,
                    fontName="Helvetica-Bold",
                    fontSize=title_size,
                    fillColor=INK,
                    textAnchor="middle",
                )
            )

        if subtitle:
            drawing.add(
                String(
                    tx,
                    y + 14,
                    subtitle,
                    fontName="Helvetica",
                    fontSize=10.5,
                    fillColor=MUTED,
                    textAnchor="middle",
                )
            )

    left_x = 18
    right_x = 600
    panel_y = 28
    panel_w = 542
    panel_h = 294

    soft_panel(drawing, left_x, panel_y, panel_w, panel_h, HexColor("#fcf4f4"))
    soft_panel(drawing, right_x, panel_y, panel_w, panel_h, HexColor("#f4f9fc"))

    add_text(drawing, left_x + 34, 278, "Unmediated (Direct Risk)", 17, INK, "Helvetica-Bold")
    add_text(drawing, right_x + 34, 278, "Mediated (ZitPit Safety)", 17, INK, "Helvetica-Bold")

    node(left_x + 30, 182, 120, 50, "Human\nrequest", WARN, fill=BG, title_size=12.5)
    node(left_x + 30, 102, 120, 50, "Agent\nrequest", WARN, fill=BG, title_size=12.5)
    node(left_x + 205, 140, 150, 60, "Download /\nopen code", WARN, fill=BG, title_size=12.5)
    node(left_x + 410, 140, 104, 60, "Protected\nhost", WARN, fill=BG)

    arrow(drawing, left_x + 150, 207, left_x + 205, 182, color=WARN)
    arrow(drawing, left_x + 150, 127, left_x + 205, 158, color=WARN)
    arrow(drawing, left_x + 355, 170, left_x + 410, 170, color=WARN, width=3.1)
    add_text(drawing, left_x + 198, 52, "Direct path to host", 13, WARN, "Helvetica-Bold")

    node(right_x + 26, 182, 120, 50, "Human\nrequest", FAST, fill=BG, title_size=12.5)
    node(right_x + 26, 102, 120, 50, "Agent\nrequest", FAST, fill=BG, title_size=12.5)
    node(right_x + 188, 140, 132, 60, "ZitPit gate", FAST, fill=BG, subtitle="policy check", title_size=12.5)
    node(right_x + 344, 134, 156, 72, "Quarantine +\nhoneypot", AMBER, fill=SOFT_AMBER, subtitle="hold / inspect", title_size=11.5)
    node(right_x + 388, 52, 112, 60, "Protected\nhost", FAST, fill=BG, title_size=12.5)

    arrow(drawing, right_x + 146, 207, right_x + 188, 178, color=FAST)
    arrow(drawing, right_x + 146, 127, right_x + 188, 162, color=FAST)
    arrow(drawing, right_x + 320, 170, right_x + 344, 170, color=FAST)
    arrow(drawing, right_x + 422, 134, right_x + 444, 112, color=FAST)
    add_text(drawing, right_x + 148, 44, "Held before host execution", 13, FAST, "Helvetica-Bold")

    return drawing


def build_intake_path():
    width = 1200
    height = 470
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    dashed_zone(drawing, 46, 258, 1108, 152, "Unmediated agentic intake")
    dashed_zone(drawing, 46, 56, 1108, 152, "ZitPit-mediated intake")

    top_y = 292
    bottom_y = 90
    box_w = 180
    box_h = 86
    xs = [72, 286, 500, 714, 928]

    top_steps = [
        ("1", "User prompt", ["\"Set up this repo\"", "and wire in tools"], SOFT_WARN, WARN),
        ("2", "Search and select", ["repo / package / action", "chosen by agent loop"], SOFT_WARN, WARN),
        ("3", "Clone / install / open", ["fetch + install + repo", "state enter one path"], SOFT_WARN, WARN),
        ("4", "Repo-controlled execution", ["hooks, MCP, devcontainer,", "build.rs, lifecycle scripts"], SOFT_WARN, WARN),
        ("5", "Protected host impact", ["secrets, network egress,", "workspace state, CI"], SOFT_WARN, WARN),
    ]
    bottom_steps = [
        ("1", "User prompt", ["same agent request", "same developer intent"], SOFT_FAST, FAST),
        ("2", "Search and select", ["selector reaches ZitPit", "before host execution"], SOFT_FAST, FAST),
        ("3", "Immutable binding", ["digest / SHA / exact", "identity when available"], SOFT_FAST, FAST),
        ("4", "Policy event", ["session, selector, verdict,", "evidence, capability"], SOFT_AMBER, AMBER),
        ("5", "Fast path or cold lane", ["approved bytes stay fast;", "first-seen goes cold"], SOFT_FAST, FAST),
    ]

    for idx, (step, title, lines, fill, accent) in enumerate(top_steps):
        box(drawing, xs[idx], top_y, box_w, box_h, title, lines, fill, stroke=accent)
        step_badge(drawing, xs[idx] + 10, top_y + box_h - 20, step, accent)
        if idx < len(top_steps) - 1:
            arrow(drawing, xs[idx] + box_w, top_y + box_h / 2, xs[idx + 1], top_y + box_h / 2, color=WARN)

    for idx, (step, title, lines, fill, accent) in enumerate(bottom_steps):
        box(drawing, xs[idx], bottom_y, box_w, box_h, title, lines, fill, stroke=accent)
        step_badge(drawing, xs[idx] + 10, bottom_y + box_h - 20, step, accent)
        if idx < len(bottom_steps) - 1:
            arrow(drawing, xs[idx] + box_w, bottom_y + box_h / 2, xs[idx + 1], bottom_y + box_h / 2, color=FAST)

    box(
        drawing,
        928,
        bottom_y,
        180,
        86,
        "Capability verdict",
        ["fetch only, build lane,", "run dev/CI, or blocked"],
        SOFT_FAST,
        stroke=FAST,
    )
    step_badge(drawing, 938, bottom_y + 66, "6", FAST)
    arrow(drawing, 892, bottom_y + 43, 928, bottom_y + 43, color=FAST)

    drawing.add(
        Rect(
            470,
            70,
            430,
            112,
            rx=18,
            ry=18,
            fillColor=None,
            strokeColor=AMBER,
            strokeWidth=2,
            strokeDashArray=[8, 4],
        )
    )
    add_text(drawing, 494, 160, "ZitPit mediation inserts a durable review checkpoint", 12.5, AMBER, "Helvetica-Bold")
    add_text(drawing, 494, 144, "before newly observed external code earns execution rights", 12.5, AMBER)

    add_text(drawing, 74, 230, "Weak checkpoint: discovery and execution collapse into one loop.", 11.5, MUTED)
    add_text(drawing, 74, 28, "Mediated path: immutable identity, policy event, evidence, then capability grant.", 11.5, MUTED)
    return drawing


def build_architecture():
    width = 1200
    height = 530
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    dashed_zone(drawing, 46, 68, 252, 386, "Protected hosts")
    dashed_zone(drawing, 332, 68, 530, 386, "ZitPit control plane")
    dashed_zone(drawing, 892, 236, 262, 218, "External sources")

    box(drawing, 76, 282, 188, 90, "Agent / IDE / CI", ["prompt-driven tool use", "selectors and repo-open state"], SOFT_FAST, stroke=FAST)
    box(drawing, 76, 128, 188, 92, "Execution gate", ["capability check before", "host execution rights"], SOFT_AMBER, stroke=AMBER)

    box(drawing, 368, 302, 188, 90, "Gateway", ["smart HTTP / package /", "workspace intake mediation"], SOFT_FAST, stroke=FAST)
    box(drawing, 598, 330, 224, 82, "Identity + policy store", ["immutable binding, provenance,", "approvals, expiry, revocation"], SOFT_FAST, stroke=FAST)
    box(drawing, 598, 224, 224, 78, "Approved cache", ["content-addressed bytes", "and hot-cache handles"], SOFT_FAST, stroke=FAST)
    box(drawing, 598, 98, 224, 90, "Cold-lane evidence engine", ["detonation, egress traps,", "evidence pack, promotion"], SOFT_AMBER, stroke=AMBER)

    box(drawing, 930, 318, 188, 82, "Git / registries / actions", ["GitHub, npm, PyPI,", "Cargo, Go, raw HTTP"], SOFT_WARN, stroke=WARN)
    box(drawing, 930, 214, 188, 74, "Revocation + attestations", ["TUF, Sigstore, in-toto,", "SLSA, trusted publishing"], SOFT_WARN, stroke=WARN)

    arrow(drawing, 264, 327, 368, 347, color=FAST)
    add_text(drawing, 286, 340, "selector", 11, MUTED, "Helvetica-Bold")

    arrow(drawing, 556, 347, 598, 360, color=FAST)
    add_text(drawing, 558, 372, "immutable identity", 10.5, MUTED)

    arrow(drawing, 710, 330, 710, 302, color=FAST)
    add_text(drawing, 720, 314, "approved", 10.5, MUTED)

    arrow(drawing, 556, 335, 598, 146, color=AMBER)
    add_text(drawing, 560, 232, "first-seen", 10.5, MUTED, "Helvetica-Bold")

    arrow(drawing, 822, 260, 264, 174, color=FAST)
    add_text(drawing, 480, 206, "approved bytes + granted capability", 10.5, MUTED)

    arrow(drawing, 930, 359, 822, 359, color=WARN)
    add_text(drawing, 844, 372, "fetch / resolve", 10.5, MUTED)

    arrow(drawing, 1024, 214, 822, 366, color=WARN, dashed=True)
    add_text(drawing, 854, 254, "revocation / provenance side-band", 10.5, MUTED)

    arrow(drawing, 710, 188, 710, 224, color=AMBER, dashed=True)
    add_text(drawing, 720, 205, "promotion", 10.5, MUTED)

    add_text(drawing, 80, 92, "Policy is artifact-aware: command approval alone is not enough.", 11.5, MUTED)
    return drawing


def log_y(value, bottom, top, min_value=10, max_value=2000):
    lo = math.log10(min_value)
    hi = math.log10(max_value)
    return bottom + (math.log10(max(value, min_value)) - lo) / (hi - lo) * (top - bottom)


def build_speedup():
    rows = load_benchmarks()
    width = 1200
    height = 620
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=BG, strokeColor=BG))

    left = 88
    bottom = 120
    top = 520
    right = 1132

    drawing.add(Line(left, bottom, left, top, strokeColor=INK, strokeWidth=1.8))
    drawing.add(Line(left, bottom, right, bottom, strokeColor=INK, strokeWidth=1.8))

    ticks = [10, 30, 100, 300, 1000, 2000]
    for tick in ticks:
        y = log_y(tick, bottom, top)
        drawing.add(Line(left, y, right, y, strokeColor=GRID, strokeWidth=1))
        add_text(drawing, 34, y - 4, str(tick), 11, MUTED)
    add_text(drawing, 22, 538, "Latency (ms, log scale)", 11, MUTED)

    legend = [(WARN, "web median"), (FAST, "cache median"), (HOT, "hot-cache median")]
    legend_x = 744
    for idx, (color, label) in enumerate(legend):
        x = legend_x + idx * 122
        drawing.add(Rect(x, 560, 18, 18, fillColor=color, strokeColor=color))
        add_text(drawing, x + 24, 565, label, 11, INK, "Helvetica-Bold")
    drawing.add(Line(744, 544, 764, 544, strokeColor=INK, strokeWidth=1.4))
    drawing.add(Line(754, 538, 754, 550, strokeColor=INK, strokeWidth=1.4))
    add_text(drawing, 772, 540, "p95 whisker", 11, INK, "Helvetica-Bold")

    group_start = 150
    group_gap = 190
    bar_w = 24
    bar_gap = 10
    modes = [
        ("web_median", "web_p95", WARN),
        ("cache_median", "cache_p95", FAST),
        ("hot_median", "hot_p95", HOT),
    ]

    for idx, row in enumerate(rows):
        base = group_start + idx * group_gap
        for mode_index, (median_key, p95_key, color) in enumerate(modes):
            x = base + mode_index * (bar_w + bar_gap)
            y = log_y(row[median_key], bottom, top)
            drawing.add(
                Rect(
                    x,
                    bottom,
                    bar_w,
                    y - bottom,
                    rx=4,
                    ry=4,
                    fillColor=color,
                    strokeColor=color,
                )
            )
            p95_y = log_y(row[p95_key], bottom, top)
            drawing.add(Line(x + bar_w / 2, y, x + bar_w / 2, p95_y, strokeColor=INK, strokeWidth=1.2))
            drawing.add(Line(x + 5, p95_y, x + bar_w - 5, p95_y, strokeColor=INK, strokeWidth=1.2))

        add_text(drawing, base + 6, 82, row["repo"], 12, INK, "Helvetica-Bold")

    add_text(drawing, 88, 42, "Repeated public demonstration run: 5 repositories, N=5 smart-HTTP intake requests per mode.", 11.5, MUTED)
    add_text(drawing, 88, 26, "Workload: direct upstream git ls-remote vs approved disk cache vs in-memory hot cache.", 11.5, MUTED)
    return drawing


def write_outputs(name, drawing):
    FIGURES.mkdir(parents=True, exist_ok=True)
    renderPDF.drawToFile(drawing, str(FIGURES / f"{name}.pdf"))
    renderPS.drawToFile(drawing, str(FIGURES / f"{name}.eps"))


def main():
    write_outputs("intake_path", build_intake_path())
    write_outputs("architecture", build_architecture())
    write_outputs("speedup", build_speedup())


if __name__ == "__main__":
    main()
