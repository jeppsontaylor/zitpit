#!/usr/bin/env python3

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "figures"

INK = "#1d2733"
MUTED = "#5c6a79"
GRID = "#d4dbe3"
BG = "#ffffff"
FAST = "#3a7ca5"
WARN = "#bc4b51"
AMBER = "#d49b32"
SOFT_FAST = "#f4f9fc"
SOFT_WARN = "#fcf4f4"
SOFT_AMBER = "#fbf3df"


def rounded(ax, x, y, w, h, face, edge=GRID, lw=1.8, radius=0.02):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.008,rounding_size={radius}",
        linewidth=lw,
        edgecolor=edge,
        facecolor=face,
    )
    ax.add_patch(patch)
    return patch


def node(ax, x, y, w, h, title, stroke, fill=BG, subtitle=None, title_size=12.4, subtitle_size=9.5):
    rounded(ax, x, y, w, h, fill, edge=stroke, lw=2.0, radius=0.015)
    lines = title.split("\n")
    if subtitle:
        top_y = y + h - 0.022
        for idx, line in enumerate(lines):
            ax.text(x + w / 2, top_y - idx * 0.03, line, fontsize=title_size, fontweight="bold", color=INK, ha="center", va="top")
        ax.text(x + w / 2, y + 0.022, subtitle, fontsize=subtitle_size, color=MUTED, ha="center", va="bottom")
    else:
        center = y + h / 2 + (0.014 if len(lines) == 2 else 0.0)
        for idx, line in enumerate(lines):
            ax.text(x + w / 2, center - idx * 0.032, line, fontsize=title_size, fontweight="bold", color=INK, ha="center", va="center")


def arrow(ax, x1, y1, x2, y2, color, lw=2.8):
    ax.add_patch(
        FancyArrowPatch(
            (x1, y1),
            (x2, y2),
            arrowstyle="-|>",
            mutation_scale=16,
            linewidth=lw,
            color=color,
            shrinkA=0,
            shrinkB=0,
        )
    )


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(12, 4.7))
    fig.patch.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Simple Reality: Unmediated vs. Mediated Intake", fontsize=20, fontweight="bold", color=INK, ha="center", va="center")

    rounded(ax, 0.04, 0.12, 0.43, 0.68, SOFT_WARN)
    rounded(ax, 0.53, 0.12, 0.43, 0.68, SOFT_FAST)

    ax.text(0.07, 0.73, "Unmediated (Direct Risk)", fontsize=17, fontweight="bold", color=INK, ha="left")
    ax.text(0.56, 0.73, "Mediated (ZitPit Safety)", fontsize=17, fontweight="bold", color=INK, ha="left")

    node(ax, 0.07, 0.49, 0.1, 0.1, "Human\nrequest", WARN, title_size=11.8)
    node(ax, 0.07, 0.32, 0.1, 0.1, "Agent\nrequest", WARN, title_size=11.8)
    node(ax, 0.22, 0.405, 0.13, 0.12, "Download /\nopen code", WARN, title_size=11.8)
    node(ax, 0.40, 0.405, 0.11, 0.12, "Protected\nhost", WARN)
    arrow(ax, 0.17, 0.54, 0.22, 0.47, WARN)
    arrow(ax, 0.17, 0.37, 0.22, 0.46, WARN)
    arrow(ax, 0.35, 0.465, 0.40, 0.465, WARN, lw=3.2)
    ax.text(0.285, 0.18, "Direct path to host", fontsize=13, fontweight="bold", color=WARN, ha="center")

    node(ax, 0.56, 0.49, 0.1, 0.1, "Human\nrequest", FAST, title_size=11.8)
    node(ax, 0.56, 0.32, 0.1, 0.1, "Agent\nrequest", FAST, title_size=11.8)
    node(ax, 0.695, 0.405, 0.12, 0.12, "ZitPit gate", FAST, subtitle="policy check", title_size=11.8)
    node(ax, 0.83, 0.39, 0.15, 0.14, "Quarantine +\nhoneypot", AMBER, fill=SOFT_AMBER, subtitle="hold / inspect", title_size=10.6, subtitle_size=8.7)
    node(ax, 0.87, 0.20, 0.1, 0.11, "Protected\nhost", FAST, title_size=11.6)
    arrow(ax, 0.66, 0.54, 0.695, 0.48, FAST)
    arrow(ax, 0.66, 0.37, 0.695, 0.45, FAST)
    arrow(ax, 0.815, 0.465, 0.83, 0.465, FAST)
    arrow(ax, 0.905, 0.39, 0.92, 0.31, FAST)
    ax.text(0.745, 0.145, "Held before host execution", fontsize=13, fontweight="bold", color=FAST, ha="center")

    pdf_path = FIGURES / "opener_comparison_matplotlib.pdf"
    svg_path = FIGURES / "opener_comparison_matplotlib.svg"
    png_path = FIGURES / "opener_comparison_matplotlib.png"
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
