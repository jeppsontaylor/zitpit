#!/usr/bin/env python3

from pathlib import Path

from reportlab.graphics import renderPDF, renderPS

from build_figures import FIGURES, build_opener_comparison


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    drawing = build_opener_comparison()
    renderPDF.drawToFile(drawing, str(FIGURES / "opener_comparison_reportlab.pdf"))
    renderPS.drawToFile(drawing, str(FIGURES / "opener_comparison_reportlab.eps"))
    try:
        from reportlab.graphics import renderPM

        renderPM.drawToFile(drawing, str(FIGURES / "opener_comparison_reportlab.png"), fmt="PNG")
    except Exception:
        pass


if __name__ == "__main__":
    main()
