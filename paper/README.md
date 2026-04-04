# ZitPit IEEE Paper Bundle

This directory contains the canonical publication bundle for the ZitPit paper.

The source of truth is `main.tex`. The canonical tracked PDF artifact is `zitpit-v1.0-paper.pdf`.

Included here:

- `references.bib`: the BibTeX bibliography
- `figures/`: publication figures in PDF and EPS form
- `diagram-prompts.md`: image-model prompt pack for opener-diagram exploration
- `IEEEtran.cls` and `IEEEtran.bst`: vendored IEEE formatting assets

## Build

Preferred local toolchain:

```bash
cd paper
latexmk -pdf -bibtex -interaction=nonstopmode main.tex
```

If `latexmk` is not available, a lightweight local fallback is:

```bash
cd paper
tectonic main.tex
```

The TeX toolchain emits `main.pdf` locally, but that output is ignored and not meant to be tracked. For releases, package the latest build as `zitpit-v1.0-paper.pdf` so the artifact has a stable, human-readable name.

## Figures

The figures are generated from source data and drawing code:

```bash
cd paper
python3 scripts/build_figures.py
python3 scripts/build_opener_reportlab.py
python3 scripts/build_opener_matplotlib.py
```

This regenerates:

- `figures/intake_path.pdf`
- `figures/intake_path.eps`
- `figures/architecture.pdf`
- `figures/architecture.eps`
- `figures/speedup.pdf`
- `figures/speedup.eps`
- `figures/opener_comparison_reportlab.pdf`
- `figures/opener_comparison_reportlab.eps`
- `figures/opener_comparison_matplotlib.pdf`
- `figures/opener_comparison_matplotlib.svg`

The speedup figure reads from `../docs/benchmarks/latest.json`, so the paper stays aligned with the benchmark source of truth.
