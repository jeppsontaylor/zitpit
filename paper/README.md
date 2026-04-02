# ZitPit IEEE Paper Bundle

This directory contains the canonical publication bundle for the ZitPit paper:

- `main.tex`: the IEEE-style manuscript
- `references.bib`: the BibTeX bibliography
- `figures/`: publication figures in PDF and EPS form
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
tectonic main.tex
```

## Figures

The figures are generated from source data and drawing code:

```bash
cd paper
python3 scripts/build_figures.py
```

This regenerates:

- `figures/speedup.pdf`
- `figures/speedup.eps`
- `figures/network.pdf`
- `figures/network.eps`

The speedup figure reads from `../docs/benchmarks/latest.json`, so the paper stays aligned with the benchmark source of truth.
