# Repository Layout

This document defines the intended public surface of the ZitPit repository.

## Root

The repository root should stay focused on:

- product and governance docs
- release and support docs
- top-level config
- workspace and build entrypoints
- canonical paper and benchmark pointers

Root should not accumulate scratch notes, ad hoc review output, or local build byproducts.

## `docs/`

The `docs/` tree contains:

- product reference docs
- policy, architecture, trust, threat, and benchmark docs
- clearly labeled archives such as review history and research notes

Historical review material belongs in `docs/reviews/`.
Research support notes belong in `docs/notes/` only when they are intentionally public and clearly labeled as support material, not product documentation.

## Publication Bundle

The canonical publication source is [`paper/main.tex`](../paper/main.tex).

The canonical tracked publication artifact is [`paper/zitpit-v1.0-paper.pdf`](../paper/zitpit-v1.0-paper.pdf).

Local TeX byproducts and duplicate build PDFs are not meant to be tracked.

## Hygiene Rules

- do not add scratch files to the root
- do not track local TeX byproducts
- do not keep duplicate paper PDFs in git
- keep the claim ladder in sync with [`BENCHMARKS.md`](../BENCHMARKS.md)
- keep public docs aligned with the canonical project description in [`CLAIMS.md`](../CLAIMS.md)
