# Benchmarks

ZitPit benchmarks are meant to answer one question: how fast is the safe path when the same artifact is requested again?

Today, the public timing benchmark is the Git smart-HTTP intake path. Coverage for other attack families lives in the benchmark matrix and battle-pack roadmap rather than in one latency chart.

We measure three timing classes for Git intake:
- `web`: direct upstream request
- `cache`: ZitPit approved disk-cache hit
- `hot-cache`: ZitPit in-memory hot-cache hit

## What Is Publicly Proven Today

- Git smart-HTTP intake mediation
- approved disk-cache reuse
- in-memory hot-cache reuse
- resolved HEAD SHA capture for benchmarked repos
- median and p95 reporting for the current five-repo benchmark set

Use [`BENCHMARKS.md`](../BENCHMARKS.md) as the source of truth for broader current-versus-roadmap claim boundaries across npm, PyPI, Cargo, GitHub Actions, raw HTTP installers, and repo-open surfaces.

## Benchmark Families Versus Claim Support

ZitPit has battle suites and scenario packs for several families, but those do not all imply full current implementation support.

- `git`: publicly benchmarked and supported today
- `npm`, `pypi`, `cargo`, `actions`, `shell`, `workspace`: represented in the matrix as partial, planned, or roadmap-backed families depending on the exact claim
- anything not mapped in [`BENCHMARKS.md`](../BENCHMARKS.md): roadmap-only or out of scope for public claims

## Running Benchmarks

Run the Git intake benchmark with:

```bash
cargo run -p xtask -- bench run
```

By default this writes:
- `docs/benchmarks/latest.md`
- `docs/benchmarks/latest.json`

You can narrow the repo set with repeated `--repo` flags and increase samples with `--samples`.

Example:

```bash
cargo run -p xtask -- bench run --repo git --repo go --repo cpython --samples 3
```

## Reporting Rules

- Report median and p95 for each timing class.
- Keep `web`, `cache`, and `hot-cache` separate.
- Record the resolved HEAD SHA for each repo.
- Do not treat a battle pack or planned family as publicly claimed coverage unless [`BENCHMARKS.md`](../BENCHMARKS.md) says the current implementation supports that claim.
