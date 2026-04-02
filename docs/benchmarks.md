# Benchmarks

ZitPit benchmarks are meant to answer one question: how fast is the safe path when the same artifact is requested again?

We measure three timing classes for Git intake:
- `web`: direct upstream request
- `cache`: ZitPit approved disk-cache hit
- `hot-cache`: ZitPit in-memory hot-cache hit

## Suites

The benchmark and battle suites now cover the main intake surfaces ZitPit is designed to mediate:

- `git`
- `npm`
- `pypi`
- `go`
- `cargo`
- `actions`
- `shell`
- `browser`
- `workspace`

## Benchmark Matrix

| Suite | What it proves | Claim support | Status |
| --- | --- | --- | --- |
| Git | Git smart-HTTP intake, approved cache, hot cache | First-seen Git repos can be mediated and accelerated locally | Supported |
| npm | Registry package admission and install-script control | Package manager intake is policy-governed | Supported |
| PyPI | Wheel/sdist policy and quarantine | Python source and wheel intake is mediated | Supported |
| Go | Module/proxy intake | Non-Git module fetches are covered | Supported |
| Cargo | Source replacement and build-script control | Rust build-time execution is mediated | Supported |
| GitHub Actions | Immutable SHA vs mutable refs | Workflow intake is policy-checked | Supported |
| Shell | Raw HTTP installer fetches | `curl | bash` style ingress is covered | Supported |
| Browser | Operator and web-flow scrutiny | Browser-side request capture is covered | Supported |
| Workspace | Repo-open surfaces such as `.claude/`, `.mcp.json`, devcontainers | Agent/workspace configuration is treated as intake | Supported |

Anything outside those families is roadmap-only unless a benchmark row explicitly proves it.

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
- Do not treat an unmeasured surface as publicly claimed coverage.

