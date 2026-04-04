# Contributing to ZitPit

The spirit of ZitPit is to make the safe path the fast path while keeping the public surface understandable, auditable, and hard to misuse.

## Our Approach

ZitPit is a security project. We value:

- `Correctness over Convenience`: policy boundaries must remain explicit
- `Transparency`: every claim should be traceable to evidence
- `Public hygiene`: the repository should stay organized and unsurprising
- `Open review`: strong criticism makes the project better

## Public Repo Hygiene

Before opening a PR, please make sure:

- the root does not contain scratch files or local review output
- `paper/` does not contain tracked TeX byproducts or duplicate PDFs
- public docs use the canonical description and claim ladder from `CLAIMS.md`
- public claims stay within `BENCHMARKS.md`
- secondary docs do not revive stale framing or broaden current proof

[`docs/repo-layout.md`](docs/repo-layout.md) is the canonical repository-organization contract.
[`scripts/check_repo_hygiene.sh`](scripts/check_repo_hygiene.sh) is the quick automated check for the same policy.

## How to Contribute

### 1. Security Research
If you find a bypass, a vulnerability, or a flaw in our isolation logic, please follow our [SECURITY.md](SECURITY.md) guidelines for responsible disclosure. Do not open a public issue for critical security flaws.

### 2. Code Contributions
We follow a standard GitHub flow:

1. Fork the repository.
2. Create a feature branch.
3. Ensure `cargo fmt` and `cargo clippy` pass:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   ```
4. Submit a pull request.

### 3. Evidence and Benchmark Contributions
If you can improve the benchmark matrix, add a proof family, or tighten a claim boundary, that is especially valuable.

## Governance and DCO

We use the **Developer Certificate of Origin (DCO)**. All commits must be signed off (`git commit -s`) to certify that you have the right to submit the code under the project's license.

ZitPit is a community-driven project. See [GOVERNANCE.md](GOVERNANCE.md) for more details.
