# Launch Checklist

Use this before creating a public release tag.

## Repo And Docs

- workspace version is correct in `Cargo.toml`
- `CHANGELOG.md` is frozen for the release
- `README.md`, `CLAIMS.md`, and `BENCHMARKS.md` agree on the current proof boundary
- `paper/zitpit-v1.0-paper.pdf` has been refreshed if the paper changed
- GitHub repository description matches the canonical project sentence

## Validation

- `cargo test -q`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo deny check all`
- `python3 scripts/check_claim_matrix.py`
- `python3 scripts/check_publication_sync.py`
- `python3 scripts/check_markdown_links.py`
- `./scripts/check_repo_hygiene.sh`
- `latexmk -pdf -bibtex -interaction=nonstopmode -halt-on-error main.tex`
- `scripts/build_release_bundle.sh <version>`

## Tag And Publish

- signed annotated tag created
- tag pushed to GitHub
- release workflow green
- GitHub release contains tarball, SBOM bundle, and `SHA256SUMS.txt`
- release tarball attestation verifies with `gh attestation verify`

## After Publish

- re-run the CI-aligned smoke path from the tagged commit if needed
- confirm the release notes match the frozen changelog section
- confirm the branch tip and release tag point to the expected commit
