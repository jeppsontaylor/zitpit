# Release Runbook

ZitPit launch releases should be reproducible, signed, and easy for reviewers to verify.

The first public release scope is intentionally modest:

- GitHub Release
- Linux `x86_64` binary bundle
- SHA-256 checksums
- CycloneDX SBOM
- GitHub artifact attestation

## Preconditions

Before creating a release tag:

1. the workspace version in `Cargo.toml` is correct
2. `CHANGELOG.md` has the release-ready notes you want published
3. `paper/zitpit-v1.0-paper.pdf` has been rebuilt if the paper changed
4. `cargo test -q` passes
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
6. `cargo deny check all` passes
7. repo-contract checks pass

Use [`docs/launch-checklist.md`](docs/launch-checklist.md) as the maintainer checklist.

## Local Dry Run

Build the release bundle locally before tagging:

```bash
chmod +x scripts/build_release_bundle.sh scripts/render_release_notes.py
scripts/build_release_bundle.sh 0.1.0
python3 scripts/render_release_notes.py 0.1.0 > dist/release/RELEASE_NOTES.md
```

This produces:

- `dist/release/zitpit-<version>-<target>.tar.gz`
- `dist/release/zitpit-<version>-<target>-sboms.tar.gz`
- `dist/release/SHA256SUMS.txt`

For the GitHub release workflow, the target is fixed to `x86_64-unknown-linux-gnu`. Local dry runs default to the current host target unless you pass one explicitly.

## Tag And Publish

1. create a signed annotated tag such as `v0.1.0`
2. push the tag to GitHub
3. let `.github/workflows/release.yml` build and publish the release
4. verify the generated checksums, SBOM, and attestation against the uploaded assets

The release workflow refuses to publish if the pushed tag version does not match the workspace version.

## Verification Contract

The public verification path is documented in [`docs/release-verification.md`](docs/release-verification.md).

The demo hash helper in [`scripts/demo_verify_hash.sh`](scripts/demo_verify_hash.sh) is intentionally separate and should not be presented as the release trust path.
