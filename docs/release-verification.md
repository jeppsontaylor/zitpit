# Release Verification

This is the public verification path for published ZitPit releases.

It replaces the old demo-only hash helper as the canonical way to validate a release artifact.

## What A Release Includes

Each tagged GitHub release should publish:

- `zitpit-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `zitpit-<version>-x86_64-unknown-linux-gnu-sboms.tar.gz`
- `SHA256SUMS.txt`
- GitHub artifact attestation for the tarball

## Verify Checksums

Download the release assets and verify the checksum file:

```bash
gh release download v0.1.0 --repo jeppsontaylor/zitpit --dir ./release-check
cd release-check
shasum -a 256 -c SHA256SUMS.txt
```

The tarball and SBOM bundle should both verify cleanly.

## Verify Attestation

Use GitHub's attestation verification path against the release tarball:

```bash
gh attestation verify zitpit-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo jeppsontaylor/zitpit
```

That check confirms GitHub recorded a provenance statement for the published artifact.

## Inspect The SBOM

The CycloneDX SBOM bundle is published so reviewers can inspect the dependency graph that was packaged for the release bundle.

At minimum, confirm the SBOM bundle itself matches `SHA256SUMS.txt` and that it corresponds to the tagged version you downloaded.

## What This Is Not

- It is not a substitute for runtime trust policy inside ZitPit itself.
- It is not the demo helper in [`hash-verification.md`](hash-verification.md).
- It does not by itself prove the software is safe.

It does provide a concrete public launch contract: named artifacts, published checksums, and provenance or attestation tied to the release.
