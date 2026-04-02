# Hash Verification Guide

At ZitPit, we're dedicated to a **Zero-Surprise** supply chain. This document explains our strict verification process and why it matters.

## The Problem with Traditional CI

Standard CI pipelines pull tags or branches (e.g., `v1.0.0`). If an attacker compromises the repository, they can "re-tag" a release with malicious code. If your build system pulls that tag, you are compromised.

## The ZitPit Solution: Bootstrap Integrity, Not Final Trust

We use hashes as a bootstrap integrity check, but not as the final trust model. ZitPit's runtime trust plane depends on provenance, freshness, and revocation in addition to digest equality.

### 1. **Commit Identity**
We don't just pull `main`. We publish the exact Git commit SHA that represents a stable release.

### 2. **SHA-256 Checksums**
We compute the SHA-256 hash of the repository checkout at that commit. This is a strong sanity check for the checkout itself, but it is only one input to the broader trust model.

### 3. **The Multi-Point Check**
Before you install or update ZitPit, you should run our verification script:
`sh scripts/verify_hash.sh`

This script performs the following checks:
*   **Local Hash**: Computes the SHA-256 of your local files.
*   **Git Hash**: Compares it against the identity in the Git history.
*   **Mirror 1 (GitHub)**: Fetches the published checksum from GitHub.
*   **Mirror 2 (ZitPit Trust Server)**: Fetches the published checksum from an independent, non-GitHub server (`trust.zitpit.dev`).

**If the bootstrap check fails, the script exits with an error.**

## How to Manual Verify

If you prefer to verify manually, follow these steps:

1.  Compute your local hash:
    ```bash
    find . -type f -not -path '*/.*' -exec sha256sum {} + | sort | sha256sum
    ```
2.  Check the `releases/hashes.txt` file in the repository.
3.  Cross-reference with the hash published at `https://trust.zitpit.dev/latest/hash`.

For runtime trust decisions, see [trust-model.md](trust-model.md) and [BENCHMARKS.md](../BENCHMARKS.md).
