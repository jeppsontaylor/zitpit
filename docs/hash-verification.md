# Hash Verification Guide

This document is intentionally conservative.

ZitPit does **not** yet ship a finished public release-verification path that would justify strong bootstrap-trust claims in the main quickstart. The current shell helper is now treated as demo scaffolding, not as a complete trust story.

## Current Status

- `scripts/demo_verify_hash.sh` is a demo helper
- it is **not** a substitute for signed releases, provenance, transparency, freshness, or revocation
- it is **not** the primary public verification path for launch

The public quickstart now focuses on the reproducible demo/CI path instead.

## Why The Old Script Was Demoted

The earlier helper compared a locally computed hash against placeholder or mocked remote data. That is useful for demonstrating the shape of a bootstrap-integrity check, but it is not strong enough to present as real release verification.

Security reviewers will reasonably ask for:

- signed release metadata
- immutable release artifacts
- provenance and build attestations
- transparency or audit logging
- key rotation and revocation semantics
- freshness and anti-rollback protections

Those concerns are better served by composing established systems such as TUF, Sigstore, in-toto, SLSA provenance, and GitHub artifact attestations than by overclaiming around a shell script.

## Demo Helper

If you want to inspect the current scaffold anyway:

```bash
sh scripts/demo_verify_hash.sh
```

Treat its output as a local demo of the shape of a bootstrap check, not as production-grade release verification.

## Launch Guidance

For public launch readiness, the trustworthy path is:

1. use the published source tree and canonical paper bundle
2. inspect [`CLAIMS.md`](../CLAIMS.md) and [`BENCHMARKS.md`](../BENCHMARKS.md)
3. run the same demo flow CI runs
4. verify published artifacts with [`release-verification.md`](release-verification.md)

For runtime trust decisions, see [trust-model.md](trust-model.md), [deployment-hardening.md](deployment-hardening.md), and [BENCHMARKS.md](../BENCHMARKS.md).
