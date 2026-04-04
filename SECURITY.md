# Security Policy

ZitPit takes vulnerabilities in its own code seriously.

## Responsible Disclosure

If you discover a security vulnerability, please do not open a public issue. Contact the maintainers privately at `security@zitpit.dev`.

We will respond promptly and coordinate a fix and disclosure timeline.

## Trust Model

ZitPit is designed around:

- signed manifests
- exact artifact identity
- provenance-aware policy
- freshness and revocation semantics
- benchmark-backed claims

The current public bootstrap helper is demo scaffolding, not the release-verification path. See [`docs/release-verification.md`](docs/release-verification.md) for published artifact verification, [`docs/hash-verification.md`](docs/hash-verification.md) for the demo helper's limited role, and [`docs/deployment-hardening.md`](docs/deployment-hardening.md) for deployment posture guidance.

## Mirage Lab Safety

Mirage Lab is a quarantined evidence environment, not a trust oracle.

- detonation is isolated
- real production secrets do not belong in the lab
- sinkholed egress is expected
- public claims should rely on benchmarks, not on hidden behavior
