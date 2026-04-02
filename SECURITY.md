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

The bootstrap path should verify the ZitPit release before use. If any bootstrap check fails, do not run the software.

## Mirage Lab Safety

Mirage Lab is a quarantined evidence environment, not a trust oracle.

- detonation is isolated
- real production secrets do not belong in the lab
- sinkholed egress is expected
- public claims should rely on benchmarks, not on hidden behavior

