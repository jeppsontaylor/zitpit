# Policy Model

ZitPit uses policy to decide whether an external artifact may be fetched, unpacked, built, tested, or executed on a protected host.

## Policy Goals

- exact digest is the primary admission unit
- mutable refs are exceptions, not the default
- fetch, build, test, and run are different trust levels
- CI fails closed on unknown or unapproved artifacts
- unsupported ingress paths are explicitly unsupported

## Verdicts

ZitPit V2 uses capability-scoped verdicts:

- `FETCH_ONLY`
- `UNPACK_ONLY`
- `BUILD_NO_NETWORK`
- `TEST_NO_SECRETS`
- `RUN_DEV`
- `RUN_CI`
- `BLOCKED`

Each verdict records:

- artifact digest
- source coordinates
- provenance and attestation status
- publisher identity continuity state
- execution-surface flags such as scripts, hooks, and native code
- platform scope
- expiry
- revocation state
- evidence pointer

## Admission Rules

### Exact Digests

If an exact digest is approved, ZitPit can serve it from the hot lane. If an exact digest is missing, ZitPit does not silently substitute a name-matched or version-matched artifact.

### Mutable Refs

Branches, tags, moving version ranges, and `latest` are policy exceptions. They must resolve to immutable identities before any execution happens.

### Stale Last Known Good

An older approved artifact may be used only when policy explicitly allows a stale-last-known-good fallback. That fallback must be:

- logged
- time-bounded
- expiry-scoped
- downgrade-aware
- visible to operators

It is never an automatic default.

## Environment Differences

Trust requirements vary by phase:

- fetch: artifact identity and source legitimacy
- build: script and hook control, network control, and reproducibility
- test: secret isolation and bounded egress
- run: runtime privilege and host exposure limits

An artifact safe to fetch may still be unsafe to build or run.

## Ecosystem Rules

Namespace and ecosystem rules are secondary filters. They can narrow or prioritize trust, but they do not replace artifact identity.

Examples:

- npm install scripts may be blocked on first sight
- Python sdists may require quarantine before build
- Rust `build.rs` may require privileged approval
- GitHub Actions must be pinned to immutable references

## Quarantine And Promotion

Unknown artifacts enter quarantine first. The Mirage Lab may collect evidence, but lab silence does not imply safety.

Promotion decisions may use:

- provenance
- identity continuity
- install and build behavior
- network behavior
- platform scope
- operator review

## Unsupported Paths

If ZitPit does not currently mediate an ingress path, the policy response is explicit unsupported status rather than implied safety.

The policy engine should not pretend that unsupported coverage is a success case.

