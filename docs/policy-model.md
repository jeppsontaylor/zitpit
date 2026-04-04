# Policy Model

ZitPit uses policy to decide whether an external artifact may be fetched, unpacked, built, tested, or executed on a protected host.

The canonical framing is:

**ZitPit is a consumer-side software admission control layer for agentic development.**

Its policy model exists to ensure that **first-seen external artifacts earn execution rights under durable policy before they affect a protected host**.

## Policy Goals

- exact immutable identity is the primary admission unit
- mutable refs are exceptions, not the default
- fetch, unpack, build, test, and run are different trust levels
- CI fails closed on unknown or unapproved artifacts
- unsupported ingress paths are explicitly unsupported
- the policy event is durable enough to support recall, audit, and incident reconstruction

## Status Ladder

Use these terms consistently across docs:

- `Implemented`
- `Partial`
- `Planned`
- `Unsupported`

## Artifact Policy Event

The artifact policy event is the shared public contract across admission, evidence, recall, README wording, and the paper.

Required fields:

- `selector`
- `resolved_immutable_identity`
- `provenance_result`
- `verdict`
- `evidence_pointer`
- `context`
- `expiry_state`
- `revocation_state`

Recommended context fields:

- `initiator`
- `session_id`
- `host_or_ci_scope`
- `platform_scope`
- `source_coordinates`
- `execution_surface_flags`
- `publisher_identity_continuity`

## Verdicts

ZitPit uses capability-scoped verdicts:

- `FETCH_ONLY`
- `UNPACK_ONLY`
- `BUILD_NO_NETWORK`
- `TEST_NO_SECRETS`
- `RUN_DEV`
- `RUN_CI`
- `BLOCKED`

Each verdict should be interpreted as a rights grant, not a generic label.

## Admission Rules

### Exact Identity

If an exact immutable identity is approved, ZitPit can serve it from the fast lane. If an identity is missing, ZitPit does not silently substitute a name-matched or version-matched artifact.

### Mutable Refs

Branches, tags, moving version ranges, and `latest` are policy exceptions. They must resolve to immutable identities before any execution rights are granted.

### Stale Last Known Good

A stale-last-known-good fallback may exist only when policy explicitly allows it. That fallback must be:

- logged
- time-bounded
- downgrade-aware
- visible to operators
- never the silent default

## Environment Differences

Trust requirements vary by phase:

- fetch: artifact identity and source legitimacy
- unpack: archive expansion and static inspection
- build: script and hook control, network control, and reproducibility
- test: secret isolation and bounded egress
- run: runtime privilege and host exposure limits

An artifact safe to fetch may still be unsafe to build or run.

## Ecosystem Rules

Ecosystem-specific rules are secondary filters layered on top of artifact identity.

Examples:

- npm lifecycle behavior may require quarantine before host execution
- Python sdists and direct URLs may require quarantine before build
- Rust `build.rs` and related build-time execution may require privileged approval
- GitHub Actions must resolve to immutable references
- repo-open bundles such as `.mcp.json`, hooks, memory files, and devcontainers are policy-visible execution surfaces

## Quarantine and Promotion

Unknown artifacts enter quarantine first. Mirage Lab may collect evidence, but lab silence does not imply safety.

Promotion decisions may incorporate:

- immutable identity
- provenance and attestation results
- publisher identity continuity
- install and build behavior
- network behavior
- operator review
- expiry and revocation state

## Unsupported Paths

If ZitPit does not currently mediate an ingress path, the policy response is explicit `Unsupported` status rather than implied safety.

The policy engine should not pretend unsupported coverage is a success case.
