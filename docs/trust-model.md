# Trust Model

ZitPit operates on a zero-trust-for-upstream basis. Every artifact is treated as untrusted until its identity, provenance, and policy state are verified.

## Trust Plane

The trust plane is designed around standards-backed primitives:

- TUF-style freshness, expiry, delegation, and anti-rollback
- Sigstore-style identity-bound signing and transparency
- in-toto-style step attestations
- SLSA-style provenance expectations

ZitPit is designed to consume these primitives progressively. The current repository does not claim to fully implement every standard end to end.

## Hashes, Identity, And Provenance

Hash equality is not provenance.

A digest can tell us that bytes are stable. It does not tell us:

- who built them
- from what source
- in which workflow
- with which approvals
- under which publisher identity
- whether the publish path drifted from normal

That is why ZitPit tracks both artifact identity and producer identity.

## Approval State

Manifest entries should carry:

- artifact digest
- source coordinates
- provenance and attestation status
- signer or publisher continuity
- expiry
- revocation state
- evidence references

Trust should decay and be renewed. Approved forever is not a safe default.

## Upstream Guarantee Preservation

ZitPit should behave as a verifying proxy, not just a caching proxy. If ZitPit rehosts or mirrors upstream content, it must preserve upstream guarantees instead of weakening them.

## Revocation And Recall

When a digest, signer, or workflow is revoked, ZitPit should support:

- cache invalidation
- host recall
- operator visibility
- blast-radius lookup

The trust plane should make stale decisions obvious rather than hidden.

## Multi-Point Verification

The project itself should be bootstrapped through multiple trust anchors, but those anchors are only part of the story. They are useful for defending ZitPit distribution, not for replacing provenance policy inside the product.
