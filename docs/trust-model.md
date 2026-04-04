# Trust Model

ZitPit operates on a zero-trust-for-upstream basis.

The decisive question is not merely whether bytes exist or can be fetched. The decisive question is whether a first-seen external artifact has earned execution rights under durable policy inside a protected trust domain.

## Trust Plane

The trust plane is designed around standards-backed primitives:

- TUF-style freshness, expiry, delegation, and anti-rollback
- Sigstore-style identity-bound signing and transparency
- in-toto-style step attestations
- SLSA-style provenance expectations

ZitPit is designed to consume these primitives progressively. The current repository does not claim to fully implement every standard end to end.

## Identity vs. Provenance

Hash equality is not provenance.

A real content digest can establish byte sameness. In ZitPit's current code, some older compatibility fields still carry identity fingerprints rather than byte-level digests, and those should not be read as stronger proof than they are. Even a real digest does not by itself say:

- who built the artifact
- whether the publish path drifted
- whether freshness still holds
- whether revocation has occurred
- whether this context should grant host execution rights

That is why ZitPit treats immutable identity, content digests, provenance, policy, and evidence as separate inputs.

## Approval State

Approval records should carry:

- immutable identity
- source coordinates
- provenance and attestation result
- signer or publisher continuity state
- verdict
- context
- expiry state
- revocation state
- evidence pointer

Trust should decay and be renewed. “Approved forever” is not a safe default.

## Current Proof Boundary

The current repository publicly proves:

- mediated Git smart-HTTP intake can stay fast
- selected protected-session enforcement families can deny execution before brokered shell actions run
- governed egress can block selected sensitive outbound payloads

The current repository does not publicly prove:

- complete package-manager-native mediation
- complete repo-open host-side closure
- universal host-side application-control semantics
- safety for unsupported or unmanaged paths

## Revocation and Recall

When an immutable identity, signer, or workflow is revoked, ZitPit should support:

- cache invalidation
- operator visibility
- blast-radius lookup
- host recall
- durable evidence review

The trust plane should make stale decisions visible rather than silent.

## Trust-Plane Risk

ZitPit itself becomes part of the trusted computing base. Cache poisoning, stale trust roots, signing-key compromise, and policy-store compromise are real risks. The correct answer is not to ignore them, but to make them explicit in the claim boundary and architecture.
