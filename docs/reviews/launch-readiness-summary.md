# Launch Readiness Summary

This summary distills the recurring themes from the April 2026 external review corpus and the local `clean*.txt` review pass without keeping those scratch files in the repository root.

## Repeated Reviewer Themes

### 1. Keep the claim discipline

The most consistent positive feedback was that ZitPit already does a better-than-average job separating:

- implemented proof
- partial evidence
- planned scope
- forbidden overclaim

That discipline should remain a project invariant.

### 2. Fix trust-boundary mismatches first

The most repeated critical theme was that the strongest wording in the repo and paper had to stay aligned with:

- exact immutable Git approval
- benchmark identity correctness
- durable break-glass behavior
- protected-session execution semantics

These were treated as launch-blocking issues because they affect the credibility of the main thesis, not just code style.

### 3. Separate demo from hardened deployment

Many reviewers independently called out the same need:

- demo fixtures must not look like production endpoints
- admin and node-agent surfaces must be authenticated
- captured-request handling must be redacted and bounded
- bootstrap verification must not be presented more strongly than it really is

### 4. Make the repo easier to audit

The repeated doc/repo asks were:

- a machine-readable claim source
- a reviewer-friendly evidence index
- a glossary
- a contributor map
- clearer hardening guidance
- better CI enforcement for the repo’s own public-claim standards

## Changes Applied In This Launch-Readiness Pass

- benchmark seeding now mirrors the real upstream repo and validates identity before timing is accepted
- approved Git serving now checks exact approved identity instead of any approved record for a source
- break-glass is durable, revisioned, and queryable rather than an in-memory mode flip
- protected-session allow paths now execute structured commands directly instead of `zsh -lc raw`
- admin and node-agent surfaces require bearer-token auth on non-health routes
- fixture routes are demo-gated
- captured-request persistence is header-allowlisted and retention-bounded
- the demo bootstrap hash script was demoted and relabeled as demo-only
- new docs were added for evidence, glossary, contributor map, deployment hardening, and machine-readable claim status

## Remaining Honest Limits

These still remain outside current public proof:

- full package-manager-native closure
- full repo-open host-side closure
- raw socket or unmanaged egress closure
- universal host-side application control
- release-signing and provenance distribution as a finished public release system

Those limits should stay explicit in the README, claims sheet, benchmarks, and paper.
