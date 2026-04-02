# ZitPit 1.0 Roadmap

ZitPit 1.0 establishes the public contract: first-seen external code should become a policy event before it becomes execution on a protected host, and approved immutable artifacts should remain fast enough that the safe path wins in practice.

This roadmap is intentionally written as a proof plan. Each phase tightens a claim boundary, broadens reproducible coverage, or improves the operator experience required for real adoption.

## Phase 1: Release Discipline And Public Clarity

- keep README, architecture, trust, policy, benchmarks, and paper language aligned
- preserve crisp boundaries between implemented behavior, partial coverage, and roadmap work
- publish benchmark snapshots, paper artifacts, and claim wording from one source of truth
- make every public release feel reviewable, reproducible, and easy to audit

## Phase 2: Universal Intake Beyond Git

- expand mediated ingress from Git into npm, PyPI, Cargo, Go, GitHub Actions, OCI, and raw HTTP installer paths
- resolve mutable selectors to immutable identities wherever the ecosystem allows it
- make unsupported paths explicit instead of relying on implied coverage
- keep approved artifacts on a low-latency hot lane

## Phase 3: Provenance-Aware Policy

- consume TUF-style freshness, expiry, delegation, and anti-rollback semantics
- integrate Sigstore, in-toto, and SLSA-compatible trust inputs where available
- add publisher continuity and publisher-drift detection for trusted packages
- separate fetch, build, test, and run trust levels through capability-scoped verdicts

## Phase 4: Cold-Lane Evidence And Recall

- strengthen Mirage Lab as a quarantine and evidence engine rather than a trust oracle
- emit signed evidence packs for promotion, denial, and recall workflows
- support host recall, blast-radius lookup, and revocation visibility
- improve persona realism, egress controls, and operator review signals

## Phase 5: Agent And Workspace Enforcement

- deepen policy hooks for agent runtimes, repo-open surfaces, and workspace automation
- cover `.claude/`, `.mcp.json`, devcontainers, tasks, startup hooks, and repo-controlled execution surfaces
- make policy state visible inside the tools developers already use
- preserve a durable audit trail for artifact- and workspace-level execution rights

## Phase 6: Publish-Side Guardrails

- add release inspection for source maps, secrets, wrong-registry publishes, and workflow drift
- connect trusted publishing, attestations, and release review into one operator flow
- keep producer-side guarantees clearly separate from consumer-side intake guarantees

## Phase 7: Stronger Public Evidence

- expand benchmark families beyond the current Git smart-HTTP intake path
- replay real incident classes with reproducible battle packs
- capture false-positive, latency, cache-hit, and fail-closed evidence
- publish coverage gaps openly so reviewers can see what remains out of scope

## Community Help Wanted

ZitPit gets better when external reviewers can attack it in public. We would especially value help with:

- new benchmark families and battle packs
- package-manager adapters and policy integration points
- paper review, threat-model critique, and claim-boundary editing
- reproducible incident replays and negative controls
- operator UX, docs, examples, and onboarding polish

If you want to contribute, start with [CONTRIBUTING.md](CONTRIBUTING.md), check the benchmark matrix in [BENCHMARKS.md](BENCHMARKS.md), and treat every addition as part of the public proof story.
