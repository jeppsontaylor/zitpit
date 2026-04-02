# ZitPit V2 Roadmap

ZitPit is executing a pivot from a Git-first proxy with a honeypot to a mandatory artifact firewall and governed execution plane for AI-assisted development.

## Phase 1: Narrative Convergence

- align README, architecture, threat, trust, policy, and paper language around the same V2 thesis
- remove deception-first as the lead story
- make the benchmark matrix the source of truth for claims

## Phase 2: Universal Artifact Gateway

- expand ingress from Git to package-manager-native artifact intake
- treat exact digests as the primary admission object
- make mutable refs and fallback paths explicit policy exceptions
- keep approved artifacts on a local hot lane

## Phase 3: Provenance And Policy

- consume TUF-style freshness, expiry, and delegation semantics
- integrate Sigstore, in-toto, and SLSA-compatible provenance signals
- represent policy as capability-scoped verdicts
- separate fetch, build, test, and run trust levels

## Phase 4: Cold Lane Evidence

- keep Mirage Lab as a quarantine and evidence engine
- emit signed evidence packs for promotion and block decisions
- support host recall and blast-radius lookup
- add platform-aware and repo-control surface benchmarks

## Phase 5: Publish And Agent Enforcement

- add a publish firewall for release artifacts
- integrate agent-native policy hooks and managed configuration
- cover repo-controlled execution surfaces such as `.claude/` and `.mcp.json`

