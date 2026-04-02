# ZitPit Research Paper Outline

**Title**: *ZitPit: A Mandatory Artifact Firewall and Governed Execution Plane for Agentic Software Supply Chains*

**Abstract**:
AI-assisted development turns dependency intake into machine-speed execution. ZitPit proposes a mandatory artifact firewall that forces external code through exact-digest admission, provenance-aware policy, and quarantine before it may execute on protected developer or CI hosts. We show how this reduces exposure to install-time attacks, repo-controlled execution surfaces, and release-path drift while preserving developer speed through local caching.

## I. Introduction

- AI agents and software intake at machine speed
- why manual review and static scanning are insufficient
- the safe path must be the fast path

## II. Threat Model

- malicious registry publishes
- install/build scripts and startup hooks
- repo-controlled execution surfaces
- agent bypass attempts
- rollback, freeze, and stale-fallback risk

## III. Architecture

- acquire, build, execute, publish
- hot lane and cold lane
- artifact-native approval objects
- provenance, policy, and evidence separation

## IV. Trust Model

- exact digest is not the same as provenance
- TUF-style freshness and delegation
- Sigstore, in-toto, and SLSA integration goals
- revocation and recall

## V. Mirage Lab And Evidence

- quarantine before execution
- behavioral evidence as a supporting signal
- signed evidence packs
- limits of sandbox-based conclusions

## VI. Evaluation

- benchmark matrix and incident replay
- install-time package attacks
- repo-controlled execution surface cases
- benign controls and false-positive analysis
- cache-hit latency versus public fetch latency

## VII. Discussion

- what ZitPit can claim
- what ZitPit cannot claim
- current MVP versus target V2
- publisher-side release firewall as future work

## VIII. Conclusion

- ZitPit as an artifact firewall for agentic development
- safer defaults for smaller teams and open-source consumers

