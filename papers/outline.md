# ZitPit Research Paper Outline

**Title**: *ZitPit: The Artifact Firewall for Agentic Software Supply Chains*

**Subtitle**: *Turning first-seen code into policy events*

**Abstract**:
AI-assisted development turns dependency intake into machine-speed execution. ZitPit proposes a mandatory artifact firewall that forces external code through exact-digest admission, provenance-aware policy, and quarantine before it may execute on protected developer or CI hosts. The current public benchmark snapshot shows five public Git repositories moving from 413-821 ms upstream to 30-34 ms from approved cache and 14-16 ms from hot cache, demonstrating that the safe path can be materially faster than the public path.

## I. Introduction

- agent speed and internet-scale code intake
- recent npm, PyPI, and agent-tool incidents
- consumer-side intake risk versus producer-side release leaks
- why the safe path must be the fast path

## II. Consumer Intake vs Producer Release

- malicious registry publishes
- install/build scripts and startup hooks
- repo-controlled execution surfaces
- raw HTTP installers and mutable refs
- release hygiene and publish gates

## III. Architecture

- acquire, build, execute, publish
- hot lane and cold lane
- current MVP versus target V2
- artifact-native approval objects
- evidence engine versus trust oracle

## IV. Trust Model

- hash equality is not provenance
- TUF-style freshness and delegation
- Sigstore, in-toto, and SLSA integration goals
- revocation, recall, and unsupported ingress

## V. Mirage Lab And Evidence

- quarantine before execution
- behavioral evidence as a supporting signal
- signed evidence packs
- limits of sandbox-based conclusions

## VI. Evaluation

- current five-repo speedup snapshot
- benchmark matrix and incident replay
- repo-open surface cases
- benign controls and false-positive analysis
- cache-hit latency versus public fetch latency
- simple control-plane diagram

## VII. Claims And Limits

- what ZitPit can say
- what ZitPit cannot say
- current MVP versus target V2
- consumer-side intake versus producer-side release failures

## VIII. Community And Reproducibility

- public benchmark matrix
- community-extendable battle packs
- future ecosystem adapters
- open-source claim boundaries

## IX. Conclusion

- ZitPit as an artifact firewall for agentic development
- safer defaults for smaller teams and open-source consumers
