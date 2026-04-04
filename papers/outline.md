# ZitPit Research Paper Outline

**Title**: *ZitPit: Consumer-Side Admission Control for Agentic Software Intake*

**Subtitle**: *Turning first-seen external artifacts into policy events*

**Abstract**:  
AI IDEs and coding agents compress discovery, fetch, workspace open, installation, and execution into one low-observability loop. ZitPit argues for a stricter boundary: first-seen external artifacts should become durable policy events before they gain execution rights on protected developer or CI hosts. The current public evidence is intentionally narrow and explicit: repeated Git smart-HTTP intake measurements, implemented protected-session enforcement families, and governed outbound DLP proof families. The broader contribution is architectural rather than universal-coverage-by-assertion.

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
- current implementation versus roadmap
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
- current implementation versus roadmap
- consumer-side intake versus producer-side release failures

## VIII. Community And Reproducibility

- public benchmark matrix
- community-extendable battle packs
- future ecosystem adapters
- open-source claim boundaries

## IX. Conclusion

- ZitPit as consumer-side admission control for agentic development
- safer defaults for smaller teams and open-source consumers
