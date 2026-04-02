# ZitPit: The Artifact Firewall for Agentic Software Supply Chains

*Turning first-seen code into policy events*

> ZitPit is a shorthand for making small supply-chain blemishes visible before they spread.

## Abstract

AI-assisted development turns dependency intake into machine-speed execution. ZitPit is a mandatory artifact firewall that forces external code through exact-digest admission, provenance-aware policy, and quarantine before it may execute on protected developer or CI hosts. In the current public benchmark snapshot, five public Git repositories show `web` medians of 433-1062 ms, approved disk-cache medians of 32-44 ms, and hot-cache medians of 13-16 ms, with `N=5` samples per repo. ZitPit uses that speed delta to make **the safe path the fast path**: first-seen artifacts are policy events, approved artifacts stay local and fast, and repo-open surfaces such as `.claude/`, `.mcp.json`, and devcontainers are treated as supply-chain input rather than ambient workspace state.

## 1. Introduction

Agentic software development compresses the time between code discovery, dependency resolution, and execution. That compression is productive, but it also gives attackers and accidental leaks less time to be noticed. An AI agent can search the internet, clone a repository, install dependencies, open a workspace, and invoke tools faster than a human can manually review the path it is about to take.

The result is a new default: packages, workflow refs, install scripts, shell bootstrap code, and repo-open configuration now arrive at machine speed. Recent public incidents across npm, PyPI, and agent tooling show the same pattern from different angles: account takeovers can turn installs into execution, build misconfigurations can leak source or metadata, and source-controlled agent configuration can be part of the supply chain. Anthropic's own [Claude Code getting started](https://docs.anthropic.com/en/docs/claude-code/getting-started) page shows npm installation, its [security page](https://docs.anthropic.com/en/docs/claude-code/security) notes that allowed MCP servers are configured in source control, and its [MCP](https://docs.anthropic.com/en/docs/claude-code/mcp) and [devcontainer](https://docs.anthropic.com/en/docs/claude-code/devcontainer) docs show that workspace configuration and outbound access are policy surfaces. GitHub Security Lab advisories likewise continue to catalog workflow leaks and poisoned-pipeline patterns.

ZitPit is built around a simple premise: **the safe path must be the fast path**. Unknown external code should not execute on a protected host until it has been resolved to an immutable identity, checked against policy, and either approved or quarantined. Approved artifacts should be faster than the public network, not slower.

### 1.1 Thesis

ZitPit is a mandatory artifact intake gate, not a Git proxy or a honeypot-first system. Its job is to convert first-seen external code from an execution event into a policy event.

## 2. Consumer Intake vs Producer Release

The criticism that shaped the current architecture was useful because it exposed a distinction the first draft blurred: consumer-side intake attacks and producer-side release failures are related but not identical problems.

### 2.1 Consumer-side intake attacks

These are the cases ZitPit is designed to stop or contain on protected developer and CI hosts:

- malicious registry publishes
- install-time and build-time scripts
- repo-controlled execution surfaces
- agent tool bypass attempts
- rollback, freeze, and stale-fallback attacks
- raw HTTP installer fetches
- mutable refs that should never have been treated as trustworthy defaults

### 2.2 Producer-side release failures

These are different. A source-map leak, wrong-registry publish, or packaging drift is a publisher-side failure. ZitPit can help with a publish firewall, but the consumer-side firewall is not a substitute for release hygiene. The paper must keep that boundary explicit so we do not overclaim on Claude Code-style packaging failures.

## 3. Architecture

ZitPit is organized around four stages:

- `Acquire`: all external artifact ingress resolves through ZitPit-managed intake
- `Build`: install-time and build-time code runs only in a controlled lane
- `Execute`: agents and workflows receive policy-scoped execution rights
- `Publish`: optional release inspection catches packaging drift and release leaks

The architecture uses two lanes:

- **Hot lane**: approved immutable artifacts are served from the local cache or hot cache
- **Cold lane**: first-seen or untrusted artifacts are quarantined and analyzed before they can influence the host

### 3.1 Current implementation vs roadmap

The current codebase proves part of the control plane, not the whole end state.

| Layer | Current implementation | Roadmap |
| --- | --- | --- |
| Acquire | Git smart-HTTP mediation, approved disk cache, in-memory hot cache, benchmark harness | Universal artifact gateway for npm, PyPI, Cargo, Go, GitHub Actions, raw HTTP downloads, and repo-open surfaces |
| Build | Controlled cold-lane execution for approved Git intake paths and battle packs | Hermetic build lanes for package ecosystems and install scripts |
| Execute | Policy hooks for agent and workspace boundaries | IDE- and MCP-native enforcement across agent runtimes |
| Publish | Claim boundaries and roadmap notes | Publisher-side release firewall with artifact inspection |

## 4. Trust Model

ZitPit does not treat hash equality as trust. Hashes are useful, but hash equality is not provenance.

The trust plane is designed to consume standards-backed inputs:

- TUF-style freshness, expiry, delegation, and rollback protection
- Sigstore-style identity-bound signing and transparency evidence
- in-toto-style step attestations
- SLSA-style provenance and build expectations

Approval records should carry:

- artifact digest
- source coordinates
- provenance and attestation status
- publisher identity continuity
- execution-surface flags
- platform scope
- expiry
- revocation state
- evidence pointer

Unsupported ingress paths must be called unsupported, not quietly assumed secure. That matters for agent workflows because "works in practice" is not a trust model.

## 5. Mirage Lab

The Mirage Lab is a cold-lane evidence engine. It is valuable for classification, enrichment, and operator review, but it is not the root trust oracle.

The strongest statement ZitPit can make is not that a lab run looked quiet. The strongest statement is that unknown artifacts never executed on the real host before quarantine and policy evaluation.

## 6. Evaluation

Public claims should be grounded in a benchmark matrix. The benchmark set currently covers:

- malicious npm install-script packages
- malicious Python sdists and startup paths
- Rust `build.rs` execution
- GitHub Actions mutable refs and unsafe action references
- repo-controlled `.claude/`, `.mcp.json`, and devcontainer surfaces
- raw HTTP installer fetches
- benign controls for the same families

For the Git intake path, the current public demonstration run used five public repositories and `N=5` samples per repo. The observed medians were:

| repo | web | cache | hot-cache |
| --- | ---: | ---: | ---: |
| git | 433 ms | 43 ms | 15 ms |
| go | 492 ms | 44 ms | 16 ms |
| node | 734 ms | 32 ms | 13 ms |
| cpython | 1062 ms | 35 ms | 14 ms |
| terraform | 582 ms | 39 ms | 15 ms |

Figure 1 shows the speedup snapshot generated from [`docs/benchmarks/latest.json`](../docs/benchmarks/latest.json). Figure 2 shows the simple control-plane diagram.

![Current five-repo speedup snapshot](../assets/figures/speedup.svg)

*Figure 1. Current five-repo demonstration run. The benchmark is intentionally small, public, and reproducible, with `N=5` samples per repo.*

![ZitPit control-plane diagram](../assets/figures/network.svg)

*Figure 2. Simple control-plane view: agent/IDE/CI requests flow through the gateway, approved artifacts hit hot cache, first-seen artifacts fall to the cold lane, and publish/revocation signals feed policy back.*

For each benchmark, ZitPit should report:

- ingress type
- immutable artifact boundary
- first execution boundary
- expected policy
- actual current behavior
- roadmap target behavior
- evidence produced
- supported claim class

## 7. Claims We Can Make

The public wording should stay aligned with [`CLAIMS.md`](../CLAIMS.md).

> **We can say**
>
> - ZitPit turns first-seen external code from an execution event into a policy event.
> - In enforced environments, unknown third-party artifacts do not execute on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine when required.
> - ZitPit makes the safe path the fast path by serving approved artifacts locally while forcing new artifacts through governed intake.
> - ZitPit is designed to block or contain short-lived registry compromises, malicious install scripts, and repo-controlled execution surfaces before they reach the host.
> - With a publish gate enabled, ZitPit can also prevent whole classes of accidental release leaks and workflow-drift publishes.
>
> **We cannot say**
>
> - ZitPit ends supply-chain attacks forever.
> - ZitPit would have prevented every Anthropic incident.
> - Hash equality means software is safe.
> - Mirage Lab silence means safety.
> - Git interception alone solves the agent-era supply chain.

## 8. Community and Reproducibility

ZitPit is open source, and the benchmark matrix is public. That matters because the point of the project is not to hide the model; it is to make the model inspectable, reproducible, and extendable.

The battle packs are intentionally community-extendable. Contributors can add new ecosystem adapters, new release scenarios, and new evidence cases without changing the core claim structure. Future work may widen coverage across other package managers and workflow systems, but the trust statement remains the same: first-seen code is a policy event, not ambient trust.

We want community help on benchmark design, ecosystem adapters, threat-model critique, battle packs, docs, and real-world incident replay cases. A world-class open-source security project should invite pressure, not hide from it.

## 9. Limits

ZitPit does not claim to prevent:

- malicious code intentionally committed by a trusted maintainer
- all producer-side release failures without a publish gate
- host kernel compromise
- physical access attacks
- every possible sandbox-evasion technique

## 10. Conclusion

ZitPit is a credibility-first security layer for agentic development. Its value is in making untrusted code execution explicit, policy-scoped, auditable, and fast for approved artifacts rather than ambient and invisible.

The references and related work are collected in [`references.md`](references.md).
