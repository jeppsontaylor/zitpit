# ZitPit: Consumer-Side Admission Control for Agentic Software Intake

*Turning first-seen external artifacts into policy events*

This Markdown file is the readable companion to the canonical paper source in [`paper/main.tex`](../paper/main.tex). It is intentionally kept in sync with the paper’s argument structure and claim boundary rather than evolving as a separate draft.

## Abstract

AI IDEs and coding agents compress discovery, fetch, workspace open, installation, and execution into one low-observability loop. Existing defenses such as provenance frameworks, package and repository firewalls, runtime protection, and tool-approval prompts each cover part of that path, but they often leave the final consumer-side execution decision implicit. ZitPit argues for a stricter boundary: first-seen external artifacts should become durable policy events before they gain execution rights on protected developer or CI hosts. The current public evidence is intentionally narrow and explicit: repeated Git smart-HTTP intake measurements, implemented protected-session enforcement families, and governed outbound DLP proof families. The broader contribution is architectural rather than universal-coverage-by-assertion: ZitPit unifies artifact admission, repo-open state, capability-scoped execution, and durable policy records at the consumer execution boundary for agentic workflows.

## 1. Introduction

Agentic development has changed the tempo of software intake. A developer can ask an AI IDE to set up a repository, and the tool may immediately clone code, open project memory files, attach MCP servers, evaluate workspace configuration, install dependencies, run build hooks, and invoke helper scripts before a human reaches a durable review checkpoint.

That creates a consumer-side problem. Provenance systems can describe identity and build lineage. Package and repository firewalls can screen specific ecosystems. Runtime protection can watch after code starts executing. Tool-approval prompts can restrict some actions. But in agentic workflows these controls often still stop short of one durable question:

**Has this exact first-seen external artifact earned execution rights on this protected host, under this policy, in this context?**

ZitPit’s thesis is:

> **ZitPit is a consumer-side software admission control layer for agentic development. First-seen external artifacts must earn execution rights under durable policy before they affect a protected host.**

The contribution is not the claim that ZitPit already closes every package manager, IDE, workflow engine, or runtime path. The contribution is narrower and more defensible: ZitPit identifies a missing enforcement boundary for agentic development and shows preliminary public evidence that this boundary can be made visible, policy-scoped, and fast enough to be deployable.

## 2. Why Admission Control Matters

This boundary matters for five reasons:

1. Provenance only matters when a consumer-side system turns it into an execution decision.
2. Repo-open state matters because opening a repository can change tool behavior before durable review.
3. Capability-scoped verdicts matter because fetch, build, test, and host execution are different trust decisions.
4. The safe path must be faster than unmanaged public fetch, or mandatory controls will be bypassed.
5. Durable policy events create the missing join key for recall, audit, and later incident reconstruction.

ZitPit does not claim to invent application control, sandboxing, or provenance. Its narrower novelty claim is that it unifies artifact admission, repo-open state, capability-scoped execution, and durable policy events at the consumer execution boundary for agentic workflows.

## 3. Current Proof Boundary

The current public evidence boundary is intentionally explicit.

| Surface | Current public evidence | Status | Supported claim |
| --- | --- | --- | --- |
| Git smart-HTTP intake | Repeated five-repository benchmark harness | `Implemented` | Approved immutable Git intake can stay faster than unmanaged public fetch |
| Brokered protected-session enforcement families | Docker demo + battle packs | `Implemented` | Protected sessions can deny selected high-value command families before execution |
| Governed outbound DLP | Demo smoke proofs + egress battle packs | `Implemented` | Governed egress can block selected sensitive outbound data before transmission |
| Rust build-time execution | Battle harness coverage for `build.rs`-style scenarios | `Partial` | Build-time execution can be modeled as a separate capability boundary |
| GitHub Actions immutable-ref enforcement | Threat-model + scenario coverage | `Partial` | Workflow references should resolve to immutable identities before execution |
| npm / PyPI / raw installer mediation | Benchmark matrix + roadmap targets only | `Planned` | Current paper does not claim package-manager-complete mediation |
| Repo-open enforcement depth | Threat model, policy model, and roadmap targets | `Planned` | Repo-open state is in scope, but host-side closure is not yet fully proven |

What ZitPit does **not** claim:

- it is not a general agent-safety system
- it does not prove unknown software is benign
- it does not provide full ecosystem closure today
- it does not make trusted-publisher compromise harmless
- it does not claim safety for unsupported or unmanaged paths

## 4. Threat Model

The current threat model emphasizes the places where skeptical reviewers are right to push:

- **mandatory mediation and bypass**: submodules, LFS hydration, partial clone follow-on fetches, direct URLs, browser downloads, and unmanaged egress all matter
- **transitive closure**: package managers, build backends, workflow reuse, and devcontainer features can discover more artifacts later
- **repo-open surfaces**: `.mcp.json`, hooks, memory files, startup tasks, and devcontainer lifecycle can influence execution before review
- **trust-plane compromise**: cache poisoning, stale trust roots, policy-store compromise, and signing-key compromise are real risks
- **operator burden**: break-glass, approval latency, and availability are part of the security story because brittle systems get bypassed

Mirage Lab is useful as an evidence and ordering engine. It is not a safety oracle, and its quiet output should never be marketed as proof that software is benign.

ZitPit therefore treats resolved immutable identity, compatibility fingerprints, and any separately computed content digests as distinct inputs rather than collapsing them into one trust bit. Provenance, freshness, expiry, revocation, and operator-visible evidence remain separate obligations.

## 5. Architecture and Policy

ZitPit organizes the control plane into four stages:

1. **Acquire**: resolve external requests to the strongest available immutable identity
2. **Build**: separate build-time and install-time execution from simple acquisition
3. **Execute**: grant policy-scoped rights rather than ambient host trust
4. **Publish**: optionally inspect release outputs and publish paths

The durable contract is the artifact policy event. It records:

- `selector`
- `resolved_immutable_identity`
- `provenance_result`
- `verdict`
- `evidence_pointer`
- `context`
- `expiry_state`
- `revocation_state`

Concrete specimen:

> `selector=acme/tool@{pre-resolution}`
> `resolved_immutable_identity=f3c1...`
> `provenance_result=verified`
> `verdict=RUN_DEV`
> `evidence_pointer=report://quarantine`
> `context=code_intake/protected_host`

ZitPit uses capability-scoped verdicts rather than simple allow/block:

- `FETCH_ONLY`
- `UNPACK_ONLY`
- `BUILD_NO_NETWORK`
- `TEST_NO_SECRETS`
- `RUN_DEV`
- `RUN_CI`
- `BLOCKED`

The repository currently demonstrates protected-session enforcement families rather than universal host guarantees. Those demonstrations are important, but they should be described as demonstrated brokered-session controls unless host-side mandatory enforcement is fully proven.

## 6. Preliminary Evaluation

The current evaluation is split into two proof obligations.

### 6.0 Benchmark Methodology

The public timing harness now mirrors the actual upstream repository at the resolved immutable target before timing the approved path. It validates that the seeded managed mirror matches the claimed upstream HEAD and fails report generation if the managed response diverges from the expected immutable target.

The mutable working outputs remain under `docs/benchmarks/latest.*`, but the paper and launch docs now cite a frozen snapshot under `docs/benchmarks/snapshots/` so the evidence reference is not a moving `latest` pointer.

### 6.1 Deployability

The public benchmark harness measures the Git smart-HTTP intake path rather than a full clone or cross-ecosystem install. Across five public repositories and `N=5` samples per repository, web medians ranged from 433–1062 ms, approved disk-cache medians from 32–44 ms, and hot-cache medians from 13–16 ms.

That does **not** prove full Git closure, package-manager-native closure, or universal ecosystem mediation.

It **does** show something operationally important: approved immutable intake can be materially faster than unmanaged public fetch.

### 6.2 Coverage Honesty

The coverage matrix is part of the argument, not something to hide. A credible paper should make unsupported or partial paths visible rather than implying full closure through architecture diagrams.

The strongest current public proof families are:

- Git smart-HTTP intake
- brokered protected-session command families
- governed outbound DLP

The next high-leverage proof families are:

- `git_follow_on_intake`
- `repo_open_execution_surface`
- one package-dynamic-execution family next, likely npm Git dependency lifecycle or Python sdist/direct-URL build paths

## 7. Related Work

ZitPit sits between and alongside several existing control families:

- provenance and attestations
- workspace trust and application control
- hermetic and reproducible build systems
- repository and package firewalls
- runtime protection
- behavioral analysis corpora such as OpenSSF Package Analysis and malicious-package datasets

The paper’s claim is not that those fields are irrelevant. It is that agentic workflows need a clearer consumer-side boundary where external software and repo-open bundles earn execution rights.

## 8. Implications

The paper makes a narrow empirical claim and a broader architectural claim.

The narrow empirical claim is that some important slices of intake, protected-session mediation, and governed egress can be made explicit and auditable today, while approved immutable intake can remain faster than unmanaged public fetch.

The broader architectural claim is that this pattern could become a standard execution boundary for agentic environments. Repo-open state, workflow references, and other machine-consumable context increasingly behave like supply-chain input. If admission systems become common, open governance matters because these systems can centralize power if their policy memory, recall logic, and evidence formats are opaque or non-portable.

## 9. Limitations and Future Work

The present-tense limitations are straightforward:

- current public proof is strongest for Git smart-HTTP intake, protected-session command families, and governed egress
- package-manager-native mediation remains incomplete
- repo-open host-side enforcement depth remains incomplete
- mandatory mediation remains hard
- Mirage Lab is not a verifier
- trusted publishers can still ship bad code
- operator burden and availability still matter

The near-term engineering agenda is also straightforward:

- broader package-manager-native mediation
- stronger follow-on Git closure for submodules, LFS, and delayed fetches
- repo-open benchmark families
- stronger provenance consumption with expiry, revocation, and recall
- public benchmark suites that distinguish implemented proof from roadmap ambition

## 10. Conclusion

The interval between discovering external software and granting it local authority is collapsing toward zero. That changes the practical trust problem.

The important question is no longer only whether a package, workflow, or repo-open bundle exists on the internet. The important question is whether it has earned execution rights in a protected environment under durable policy.

That is the boundary ZitPit is trying to make explicit.
