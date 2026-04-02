# ZitPit: A Mandatory Artifact Firewall and Governed Execution Plane for Agentic Software Supply Chains

*(Working Draft: Version 2.0)*

## Abstract

AI-assisted development turns dependency intake into machine-speed execution. ZitPit is a mandatory artifact firewall that forces external code through exact-digest admission, provenance-aware policy, and quarantine before it may execute on protected developer or CI hosts. The design preserves speed by serving approved artifacts from a local cache while treating first-seen artifacts, mutable refs, and repo-controlled execution surfaces as policy events rather than ambient trust.

## 1. Introduction

Agentic software development compresses the time between code discovery, dependency resolution, and execution. That compression is useful for productivity, but it also collapses the window in which humans can safely notice hostile or anomalous artifacts.

ZitPit is built around a simple premise: the safe path must be the fast path. Unknown external code should not execute on a protected host until it has been resolved to an immutable identity, checked against policy, and either approved or quarantined.

### 1.1 Thesis

ZitPit is a mandatory artifact intake gate, not a Git proxy or a honeypot-first system. Its job is to convert first-seen external code from an execution event into a policy event.

## 2. Threat Model

ZitPit targets classes of supply-chain risk that matter in AI-assisted workflows:

- malicious registry publishes
- install-time and build-time scripts
- repo-controlled execution surfaces
- agent tool bypass attempts
- rollback, freeze, and stale-fallback attacks
- sandbox-aware malware that delays or hides behavior

## 3. Architecture

### 3.1 Acquire

All external artifact ingress resolves through ZitPit-managed intake. Approved artifacts are served from a local content-addressed cache. Mutable selectors such as branches, tags, and `latest` are treated as policy exceptions.

### 3.2 Build

Install-time and build-time code runs only in a controlled lane. First-seen artifacts are quarantined before scripts or hooks may execute on the protected host.

### 3.3 Execute

Agents and workflows receive policy-scoped execution rights. Repo-open and agent configuration are part of the supply chain, not a separate trust domain.

### 3.4 Publish

A publish firewall can inspect outbound artifacts before release to catch packaging drift, secret leaks, and wrong-registry publication.

## 4. Trust Model

ZitPit does not treat hash equality as trust. The trust plane is designed to consume TUF-style freshness and delegation semantics, Sigstore-style identity-bound signing, in-toto-style step attestations, and SLSA-style provenance expectations.

Approval records should carry:

- artifact digest
- source coordinates
- provenance and attestation status
- publisher identity continuity
- execution-surface flags
- platform scope
- expiry
- revocation state

## 5. Mirage Lab

The Mirage Lab is a cold-lane evidence engine. It is useful for classification, enrichment, and operator review, but it is not the root trust oracle.

The strongest statement ZitPit can make is not that a lab run looked quiet. The strongest statement is that unknown artifacts never executed on the real host before quarantine and policy evaluation.

## 6. Evaluation

Public claims should be grounded in a benchmark matrix. The benchmark set should include:

- malicious npm install-script packages
- malicious Python sdists and startup paths
- Rust `build.rs` execution
- GitHub Actions mutable refs and unsafe action references
- repo-controlled `.claude/`, `.mcp.json`, and devcontainer surfaces
- raw HTTP installer fetches
- benign controls for the same families

For each benchmark, ZitPit should report:

- ingress type
- immutable artifact boundary
- first execution boundary
- expected policy
- actual current behavior
- V2 target behavior
- evidence produced
- supported claim class

## 7. Limits

ZitPit does not claim to prevent:

- malicious code intentionally committed by a trusted maintainer
- all producer-side release failures without a publish gate
- host kernel compromise
- physical access attacks
- every possible sandbox-evasion technique

## 8. Conclusion

ZitPit is a credibility-first security layer for agentic development. Its value is in making untrusted code execution explicit, policy-scoped, and auditable rather than ambient and invisible.

