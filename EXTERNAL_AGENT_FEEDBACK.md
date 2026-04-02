# ZitPit Technical Feedback & Independent Review Document (V2)

**Intended Audience:** External Security Researchers, Agentic Workflow Engineers, and Open Source Architects
**Purpose:** To provide an exhaustive technical breakdown of the ZitPit V2 defense architecture, its four-stage policy pipeline, and benchmark-driven proof strategy. This document serves to secure alignment, eliminate ambiguities around claims, and solicit targeted feedback.

---

## 1. Executive Summary & V2 Pivot

The original ZitPit architecture proved the concept of routing autonomous agent workflows through a local choke-point. However, responding to feedback from senior security engineers across the industry, V2 pivots from a **"Git-first proxy with a honeypot"** to a **"Mandatory Artifact Firewall and Governed Execution Plane."**

We are shifting the center of gravity: deception (the Mirage Lab) is no longer the primary security guarantee. Our absolute invariant is **admission control and provenance-backed governance**. 

### The Revised Posture
*   **Artifacts over Git Trees**: We enforce policy based on exact artifact digests (npm tarballs, PyPI wheels), not merely repository tree hashes.
*   **Standards, Not Bespoke Hashes**: We consume TUF freshness bounds, Sigstore identities, and SLSA provenance.
*   **Cold-Lane First-Run**: "First-seen" unapproved third-party artifacts *do not* execute on protected developer or CI environments. They are held in quarantine (Mirage Lab) until policy executes.

---

## 2. Public Claims & Constraints

We write for skeptical security reviewers, avoiding absolute marketing claims.

### ✅ Bold Claims (True for V2 Build)
*   **Policy Over Execution**: ZitPit turns first-seen external code from an execution event into a policy event.
*   **Hermetic Default**: In enforced environments, unknown third-party artifacts do not execute on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine when required.
*   **Safe Path = Fast Path**: ZitPit serves approved artifacts locally while forcing new artifacts through governed intake.
*   **Incident Resilience (The Axios Scenario)**: Under enforced ZitPit protection (exact-digest approvals, no direct egress bypass, default-deny install execution, and first-seen quarantine), the March 31, 2026 Axios install-time RAT compromise would likely have been blocked from executing on protected developer and CI endpoints.

### ❌ Claims We Strictly Avoid
*   "ZitPit ends supply-chain attacks forever."
*   "If Anthropic had used this, none of the Claude Code incident would have happened." (The Claude Code incident was an upstream publishing error, not an intake attack. Our new `Publish Gate` answers that.)
*   "Keeping the honeypot private is our security model." (Security rests on the admission boundary, not obscurity.)

---

## 3. Architecture: The 4-Stage Control Plane

ZitPit protects environments across four boundaries:

1.  **Acquire**: All external artifacts resolve through `zitpit-gateway`. Exact immutable digests are the enforcement unit. Mutable tags/refs (`latest`) are policy exceptions.
2.  **Build**: Install/build scripts (e.g., `postinstall`, `build.rs`) never run on the protected host before policy approval. They are relegated to cold-lane or quarantine execution.
3.  **Execute**: Agent execution privileges are explicitly managed (e.g., `.claude/` setting enforcement, `PreToolUse` hook control). We use an "Agent Capsule" to isolate the agent from ambient host secrets.
4.  **Publish**: The `zitpit-publish` release gate ensures that developers cannot accidentally ship secrets or source maps upwards into registry supply chains.

---

## 4. The Mirage Lab: Evidence over Magic

The Mirage Lab remains crucial but its role is narrowed. It is an **evidence engine and cold-lane detonation system**.
*   **Multi-Persona Execution**: Evaluates artifacts against Linux CI environments, macOS laptops, and isolated containers.
*   **Evidence Bundling**: Every block/promotion decision generates a signed evidence pack, establishing a trail for retroactive blast-radius search and recall operations.

---

### We Request Your Help
Review our [BENCHMARKS.md](BENCHMARKS.md) to inspect the specific threat matrix we validate against. We invite you to scrutinize our admission unit logic, TUF integrations, and cold-lane execution wrappers.
