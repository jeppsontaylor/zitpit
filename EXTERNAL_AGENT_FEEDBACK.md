# ZitPit Technical Feedback & Independent Review Document

**Intended Audience:** External security researchers, agentic workflow engineers, and open-source architects  
**Purpose:** To provide a concise technical breakdown of the ZitPit 1.0 architecture, its four-stage policy pipeline, its benchmark-driven proof strategy, and the areas where outside review can most improve the project.

---

## 1. Executive Summary

ZitPit started by proving that autonomous agent workflows could be routed through a local choke point. The project has since matured into a clearer `1.0` posture: a **mandatory artifact firewall and governed execution plane** for AI-assisted development.

The core invariant is straightforward:

**First-seen external code should become a policy event before it becomes execution on a protected host.**

That means the center of gravity is admission control, immutable identity, provenance-aware policy, and quarantine when required. The Mirage Lab remains important, but it is an evidence engine, not the root trust model.

### The Current Posture

*   **Artifacts over Git trees**: policy should bind to exact artifact digests and immutable identities, not only repository tree hashes.
*   **Standards, not bespoke trust**: the trust plane is designed to consume TUF, Sigstore, in-toto, and SLSA-style inputs.
*   **Cold-lane first run**: unknown or drifted artifacts should not execute on protected developer or CI environments before policy review.

---

## 2. Public Claims & Constraints

We write for skeptical security reviewers and try to keep the claim boundary strict.

### Claims we believe are supportable

*   **Policy over execution**: ZitPit turns first-seen external code from an execution event into a policy event.
*   **Hermetic default posture**: in enforced environments, unknown third-party artifacts should not execute on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine when required.
*   **Safe path = fast path**: ZitPit serves approved artifacts locally while forcing new artifacts through governed intake.
*   **Consumer-side incident resilience**: under enforced mediation, exact-digest approvals, and no bypass, short-lived install-time supply-chain compromises should be containable before they hit the protected host.

### Claims we avoid

*   "ZitPit ends supply-chain attacks forever."
*   "Every AI tooling incident would have been prevented by ZitPit."
*   "The lab is the security model."
*   "Hash equality means software is safe."

---

## 3. Architecture: The 4-Stage Control Plane

ZitPit protects environments across four boundaries:

1. **Acquire**: external artifacts resolve through `zitpit-gateway`, with immutable identity as the enforcement unit wherever possible.
2. **Build**: install/build scripts such as `postinstall` and `build.rs` should not run on the protected host before policy approval.
3. **Execute**: agent execution privileges, workspace surfaces, and tool use are mediated as policy surfaces.
4. **Publish**: optional release inspection can catch packaging drift, source-map leaks, and related release hygiene failures.

---

## 4. Mirage Lab: Evidence Over Magic

The Mirage Lab remains crucial, but its role is narrower and more honest:

*   **Multi-persona execution**: evaluate artifacts in controlled Linux, macOS-style, or containerized personas.
*   **Evidence bundling**: every block, promotion, or recall decision should produce evidence that operators can inspect later.
*   **Cold-lane support**: the lab helps classify and enrich decisions; it should not be the only barrier between unknown code and the protected host.

---

## 5. Where We Want Community Help

Review [BENCHMARKS.md](BENCHMARKS.md) to inspect the threat matrix we validate against. We would especially value help with:

*   attack-family benchmarks and benign controls
*   ecosystem adapters for npm, PyPI, Cargo, Go, OCI, and raw installer paths
*   repo-open and agent-surface enforcement design
*   provenance and policy review
*   paper critique, threat-model pressure testing, and reproducibility review

If you want to stress-test the project, that is welcome. The fastest way to make ZitPit better is to make the claim boundary sharper in public.
