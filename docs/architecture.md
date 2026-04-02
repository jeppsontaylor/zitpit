# ZitPit Architecture

## Thesis

ZitPit is a mandatory artifact firewall and governed execution plane for AI-assisted development. The project exists to make the safe path the fast path by forcing untrusted external code through policy, provenance, and quarantine before it can execute on a protected host.

## Current Implementation

The repository currently proves parts of the control plane, not the full end state. The current services model is:

- `zitpit-gateway`: admin API plus a real forward proxy with `CONNECT` handling
- `zitpit-manifest`: publishes signed manifest roots and shards from the shared store
- `zitpit-lab`: plans Firecracker-backed detonation runs and persists evidence
- `zitpit-watch`: publishes incident feeds and evidence from the shared store
- `zitpit-node-agent`: generates Linux bootstrap material for CA trust and transparent capture

Supporting crates keep the binaries thin:

- `zitpit-config`: runtime path helpers for data directories and cache roots
- `zitpit-flags`: shared CLI and env parsing for service startup
- `zitpit-testing`: temp-path, seeded-store, and harness helpers for test code
- `zitpit-admin-client`: typed client bindings for the admin APIs
- `zitpit-tui`: operator console over the same APIs
- `zitpit-battle-types`: benchmark schema, expectations, and result models
- `zitpit-battle-runner`: benchmark executor over the same queue, lab, and evidence contracts
- `zitpit-battle-cli`: thin CLI wrapper for benchmark execution
- `xtask`: Docker demo orchestration, SSH config generation, smoke flows, and benchmark entrypoints

This implementation validates:

- request logging and decision contracts
- signed manifest transport
- cache and quarantine behavior
- evidence emission and persistence
- Firecracker run planning
- benchmark harness plumbing

It does not yet claim full coverage of every package manager, IDE, or agent runtime.

## Control Plane

The architecture is organized around four stages:

### Acquire

All external artifact ingress should resolve through ZitPit-managed intake. Approved content is served from a local content-addressed cache. Mutable refs such as branches, tags, and `latest` are policy exceptions, not the default trust model.

### Build

Install-time and build-time execution should happen only in a controlled lane. Unknown or first-seen artifacts are quarantined before scripts, hooks, or build steps can run on the protected host.

### Execute

Agents and workflows receive policy-scoped execution rights. Tool calls, shell commands, and repo-controlled execution surfaces are mediated by the agent policy layer rather than by ambient host trust.

### Publish

Optional publisher-side controls inspect release artifacts before they leave a build pipeline. This protects against accidental source-map leaks, wrong-registry publishes, and workflow drift.

## Hot Lane And Cold Lane

ZitPit uses two lanes:

- hot lane: known-good immutable artifacts served locally from cache
- cold lane: first-seen or policy-drift artifacts quarantined for analysis and evidence generation

The safety invariant is simple: unknown artifacts never execute on the real developer or CI host by default.

## Trust Boundary

The cache and the trust plane share a content-addressed boundary. Approval is keyed to the delivered artifact digest, not to a mutable name, branch, or tag. The manifest plane records provenance, publisher continuity, expiry, and revocation state alongside the digest.

## Provenance, Policy, And Evidence

ZitPit separates three steps:

1. verify provenance and identity
2. evaluate policy
3. emit signed evidence

Where they happen:

- provenance verification: manifest plane, backed by standards-native attestations
- policy evaluation: gateway and execution policy engine
- evidence emission: lab and watch services, plus any publish gate

## Agent-Native Enforcement

ZitPit treats repo-open and agent configuration as part of the supply chain. The enforcement surface includes:

- `.claude/`
- `.mcp.json`
- devcontainers
- workspace task files
- editor extensions and hooks
- shell startup files and automation scripts

The goal is to prevent agents from routing around the gateway by editing their own guardrails.

## Current Versus Roadmap

Current:

- Git-first proxying
- signed manifest transport
- quarantine planning
- battle harnesses for selected families

Roadmap:

- universal artifact intake
- exact-digest policy enforcement
- provenance-aware trust decisions
- agent-policy integration
- publisher-side release gating
- benchmark-driven public claims
