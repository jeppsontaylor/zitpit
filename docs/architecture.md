# ZitPit Architecture

## Canonical Framing

ZitPit is a **consumer-side software admission control layer for agentic development**.

The project still uses the product language of a mandatory artifact firewall and governed execution plane, but the core architectural invariant is narrower and stronger:

**First-seen external artifacts must earn execution rights under durable policy before they affect a protected host.**

## Current Implementation Boundary

The repository currently proves parts of the control plane, not the full end state.

Strongest public proof today:

- Git smart-HTTP intake benchmarking
- brokered protected-session enforcement families
- governed outbound DLP

Publicly partial or planned areas:

- package-manager-native mediation across npm, PyPI, Cargo, Go, OCI, and raw installer paths
- repo-open host-side enforcement depth
- full workflow graph closure
- universal host-side mandatory enforcement

## Services

The current services model is:

- `zitpit-gateway`: admin API plus forward proxy and governed egress surface
- `zitpit-manifest`: manifest publication from shared store
- `zitpit-lab`: controlled evidence-lane planning and evidence persistence
- `zitpit-watch`: incident and evidence publication
- `zitpit-node-agent`: Linux bootstrap material for capture and node setup

Supporting crates keep binaries thin and provide battle harnesses, typed admin clients, demo orchestration, and operator surfaces.

## Control Plane

### Acquire

Resolve external requests to the strongest available immutable identity. Approved immutable content is eligible for the fast lane. Mutable refs are policy exceptions, not default trust.

### Build

Separate build-time and install-time execution from acquisition. Unknown or policy-sensitive artifacts should not run install scripts or build hooks on the protected host by default.

### Execute

Grant policy-scoped rights rather than ambient host trust. The current repository publicly proves selected protected-session enforcement families here, not universal host closure.

### Publish

Inspect outgoing release artifacts and workflow outputs when publish controls are enabled.

## Fast Lane and Evidence Lane

- fast lane: approved immutable artifacts served from local cache or hot cache
- evidence lane: first-seen or policy-sensitive artifacts held for controlled analysis and operator-visible evidence

The evidence lane improves ordering and evidence; it is not the root trust model.

## Policy Event Contract

The shared architecture contract is the artifact policy event documented in [`policy-model.md`](policy-model.md):

- `selector`
- `resolved_immutable_identity`
- `provenance_result`
- `verdict`
- `evidence_pointer`
- `context`
- `expiry_state`
- `revocation_state`

This is the bridge between admission, evidence, and later recall.

Terminology used here is stabilized in [`docs/glossary.md`](glossary.md). The reviewer-facing claim map lives in [`docs/evidence-index.md`](evidence-index.md).

## Current vs. Roadmap

Current:

- proof that approved immutable intake can be faster than unmanaged public fetch for mediated Git smart-HTTP requests
- proof that selected protected-session execution families can be denied before execution
- proof that selected sensitive outbound data can be blocked before transmission

Roadmap:

- `git_follow_on_intake` for submodules, LFS, and delayed Git fetch closure
- `repo_open_execution_surface` for devcontainer lifecycle and agent-config-triggered behavior
- package-dynamic-execution proof families for npm or Python
- stronger provenance consumption, recall, and revocation handling
- host-side mandatory enforcement beyond the current protected-session demo boundary
