# Deployment Hardening

This document draws a bright line between the local demo posture and the hardened posture expected for any serious deployment.

## Current Launch Posture

ZitPit should currently be presented as a **credible open-source research prototype with hardened defaults**, not as a production-complete universal enforcement system.

The strongest current public proof is still limited to:

- Git smart-HTTP intake
- brokered protected-session enforcement families
- governed outbound DLP

## Demo vs Hardened

### Demo Mode

Use demo mode for:

- local research
- CI smoke flows
- fixture endpoints
- screenshots and operator walk-throughs

Demo mode may expose:

- fixture routes
- extra introspection convenience
- local demo ports through Compose
- demo bootstrap helpers such as `scripts/demo_verify_hash.sh`

### Hardened Mode

Use hardened mode for:

- any shared environment
- any environment with real credentials
- any environment where captured traffic could contain sensitive metadata

Hardened mode expectations:

- admin and node-agent listeners bind to loopback or another explicitly private control plane
- non-health admin and node-agent endpoints require bearer-token auth
- fixture routes are disabled
- captured-request retrieval is disabled outside debug/demo workflows
- redaction and retention are treated as part of the security boundary

## Ports and Surfaces

The current default surface is:

| Surface | Default port | Current expectation |
| --- | ---: | --- |
| Admin API | `3000` | Loopback/private control plane only; bearer token required |
| Manifest service | `3001` | Internal service plane |
| Lab service | `3002` | Internal service plane |
| Watch service | `3003` | Internal service plane |
| Proxy / governed egress | `3004` | User traffic path |
| Node-agent API | `3006` | Loopback/private control plane only; bearer token required |

The Compose stack in [`compose.yaml`](../compose.yaml) is a **demo stack**, not a hardened deployment blueprint.

## Auth Expectations

Current minimum launch expectation:

- bearer-token auth on non-health admin and node-agent endpoints
- explicit operator control of token distribution
- no assumption that a public bind address is safe just because auth exists

Future hardening layers may include:

- mTLS
- Unix-socket or sidecar-only admin planes
- stronger operator identity and policy-signing workflows

## Captured Requests, Redaction, and Retention

Captured-request handling is sensitive because request metadata can contain credentials or session-bearing headers.

Current hardened expectations:

- only an allowlisted header subset is persisted
- `Authorization`, `Cookie`, `Proxy-Authorization`, and similar session-bearing headers are stripped before storage
- retention is bounded by policy
- captured-request read APIs stay disabled outside demo/debug mode

## DLP Boundaries

Current DLP proof is intentionally bounded.

Important current limits include:

- top-level scan byte cap
- archive depth cap
- archive entry cap
- per-entry byte cap
- explicit partial-inspection outcomes such as `truncated`, `archive_depth_limit_hit`, `archive_entry_limit_hit`, `encrypted_archive`, and `inspection_partial`

Treat those limits as part of the proof boundary, not as an invisible implementation detail.

## Current Non-Claims

Hardened deployment guidance does **not** imply:

- full package-manager-native closure
- full repo-open host-side closure
- raw socket or unmanaged egress closure
- universal host-side application control
- safety for unsupported or unmanaged paths

For those claim boundaries, see [`CLAIMS.md`](../CLAIMS.md), [`BENCHMARKS.md`](../BENCHMARKS.md), and [`docs/evidence-index.md`](evidence-index.md).
