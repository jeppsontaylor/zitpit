# Glossary

## Core Terms

### Artifact

The external code object or repo-scoped execution bundle being mediated: a Git ref target, package tarball, workflow action, raw installer payload, or repo-open configuration surface.

### Selector

The mutable or user-facing reference used to request an artifact, such as a branch, tag, semver range, direct URL, or pre-resolution Git request marker.

### Unspecified Selector

A first-class state meaning the request did not provide a meaningful immutable selector yet. This is different from an explicit `latest` or other floating selector.

### Resolved Immutable Identity

The concrete identity the system binds policy to after resolution, such as a Git commit or another immutable content identity.

### Artifact Key

The normalized internal key used to track an artifact in storage and policy. In ZitPit this includes ecosystem, source, selector text, and selector kind.

### Policy Event

The durable admission record that ties selector, resolved identity, provenance result, verdict, evidence, context, and expiry or revocation state together.

### Provenance Result

The current trust-plane evaluation about origin, attestation, or continuity. It is an input to policy, not proof that software is benign.

### Capability Verdict

A rights grant such as `FETCH_ONLY`, `BUILD_NO_NETWORK`, or `RUN_DEV`. It is more precise than a binary allow/block decision.

### Proxy Action

The immediate routing outcome in the gateway path, such as allow, fallback, pending, or blocked. This is narrower than the higher-level capability verdict.

### Fallback

A time-bounded or policy-permitted substitution from a floating selector to a previously approved immutable target. Fallback is never meant to be a silent default.

### Protected Session

The brokered shell/session environment used for the current public proof families around pre-execution command denial. This is not the same thing as universal host-side mandatory enforcement.

### Repo-Open Surface

Files or settings that can influence behavior when a repository is opened, such as `.mcp.json`, hooks, memory files, task configuration, or devcontainer lifecycle data.

### Governed Egress

The current managed upload and outbound data path where ZitPit can inspect and block selected payloads before transmission.

### Demo Mode

The intentionally more permissive local research posture where fixture endpoints and example surfaces may be enabled for demonstration or testing.

### Hardened Mode

The stricter posture where admin surfaces are authenticated, captured-request handling is restricted, and demo-only routes are disabled.
