# Operator Guide

As a ZitPit operator, you are responsible for maintaining the trust perimeter for your developer team.

## Architecture & Services

ZitPit consists of a small set of Rust services that implement intake, policy, evidence, and observability:

*   **`zitpit-gateway`**: The intake entry point. Handles SSH, Git, and HTTP requests and forwards approved artifacts to cache or cold lane.
*   **`zitpit-manifest`**: The policy and provenance ledger. It records capability-scoped verdicts, digest identity, and revocation state.
*   **`zitpit-lab`**: The Mirage Lab coordinator. It runs cold-lane detonation jobs and collects evidence.
*   **`zitpit-watch`**: Observability and incident feed. It surfaces policy decisions and high-risk request traces.

## Configuration

Services can be configured via environment variables or CLI flags (`zitpit-flags`).

### Environment Variables

*   `DATABASE_URL`: Postgres connection string (e.g., `postgres://user:pass@localhost/zitpit`). If unset, services default to an in-memory store.
*   `DATA_DIR`: Path to persistent file storage for artifacts and logs.
*   `MANIFEST_PRIVATE_KEY`: Path to the private key for signing manifests (do not check this into Git!).

### Policy Management

ZitPit policies are defined in the trust plane. You can manage them through:
1.  **TUI Console**: `cargo run -p zitpit-tui`
2.  **API**: Direct interaction with the `zitpit-manifest` API.

## Handling Unknown Requests

When a developer or agent requests an unapproved artifact, ZitPit will:
1.  Return a `Quarantine` or `Blocked` decision depending on policy.
2.  Suggest a known-good alternative if one exists.
3.  Queue a cold-lane job in the Lab and emit evidence.

Operators must then:
1.  Review the Lab's evidence report.
2.  Determine the verdict (`FETCH_ONLY`, `BUILD_NO_NETWORK`, `RUN_CI`, or `BLOCKED`).
3.  Sign the new manifest entry to update the policy ledger.

## Monitoring

Use **`zitpit-watch`** to monitor real-time requests. The incident feed will highlight attempted bypasses, stale fallback use, or high-risk detonation results.
