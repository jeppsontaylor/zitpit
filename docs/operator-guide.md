# Operator Guide

As a ZitPit operator, you are responsible for maintaining the trust perimeter for your developer team.

## Architecture & Services

ZitPit consists of several interconnected Rust microservices:

*   **`zitpit-gateway`**: The entry point. Handles SSH, Git, and HTTP requests. Implements the `Gateway` logic.
*   **`zitpit-manifest`**: Manages signed manifests and artifact shards. This is your source of truth for "Approved" state.
*   **`zitpit-lab`**: Orchestrates the Mirage Lab. Manages detonation jobs and keeps track of evidence.
*   **`zitpit-watch`**: An observability service that provides an incident feed and logs of every intercepted request.

## Configuration

Services can be configured via environment variables or CLI flags (`zitpit-flags`).

### Environment Variables

*   `DATABASE_URL`: Postgres connection string (e.g., `postgres://user:pass@localhost/zitpit`). If unset, services default to an in-memory store.
*   `DATA_DIR`: Path to persistent file storage for artifacts and logs.
*   `MANIFEST_PRIVATE_KEY`: Path to the private key for signing manifests (do not check this into Git!).

### Policy Management

ZitPit policies are defined in the `Trust Plane`. You can manage these through:
1.  **TUI Console**: `cargo run -p zitpit-tui`
2.  **API**: Direct interaction with the `zitpit-manifest` API.

## Handling Unknown Requests

When a developer or agent requests an unapproved artifact, ZitPit will:
1.  Return a `Pending` response.
2.  Suggest a known-good alternative if one exists.
3.  Queue a `Quarantine` job in the Lab.

Operators must then:
1.  Review the Lab's `Evidence` report.
2.  Determine the `Verdict` (Promote or Block).
3.  Sign the new manifest entry to update the Trust Plane.

## Monitoring

Use **`zitpit-watch`** to monitor real-time requests. The incident feed will highlight any attempted bypasses or high-risk detonation results.
