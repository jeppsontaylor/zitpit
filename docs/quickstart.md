# ZitPit Quickstart

Welcome to the ZitPit defensive perimeter. This guide will help you get the current demo environment running quickly.

The public benchmark matrix in [BENCHMARKS.md](../BENCHMARKS.md) defines the supported claim boundaries. This quickstart demonstrates the current Git intake path, protected-session workflow, and governed egress path, not every roadmap surface.

## Prerequisites

*   **Rust (latest stable)**: [rustup.rs](https://rustup.rs/)
*   **Docker & Docker Compose**: For the containerized demo services.
*   **Linux (recommended)**: For the strongest end-to-end demo experience. macOS and Windows can be configured for some local proxy flows, but broader coverage is still partial on those platforms.

## Step 1: Verify the Repository

Before running any code, verify that your local copy matches the published bootstrap integrity check:

```bash
sh scripts/verify_hash.sh
```

## Step 2: Launch the Docker Demo

We provide an `xtask` to simplify launching the demo stack.

1.  **Run Setup**: This checks your host prerequisites, picks an SSH key, starts the stack, and prints a safe `~/.ssh/config` block for `ssh zitpit`.
    ```bash
    cargo run -p xtask -- demo setup
    ```

2.  **Paste the SSH Config Block**: ZitPit will not edit your local SSH config for you. Paste the printed block into `~/.ssh/config`, then connect:
    ```bash
    ssh zitpit
    ```

## Step 3: Access the Admin UI

Open the TUI (Terminal User Interface) to monitor the proxy and manage artifacts:

```bash
cargo run -p zitpit-tui
```

## Step 4: Test a Protected Clone

From the protected `ssh zitpit` shell, try a Git operation through the proxy. ZitPit will intercept the request, check policy, and either allow it from the local cache or route it to quarantine.

```bash
git ls-remote https://github.com/jeppsontaylor/approved.git
```

## Next Steps

*   Read the [Operator Guide](operator-guide.md) for detailed configuration.
*   Check the [Agent Setup](agent-setup.md) to integrate with tools like Antigravity or Cursor.
*   Review [CLAIMS.md](../CLAIMS.md) and [BENCHMARKS.md](../BENCHMARKS.md) before making public claims.
*   Understand the [Trust Model](trust-model.md).
