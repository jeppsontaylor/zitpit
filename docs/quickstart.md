# ZitPit Quickstart

Welcome to the ZitPit defensive perimeter. This guide will help you get a local demo environment running quickly.

## Prerequisites

*   **Rust (latest stable)**: [rustup.rs](https://rustup.rs/)
*   **Docker & Docker Compose**: For the containerized demo services.
*   **Linux (recommended)**: For full SSH-proxy interception. macOS/Windows are supported for the local Git/HTTP proxy through manual configuration.

## Step 1: Verify the Repository

Before running any code, verify that your local copy matches the published trust anchors:

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

From the protected `ssh zitpit` shell, try a Git operation through the proxy. ZitPit will intercept the request, check the manifest, and either allow it (if cached/approved) or stall it for quarantine.

```bash
git ls-remote https://github.com/jeppsontaylor/approved.git
```

## Next Steps

*   Read the [Operator Guide](operator-guide.md) for detailed configuration.
*   Check the [Agent Setup](agent-setup.md) to integrate with tools like Antigravity or Cursor.
*   Understand our [Trust Model](trust-model.md).
