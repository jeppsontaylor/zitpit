# Contributing to ZitPit

The spirit of ZitPit is to save the world and stop supply-chain nonsense. To do this, we need the **most open**, **most collaborative** environment possible. We need the most brains working on this.

## Our Approach

ZitPit is a security project. We value:
*   **Correctness over Convenience**: Defending the builder is the priority.
*   **Transparency**: Every decision and manifest should be traceable.
*   **Deception Excellence**: We want the most creative honeypot decoys.

## How to Contribute

### 1. Security Research
If you find a bypass, a vulnerability, or a flaw in our isolation logic, please follow our [SECURITY.md](SECURITY.md) guidelines for responsible disclosure. Do not open a public issue for critical security flaws.

### 2. Code Contributions
We follow a standard GitHub flow:
1.  Fork the repository.
2.  Create a feature branch.
3.  Ensure `cargo fmt` and `cargo clippy` pass:
    ```bash
    cargo clippy --workspace --all-targets -- -D warnings
    ```
4.  Submit a Pull Request.

### 3. Honeypot Payloads (Mirage Lab)
We are actively looking for contributors to the `crates/zitpit-lab` logic. If you have detection patterns for common exploit frameworks, or if you can improve our decoy assets (fake keys, fake cloud profiles), please contribute!

## Governance & DCO

We use the **Developer Certificate of Origin (DCO)**. All commits must be signed-off (`git commit -s`) to certify that you have the right to submit the code under the project's license.

ZitPit is a community-driven project. See [GOVERNANCE.md](GOVERNANCE.md) for more details.
