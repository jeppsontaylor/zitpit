# Evidence Index

This document is the shortest reviewer path from a public claim to the code, demo, and benchmark artifact that support it.

The machine-readable source of truth is [`claim-matrix.yaml`](claim-matrix.yaml).

## Implemented Today

### Git Smart-HTTP Intake

- Supported claim: approved immutable Git intake can stay faster than unmanaged public fetch.
- Code paths:
  - [`xtask/src/bench.rs`](../xtask/src/bench.rs)
  - [`crates/zitpit-core/src/gitlane.rs`](../crates/zitpit-core/src/gitlane.rs)
- Public evidence:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
  - [`docs/benchmarks/latest.md`](benchmarks/latest.md)
  - [`docs/benchmarks/snapshots/2026-04-04-prelaunch.md`](benchmarks/snapshots/2026-04-04-prelaunch.md)
- Demo/test path:
  - `cargo test -q -p zitpit-core approved_git_source_promotes_hot_cache_after_disk_hit -- --nocapture`
  - `cargo run -p xtask -- bench run`
- Not yet proven:
  - submodules
  - LFS hydration
  - delayed follow-on fetch closure

### Brokered Protected-Session Enforcement

- Supported claim: protected sessions can deny selected high-value command families before execution.
- Code paths:
  - [`crates/zitpit-core/src/behavior.rs`](../crates/zitpit-core/src/behavior.rs)
  - [`crates/zitpit-sessiond/src/lib.rs`](../crates/zitpit-sessiond/src/lib.rs)
- Public evidence:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
  - [`docs/quickstart.md`](quickstart.md)
- Demo/test path:
  - `cargo run -p xtask -- battle shell`
  - `cargo test -q -p zitpit-core allows_demo_git_probe_commands -- --nocapture`
- Not yet proven:
  - universal host-side application control
  - arbitrary shell semantics outside the structured protected path

### Governed Outbound DLP

- Supported claim: governed egress can block selected sensitive outbound data before transmission.
- Code paths:
  - [`crates/zitpit-core/src/dlp.rs`](../crates/zitpit-core/src/dlp.rs)
  - [`crates/zitpit-core/src/egress.rs`](../crates/zitpit-core/src/egress.rs)
  - [`crates/zitpit-gateway/src/lib.rs`](../crates/zitpit-gateway/src/lib.rs)
- Public evidence:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
  - [`docs/deployment-hardening.md`](deployment-hardening.md)
- Demo/test path:
  - `cargo run -p xtask -- battle egress`
  - `cargo run -p xtask -- demo smoke`
- Not yet proven:
  - raw socket closure
  - unmanaged egress beyond the governed path

## Partial Today

### Rust Build-Time Execution

- Supported claim: build-time execution can be modeled as a separate capability boundary.
- Public evidence:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
- Current status:
  - battle-harness coverage exists
  - Cargo-native closure remains incomplete

## Planned Next

### Git Follow-On Intake

- Planned proof family: `git_follow_on_intake`
- Why it matters:
  - closes the loudest Git reviewer objections around submodules, LFS, and delayed fetches
- Tracked in:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
  - [`ROADMAP.md`](../ROADMAP.md)

### Repo-Open Execution Surface

- Planned proof family: `repo_open_execution_surface`
- Why it matters:
  - opening a repo can change tool behavior before review
- Tracked in:
  - [`BENCHMARKS.md`](../BENCHMARKS.md)
  - [`docs/threat-model.md`](threat-model.md)
  - [`docs/policy-model.md`](policy-model.md)

## Reading Rules

- If a claim is not mapped here and in [`BENCHMARKS.md`](../BENCHMARKS.md), treat it as roadmap or unsupported.
- The current paper is best read as architecture plus working prototype plus narrow proof families.
- Demo surfaces and hardened deployment posture are different. Read [`deployment-hardening.md`](deployment-hardening.md) before treating the Compose stack as a production blueprint.
