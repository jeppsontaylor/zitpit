# Contributor Map

This is the fastest map from repository area to responsibility, maturity, and proof relevance.

## Core Crates

| Crate | Responsibility | Maturity | Proof relevance |
| --- | --- | --- | --- |
| `zitpit-core` | policy engine, broker, Git lane, DLP, storage types, benchmark-critical logic | highest | central to all current public claims |
| `zitpit-config` | runtime paths and configuration helpers | stable support | supports repeatable demo and benchmark paths |
| `zitpit-flags` | shared CLI/service flags | stable support | operational glue |

## Runtime Services

| Binary/crate | Responsibility | Maturity | Proof relevance |
| --- | --- | --- | --- |
| `zitpit-gateway` | admin API, forward proxy, governed egress, Git-path mediation entrypoint | high | central to intake and egress proof |
| `zitpit-manifest` | manifest publication and promote/block surfaces | medium | evidence/control-plane support |
| `zitpit-lab` | controlled evidence-lane orchestration | medium | evidence-engine support, not a safety oracle |
| `zitpit-watch` | feed and evidence publication | medium | operator/reviewer visibility |
| `zitpit-node-agent` | node bootstrap and interception support | medium | hardening/support path, not primary proof slice |
| `zitpit-sessiond` | brokered protected-session executor | high | central to protected-session proof families |
| `zitpit-tui` | operator UI | medium | visibility/demo surface |

## Test, Benchmark, and Demo Support

| Crate/tool | Responsibility | Maturity | Proof relevance |
| --- | --- | --- | --- |
| `zitpit-testing` | cross-service integration harness | high | validates hardened demo flows |
| `zitpit-battle-types` | shared battle-pack types | medium | proof-family support |
| `zitpit-battle-runner` | battle execution harness | medium | proof-family support |
| `zitpit-battle-cli` | CLI entrypoint for battle packs | medium | proof-family support |
| `zitpit-admin-client` | typed admin client helpers | medium | operator tooling |
| `xtask` | demo orchestration, benchmark runs, battle entrypoints, report generation | high | first public proof path and benchmark generation |

## First Places To Look

- For Git identity and benchmark correctness:
  - [`xtask/src/bench.rs`](../xtask/src/bench.rs)
  - [`crates/zitpit-core/src/gitlane.rs`](../crates/zitpit-core/src/gitlane.rs)
- For protected-session behavior:
  - [`crates/zitpit-core/src/behavior.rs`](../crates/zitpit-core/src/behavior.rs)
  - [`crates/zitpit-sessiond/src/lib.rs`](../crates/zitpit-sessiond/src/lib.rs)
- For governed egress and DLP:
  - [`crates/zitpit-core/src/dlp.rs`](../crates/zitpit-core/src/dlp.rs)
  - [`crates/zitpit-core/src/egress.rs`](../crates/zitpit-core/src/egress.rs)
  - [`crates/zitpit-gateway/src/lib.rs`](../crates/zitpit-gateway/src/lib.rs)
