# ZitPit

<p align="center">
  <img src="assets/mascot.png" alt="ZitPit Lighthouse Crab Mascot" width="400" />
</p>

ZitPit is a **Mandatory Artifact Firewall and Governed Execution Plane** for AI-assisted development.

In the age of autonomous agents, "first-seen" external code must transition from an *execution event* into a *policy event*. ZitPit prevents unapproved third-party artifacts from executing on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine.

Current public evidence shows why the safe path needs to be fast: the five-repo benchmark snapshot in [`docs/benchmarks/latest.md`](docs/benchmarks/latest.md) shows `web` at 413-821 ms, approved cache at 30-34 ms, and hot cache at 14-16 ms, with `N=1` sample per repo.

The draft paper lives in [`papers/publication-draft.md`](papers/publication-draft.md), and the public claim boundaries live in [`CLAIMS.md`](CLAIMS.md) and [`BENCHMARKS.md`](BENCHMARKS.md).

---

## 🛡️ The Paradigm Shift

When AI coding agents (Antigravity, Cursor, Claude, Codex) operate at speed, an unmediated `npm install` or `pip install` rolls the dice with your infrastructure. ZitPit decouples your agentic workflows from direct open-internet execution.

**The safe path is the fast path:** We serve approved immutable artifacts from a local cache while forcing unknown artifacts through a governed intake and detonation pipeline.

---

## 🏗️ Architecture: The 4-Stage Control Plane

ZitPit protects your supply chain across four absolute boundaries:

### 1. Acquire (The Universal Artifact Gateway)
All external dependency traffic ZitPit mediates (npm, PyPI, Cargo, Go, OCI, Git) resolves through `zitpit-gateway`. Mutable references (e.g., tags, `latest`) are treated as policy exceptions. Everything is governed strictly by exact immutable digests.

### 2. Build (The Cold Lane)
Install-time and build-time scripts (e.g., `postinstall`, `build.rs`) *never* run dynamically on the protected host. They are quarantined and executed in the **Mirage Lab** - our evidence engine - until explicit policy allows them. 

### 3. Execute (The Agent Capsule)
Agent tool use and execution privileges are policy-controlled (e.g., via `PreToolUse` hooks). Isolation starvation is standard: agents run in an ephemeral workspace isolated from ambient secrets.

### 4. Publish (The Release Firewall)
An optional publisher-side release gate inspects artifacts before shipment, blocking accidental internal packaging leaks (e.g., source maps, keys, tokens).

The current repo proves the Git intake path, the local cache, the hot cache, and the benchmark harness; the broader artifact-native lanes in this section are the V2 target.

---

## 📸 Proof Gallery

### Agent Setup

<p align="center">
  <img src="assets/cursor_zitt.png" alt="Cursor setup screenshot" width="380" />
</p>

This screenshot shows the kind of protected workspace setup ZitPit is built to guard. The agent-facing bootstrap, shell config, and repo-open surface all matter because they determine whether first-seen code can reach execution on the host.

### Operator Console

<p align="center">
  <img src="assets/zitt_TUI.png" alt="ZitPit TUI screenshot" width="760" />
</p>

The TUI is the operator's live view into the intake perimeter. It is where approved artifacts, pending quarantine jobs, and policy decisions become visible instead of hiding inside logs.

### Benchmark Snapshot

<p align="center">
  <img src="assets/figures/speedup.svg" alt="Current five-repo benchmark snapshot" width="760" />
</p>

The benchmark chart shows the claim we are making publicly: approved cache hits and hot-cache hits are dramatically faster than direct upstream fetches, so the safe path is not the slow path.

### Control Plane

<p align="center">
  <img src="assets/figures/network.svg" alt="ZitPit control-plane diagram" width="760" />
</p>

The network diagram shows the control flow at a glance: agent and CI requests enter the gateway, approved artifacts take the hot path, first-seen artifacts fall into the cold lane, and publish or revocation signals flow back into policy.

The current public benchmark matrix is the claim boundary. See [`BENCHMARKS.md`](BENCHMARKS.md) for the supported surfaces and [`CLAIMS.md`](CLAIMS.md) for the exact public wording.

---

## 🚀 Key Features

*   **Standards-Backed Trust Plane**: Designed to consume TUF (The Update Framework), Sigstore, in-toto, and SLSA provenance for true cryptographic verification rather than simple file hashes.
*   **Capability-Scoped Verdicts**: Approvals are granular (`FETCH_ONLY`, `BUILD_NO_NETWORK`, `RUN_DEV`, `BLOCKED`).
*   **Anti-Evasion Evidentiary Engine**: The Mirage Lab runs unknown code across diverse personas (Linux CI, macOS dev) to generate auditable behavior graphs, emitting signed evidence packs for every decision.
*   **Agent-Native Interception**: Governs `.claude/`, `.mcp.json`, and tool execution bounds natively.

---

## 🏁 Quickstart

> [!CAUTION]
> ZitPit is actively migrating to the V2 architecture. The quickstart below demonstrates the current MVP Git intake path. Let [`BENCHMARKS.md`](BENCHMARKS.md) and [`CLAIMS.md`](CLAIMS.md) guide public claims and the V2 migration path.

### 1. Verification Bootstrap
Always verify ZitPit before running. This is a bootstrap integrity check, not the full provenance model:

```bash
sh scripts/verify_hash.sh
```

### 2. Demo Orchestration (Docker)
Run the guided demo setup:

```bash
cargo run -p xtask -- demo setup
```

Then paste the printed SSH block into `~/.ssh/config` and open the protected shell:

```bash
ssh zitpit
```

Access the TUI Admin Console:

```bash
cargo run -p zitpit-tui
```

### 3. Battle-Test Suites
Run the Rust-orchestrated exploit-pack suites:

```bash
cargo run -p xtask -- battle lint
cargo run -p xtask -- battle fast
cargo run -p xtask -- battle go
cargo run -p xtask -- battle cargo
cargo run -p xtask -- battle shell
cargo run -p xtask -- battle workspace
cargo run -p xtask -- battle public-core
```

*(Refer to [BENCHMARKS.md](BENCHMARKS.md) for the V2 public evaluation matrix and claim boundaries.)*

---

## 🗺️ Roadmap & Community

ZitPit is built to be the **most open** and **collaborative** project in the security space. See our [ROADMAP.md](ROADMAP.md) for the V2 timeline, [BENCHMARKS.md](BENCHMARKS.md) for the claim boundaries, and [CLAIMS.md](CLAIMS.md) for the public wording we are standing behind.

Read our [MISSION.md](MISSION.md) to understand the ethos, and see [CONTRIBUTING.md](CONTRIBUTING.md) to help out.

---

## 📄 License

ZitPit is dual-licensed under **MIT** and **Apache 2.0**.
