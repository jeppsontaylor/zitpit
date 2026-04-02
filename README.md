# ZitPit

<p align="center">
  <img src="assets/mascot.png" alt="ZitPit Lighthouse Crab Mascot" width="400" />
</p>

ZitPit is a **Mandatory Artifact Firewall and Governed Execution Plane** for AI-assisted development.

In the age of autonomous agents, "first-seen" external code must transition from an *execution event* into a *policy event*. ZitPit prevents unapproved third-party artifacts from executing on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine.

---

## 🛡️ The Paradigm Shift

When AI coding agents (Antigravity, Cursor, Claude, Codex) operate at speed, an unmediated `npm install` or `pip install` rolls the dice with your infrastructure. ZitPit decouples your agentic workflows from direct open-internet execution.

**The safe path is the fast path:** We serve approved immutable artifacts from a local cache while forcing unknown artifacts through a governed intake and detonation pipeline.

---

## 🏗️ Architecture: The 4-Stage Control Plane

ZitPit protects your supply chain across four absolute boundaries:

### 1. Acquire (The Universal Artifact Gateway)
All external dependency traffic (npm, PyPI, Cargo, Go, OCI, Git) resolves through `zitpit-gateway`. Mutable references (e.g., tags, `latest`) are treated as policy exceptions. Everything is governed strictly by exact immutable digests.

### 2. Build (The Cold Lane)
Install-time and build-time scripts (e.g., `postinstall`, `build.rs`) *never* run dynamically on the protected host. They are quarantined and executed in the **Mirage Lab** - our evidence engine - until explicit policy allows them. 

### 3. Execute (The Agent Capsule)
Agent tool use and execution privileges are policy-controlled (e.g., via `PreToolUse` hooks). Isolation starvation is standard: agents run in an ephemeral workspace isolated from ambient secrets.

### 4. Publish (The Release Firewall)
An optional publisher-side release gate inspects artifacts before shipment, blocking accidental internal packaging leaks (e.g., source maps, keys, tokens).

---

## 🚀 Key Features

*   **Standards-Backed Trust Plane**: Designed to consume TUF (The Update Framework), Sigstore, in-toto, and SLSA provenance for true cryptographic verification rather than simple file hashes.
*   **Capability-Scoped Verdicts**: Approvals are granular (`FETCH_ONLY`, `BUILD_NO_NETWORK`, `RUN_DEV`, `BLOCKED`).
*   **Anti-Evasion Evidentiary Engine**: The Mirage Lab runs unknown code across diverse personas (Linux CI, macOS dev) to generate auditable behavior graphs, emitting signed evidence packs for every decision.
*   **Agent-Native Interception**: Governs `.claude/`, `.mcp.json`, and tool execution bounds natively.

---

## 🏁 Quickstart

> [!CAUTION]
> ZitPit is actively migrating to the V2 architecture. The quickstart below demonstrates the V1 baseline Git/SSH proxy functionality. Let the benchmark matrix guide public claims and the V2 migration path.

### 1. Verification Bootstrap
Always verify ZitPit before running. This script compares the local hash against Git and our independent mirror:

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
