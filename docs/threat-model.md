# Threat Model

ZitPit is designed to protect developers and AI agents from supply-chain attacks that turn untrusted external software into protected-host execution too early.

## Core Threats

### 1. Mandatory-mediation bypass

If an artifact reaches the host through an unmanaged path, the admission guarantee weakens.

Examples:

- browser downloads
- vendored tarballs
- local copies
- alternate registries or direct URLs
- Git submodules, LFS hydration, or delayed follow-on fetches
- direct unmanaged egress

### 2. Install-time and build-time execution

Packages and build systems can execute code during install, build, or startup.

Examples:

- npm lifecycle scripts and Git dependencies
- Python sdists and dynamic build backends
- Rust `build.rs` and related build-time execution
- raw `curl | bash` style installers

### 3. Repo-open and workspace execution surfaces

Opening a repository can influence execution before review.

Examples:

- `.mcp.json`
- hooks
- memory files
- devcontainer lifecycle and Feature install paths
- workspace tasks and similar project-level automation

### 4. Workflow and CI trust drift

Mutable references, reusable workflow chains, cache poisoning, and unsafe action composition can turn trusted automation into an intake path.

### 5. Secret theft and reusable trust abuse

High-value reads and outward movement matter because reusable secrets outlive the original compromise.

Examples:

- `.env` and cloud-credential reads
- SSH-agent touch
- metadata endpoint access
- browser or session-token access
- registry or signing-key reads

### 6. Cache and trust-plane compromise

The control plane becomes part of the trusted computing base.

Examples:

- cache poisoning
- stale trust roots
- policy-store compromise
- signing-key compromise
- parser or archive-handling weaknesses

### 7. Operator and availability failure

Approval bottlenecks, break-glass overuse, or brittle availability can create bypass pressure and undermine the security model.

## Current Mitigations

- exact immutable identity before execution rights
- capability-scoped verdicts
- no direct protected-host execution for first-seen artifacts by default on mediated paths
- quarantine before build or run when required
- governed egress for selected outbound flows
- signed or durable evidence for promotion, block, and review events
- explicit unsupported-path handling

## Out of Scope

ZitPit does not claim to solve:

- malicious code intentionally committed by a trusted developer or maintainer
- kernel compromise of the host
- physical access to the protected environment
- every producer-side release failure without a publish gate
- safety for unsupported or unmanaged paths by implication
- general agent safety independent of software intake and governed execution
