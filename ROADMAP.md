# ZitPit Full-Surface SSH Node Security Roadmap

ZitPit should stop presenting the SSH node as only a protected terminal plus artifact gateway and instead define it as a mandatory behavior firewall for humans and agents.

The current repository already proves important pieces of that story:

- Git-first intake and quarantine
- a protected SSH and tmux session
- Linux node bootstrap material
- malicious tripwires for secret scraping, metadata probing, exfiltration, browser token theft, SSH-agent touch, Git-hook writes, and persistence

See [docs/architecture.md](docs/architecture.md), [deploy/workspace/protected-session.sh](deploy/workspace/protected-session.sh), and [crates/zitpit-core/src/types.rs](crates/zitpit-core/src/types.rs) for the current implementation boundary.

This roadmap replaces the earlier phase plan with a max-containment roadmap for the SSH node itself. The enforcement point is the node wrapper, and the proof burden is benchmark-driven evidence rather than optimistic policy language.

## Roadmap Summary

The SSH node should become the policy enforcement point for:

- process execution
- sensitive file and secret access
- outbound data movement
- repo-open and agent configuration surfaces
- publish, deploy, and control-plane mutations
- persistence and anti-monitoring behavior
- recall, evidence, and benchmark-driven proof

The public claim is not "all attacks are solved." The public claim is narrower and stronger: ZitPit should block or broker the highest-value outcomes attackers want from a developer shell or AI agent runtime, including unapproved execution, secret theft, data exfiltration, release abuse, cloud or control-plane pivoting, persistence, and quiet destructive actions.

## P0: Mandatory Mediation Layer

The SSH node must become a mandatory mediation layer rather than a themed protected shell.

### Attack Modes

- direct shell bypass via `SSH_ORIGINAL_COMMAND`
- nested interpreters such as `python -c`, `node -e`, `bash -lc`, and `sh -c`
- renamed binaries, BusyBox-style multicall binaries, and alternate package managers
- raw socket clients, agent-spawned subprocesses, browser launches, MCP helper daemons, and unsupported side exits that avoid the current Git-first path

### What Happens

If process spawn and resource access are not mediated, every later control can be bypassed by changing tooling instead of changing behavior.

### Required Controls

- broker every `exec` request
- attach session identity, actor identity, repo identity, trust state, and destination context to each request
- canonicalize command intent before evaluation
- treat unsupported paths as explicit `UNSUPPORTED` or `DENY`, never silent allow
- emit signed evidence for every allow, deny, quarantine, and break-glass event

### Wrapper Technologies

- Linux-first brokered execution
- process ancestry tracking
- binary and script hashing
- interpreter expansion
- syscall-level or kernel-assisted mediation for process, file, and network policy
- immutable local policy enforcement that survives agent tool changes

### Why First

This phase closes the gap between tool-level permission prompts and actual behavior control. Anthropic's computer-use guidance recommends dedicated isolation, minimal privileges, allowlisted internet access, and human confirmation for meaningful actions because prompt injection can redirect an agent through untrusted content. Claude Code security guidance and Anthropic's sabotage-risk work point in the same direction: hard enforcement should come before trust in model intent.

References:

- [Anthropic computer use guidance](https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool)
- [Claude Code security](https://code.claude.com/docs/en/security)
- [Anthropic sabotage-risk report](https://www-cdn.anthropic.com/f21d93f21602ead5cdbecb8c8e1c765759d9e232.pdf)

## P1: Secrets, Identity, and Reusable Trust

This is the highest-value protection after mandatory mediation.

### Attack Modes

- `.env` scraping
- cloud credential reads
- SSH private key reads
- kube token reads
- Git credential reads
- browser and session token theft
- Terraform state access
- package-registry token reads
- signing-key access
- SSH-agent socket use
- metadata service queries
- CI secret scraping
- model or API key theft from repo-controlled configuration

### What Happens

Once a reusable secret leaves the boundary, the attacker no longer needs the compromised shell. They can pivot to cloud, CI, release systems, source control, or customer data from outside the protected node.

### Required Controls

- classify secret-bearing paths and environment variables
- deny-read by default for high-value secret classes
- prefer brokered short-lived credentials over ambient long-lived secrets
- trap metadata endpoints
- isolate or virtualize agent and browser credential stores
- broker SSH-agent usage
- mark all sensitive reads as policy events
- detect bulk collection and archive staging before egress

### Wrapper Technologies

- secret path taxonomy
- high-entropy and structured secret detectors
- per-session credential minting
- metadata sinkholes
- canary secrets
- credential-use attestations
- secret-aware audit logging

### Recent Incidents This Phase Targets

- the April 2, 2026 PyPI LiteLLM and Telnyx supply-chain incident
- the March 18, 2025 reviewdog and `tj-actions` chain
- CircleCI's January 4, 2023 laptop and session theft incident
- Check Point's February 25, 2026 Claude Code project-file findings

References:

- [PyPI LiteLLM and Telnyx incident report](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/)
- [reviewdog advisory](https://github.com/reviewdog/reviewdog/issues/2079)
- [CircleCI incident report](https://circleci.com/blog/jan-4-2023-incident-report/)
- [Check Point Claude Code research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

## P2: Outbound Data-Flow Control and DLP

All meaningful egress must become policy-visible.

### Attack Modes

- HTTP POST exfiltration
- webhook abuse
- `git push` to hostile remotes
- `scp`, `rsync`, and `sftp`
- object-storage uploads
- issue, PR, and comment leaks
- pastebins and gist-style leaks
- external AI API calls
- browser beacons
- DNS tunneling
- encrypted archive exfiltration
- low-and-slow trickle leaks
- internal IP or topology disclosure

### What Happens

The attacker turns local access into data theft, IP loss, customer-data disclosure, or secret reuse outside the node.

### Required Controls

- default-deny destination policy
- protocol-aware inspection
- content classification for secrets, PII or PHI, source, prompts, evals, signing material, and infra state
- archive unpack-and-scan before send
- destination classification for trusted registry, VCS, model, and internal service endpoints
- anomaly detection on destination novelty, byte volume, repetition, compression, and encryption use

### Wrapper Technologies

- transparent egress broker
- payload DLP pipeline
- destination reputation and allowlists
- sinkhole and quarantine routing
- DNS and CONNECT mediation
- browser upload mediation
- policy-aware redaction

### Recent Incidents This Phase Targets

- LiteLLM and Telnyx exfiltration behavior
- Trivy's March 2026 CI secret theft path
- browser token theft scenarios already reflected in ZitPit's battle packs
- Anthropic's own prompt-injection risk guidance for computer use

References:

- [PyPI LiteLLM and Telnyx incident report](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/)
- [Aqua Trivy update](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- [Anthropic computer use guidance](https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool)
- [HHS transmission security guidance](https://www.hhs.gov/hipaa/for-professionals/faq/2006/does-the-security-rule-allow-for-sending-electronic-phi-in-an-email/index.html)

## P3: Repo-Open, Agent Config, MCP, Hooks, and Browser State

In the agent era, repo-open is part of the attack surface.

### Attack Modes

- malicious `.claude/`
- malicious `.mcp.json`
- hostile devcontainer files
- task runners and workspace hooks
- extension install prompts
- project-level environment overrides
- hostile `ANTHROPIC_BASE_URL`
- malicious MCP servers
- prompt injection in README files, issues, docs, and web pages
- browser session and token scraping

### What Happens

The attacker turns "open this repo" or "use this tool" into code execution, key theft, silent API redirection, or exfiltration before the user understands trust has been crossed.

### Required Controls

- sterile first-open mode
- neutralize repo-controlled configuration until explicit trust elevation
- managed-only hooks and managed-only MCP server policy
- project config diffing and risk scoring
- taint untrusted content so it cannot directly trigger privileged tools
- browser session isolation
- deny reads of cookies, local storage, and session databases outside brokered browser flows

### Wrapper Technologies

- workspace-open broker
- repo-config parser and linter
- MCP attestation and allowlist enforcement
- browser token vault separation
- prompt-to-action taint tracking

### Recent Incidents This Phase Targets

- Check Point's February 25, 2026 Claude Code project-file RCE and key-exfiltration chain
- Anthropic's broader prompt-injection warnings for computer use

References:

- [Check Point Claude Code research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [Anthropic computer use guidance](https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool)
- [Anthropic MCP documentation](https://docs.anthropic.com/en/docs/claude-code/mcp)

## P4: Universal Code Ingress, Build, and Release-Path Enforcement

ZitPit should expand from Git-first intake to universal code ingress and release-path control.

### Attack Modes

- malicious npm, PyPI, Cargo, Go, OCI, and raw HTTP installs
- lifecycle hooks and install scripts
- Rust `build.rs`
- GitHub Action tag drift
- poisoned release assets
- release-vs-source mismatch
- dependency confusion
- first-seen version compromise
- compromised maintainer publishes
- compromised CI helpers
- malicious IDE extensions
- accidental source-map or source leak in release artifacts

### What Happens

Trusted developer actions such as install, build, run, or update become the execution path for malware or publish trust corruption.

### Required Controls

- universal intake broker for package managers and raw downloads
- exact-digest resolution wherever the ecosystem supports it
- first-seen quarantine and cooldown windows
- mirror and proxy enforcement
- build-without-network verdicts
- publish only through a brokered release path
- provenance verification on intake and on publish
- artifact content scanning for source maps, embedded source, secrets, internal URLs, and release drift

### Wrapper Technologies

- ecosystem adapters
- digest pinning
- provenance and attestation verification
- release artifact scanners
- package-manager policy plugins
- publish-time policy hooks

### Recent Incidents This Phase Targets

- the March 2025 reviewdog and `tj-actions` compromise chain
- the December 11, 2024 Ultralytics incident analysis
- Trivy's March 2026 compromise
- the April 2, 2026 LiteLLM and Telnyx incident
- AWS's July 23 and July 25, 2025 Amazon Q and CodeBuild chain

References:

- [GitHub secure use for Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [PyPI Ultralytics attack analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [PyPI LiteLLM and Telnyx incident report](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/)
- [AWS bulletin AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [AWS bulletin AWS-2025-016](https://aws.amazon.com/security/security-bulletins/aws-2025-016/)
- [npm scripts documentation](https://docs.npmjs.com/cli/v9/using-npm/scripts/)
- [Cargo build scripts reference](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [Go modules reference](https://go.dev/ref/mod)

## P5: Publish, Deploy, Identity, and Control-Plane Mutations

The node must treat trust-distribution and control-plane mutations as privileged actions.

### Attack Modes

- `npm publish`
- `twine upload`
- `cargo publish`
- `docker push`
- `gh release`
- `git push --tags`
- IAM changes
- GitHub App changes
- webhook creation
- deploy key creation
- branch-protection changes
- cluster role grants
- production deploys
- schema migrations
- DNS and CDN changes
- signing and notary use

### What Happens

An already-compromised node becomes a distribution point or persistence point for downstream compromise.

### Required Controls

- privileged action classes with stronger policy than local reads and edits
- release destinations and registries bound to approved identities
- dual control or step-up approval for externally visible trust mutations
- signing isolated behind brokered services
- break-glass with reason capture and expiry
- policy on who or what may publish from which session or repo state

### Wrapper Technologies

- action-class policy engine
- approval workflow service
- brokered signing and notarization
- destination binding
- immutable audit trail
- revocation and recall linkage

### Why This Matters

GitHub recommends full-SHA pinning for Actions and least-privilege use of `GITHUB_TOKEN`. GitHub OIDC replaces long-lived cloud secrets with short-lived workload identity, and GitHub artifact attestations only help if consumers verify them. This phase brings those ideas into ZitPit's node policy model.

References:

- [GitHub secure use guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub OIDC documentation](https://docs.github.com/en/enterprise-cloud%40latest/actions/concepts/security/openid-connect)
- [GitHub artifact attestations](https://docs.github.com/en/enterprise-cloud%40latest/actions/concepts/security/artifact-attestations)
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)

## P6: Persistence, Lateral Movement, Destructive Actions, and Anti-Monitoring

The goal is to make these behaviors impossible to do quietly.

### Attack Modes

- shell RC edits
- `authorized_keys` changes
- cron, systemd, launchd, and scheduled-task writes
- Git hooks
- Docker socket access
- cloud metadata probing
- Kubernetes token enumeration
- port scans
- internal recon
- tunnels and reverse shells
- disabling logs or scanners
- deleting evidence
- force-pushes
- recursive deletion
- backup wipes

### What Happens

The attacker survives session end, pivots into infrastructure, or destroys data while the node still looks normally used.

### Required Controls

- persistence path deny rules
- internal address-space and metadata policy
- container and runtime socket controls
- port-scan and recon rate controls
- action classes for destructive commands
- immutable local logging
- watchdog coverage for wrapper health
- self-protection against policy tampering and service disablement

### Wrapper Technologies

- persistence surface inventory
- recon heuristics
- container and runtime policy
- tamper-evident local logs
- watchdog and health attestation
- sealed policy bundles

### Continuity With Current ZitPit Proofs

This phase should extend the tripwire system already present in the repo rather than invent a disconnected detection story. Current tripwires already include persistence, port scan, container socket touch, SSH-agent touch, browser token scrape, exfil attempts, workspace config load, and workspace secret scrape.

## P7: Benchmarked Proof, Not Aspirational Claims

Every new enforcement family should ship with a benchmark and an evidence standard.

### Attack Modes To Replay Publicly

- Claude Code repo-config abuse
- browser token exfiltration
- GitHub Actions secret scraping
- self-hosted runner persistence
- `pull_request_target` exfiltration
- first-seen package malware
- release-asset mismatch
- tag drift
- submodule rewrite
- secret staging
- metadata theft
- publish-path abuse

### What Happens If Omitted

The roadmap becomes aspirational and hard to audit.

### Required Proof Standard

- at least one malicious pack and one benign control per family
- pre-execution interception proof
- correct policy decision proof
- evidence completeness proof
- low-noise benign behavior proof
- explicit unsupported-gap reporting
- latency and operator-visibility reporting

### Wrapper and Lab Work

- richer tripwires
- session replay bundles
- allow and deny reasoning records
- recall feeds
- benchmark harness expansion across developer workstation, CI runner, browser, and cloud-operator personas

## Public Interface and Policy Changes

The policy model should expand from artifact verdicts only to behavior verdicts.

### Action Families

- `PROCESS_EXEC`
- `SECRET_READ`
- `BROWSER_STATE_READ`
- `NET_CONNECT`
- `NET_SEND`
- `REPO_OPEN_CONFIG`
- `MCP_SERVER_START`
- `PUBLISH`
- `DEPLOY`
- `IAM_MUTATE`
- `PERSISTENCE_WRITE`
- `DESTRUCTIVE_OP`
- `BREAK_GLASS`

### Evidence Model Additions

- actor type such as `human`, `agent`, or `automation`
- session trust state
- repo trust state
- destination trust zone
- secret or data class
- whether the operation crossed a trust boundary

### Policy Outcomes

- `ALLOW`
- `PROMPT`
- `STEP_UP`
- `QUARANTINE`
- `DENY`
- `UNSUPPORTED`
- `BROKER_ONLY`

### Default Data Classes

- credentials
- customer data
- regulated data
- source and IP
- infrastructure state
- release authority
- model and agent internals

## Test Plan

- build one benchmark family per top-priority incident class, with at least one malicious case and one benign control
- require each family to prove pre-execution interception, correct policy decision, evidence completeness, and low-noise benign behavior
- run the matrix across the four personas already modeled in the repo: developer workstation, CI runner, container build node, and cloud operator
- add explicit tests for bypass forms such as interpreter one-liners, shell built-ins, renamed binaries, indirect tool launches, archive staging, encrypted exfiltration, DNS or CONNECT egress, and browser-mediated uploads
- publish residual-risk tables showing what remains out of scope after each phase

## Assumptions and Defaults

- this roadmap replaces the earlier roadmap rather than appending a security appendix
- maximum containment takes priority over lowest-friction developer ergonomics
- wording remains Linux-first for enforcement while keeping the broader architecture progressive and benchmark-bound
- network-routing implementation details remain flexible, but all meaningful egress must become policy-visible for the public claim to hold
- ZitPit should not promise that every attack is solved; it should promise that the highest-value behaviors are blocked, brokered, or made explicit
