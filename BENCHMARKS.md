# ZitPit Benchmark Matrix

This document is the source of truth for public proof claims about ZitPit.

If a claim is not backed by a benchmark family here, it should be treated as roadmap or unsupported rather than implied proof.

## Status Ladder

- `Implemented`: public benchmark family or demo proof exists and supports present-tense claims
- `Partial`: some public proof exists, but the execution graph or ecosystem closure is incomplete
- `Planned`: explicit target for the next revision cycle; not a current public proof
- `Unsupported`: outside the current mediated boundary; do not imply safety

## Claim Ladder

Each benchmark family should distinguish:

- `implemented proof`
- `partial evidence`
- `roadmap target`
- `forbidden overclaim`

## Benchmark Families

### 1. Git smart-HTTP intake

- claim class: `git_smart_http_intake`
- ingress type: Git smart-HTTP refs and initial intake requests
- immutable artifact boundary: resolved commit identity for mediated Git intake
- first execution boundary: checkout or follow-on Git activity after initial mediated resolution
- current public evidence: repeated latency runs across five public repositories in [`docs/benchmarks/latest.md`](docs/benchmarks/latest.md)
- status: `Implemented`
- supported claim: approved immutable Git intake can stay faster than unmanaged public fetch
- roadmap target: extend proof to submodules, LFS, and follow-on fetch closure
- forbidden overclaim: "Git-path mediation proves complete Git execution closure"

### 2. Brokered shell blocked-command families

- claim class: `brokered_shell_enforcement`
- ingress type: protected SSH noninteractive command or brokered shell action
- immutable artifact boundary: session broker policy revision plus command classification
- first execution boundary: session broker before shell execution
- current public evidence: Docker demo through `zitpit-sessiond` plus battle packs
- status: `Implemented`
- supported claim: selected high-value command families are denied or marked unsupported before execution in protected sessions
- roadmap target: move the same behavior model to host-side mandatory enforcement
- forbidden overclaim: "Battle packs prove universal host-side application control"

### 3. Outbound DLP and regulated-data blocking

- claim class: `governed_egress_dlp`
- ingress type: governed HTTP POST/PUT/PATCH uploads and governed `git push`-style sends
- immutable artifact boundary: streaming DLP verdict plus egress policy revision
- first execution boundary: gateway before upstream routing
- current public evidence: gateway egress decisions, battle packs, and smoke assertions
- status: `Implemented`
- supported claim: governed egress can block selected sensitive outbound data before transmission
- roadmap target: extend policy surface to raw sockets and unsupervised kernel-visible egress through host enforcement
- forbidden overclaim: "Current egress proof covers all outbound data paths"

### 4. Rust build-time execution

- claim class: `cargo_build_time_execution`
- ingress type: Cargo dependency or Git source
- immutable artifact boundary: crate or source digest
- first execution boundary: build script or other build-time execution surface
- current public evidence: partial support via current battle harnesses
- status: `Partial`
- supported claim: build-time execution can be modeled as a distinct capability boundary
- roadmap target: cold-lane build with no host execution and stronger Cargo-native mediation
- forbidden overclaim: "Rust dependency execution is fully mediated today"

### 5. GitHub Actions immutable-ref and unsafe-action handling

- claim class: `github_actions_reference_hardening`
- ingress type: workflow reference
- immutable artifact boundary: full commit SHA
- first execution boundary: workflow runner
- current public evidence: partial support in the current threat model and scenarios
- status: `Partial`
- supported claim: workflow references should resolve to immutable identities before execution
- roadmap target: mutable refs denied or rewritten to policy-backed immutable references with broader workflow-graph closure
- forbidden overclaim: "Current proof covers all GitHub Actions execution paths and reusable workflow chains"

### 6. Malicious npm install-script package

- claim class: `npm_install_time_mediation`
- ingress type: npm registry package, tarball, or Git dependency path
- immutable artifact boundary: tarball digest, resolved Git identity, and provenance record
- first execution boundary: install or lifecycle script
- current public evidence: benchmark matrix and threat-model target only
- status: `Planned`
- supported claim: none yet beyond architectural intent
- roadmap target: first-seen artifact quarantined before host execution
- forbidden overclaim: "npm lifecycle attacks are publicly proven blocked today"

### 7. Malicious Python sdist, direct URL, or startup path

- claim class: `python_build_startup_mediation`
- ingress type: Python package index artifact, VCS URL, or direct URL
- immutable artifact boundary: wheel or sdist hash plus provenance record
- first execution boundary: build backend, startup hook, or install-time code execution
- current public evidence: benchmark matrix and threat-model target only
- status: `Planned`
- supported claim: none yet beyond architectural intent
- roadmap target: quarantine before build or run
- forbidden overclaim: "Python build and startup attacks are publicly proven contained today"

### 8. Repo-open execution surfaces

- claim class: `repo_open_execution_surface`
- ingress type: repo-open or workspace configuration
- immutable artifact boundary: config bundle hash and policy state
- first execution boundary: workspace open, host lifecycle hook, or agent startup
- current public evidence: threat model, policy model, and roadmap target only
- status: `Planned`
- supported claim: repo-open state is in scope and should be policy-gated before host execution
- roadmap target: mediated enforcement for devcontainer host lifecycle, Feature install, and agent-config-triggered behavior
- forbidden overclaim: "Repo-open host execution is fully controlled today"

### 9. Raw HTTP installer fetch

- claim class: `raw_http_installer_control`
- ingress type: direct HTTP or HTTPS download
- immutable artifact boundary: content digest after fetch
- first execution boundary: shell or installer execution
- current public evidence: benchmark matrix and roadmap target only
- status: `Planned`
- supported claim: none yet beyond architectural intent
- roadmap target: direct fetch denied or forced through governed intake
- forbidden overclaim: "Raw installer fetches are fully mediated today"

### 10. Git follow-on intake

- claim class: `git_follow_on_intake`
- ingress type: Git submodules, LFS hydration, and delayed follow-on fetch paths
- immutable artifact boundary: superproject commit plus submodule commits, LFS object digests, and follow-on object identities
- first execution boundary: checkout, hydration, or delayed fetch after initial intake
- current public evidence: none yet
- status: `Planned`
- supported claim: none yet
- roadmap target: close the most obvious Git-path reviewer objections around submodule, LFS, and follow-on fetch closure
- forbidden overclaim: "Initial smart-HTTP proof already covers these paths"

### 11. Benign controls

- claim class: `benign_controls`
- ingress type: same as above, but safe sample
- immutable artifact boundary: same as above
- first execution boundary: same as above
- current public evidence: battle packs and control families
- status: `Implemented`
- supported claim: approved or known-good samples should not trigger the same denial path as malicious proof cases
- roadmap target: publish broader false-positive and latency data across more ecosystems
- forbidden overclaim: "Current benign controls prove low-friction production-scale usability everywhere"

## Rules

- Public wording must map to one or more benchmark families above.
- Unsupported coverage must be labeled `Planned` or `Unsupported`, never implied.
- Lab silence does not equal safety.
- Protected-session proof should be described as protected-session proof unless host-side mandatory enforcement is specifically demonstrated.
- Benchmark results must distinguish current implementation from roadmap targets.
