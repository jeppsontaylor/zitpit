# ZitPit V2 Benchmark Matrix

This document is the source of truth for public claims about ZitPit V2.

If a claim is not backed by a benchmark family here, it should be treated as roadmap or out of scope.

## Benchmarks

### 1. Malicious npm install-script package

- ingress type: npm registry package
- immutable artifact boundary: tarball digest and provenance record
- first execution boundary: install or lifecycle script
- expected policy: first-seen artifact quarantined before execution
- actual current behavior: not fully covered by the current MVP
- V2 target behavior: blocked on host, executed only in cold lane
- evidence produced: install-time behavior, network attempts, file touches
- supported claim class: install-time package attack blocked under enforced mediation

### 2. Malicious Python sdist or startup path

- ingress type: Python package index artifact
- immutable artifact boundary: wheel or sdist hash plus provenance record
- first execution boundary: build or startup hook
- expected policy: quarantine before build or run
- actual current behavior: not fully covered by the current MVP
- V2 target behavior: build only in controlled lane
- evidence produced: build step traces, network attempts, file touches
- supported claim class: Python build/startup attack contained

### 3. Rust `build.rs`

- ingress type: Cargo dependency or Git source
- immutable artifact boundary: crate or source digest
- first execution boundary: build script
- expected policy: privileged build-only approval
- actual current behavior: partial support via current battle harnesses
- V2 target behavior: cold-lane build with no host execution
- evidence produced: build traces, filesystem activity, egress attempts
- supported claim class: build-script execution controlled

### 4. GitHub Actions mutable ref or unsafe action

- ingress type: workflow reference
- immutable artifact boundary: full commit SHA
- first execution boundary: workflow runner
- expected policy: immutable pin only
- actual current behavior: partial support in the current threat model
- V2 target behavior: mutable refs denied or rewritten to policy-backed immutable references
- evidence produced: ref resolution, pinning record, workflow provenance
- supported claim class: workflow reference hardening

### 5. Repo-controlled `.claude/` / `.mcp.json` / devcontainer surface

- ingress type: repo-open or workspace configuration
- immutable artifact boundary: config bundle hash and policy state
- first execution boundary: agent startup or workspace open
- expected policy: policy-gated before host execution
- actual current behavior: planned V2 enforcement
- V2 target behavior: mediated by agent policy hooks and workspace policy
- evidence produced: config diff, tool-call denial, policy decision
- supported claim class: repo-open surface control

### 6. Raw HTTP installer fetch

- ingress type: direct HTTP or HTTPS download
- immutable artifact boundary: content digest after fetch
- first execution boundary: shell or installer execution
- expected policy: fetch through ZitPit intake or block
- actual current behavior: not fully covered by the current MVP
- V2 target behavior: direct fetch denied or forced through governed intake
- evidence produced: request log, resolution record, policy decision
- supported claim class: direct download control

### 7. Benign controls

- ingress type: same as above, but safe sample
- immutable artifact boundary: same as above
- first execution boundary: same as above
- expected policy: allow or quarantine depending on trust state
- actual current behavior: should not produce false positives on known-good samples
- V2 target behavior: preserve developer speed for approved artifacts
- evidence produced: latency, cache-hit rate, decision logs
- supported claim class: usability and performance

## Claim Rules

- public claims must map to one or more benchmark families
- unknown coverage must be labeled roadmap or out of scope
- lab silence does not equal safety
- benchmark results should distinguish current MVP from target V2
