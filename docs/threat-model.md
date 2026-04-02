# Threat Model

ZitPit is designed to protect developers and AI agents from supply-chain attacks that turn untrusted external code into host execution.

## Current Threats

### 1. Malicious registry publishes

Attackers may compromise a maintainer account, ship a typosquatted package, or publish a malicious release that looks legitimate by name but not by identity.

### 2. Install and build execution

Packages can execute code during install, unpack, build, or startup. That includes lifecycle scripts, build scripts, native extensions, and startup hooks.

### 3. Repo-controlled execution surfaces

Repositories may contain agent and IDE configuration that triggers code execution or credential exposure when a workspace is opened.

### 4. Agent tool bypass attempts

Agents may try to route around policy by editing config, changing tool settings, invoking direct network calls, or using unsupported paths.

### 5. Rollback, freeze, and stale-fallback risk

An older approved artifact may be known vulnerable or may no longer match current trust expectations. A fallback path can become a downgrade path if it is not policy-scoped and expiring.

### 6. Sandbox evasion

Malware may delay execution, look for virtualization artifacts, wait for secrets, or change behavior when it sees a lab.

### 7. Trust infrastructure compromise

ZitPit itself may be targeted. If the trust plane, manifest service, or signing material is compromised, protected hosts inherit that risk.

## Mitigations

- exact-digest admission
- capability-scoped verdicts
- no-direct-execution default for unknown artifacts
- quarantine before build or run
- signed evidence for every promotion or block
- explicit unsupported-path handling
- operator-visible downgrade and stale-use decisions

## Out Of Scope

ZitPit does not claim to solve:

- malicious code intentionally committed by a trusted developer
- kernel compromise of the host
- physical access to the protected environment
- every possible producer-side release failure without a publish gate

