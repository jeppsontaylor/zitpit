# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Durable artifact policy events, capability verdict vocabulary, and persisted break-glass override records.
- Reviewer-facing docs including the claim matrix, evidence index, deployment hardening guide, glossary, contributor map, dependency policy, release verification guide, and launch checklist.
- Frozen benchmark snapshots for launch review and paper citations.
- Repo contract scripts for claim-matrix sync, publication sync, markdown links, and hygiene checks.
- A pinned GitHub release workflow that builds a Linux release bundle, SBOM, checksums, and artifact attestation.
- A checked-in `cargo-deny` policy for advisory, license, and source governance.

### Changed
- Git benchmark seeding now mirrors the actual upstream target and validates identity before timings are accepted.
- Approved Git serving is exact-identity scoped instead of source-scoped.
- Protected sessions now execute structured `argv` commands directly instead of allowing protected-mode `zsh -lc` execution.
- Admin and node-agent planes now default to hardened auth and loopback binding.
- Captured request storage now redacts sensitive headers and applies retention limits.
- Public docs, paper text, and benchmark language now share one claim ladder and one canonical project description.
- Release docs now point to a real artifact verification path instead of the demo hash helper.

### Fixed
- Selector identity consistency across in-memory and persisted artifact records.
- Browse-lane policy gating and destination trust-zone classification drift.
- DLP policy visibility for truncated and partial inspection outcomes.
- Root and paper public-surface cleanup issues that made the repo look like a working directory instead of a launch candidate.
