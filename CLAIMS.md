# ZitPit Claims Sheet

## Canonical Description

ZitPit is a **consumer-side software admission control layer for agentic development**.

Core thesis:

**First-seen external artifacts must earn execution rights under durable policy before they affect a protected host.**

ZitPit still uses the product language of a mandatory artifact firewall and governed execution plane, but that thesis is the canonical project description across the paper, README, and policy docs.

## Claim Ladder

Use the following status ladder consistently:

- `Implemented`: backed by public benchmark families, demos, or battle-pack evidence
- `Partial`: some public proof exists, but closure is incomplete
- `Planned`: explicit roadmap target, not a current public proof claim
- `Unsupported`: outside the current mediation boundary; do not imply safety

If a claim is not backed by [`BENCHMARKS.md`](BENCHMARKS.md), treat it as `Planned` or `Unsupported`.

## Approved Claims

- ZitPit turns first-seen external artifacts from execution events into policy events.
- In enforced environments and for mediated paths, unknown third-party artifacts do not execute on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine when required.
- ZitPit makes the safe path the fast path by serving approved immutable intake locally while forcing new artifacts through governed intake.
- ZitPit is designed to unify artifact admission, repo-open state, capability-scoped execution, and durable policy records at the consumer execution boundary for agentic workflows.
- The current public repository proves important slices of that boundary today: Git smart-HTTP intake latency, brokered protected-session enforcement families, and governed outbound DLP.
- With a publish gate enabled, ZitPit can also help prevent classes of accidental release leaks and workflow-drift publishes.

## Approved Implication Language

The following is acceptable as implication or future-facing language, not as present-tense proof:

- This pattern could become a standard execution boundary for agentic environments.
- Repo-open state is increasingly part of the software supply chain.
- Capability-scoped admission could become a more realistic trust model than binary allow/block decisions.
- Open governance matters because admission systems can centralize power if their evidence and policy memory are opaque.

## Forbidden Claims

- ZitPit solves agent safety in general.
- ZitPit ends supply-chain attacks forever.
- ZitPit provides full ecosystem closure today.
- ZitPit would have prevented every Anthropic-related or AI-tooling incident.
- Hash equality means software is safe.
- Mirage Lab silence means software is safe.
- Protected-session battle packs imply universal host-side enforcement.
- Unsupported or unmanaged paths are secure by implication.
- Git interception alone solves the agent-era supply chain.

## Incident Wording

- Safe: "Under enforced ZitPit protection for mediated paths, exact-digest approvals, default-deny host execution for first-seen artifacts, and quarantine when required, a short-lived install-time compromise would likely have been blocked from executing on protected developer and CI endpoints."
- Unsafe: "ZitPit would have prevented the entire class of AI tooling incidents."
