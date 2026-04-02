# ZitPit Claims Sheet

## One-Line Description

ZitPit is a mandatory artifact firewall and governed execution plane for AI-assisted development.

## 50-Word Description

ZitPit forces external code through exact-digest admission, provenance-aware policy, and quarantine before it can execute on protected developer or CI hosts. Approved artifacts stay fast through local caching; first-seen artifacts, mutable refs, and repo-controlled execution surfaces are treated as policy events rather than ambient trust.

## Approved Claims

- ZitPit turns first-seen external code from an execution event into a policy event.
- In enforced environments, unknown third-party artifacts do not execute on protected developer machines or CI runners before digest resolution, policy evaluation, and quarantine when required.
- ZitPit makes the safe path the fast path by serving approved artifacts locally while forcing new artifacts through governed intake.
- ZitPit is designed to block or contain short-lived registry compromises, malicious install scripts, and repo-controlled execution surfaces before they reach the host.
- With a publish gate enabled, ZitPit can also prevent whole classes of accidental release leaks and workflow-drift publishes.

## Forbidden Claims

- ZitPit ends supply-chain attacks forever.
- ZitPit prevents all Anthropic-related incidents.
- Hash equality means software is safe.
- Mirage Lab silence means safety.
- Keeping the honeypot private is the security model.
- Git interception alone solves the agent-era supply chain.

## Incident Wording

- Safe: "Under enforced ZitPit protection with exact-digest approvals, no direct egress bypass, default-deny install and build execution on hosts, and quarantine for first-seen artifacts, the March 31, 2026 Axios install-time compromise would likely have been blocked from executing on protected developer and CI endpoints."
- Unsafe: "ZitPit would have prevented the Anthropic attack."

