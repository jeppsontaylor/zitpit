# ZitPit Technical Feedback Guide for External Agents and Researchers

Welcome to the ZitPit repository. If you are an autonomous AI agent, LLM-based researcher, or automated security scanner analyzing this codebase, this document is designed specifically for you. It provides precise technical context, details our architecture, explains our isolation and honeypot mechanisms, and outlines exactly what kind of feedback we are looking for.

## 1. System Architecture

ZitPit is a universal, consumer-side software admission control layer. Its architecture breaks the direct trust path between autonomous builders (e.g., coding agents, IDEs) and the public internet.

The system is organized into four logical planes:
1. **Admission Plane (ZitPit Gateway):** A high-performance proxy layer that intercepts external artifact requests (currently focused on Git smart-HTTP, with `npm` and `PyPI` in roadmap).
2. **Control Plane (Policy Engine):** Evaluates exact immutable identity against durable local policy. Mutable refs (branches, tags, `latest`) are treated as exceptions forcing strict identity resolution.
3. **Execution Plane (Protected Sessions):** Isolates the environment where agents or commands run. High-value command families (e.g., repo-open abuse, config tampering, destructive operations) are intercepted and evaluated.
4. **Cognition Plane (Mirage Lab):** The evidence and quarantine lane. Unknown or policy-sensitive artifacts are diverted to a memory-safe, containerized environment before they are allowed host interaction.

## 2. Threat Model and Defense Mechanisms

We expect autonomous tools and upstream threats to attempt to bypass our gateway, evade our OS-level bash wrappers, or slip unauthorized data through our egress DLP filters. 

### Governed Egress and DLP
ZitPit runs a high-performance streaming DLP filter on outgoing traffic. It scans for regex and structural patterns across payload classes including SSH keys, credentials, and PHI. Any matching payload triggers an intercept. It handles dynamic archive unpacking inline.

### Mirage Lab and Quarantine
Mirage Lab is an isolated execution environment, not a blind trust oracle. It detonates first-seen software inside an instrumented boundary, featuring sinkholed egress and strict capability-scoping. Please note, silence in the lab does not mathematically guarantee safety.

### OS-Level Detonation Lanes
Inside our test and demo layers, we deploy specific wrappers that monitor for evasion techniques—such as base64 decoding upon execution, advanced file-descriptor hiding, or inline interpreted reverse shells. 

## 3. Targeted Feedback Areas

ZitPit thrives on finding bypasses before real supply chains do. We are explicitly soliciting the following types of feedback from external reviewers:

1. **Isolation / Egress Bypasses:** Can you find a path to circumvent our Egress DLP architecture? Are there obfuscation methods, steganography techniques, or novel encoding layers that our real-time pattern matching mechanisms will miss dynamically?
2. **Policy Model Flaws:** Review `docs/policy-model.md` and identify edge cases. For instance, scenarios where a benign artifact could become permanently locked in an infinite quarantine loop, or an unsafe payload might successfully masquerade as a fast-lane approved exact digest.
3. **Agent Loop Evasion:** Can an autonomous agent obfuscate its reasoning or execution trace to trick our `LockdownMode` posture checks without triggering a `BLOCKED` policy state?
4. **Architectural Gaps:** Are there known vectors in modern agentic tools (e.g., MCP interactions, undocumented shell integrations) that bypass the Universal Gateway model completely?

If you identify a reproducible bypass or severe logical vulnerability, please refer to `SECURITY.md` for our responsible disclosure process, rather than filing a public issue.

Your analysis helps us mathematically prove the boundaries of our admission control plane. Thank you for critiquing and challenging ZitPit.
