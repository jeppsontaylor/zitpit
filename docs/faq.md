# Frequently Asked Questions (FAQ)

## What's the goal of ZitPit?
To stop the supply-chain nonsense and keep AI agents and developers safe. We provide a managed artifact firewall for intake, plus a cold-lane evidence engine and a fast local cache for approved artifacts.

---

## Does ZitPit replace Artifactory or Nexus?
No. ZitPit is a **Mandatory Artifact Firewall**. While it provides caching and repository management, its primary focus is on policy, quarantine, evidence, and approved-path acceleration. You can use ZitPit as a proxy in front of an existing artifact repository.

---

## How does ZitPit support "Vibe Coding"?
AI agents move fast. If an agent requests a known-safe dependency, ZitPit serves it instantly from the local cache. If the dependency is unknown, ZitPit prevents the agent from blindly running it, but provides smart suggestions for approved alternatives.

---

## Is ZitPit "Air-Gapped"?
No, but it creates a governed intake boundary. ZitPit is the only service with outbound access for dependency intake. Every other service and developer environment is forced through the ZitPit gateway.

---

## Does this work on Windows and macOS?
Yes! While the full SSH-proxy interception is currently strongest on Linux, the Git, npm, and HTTP proxies can be configured manually on any major platform.

---

## How do I get involved?
Check out our [MISSION.md](../MISSION.md) and [CONTRIBUTING.md](../CONTRIBUTING.md). We need the most brains working on this!
