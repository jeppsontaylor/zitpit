# Frequently Asked Questions (FAQ)

## What's the goal of ZitPit?
To keep first-seen external artifacts from silently turning into host execution in agentic workflows. ZitPit is a consumer-side software admission control layer, plus a cold-lane evidence engine and a fast local cache for approved artifacts.

---

## Does ZitPit replace Artifactory or Nexus?
No. ZitPit is primarily a consumer-side admission layer. While it provides caching on the approved path, its primary focus is policy, quarantine, evidence, and approved-path acceleration. You can use ZitPit as a proxy in front of an existing artifact repository, but package-manager-native closure is only partial or roadmap for several surfaces today.

---

## How does ZitPit support "Vibe Coding"?
AI agents move fast. If an agent requests an approved immutable artifact, ZitPit can serve it quickly from local cache. If the artifact is first-seen or policy-sensitive, ZitPit is designed to stop it from blindly executing on the protected host before review.

---

## Is ZitPit "Air-Gapped"?
No, but it creates a governed intake boundary. ZitPit is the controlled path for mediated intake, while unsupported or unmanaged paths remain outside the guarantee.

---

## Does this work on Windows and macOS?
Partially. The current public implementation is strongest on Linux and on the Git smart-HTTP intake path. Some local proxy and demo flows can be configured manually on macOS and Windows, but broader ecosystem coverage remains partial or roadmap depending on the surface.

---

## How do I get involved?
Check out our [MISSION.md](../MISSION.md) and [CONTRIBUTING.md](../CONTRIBUTING.md). We need the most brains working on this!
