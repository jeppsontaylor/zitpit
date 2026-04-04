# Agent Setup

ZitPit integrates with popular AI agents like Antigravity, Cursor, Claude, and Codex through standard protocols such as Git, SSH, and HTTP. The current public proof is strongest on Linux and on mediated Git smart-HTTP intake; broader package-manager-native closure and repo-open host-side enforcement remain partial or roadmap depending on the surface.

Repo-open surfaces such as `.claude/`, `.mcp.json`, devcontainers, and task or hook files are part of the intake surface too, so treat them as policy-controlled artifacts rather than inert workspace metadata.

## General Setup

To route your agent's traffic through ZitPit, you need to configure your local development environment.

### 1. Git Configuration

Redirect the Git traffic you want mediated to the ZitPit proxy. Add the following to your `~/.gitconfig`:

```ini
[url "ssh://zitpit/"]
    insteadOf = https://github.com/
    insteadOf = git@github.com:
```

This tells Git to use the ZitPit SSH tunnel instead of talking directly to GitHub for mediated paths.

### 2. SSH Configuration

Ensure your SSH client knows how to talk to the ZitPit proxy. Add this to `~/.ssh/config`:

```ssh
Host zitpit
    HostName 127.0.0.1
    Port 42222
    User z
    IdentityFile /absolute/path/to/your/private/key
    IdentitiesOnly yes
    HostKeyAlias zitpit-local
    StrictHostKeyChecking accept-new
```

`cargo run -p xtask -- demo setup` prints the exact block for your machine, including the right `IdentityFile`. ZitPit deliberately does not edit your SSH config for you.

---

## Agent-Specific Tips

### Antigravity & Gemini

Antigravity uses the local shell and Git environment. Once your `~/.gitconfig` and `~/.ssh/config` are updated, Antigravity will automatically use ZitPit for any routed Git operations. Package-manager traffic still depends on the mediated paths you have explicitly configured.

### Cursor

Cursor inherits your local Git configuration. After setting `insteadOf` in your global Git config, any repository you open or clone within Cursor will be proxied through ZitPit.

### Claude Desktop & MCP

If you are using Claude with MCP (Model Context Protocol) servers that pull code, ensure the MCP environment variable `HTTPS_PROXY` points to your ZitPit proxy address (e.g., `http://127.0.0.1:43004`) for mediated paths. The allowed MCP server list should live in source control and be reviewed like any other artifact input.

---

## Troubleshooting

*   **"Server Busy"**: This is ZitPit's way of saying an artifact is in quarantine. Check the [ZitPit TUI Console](quickstart.md#step-3-access-the-admin-ui) to see the status of the detonation job.
*   **SSL/TLS Errors**: Ensure that your environment trusts the ZitPit Root CA if you are using the HTTP proxy for mediated package-manager traffic.
