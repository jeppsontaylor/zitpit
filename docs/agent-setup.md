# Agent Setup

ZitPit is designed to be **platform-agnostic**, making it compatible with popular AI agents like Antigravity, Cursor, Claude, and Codex. Since these agents use standard protocols (Git, SSH, HTTP), ZitPit can intercept and protect their dependencies without requiring custom integration.

## General Setup

To route your agent's traffic through ZitPit, you need to configure your local development environment.

### 1. Git Configuration

Redirect all Git traffic to the ZitPit proxy. Add the following to your `~/.gitconfig`:

```ini
[url "ssh://zitpit/"]
    insteadOf = https://github.com/
    insteadOf = git@github.com:
```

This tells Git to use the ZitPit SSH tunnel instead of talking directly to GitHub.

### 2. SSH Configuration

Ensure your SSH client knows how to talk to the ZitPit proxy. Add this to `~/.ssh/config`:

```ssh
Host zitpit
    HostName 127.0.0.1
    Port 42222
    User zitpit
    IdentityFile /absolute/path/to/your/private/key
    IdentitiesOnly yes
    HostKeyAlias zitpit-local
    StrictHostKeyChecking accept-new
```

`cargo run -p xtask -- demo setup` prints the exact block for your machine, including the right `IdentityFile`. ZitPit deliberately does not edit your SSH config for you.

---

## Agent-Specific Tips

### Antigravity & Gemini

Antigravity uses the local shell and Git environment. Once your `~/.gitconfig` and `~/.ssh/config` are updated, Antigravity will automatically use ZitPit for any `git clone` or `npx` (if HTTP proxy is set) commands.

### Cursor

Cursor inherits your local Git configuration. After setting `insteadOf` in your global Git config, any repository you open or clone within Cursor will be proxied through ZitPit.

### Claude Desktop & MCP

If you are using Claude with MCP (Model Context Protocol) servers that pull code, ensure the MCP environment variable `HTTPS_PROXY` points to your ZitPit proxy address (e.g., `http://127.0.0.1:43004`).

---

## Troubleshooting

*   **"Server Busy"**: This is ZitPit's way of saying an artifact is in quarantine. Check the [ZitPit TUI Console](quickstart.md#step-3-access-the-admin-ui) to see the status of the detonation job.
*   **SSL/TLS Errors**: Ensure that your environment trusts the ZitPit Root CA if you are using the HTTP proxy for package managers like `npm` or `pip`.
