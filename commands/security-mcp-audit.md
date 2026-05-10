---
description: Audit MCP (Model Context Protocol) server configurations for agent-host security risks — untrusted install vectors, over-scoped grants, hardcoded credentials, prompt-injection in server metadata, dangerous capabilities exposed to the model.
argument-hint: "[path]"
---

Audit the project's MCP configuration files (`claude_desktop_config.json`, `.mcp.json`, `*.mcp.json`, `mcp_servers.json`).

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format cli
```

The audit covers six categories of agent-host risk:

| Pattern | Severity | Why it matters |
|---|---|---|
| Untrusted install vector (`curl http://… \| sh`) | critical | Bootstraps unverified code into your agent every launch |
| Hardcoded API key in `env:` block | critical | Credential lives in plain text in the project repo |
| Prompt-injection text inside server description | critical | Servers' metadata is read by the agent — instructions there override your system prompt |
| Filesystem server granted `/`, `~`, or `$HOME` | high | The agent can read every file on disk |
| Dangerous capability name exposed (`shell`, `exec`, `eval`) | high | Lets the model execute arbitrary commands on your behalf |
| Floating tag pin (`@latest`, `@main`) | high | Publisher (or anyone who compromises them) can ship code into your agent silently |

## Why this exists

The Claude Code agent host is itself an attack surface that grew faster than tooling. Every MCP server you install runs in your local context, reads files you grant it, and supplies metadata the agent treats as system context. This command catches the canonical mistakes before they hit your machine.
