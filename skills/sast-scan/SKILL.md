---
name: sast-scan
description: Use when the user asks Claude to find SQL injection, XSS, command injection, IDOR, SSRF, path traversal, prototype pollution, ReDoS, JWT issues, mass assignment, weak crypto, or other static-analysis-detectable vulnerabilities in their code. Also use when the user asks "is this code safe?" or "can you audit this file?". Skip if the user is only asking about CVEs in dependencies (use sca-scan) or leaked credentials (use secret-scan).
---

# SAST scanning with agentic-security

The `agentic-security` plugin ships an AST + regex SAST engine covering 50+ vulnerability sinks across JS/TS, Python, PHP, Ruby, Java, Go, and Laravel. Each finding includes CWE, STRIDE category, severity, file:line, and a canonical fix template.

## When to invoke

- User asks to find / audit / review code for security issues
- User pastes a code snippet and asks "what's wrong here from a security perspective?"
- User just generated new code and you want to check it before declaring done
- A `PostToolUse` hook surfaces a new finding and the user wants more detail

## How to invoke

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <path> --only sast --format cli
```

For a single file's worth of context:
```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <dir-containing-file> --only sast --format json | jq '.findings[] | select(.file=="<file>")'
```

## Key behaviors

- AST-based taint tracking for JS/TS (cross-file BFS up to 3 hops)
- Regex fallback for non-JS languages
- Sanitizer learning: project-local helpers like `escapeHtml()` are auto-detected and downgrade matching findings
- Reachability annotation: findings only escalate if the path is actually called from a route handler
- STRIDE coverage: every finding is tagged Spoofing/Tampering/Repudiation/Info-Disclosure/DoS/Elevation
