# Security Policy

agentic-security is a security-scanning tool, so vulnerabilities in the tool
itself get the same seriousness as the ones it finds in your code.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — not as a public GitHub
issue — to **ross@clearcapabilities.com**. Include:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal repro repo/snippet is ideal).
- The version (`scanner/package.json` `version`, or `agentic-security --version`)
  and how you're running it (Claude Code plugin vs. standalone CLI/npx).

We aim to acknowledge reports within 3 business days and to ship a fix or
mitigation before any public disclosure. Please give us reasonable time to
respond before disclosing publicly.

## Supported versions

Only the latest published version is supported. There is no LTS branch — always
update before filing a report (`/plugin marketplace update clearcapabilities`
or `npm install -g @clear-capabilities/agentic-security-scanner@latest`).

## Scope

In scope: the scanner engine (`scanner/`), the MCP server, Claude Code hooks
(`hooks/`), and the slash commands/agents shipped in this repository.

Out of scope: vulnerabilities in third-party dependencies flagged *by* the
scanner in a target project — that's the product working as intended, not a
security issue in agentic-security itself. Report those upstream to the
dependency's maintainers.
