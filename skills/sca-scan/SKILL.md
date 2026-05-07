---
name: sca-scan
description: Use when the user references CVEs, dependency vulnerabilities, supply-chain risk, or asks "is this library safe?", "what CVEs are in our deps?", "can we update this lockfile?". Also use when reviewing a `package.json` / `requirements.txt` / `go.mod` change. Skip when the user is asking about secret leaks (use secret-scan) or code-level vulns (use sast-scan).
---

# SCA scanning with agentic-security

The plugin parses 20 manifest formats and queries `api.osv.dev` for known vulnerabilities. Findings are filtered by **vulnerable-call-depth** — a CVE only escalates if the project actually imports/calls the vulnerable export.

## When to invoke

- User mentions a specific CVE / GHSA / advisory
- User asks whether a package version is safe
- User adds, removes, or upgrades a dependency
- A `package-lock.json` / `yarn.lock` / `Pipfile.lock` shows up in a diff
- User asks for a "supply chain audit"

## How to invoke

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <path> --only sca --format cli
```

For a JSON list of vulnerable components:
```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <path> --only sca --format json | jq '.findings[] | select(.kind=="sca")'
```

## What the engine does

- Parses: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, composer(.json|.lock), Gemfile(.lock), go.mod, Cargo(.toml|.lock), pom.xml, build.gradle(.kts), pubspec(.yaml|.lock)
- Queries OSV.dev in batches; results cached at `~/.claude/agentic-security/osv-cache/` for 7 days
- Annotates each component with `latestVersion`, `isDeprecated`, `license`, `reachable` (whether the project imports it)
- Surfaces a `lockfile_missing` finding when manifest exists but lockfile is absent

## Malware verdict (opt-in)

For deeper analysis on suspicious packages, dispatch the `sca-malware-analyst` subagent — it produces a CLEAN / SUSPICIOUS / MALICIOUS label per component using strict grounding rules.
