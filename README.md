# agentic-security

> Defensive AppSec for Claude Code — SAST, SCA, and Secret scanning with auto-remediation.

**Author:** Ross Young, [Clear Capabilities Inc.](https://clearcapabilities.com)
**Status:** v0.1 — initial public release
**License:** [Elastic License 2.0](./LICENSE) — free use and modification, but you may not offer the software as a hosted/managed service to third parties.

`agentic-security` is an official Claude Code plugin. It gives any Claude Code session first-class application-security analysis: run `/security-scan` to sweep the working tree for vulnerabilities, dependency CVEs, and leaked credentials, then dispatch the `security-fixer` subagent to patch them.

## What it scans

- **SAST** — 50+ vulnerability sinks (SQLi, XSS, RCE, SSRF, IDOR, Path Traversal, Prototype Pollution, ReDoS, JWT, Mass Assignment, weak crypto, …) with AST-based taint tracking for JS/TS and regex fallback for Python, PHP, Ruby, Java, Go, Laravel.
- **SCA** — 20 manifest formats parsed; vulnerabilities pulled from OSV.dev with a vulnerable-call-depth filter so noise from unused dependencies is suppressed.
- **Secrets** — 60+ provider patterns (Stripe, AWS, GitHub PAT, Shopify, Slack, …) plus entropy-based detection. Values are masked by default.

Each finding ships with severity, CWE, STRIDE category, and a canonical fix.

## Install

```bash
/plugin install agentic-security@clearcapabilities
```

Or, locally for development:

```bash
git clone https://github.com/clearcapabilities/agentic-security ~/.claude/plugins/agentic-security
cd ~/.claude/plugins/agentic-security/scanner && npm install
```

## Commands

| Command | What it does |
|---|---|
| `/security-scan [path]` | Full SAST + SCA + Secrets sweep |
| `/security-sca [path]` | Dependency / CVE audit only |
| `/security-secrets [path]` | Secret scan only |
| `/security-fix <id>` | Apply remediation for a single finding |
| `/security-fix-all [--severity X]` | Loop the fixer over every finding ≥ X |
| `/security-threat-model` | STRIDE coverage table |
| `/security-report [--format md\|json\|sarif]` | Re-render last scan |
| `/security-baseline save\|diff` | Save / diff against a baseline |

## Hooks

- **PostToolUse on Edit/Write/MultiEdit** — silently scans the touched file, surfaces only NEW high/critical findings to Claude.
- **PreToolUse on Bash matching `git commit`** — blocks commits that introduce critical findings (vs. baseline). Override with `AGENTIC_SECURITY_BYPASS=1`.
- **SessionStart** — one-line tip if no baseline exists yet.

All hooks are opt-in via `plugin.json`.

## Subagents

- `security-fixer` — applies fix templates adapted to local code patterns; runs tests after.
- `security-triager` — scores exploitability, dedupes, ranks findings.
- `sca-malware-analyst` — CLEAN / SUSPICIOUS / MALICIOUS verdict per dependency, with strict grounding rules.

## CLI usage (without Claude Code)

The scanner ships as a standalone Node CLI:

```bash
node scanner/bin/agentic-security.js scan . --format cli
node scanner/bin/agentic-security.js scan . --format sarif --output security.sarif
node scanner/bin/agentic-security.js baseline save
node scanner/bin/agentic-security.js baseline diff
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Low / Medium findings |
| 2 | High findings |
| 3 | Critical findings |
| 4 | Execution error |

### Output formats

- `cli` (default) — ANSI-colored severity-grouped table
- `json` — JSON schema with stable finding IDs (good for piping)
- `md` — Markdown table per severity, ready to paste into a PR description
- `sarif` — SARIF 2.1.0 for GitHub Advanced Security / VS Code Problems pane

## Privacy

- SAST and Secret scanning run **fully offline** — no code leaves your machine.
- SCA queries OSV.dev with package name + version only (a `purl`). **Source code is never transmitted.**
- Pass `--no-network` to skip OSV/registry calls entirely; SCA falls back to disk cache.
- The opt-in `sca-malware-analyst` subagent uses Claude Code's existing API key to send package metadata (not source) to Claude. Off by default.

## Engine

The scanner is a Node port of `attacksurface.html`, a 4,150-line analyzer with proven detection across multiple public vulnerable apps (Juice Shop, NodeGoat, DVWA, Vulpy). The HTML version runs entirely in the browser; this plugin packages the engine for terminal use.

## License

[Elastic License 2.0](./LICENSE). You may use, copy, modify, and redistribute the software for free — including inside commercial products and internal tooling. You may **not**:

- Offer the software (or substantially the same functionality) as a hosted or managed service to third parties.
- Move, change, disable, or circumvent any license-key functionality.
- Remove, alter, or obscure copyright / license notices.

If you want a different licensing arrangement (e.g. a SaaS exemption), contact ross@clearcapabilities.com.

## Author

Ross Young  ·  Clear Capabilities Inc.  ·  ross@clearcapabilities.com
