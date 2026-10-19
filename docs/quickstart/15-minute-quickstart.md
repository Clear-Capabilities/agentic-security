# The 15-minute quickstart

<!-- seo: title="Developer quickstart: install, scan, fix and verify in 15 minutes" description="Install Agentic Security, scan the demo app, read the verdict, fix a finding with verification, export a report, and run it on your own project." -->

The complete guided walkthrough lives in [the quickstart guide](../guides/quickstart.md). This page is the map of it, organised around the assurance lifecycle, so you know what each step is for.

## Install

In Claude Code:

```text
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

In a terminal (Node.js 24 or later):

```bash
npx @clear-capabilities/agentic-security-scanner secure .
```

or install once and use the short form:

```bash
npm install -g @clear-capabilities/agentic-security-scanner
agentic-security secure .
```

`secure` looks at your project and tells you the single best next action.

## The steps

| Step | Command | Lifecycle stage | Guide section |
|---|---|---|---|
| Scan the demo app | `agentic-security scan examples/demo-app` | Discover, Corroborate | [Quickstart](../guides/quickstart.md) |
| Read the verdict and the scan health | (printed) | Corroborate | [Scan health](../trust/scan-health.md) |
| Fix a finding | `agentic-security fix --finding <id> --preview --root .` | Fix | [Fixing vulnerabilities](../guides/fixing-vulnerabilities.md) |
| Read the verification legs | (printed after `--apply`) | Verify | [Verified remediation](../trust/verified-remediation.md) |
| Export a report | `agentic-security scan . --format html --output report.html` | Trace | [Scanning](../guides/scanning.md) |
| Gate a pull request | `agentic-security ci . --assurance strict` | Verify | [CI gating](../workflows/ci-gating.md) |

Report formats: `html`, `json`, `md`, `sarif`, `oscal`, `csv`.

## Then your own project

Replace `examples/demo-app` with `.`. For a legacy codebase, snapshot what already exists and see only what is new:

```bash
agentic-security scan . --set-baseline
agentic-security scan . --since-baseline
```

## If something is off

- [Quickstart troubleshooting](../guides/quickstart.md#troubleshooting)
- [Why a scan reported partial](../troubleshooting/scan-health.md)
- [Harness setup for Codex, Cursor and Gemini CLI](../HARNESS_COMPATIBILITY.md)
