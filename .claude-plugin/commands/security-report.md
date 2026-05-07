---
description: Re-render the last scan in JSON, Markdown, or SARIF format.
argument-hint: "[--format json|md|sarif] [--output <file>]"
---

Re-emit `.agentic-security/last-scan.json` in the requested format without re-scanning.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format ${1:-md}
```

Common uses:
- `--format md --output report.md` — paste into a PR description
- `--format sarif --output security.sarif` — upload to GitHub Advanced Security
- `--format json` — pipe into other tools

Note: this re-runs the scan to ensure the report is current. To skip re-scanning, read `.agentic-security/last-scan.json` directly.
