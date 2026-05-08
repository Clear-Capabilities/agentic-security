---
description: Generate an HTML security report from the last scan (or JSON/Markdown/SARIF).
argument-hint: "[--format html|json|md|sarif] [--output <file>]"
---

Re-scan and render a report. Defaults to an interactive HTML file.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format ${1:-html} --output ${2:-security-report.html}; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

Common uses:
- _(no args)_ — produces `security-report.html`, a self-contained interactive page with severity charts, filterable findings, and fix templates. Open with `open security-report.html`.
- `--format md --output report.md` — paste into a PR description or GitHub issue
- `--format sarif --output security.sarif` — upload to GitHub Advanced Security
- `--format json` — pipe into other tools

The HTML report has no external dependencies — one file you can email, drop in Slack, or attach to a ticket.
