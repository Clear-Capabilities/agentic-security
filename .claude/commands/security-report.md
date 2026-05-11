---
description: Generate an HTML security report (or JSON/Markdown/SARIF).
argument-hint: "[--format html|json|md|sarif] [--output <file>]"
---
```bash
node /Users/ross/.claude/plugins/cache/clearcapabilities/agentic-security/0.3.1/scanner/dist/agentic-security.mjs scan . --format ${1:-html} --output ${2:-security-report.html}
```
