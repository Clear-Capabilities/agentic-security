---
description: Save current findings as a baseline, or diff the current scan against the saved baseline.
argument-hint: "save|diff [path]"
---
```bash
node /Users/ross/.claude/plugins/cache/clearcapabilities/agentic-security/0.3.1/scanner/dist/agentic-security.mjs baseline ${1} ${2:-.}
```
- `save` — copy `.agentic-security/last-scan.json` to `.agentic-security/baseline.json`
- `diff` — re-scan and compare against the baseline, reporting regressions and fixed findings
