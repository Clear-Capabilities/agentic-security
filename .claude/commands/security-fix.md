---
description: Apply a remediation patch for a single finding from the last scan.
argument-hint: "<finding-id>"
---
```bash
node /Users/ross/.claude/plugins/cache/clearcapabilities/agentic-security/0.3.1/scanner/dist/agentic-security.mjs fix --finding ${1}
```
Hand the finding off to the security-fixer subagent: read the affected file, apply the fix template adapted to the surrounding code, and run the project's test command if one is configured. Do not declare the fix complete until the finding no longer reproduces on re-scan.
