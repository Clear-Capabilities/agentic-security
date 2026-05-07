---
description: Apply a remediation patch for a single finding from the last scan.
argument-hint: "<finding-id>"
---

Looking up finding `${1}` from `.agentic-security/last-scan.json`.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs fix --finding ${1}
```

The CLI prints the canonical fix template. Now hand the finding off to the `security-fixer` subagent: read the affected file, apply the template adapted to the surrounding code, and run the project's test command (`npm test` / `pytest` / etc.) if one is configured.

Do not declare the fix complete until:
1. The finding no longer reproduces (re-run `/agentic-security:security-scan` on the file)
2. Existing tests still pass
