---
description: Save current findings as a baseline, or diff the current scan against the saved baseline.
argument-hint: "save|diff [path]"
---

Manage the security baseline so /agentic-security:security-scan can highlight only NEW findings.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs baseline ${1} ${2:-.}; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

- `save` — copy `.agentic-security/last-scan.json` to `.agentic-security/baseline.json`. Run after the codebase has been triaged and acknowledged findings have been accepted.
- `diff` — re-scan and compare against the baseline. Reports findings added (regressions) and findings fixed.

The pre-commit hook (`PreToolUse` on `git commit`) compares against this baseline and blocks commits that introduce critical findings unless `AGENTIC_SECURITY_BYPASS=1` is set.
