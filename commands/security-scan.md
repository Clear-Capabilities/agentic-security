---
description: Run a full SAST + SCA + Secret scan on the working tree (or a path argument).
argument-hint: "[path]"
---

Run the agentic-security scanner against `${1:-.}` and surface the findings inline.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format cli --verbose
```

After the scan, the JSON report is persisted to `.agentic-security/last-scan.json` for use by `/security-fix` and `/security-report`.

If you see critical findings, you can:
- Run `/agentic-security:security-fix <finding-id>` to apply a remediation patch via the `security-fixer` subagent
- Run `/agentic-security:security-fix-all --severity critical` to remediate every critical finding
- Run `/agentic-security:security-baseline save` to lock in the current findings as a baseline; future runs will diff against it
