---
description: Run a full SAST + SCA + Secret scan on the working tree (or a path argument).
argument-hint: "[path]"
---

Run the agentic-security scanner against `${1:-.}` and surface the findings inline.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format cli --verbose; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

After the scan, the JSON report is persisted to `.agentic-security/last-scan.json` for use by `/security-fix` and `/security-report`.

If you see critical findings, you can:
- Run `/agentic-security:security-fix <finding-id>` to apply a remediation patch via the `security-fixer` subagent
- Run `/agentic-security:security-fix-all --severity critical` to remediate every critical finding
- Run `/agentic-security:security-drift` to compare this scan against a prior scan JSON
