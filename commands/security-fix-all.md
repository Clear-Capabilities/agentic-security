---
description: Remediate every finding at or above a severity threshold (default critical).
argument-hint: "[--severity critical|high|medium]"
---

Read `.agentic-security/last-scan.json`. For every finding whose severity is at or above `${1:-critical}`, dispatch the `security-fixer` subagent in sequence (not parallel — each fix may invalidate later findings via re-scan).

After each batch:
1. Re-run `/agentic-security:security-scan` to confirm fixes landed and to surface any new findings the patches introduced.
2. Stop and report if a fix's tests fail — do not auto-revert; the user will choose.

Sequence:
- Critical first, then High (if requested), then Medium (if requested)
- Same-severity findings ordered by exploitability score (descending)
