---
description: Remediate every finding at or above a severity threshold (default critical).
argument-hint: "[--severity critical|high|medium]"
---
Read `.agentic-security/last-scan.json`. For every finding whose severity is at or above `${1:-critical}`, dispatch the security-fixer subagent in sequence (not in parallel — each fix may invalidate later findings). After each batch, re-run `/security-scan` to confirm fixes landed. Stop and report if a fix's tests fail.
