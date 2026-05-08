---
description: Validate scan findings for false positives and suppress confirmed FPs before reporting.
argument-hint: "[--severity critical|high|all]"
---

Read `.agentic-security/last-scan.json` and validate each finding at or above `${1:-critical}` severity for false positives.

For each finding:
1. Read the file at the reported path and extract ±20 lines around the flagged line
2. Evaluate whether it is a **true positive** using these criteria:
   - **True positive**: user-controlled input demonstrably reaches the sink without validation — flag it
   - **False positive**: the value is validated against an allowlist / switch / explicit enum before the sink, the sink is a safe API overload (e.g. `execFile` with an array, parameterized query), the finding is in a test fixture or mock, or the "source" is an internal constant rather than external input
3. For each confirmed false positive, add a suppression entry to `.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "<vuln name from finding>"
    files: ["<file path>"]
    reason: "<one sentence: why this is a FP>"
```

If `.agentic-security/rules.yml` does not exist, create it with the suppressions block.

After processing all findings, print a summary table:

| File:Line | Vulnerability | Verdict | Reason |
|---|---|---|---|
| ... | ... | TP / FP | ... |

Then re-run the scan so suppressions take effect:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format cli; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

Do not suppress anything you are not certain is a false positive. When in doubt, mark it TP and leave remediation to `/security-fix`.
