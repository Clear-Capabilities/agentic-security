---
description: Score a git diff by architectural risk — auth removed, new endpoints, new prompts with user input, new shell calls, new IaC privilege grants. Separates routine refactors from material change.
argument-hint: "[--since <git-ref>]"
---

Compute the material-risk score of the changes between `${SINCE:-HEAD~1}` and `HEAD`.

1. Run the classifier:

```bash
node -e "
import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/material-change.js').then(m => {
  const r = m.classifyGitDiff(process.cwd(), '${1:-HEAD~1}');
  process.stdout.write(JSON.stringify(r, null, 2));
});
"
```

(if the user is in a non-git directory or the ref is invalid, stop and ask which ref to use.)

2. Pass the JSON to the `security-material-change` subagent. It will emit a Markdown report with per-file findings, severity-ranked, and a "what to verify before merging" checklist citing specific findings.

3. Print the agent's output verbatim.

4. Suggest follow-ups based on `materialRisk`:
   - `critical` → recommend `/fix --one` for any auth-removed / priv-from-body / new-shell-call findings, and `/security-poc` to validate a working exploit before merging.
   - `high` → recommend `/security-poc` for the highest-tier finding.
   - `medium` / `low` / `none` → no follow-up; the diff is safe to merge from a posture standpoint.

## Why this exists

A line count is not a risk metric. This command separates "200-file rename" (routine) from "3-line change that removes `verifyToken()` from a middleware" (critical). The same principle that makes commercial ASPM pre-merge gates valuable — in plugin form.
