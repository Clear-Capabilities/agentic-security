---
description: Generate a working exploit payload + regression test for one finding (or flag PROBABLE_FP if no payload can be constructed). Validates that a finding is real before fixing.
argument-hint: "<finding-id>"
---

Generate a concrete proof-of-concept (or false-positive verdict) for finding `${1}`.

1. If `.agentic-security/last-scan.json` does not exist, ask the user to run `/scan --all` first and stop.

2. Load the finding by ID:
   ```bash
   jq --arg id "${1}" '.findings[] | select(.id == $id)' .agentic-security/last-scan.json
   ```
   If no finding matches, list the available IDs (top 20 by severity) and stop.

3. Read the file at the finding's path. Extract ±60 lines around the flagged line (use the Read tool — do not exceed 120 lines total).

4. Invoke the `security-poc-generator` subagent with the finding object and the file context. The subagent will return one of three verdicts:
   - `TP_CONFIRMED` + a `PAYLOAD` block + a `TEST` block.
   - `PROBABLE_FP` + a `BLOCKER` block + a suppression entry.
   - `INDETERMINATE` + a one-sentence reason.

5. Print the agent's output verbatim. Do not summarise or rewrite.

6. After printing:
   - If verdict is `TP_CONFIRMED`: offer to write the test to `tests/security/<finding-id>.test.<ext>` (matching project conventions). Ask before writing.
   - If verdict is `PROBABLE_FP`: offer to apply the suppression (append to `.agentic-security/rules.yml`). Ask before writing.
   - If verdict is `INDETERMINATE`: leave the finding as-is and recommend `/fix --one ${1}` only if the user accepts the residual risk.

## Why this exists

A finding the team can't reproduce is a finding the team won't fix. By forcing a concrete PoC for every flagged issue, this command:

- Raises **precision**: findings whose data flow can't actually be exploited are demoted to PROBABLE_FP and suppressed at source.
- Raises **recall on real bugs over time**: the regression test lives in CI and re-fires if the bug is reintroduced by a future commit.

Together with `/fix --one`, this closes the loop: **find → prove → fix → test**.
