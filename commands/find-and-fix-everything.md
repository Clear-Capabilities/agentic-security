---
description: Full /scan --all then /fix --all --low in one command. The vibecoder "just make it safe" path.
argument-hint: "[path]"
---

Run a full SAST + SCA + secrets sweep and fix every finding at every severity tier in one shot.

This is the one-command equivalent of:
1. `/scan --all [path]`
2. `/fix --all --low`

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  agentic-security: find-and-fix-everything"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Step 1 of 2 — Full scan"
echo ""

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship "$PATH_ARG"
SCAN_EC=$?

if [ $SCAN_EC -gt 3 ]; then
  echo "Scanner error (exit $SCAN_EC). Check output above."
  exit $SCAN_EC
fi

echo ""
echo "Step 2 of 2 — Fixing all findings (critical → high → medium → low)"
echo ""
```

After the scan completes:

1. Read `.agentic-security/last-scan.json` to get the full finding list.
2. If the scan produced zero findings, print a ✅ and stop — nothing to fix.
3. **Checkpoint branch.** If the working tree is clean and the repo is a git repo, create and switch to `agentic-security/fix-<timestamp>` so the entire batch is atomically revertible. If the tree is dirty, suggest `git stash` / `git commit` first and ask whether to proceed (or skip the branch). Tell the user the branch name.
4. Dispatch `security-fixer` on the findings, ordered critical → high → medium → low (`toxicityScore` DESC within a tier). Fix **independent** findings in parallel (up to ~10 in flight); serialize only findings that share a file. Each fix runs the closed, verified loop — `synthesize_fix` → a deterministic `autofix.patch` or a composed patch → `apply_fix` (re-verifies inline: finding gone + no new ≥medium + lint) → re-scan — and writes any returned `regression_test` alongside the fix.
5. **Do NOT halt on the first failure.** Record each finding's outcome (`fixed | skipped-verify | skipped-test | refused`) and keep going — a single flaky test must not block the rest of the batch. The checkpoint branch (step 3) is the rollback net, so the batch never needs to stop early.
6. Publish the **auto-fix acceptance rate** (`apply_fix` returns it on every applied fix) — the measured success metric of the whole loop.
7. Print a final summary, then offer the PR-ready next step: a one-paragraph summary of what changed (findings closed, files touched, tests run) suitable for a PR body, plus the commands to merge the checkpoint branch forward or drop it wholesale.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  find-and-fix-everything — complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scanned:   <N> files
  Found:     <C> critical · <H> high · <M> medium · <L> low
  Fixed:     <N> findings
  Accepted:  <rate>%  (patch landed + verified + no new ≥medium)
  Skipped:   <N> (verify/test failed — see above)
  Branch:    agentic-security/fix-<timestamp>  (checkpoint)
  Confirm:   /scan --all
  Keep:      git checkout <base> && git merge --no-ff agentic-security/fix-<timestamp>
  Drop:      git checkout <base> && git branch -D agentic-security/fix-<timestamp>
```

🛡  agentic-security · created by ClearCapabilities.Com
