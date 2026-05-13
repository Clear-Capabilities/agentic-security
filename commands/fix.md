---
description: Remediate security findings. Use --one <id> to patch a single finding, --all to batch-fix by severity, or --pr to bundle fixes into a pull request.
argument-hint: "[--one <finding-id>] | [--all [--critical|--high|--medium|--low]] | [--pr [--severity critical|high|all] [--apply] [--branch <name>]]"
---

Apply security fixes from `.agentic-security/last-scan.json`.

## Modes

### `/fix --one <finding-id>`

Patch a single finding.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs fix --finding ${2}
```

The CLI prints the canonical fix template. Hand the finding off to the `security-fixer` subagent: read the affected file, apply the template adapted to the surrounding code, and run the project's test command (`npm test` / `pytest` / etc.) if one is configured.

Do not declare the fix complete until:
1. The finding no longer reproduces (re-scan the file)
2. Existing tests still pass

---

### `/fix --all [--critical|--high|--medium|--low]`

Batch-fix every finding at or above a severity tier. **Non-interactive — no prompts.**

The tier is cumulative: `--high` fixes critical + high. Default is `--critical`.

| Flag | Fixes |
|------|-------|
| `--critical` (default) | Critical only |
| `--high` | Critical + High |
| `--medium` | Critical + High + Medium |
| `--low` | Everything |

**Behavior:**

1. Dispatch the `security-fixer` subagent per finding, in sequence (not parallel).
2. Order: critical first, then high, medium, low. Within a tier, order by `toxicityScore` DESC.
3. After each fix, re-scan the affected file to verify the finding is gone and no regression was introduced.
4. If tests fail, **stop and report** — do not auto-revert. Let the user decide (`git checkout <file>`).

Warn before starting if the git tree is dirty — the batch can't be safely rolled back with uncommitted changes mixed in. Suggest committing or stashing first.

Print a final summary:
```
Applied N fixes, M skipped (tests failed), K regressions introduced.
```

After the run, the user can run `/scan --all` to confirm the final state.

---

### `/fix --pr [--severity critical|high|all] [--apply] [--branch <name>]`

Bundle fixes into a feature branch and open a pull request. **Default is dry-run** — pass `--apply` to actually modify code.

**Workflow:**

1. **Pre-flight**: verify clean working tree, `gh auth status`, and `.agentic-security/last-scan.json` exists.
2. **Build bundle plan**: filter findings by severity, group by shared helper, print the plan.
3. **Confirm with the user** before proceeding.
4. **If `--apply`**:
   - Create branch `${BRANCH:-security/auto-fix-$(date +%Y%m%d)}`.
   - For each finding: invoke `security-fixer`, run tests.
     - Tests pass → commit `security: fix <vuln> in <file>:<line> (finding <id>)`.
     - Tests fail → revert the file, label finding `INDETERMINATE`, continue.
   - Push branch and open PR via `gh pr create`.
5. Print summary with PR URL.

**Hard rules:**
- Never run without `--apply` unless explicitly requested. Default to dry-run plan.
- Never amend or force-push an existing branch.
- Never widen assertions or skip tests to make a fix pass.
- Skip findings labelled `PROBABLE_FP` by `/validate-findings`.

```bash
gh pr create \
  --title "security: auto-bundle fix for ${COUNT} findings (severity >= ${SEVERITY:-critical})" \
  --body "$(cat <<EOF
## Auto-generated security fix bundle

This PR bundles ${COUNT} findings remediated by \`agentic-security\`.

### Findings fixed
${FIXED_LIST}

### Findings skipped (tests failed)
${SKIPPED_LIST}

### Verification
Each fix was validated by running the project test suite. Any fix that broke tests was reverted.
Re-run \`/scan --all\` and \`/validate-findings\` for any individual finding to verify.

Generated with [agentic-security](https://github.com/clearcapabilities/agentic-security)
EOF
)"
```

🛡  agentic-security · created by ClearCapabilities.Com
