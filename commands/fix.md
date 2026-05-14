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

The CLI prints the canonical fix template. Hand the finding off to the `security-fixer` subagent with **full codebase context**: read the affected file AND its imports, the auth middleware, any ORM/DB helpers it calls, and the route registration. Apply the fix adapted to how this specific project is structured — not the generic template.

**Contextual fix rules:**
- Detect the auth library in use (Clerk, NextAuth, Lucia, etc.) and write the fix using that library's idioms, not a generic pattern.
- Detect the ORM/DB (Prisma, Drizzle, raw pg, Supabase) and scope data queries to `session.userId` using that library's syntax.
- Detect the framework (Next.js App Router, Pages Router, Express, Fastify) and place the fix in the correct layer (middleware.ts, API route, server action).
- If rate limiting is the fix, detect which platform is deployed (Vercel → @upstash/ratelimit, Node → express-rate-limit) and generate the correct integration.

Do not declare the fix complete until:
1. The finding no longer reproduces (re-scan the file)
2. Existing tests still pass
3. The fix matches the idioms of the rest of the codebase (no mismatched patterns)

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

Generated with [agentic-security](https://github.com/Clear-Capabilities/agentic-security)
EOF
)"
```

🛡  agentic-security · created by ClearCapabilities.Com
