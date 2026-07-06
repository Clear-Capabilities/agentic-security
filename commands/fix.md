---
description: "Remediate findings: --one <id>, --all by severity, --pr bundles a PR, --sca upgrades vulnerable deps."
argument-hint: "[--one <finding-id>] | [--all [--critical|--high|--medium|--low]] | [--pr [--severity critical|high|all] [--apply] [--branch <name>]] | [--sca [--pr] [--apply] [--tier critical|high|all]]"
---

Apply security fixes from `.agentic-security/last-scan.json`.

## Modes

### `/fix --one <finding-id>`

Patch a single finding.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
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

1. Dispatch `security-fixer` for **independent** findings in parallel (up to ~10 in flight); serialize only findings that touch the SAME file, since each fix rewrites it. This clears a repo in one pass instead of one-finding-at-a-time.
2. Order: critical first, then high, medium, low. Within a tier, order by `toxicityScore` DESC.
3. Each fix runs the closed loop the MCP layer enforces: `synthesize_fix` → (a deterministic `autofix.patch` when present, else a composed patch) → `apply_fix` (which **re-verifies inline**: original finding gone + no new ≥medium + lint) → re-scan the affected file. If `synthesize_fix` returned a `regression_test`, write it so the fix ships with a test that fails pre-fix and passes post-fix.
4. **Do NOT halt on the first failure.** Record each finding's outcome (`fixed | skipped-verify | skipped-test | refused`) and keep going; report the full per-finding list at the end. A single flaky test must not block the rest of the batch.
5. Publish the running **auto-fix acceptance rate** (`apply_fix` returns `acceptance` on every applied fix) so the loop reports its own success metric.

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
- Skip findings labelled `PROBABLE_FP` by `/triage --validate`.

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
Re-run \`/scan --all\` and \`/triage --validate\` for any individual finding to verify.

Generated with [agentic-security](https://github.com/Clear-Capabilities/agentic-security)
EOF
)"
```

---

### `/fix --sca [--pr] [--apply] [--tier critical|high|all]`

Upgrade every vulnerable dependency in the project. **Default is dry-run** — pass `--apply` to actually upgrade.

This is the SCA counterpart to `/fix --all` for SAST findings. Instead of patching source files, it shells to the ecosystem's package manager (`npm install`, `pip install --upgrade`, `cargo update`, `go get`) with the OSV-recommended target version, gates each upgrade on the project's test command, and rolls back any upgrade whose tests fail.

**Workflow:**

1. **Pre-flight**:
   - Read `.agentic-security/last-scan.json` for every `type: "vulnerable_dep"` finding.
   - Filter by `--tier`:
     - `critical` (default): only `compositeRiskTier === 'critical'` or `kev === true`.
     - `high`: critical + high tiers.
     - `all`: every vulnerable_dep finding.
   - Order by `compositeRisk` DESC. KEV-listed + route-reachable-via-function findings always sort first.
   - Skip any finding whose `mitigationVerdict === 'mitigated-in-prod'` (already neutralized).
   - Skip any finding suppressed by `.agentic-security/sca-policy.yml` (when present).

2. **Per finding**:
   - Call the MCP `synthesize_sca_upgrade(finding_id)` tool. Inspect:
     - `isBreaking` — if true, surface to the user; in `--apply` mode skip by default unless the user explicitly opts in.
     - `dryRun.peerDeps` — if non-empty, surface; consider skipping if the warnings indicate a hard conflict.
   - In `--apply` mode: call `apply_sca_upgrade(finding_id, confirm: true)`. The tool itself runs the install, runs the project tests, and rolls back manifests on test failure.
   - Record per-finding outcome: `applied | skipped-breaking | skipped-peer-conflict | rolled-back-test-failure`.

3. **`--pr` mode** (combines with `--apply`):
   - Pre-flight: clean working tree (warn + suggest commit/stash if dirty), `gh auth status` ok, on a feature branch (create `security/sca-upgrade-$(date +%Y%m%d)` if currently on main).
   - After each successful upgrade, commit the manifest changes:
     - `security: bump <pkg> <from> → <to> (fixes <OSV id>)`
   - After the batch: push branch + open PR via `gh pr create`. Body lists every applied upgrade with CVE + fixed-version + composite-risk score.

**Hard rules:**

- Never run with `--apply` unless explicitly requested. Default is dry-run plan.
- Never amend or force-push an existing branch.
- Never skip the test gate. `apply_sca_upgrade` runs the project tests by default; if a project has no test command detected, surface that and require explicit user confirmation per finding.
- Major-version bumps (`isBreaking: true`) are NOT auto-applied in v1; they require user opt-in via interactive confirm.
- Surface the **upgrade break-rate** (rolled-back ÷ attempted) in the final summary. Build-and-test verification is the default and is never bypassed — an upgrade whose build/tests fail is rolled back, so the break-rate is how often an "available" upgrade was actually unsafe to take.

**Output:**

```
Plan: N vulnerable dependencies, M upgrade candidates, K skipped (breaking)
  applied:     <count>  (tests passed)
  skipped-breaking: <count>  (major version bump)
  skipped-peer:     <count>  (peer-dep conflict)
  rolled-back:      <count>  (tests failed; manifests restored)
```

**Why this isn't just `/fix --all` extended:**

SAST fixes write source code via the `apply_fix` MCP tool. That tool refuses every manifest basename (`package.json`, `package-lock.json`, `poetry.lock`, `Cargo.lock`, …) by design. SCA upgrades need a separate write path because the canonical way to modify a manifest is to delegate to the package manager — that's what `apply_sca_upgrade` does.

## Consolidated modes (v0.85.0+)

`/fix` now also routes:

| Flag | Behaviour |
|---|---|
| `--compliance` | Route every Not-Compliant control from the compliance report to the command that closes it |
| `--rotate-secret` | Guided revoke + scrub of a leaked secret. `--auto` runs end-to-end; `--scrub-history` rewrites git |
| `--vault` | Guided migration from scattered env vars to a secrets vault (Doppler / Infisical / Vercel / Railway) |
| `--harden` | Apply project-wide hardening defaults (CSP, security headers, rate limit, etc.) |
| `--trim` | Trim unused code or unused packages. `--what code|deps|both` |
| `--generate <type>` | Generate security artifacts: privacy policy, disaster playbook, regression tests, social posts |
| `--all` | All findings in one batch (see also `/find-and-fix-everything` — first-class command for the vibecoder path) |
| `--checkpoint` | Modifier for any batch fix: do the whole batch on a throwaway git branch so it's atomically revertible |

Add `--json` to emit the fix plan / result as machine-readable output.

## `--checkpoint` (atomic, revertible batches)

`--checkpoint` wraps a batch fix (`--all`, `--sca`, `--harden`) in a git safety net so an unwanted run is one command to undo:

1. Refuse if the working tree is dirty (or require `--checkpoint-allow-dirty`) — checkpointing only makes sense from a clean base.
2. Create and switch to `agentic-security/fix-<timestamp>`.
3. Apply the batch with per-finding verification as usual.
4. Print the branch name and the exact undo (`git checkout - && git branch -D agentic-security/fix-<timestamp>`) plus the merge-forward (`git checkout <base> && git merge --no-ff …`).

This replaces the all-or-nothing tension in `/find-and-fix-everything`: the whole batch lives on one branch, so the user reviews the diff and keeps or drops it wholesale.

🛡  agentic-security · created by ClearCapabilities.Com
