---
description: Remediate findings: --one <id>, --all by severity, --pr bundles a PR, --sca upgrades vulnerable deps.
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

| Flag | Behaviour | Legacy alias |
|---|---|---|
| `--compliance` | Route every Not-Compliant control from the compliance report to the command that closes it | `/compliance-fix` |
| `--rotate-secret` | Guided revoke + scrub of a leaked secret. `--auto` runs end-to-end; `--scrub-history` rewrites git | `/rotate-secret` |
| `--vault` | Guided migration from scattered env vars to a secrets vault (Doppler / Infisical / Vercel / Railway) | `/vault-wizard` |
| `--harden` | Apply project-wide hardening defaults (CSP, security headers, rate limit, etc.) | `/harden` |
| `--trim` | Trim unused code or unused packages. `--what code|deps|both` | `/trim` |
| `--generate <type>` | Generate security artifacts: privacy policy, disaster playbook, regression tests, social posts | `/generate` |
| `--all` | All findings in one batch (existing) | (see also `/find-and-fix-everything` — first-class command for the vibecoder path) |

🛡  agentic-security · created by ClearCapabilities.Com
