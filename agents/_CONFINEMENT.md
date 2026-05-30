# Subagent path-confinement schema (premortem #17)

Subagents that hold `Edit` MUST follow the same write-confinement contract
the MCP server enforces (`scanner/src/mcp/tools.js`). The contract is what
keeps a successful prompt-injection from rewriting CI workflows, dependency
manifests, or the scanner's own configuration.

## The contract

Refuse to write to any path that:

1. Resolves outside the scan root (lexical `..` or symlink-traversal).
2. Is reserved as scanner / source-control / dependency / CI state:
   - `.git/`, `.github/`, `.gitlab/`, `.circleci/`, `.buildkite/`
   - `.agentic-security/`
   - `node_modules/`, `.terraform/`, `.aws/`, `k8s/`, `kubernetes/`
   - File basenames: `Dockerfile`, `Jenkinsfile`, `.gitlab-ci.yml`,
     `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
     `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`,
     `requirements.txt`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`,
     `composer.json`, `composer.lock`, `Gemfile`, `Gemfile.lock`, `pom.xml`,
     `build.gradle`, `build.gradle.kts`
   - Suffixes: `*.tf`, `*.tfvars`, `docker-compose.yml`, `docker-compose.yaml`
3. Is a backup, lock, or build-output file (`*.bak`, `*.lock`, `dist/`,
   `build/`, `target/`).

If the user explicitly asks for one of these in their prompt, the subagent
should refuse with a one-line explanation and a pointer to `/fix --rotate-secret`
(for credential files), `/setup --hooks` (for `.git/hooks/`), or
`/ci` (for CI workflows).

## What is allowed

Edits under the scan root that are NOT on the reserved list. Apply the
finding's stored `fix.replacement` verbatim — do not paraphrase, do not
"improve while you're there." The verifier and history depend on the patch
being exactly what the scan produced.

## Verification

Before claiming a fix is applied, every Edit-capable subagent SHOULD:

1. Run `verify_fix` (via MCP) on the proposed patch in memory.
2. Refuse to commit the change if `verify_fix` reports the original
   `stableId` is still present OR if a new ≥medium finding was introduced.
3. Report the outcome (re-scan + lint verdict) back to the caller.

## Why this matters

Premortem #17: a successful prompt-injection attack on a subagent that holds
Edit but no confinement contract is equivalent to a successful attack on the
MCP `apply_fix` tool — but without any of the hardening the MCP path enforces
(HMAC on findings, reserved-paths refusal, audit log). The path the attacker
would use is whichever has the least friction; we close it here.

## Batch-size limits (harness-anatomy #3)

Subagents in this plugin are **scoped, short-lived workers** — one task per
invocation. They are NOT designed to grind through dozens of findings in a
single context window. We do not implement context compaction; once the
context fills, the harness gives up.

The deterministic toolchain enforces a 2-attempt budget per `stableId`
(`scanner/src/posture/fix-history.js`), which caps individual fixes. The
*sum* across many findings in one session is not bounded.

**Caller responsibility:** when invoking `security-fixer` (or any subagent
that consumes the deterministic write toolchain), batch by N at a time:

| Subagent | Recommended batch size | Reason |
|----------|------------------------|--------|
| `security-fixer`    | ≤ 10 findings per invocation | each fix ≈ 5 tool calls (synth + verify + apply + retest + record); 10 × 5 = 50 calls fits comfortably in one context |
| `refactor-cleaner`  | ≤ 5 dead symbols per invocation | each removal runs the full test suite |
| `security-triager`  | ≤ 30 findings per invocation | read-only; cheaper |
| `security-poc-generator` | ≤ 5 findings per invocation | PoC template + regression test gen is verbose |

If the caller has more findings than the limit, **split across multiple
invocations**, not one long-running agent. Each subagent invocation gets a
fresh context window — that's the project's substitute for compaction.

The supervisor agent (or the human user) is the right place to maintain
inter-batch state. Use `append_agents_memory` to record progress between
batches; the next invocation will see it on session start.

## Plan files for batched work (harness-anatomy #6)

When operating on a batch (a list of findings handed in as one task), each
Edit-capable subagent SHOULD write a plan file to its scratchpad before
starting work, then tick items off as it proceeds:

```
.agentic-security/agent-scratchpad/<agent>/<session>/PLAN.md
```

Conventions:

- **One bullet per item to address.** Each bullet records `stableId`, the
  finding's `vuln`, `file:line`, and a status checkbox (`[ ]` pending,
  `[x]` done, `[!]` refused, `[~]` skipped-budget-exceeded).
- **Update the file as each item resolves.** Call `append_scratchpad` with
  one line per status change — don't rewrite the whole file. The file is
  append-only by convention, even though the MCP tool allows replacement.
- **Final status block at the end.** When the batch is done (success or
  bail-out), append a single SUMMARY block listing counts: total / done /
  refused / skipped.

Why this matters:

1. **Auditable artifact.** A human reviewer or governance auditor can read
   the plan post-hoc to see what the agent intended vs. what actually
   happened. The audit log (`mcp-audit.log`) has the call-level transcript;
   the plan has the decision-level narrative.
2. **Context-reset survival.** If the agent's context fills mid-batch and
   the harness restarts it, the plan tells the resumed agent which items
   are already done. Combined with the fix-history log (`fix-history.json`)
   and the `attemptOrdinal` field on each entry, the agent can resume
   correctly without re-attempting closed items.
3. **Caller composability.** A supervisor agent can pre-write the plan file
   and hand the subagent a "work this PLAN.md" pointer, rather than passing
   N findings inline. Keeps the supervisor's context small too.

Example PLAN.md shape:

```markdown
# security-fixer PLAN — session 2026-05-20T...

Batch: 6 critical/high findings from /security-scan.

- [x] stableId=abc12345  Command Injection at app.js:14    (verifier OK)
- [x] stableId=def67890  SQL Injection at search.js:22     (verifier OK)
- [!] stableId=ff112233  CSRF Missing at routes/post.js:5  (refused: route is
      auth-gated upstream; rule doesn't see the middleware)
- [~] stableId=00aabbcc  XSS in template (budget exceeded: canonical fix
      introduced a CSP-Header finding; routing to /csp-cors)
- [ ] stableId=99887766  Weak Crypto at auth.js:8
- [ ] stableId=11223344  Hardcoded Secret at config.js:3

## SUMMARY
total: 6 | done: 2 | refused: 1 | budget: 1 | pending: 2

next-action: hand pending items + the refused one back to the supervisor;
they'll be routed (CSP-Header → /csp-cors, refused → human).
```

Subagents whose tools list does NOT include `append_scratchpad` cannot follow
this convention — record the plan inline in the final report instead.
