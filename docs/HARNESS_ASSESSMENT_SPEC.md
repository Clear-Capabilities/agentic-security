# Harness Assessment Spec (v1.0)

A six-domain rubric for scoring an AI agent harness's operational maturity — not the target project's code, the **harness** running it (tool mediation, guardrails, feedback loops, audit evidence, failure handling, compliance mapping).

**Source of truth.** This document is derived from `scripts/harness-score.cjs`, which was shipped before this spec was — the checks below are transcribed from the scorer's own `SPEC` table, not authored independently of it. If the two ever disagree, the scorer is what actually ran; fix whichever is wrong and keep them in sync. Run it with:

```bash
node scripts/harness-score.cjs                    # markdown to stdout
node scripts/harness-score.cjs --format json       # machine-readable
```

The npm script alias is `npm run harness-score` (from `scanner/`).

## Levels

| Level | Label | Meaning |
|---|---|---|
| 0 | Absent | No P0 control in the domain has status `present`. |
| 1 | Partial | At least one P0 control is not `absent` (some P0 traction), but not all. |
| 2 | Operating | Every P0 control in the domain is `present`. |
| 3 | Operating with continuous evidence | Level 2, plus the domain's `continuous()` check confirms the evidence is generated on an ongoing basis, not just present once. |

**Overall score = MIN(the six domain levels).** One weak domain caps the whole assessment — a harness with excellent audit logging and no sandboxing is not "mostly Operating," it is whatever level its weakest domain reaches. A harness passes when every domain is at least `Operating` (2), and Audit Evidence + Compliance reach `Operating with continuous evidence` (3).

Each control also carries a **priority**: `P0` controls gate the level; `P1` controls are recorded and reported but do not by themselves change the level.

## The six domains

### Tool Access (`tool-access`)

| ID | Priority | Control |
|---|---|---|
| T-1 | P0 | Tool allowlist with schema |
| T-2 | P0 | Every tool call mediated by the harness |
| T-3 | P0 | Sensitivity tiers + scoping |
| T-4 | P0 | Denied calls logged with reason |
| T-5 | P1 | Just-in-time elevation for high-sensitivity calls |
| T-6 | P1 | Tool descriptions versioned |

### Guardrails (`guardrails`)

| ID | Priority | Control |
|---|---|---|
| G-1 | P0 | Denylist enforced outside the model |
| G-2 | P0 | Rate / cost / time limits |
| G-3 | P0 | Untrusted-input tagging + confirm-before-effect |
| G-4 | P0 | Sandboxing for code execution |
| G-5 | P1 | Semantic guardrails (secondary classifier) |
| G-6 | P1 | Limits differentiated by role / risk tier |

### Feedback Loops (`feedback-loops`)

| ID | Priority | Control |
|---|---|---|
| F-1 | P0 | Output validation |
| F-2 | P0 | Anomaly detection + circuit breakers |
| F-3 | P0 | Human-in-the-loop checkpoints |
| F-4 | P0 | Self-consistency: intent vs. tool calls |
| F-5 | P1 | Separate verifier model for high-stakes plans |
| F-6 | P1 | "Explain what you are about to do" affordance |

### Audit Evidence (`audit-evidence`)

| ID | Priority | Control |
|---|---|---|
| A-1 | P0 | Structured append-only logs with trace ID |
| A-2 | P0 | Integrity-protected storage |
| A-3 | P0 | Sessions can be replayed from logs |
| A-4 | P0 | Retention meets longest applicable obligation |
| A-5 | P1 | Chain-of-custody metadata for audit-bound evidence |
| A-6 | P1 | Public, queryable control status |

The evidence *wire format* this domain checks for is specified separately in `docs/HARNESS_ASSESSMENT_EVIDENCE.md` and `docs/schemas/harness-evidence.schema.json`.

### Failure Mode (`failure-mode`)

| ID | Priority | Control |
|---|---|---|
| M-1 | P0 | Defined blast radius per tool category |
| M-2 | P0 | Circuit breakers |
| M-3 | P0 | Rollback / compensation / explicit confirm |
| M-4 | P0 | Incident response playbook exercised |
| M-5 | P1 | Chaos drills with injected bad tool calls |
| M-6 | P1 | Customer-facing incident comms templates |

### Compliance (`compliance`)

| ID | Priority | Control |
|---|---|---|
| C-1 | P0 | Domains mapped to framework controls |
| C-2 | P0 | Reports for any window without manual collection |
| C-3 | P0 | Control failures auto-generate exceptions |
| C-4 | P1 | Continuous control monitoring dashboard |
| C-5 | P1 | Auto-bundled evidence packages per audit |

## Scoring a harness that isn't this project

`harness-score.cjs` checks the state of whatever project it runs against (`CLAUDE_PROJECT_DIR` or `cwd`), not specifically this repository — the P0/P1 checks look for artefacts (tool-schema files, guardrail config, log formats matching the evidence schema, etc.) generic to a Claude Code-based harness. A `--verbose` flag surfaces per-control evidence paths so a `partial`/`absent` verdict is traceable to what was and wasn't found, per this project's own no-unverifiable-claims discipline.

## Changing this spec

Edit `scripts/harness-score.cjs`'s `SPEC` table first (it is the implementation), then update this document to match in the same change — never the reverse, since a spec edit with no matching code change silently stops describing what the scorer actually does.
