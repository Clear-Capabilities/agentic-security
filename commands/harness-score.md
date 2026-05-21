---
description: Score this project's AI agent harness against the six-domain rubric defined in docs/HARNESS_ASSESSMENT_SPEC.md (PRD-derived). Emits a domain-level report with overall = MIN(six).
argument-hint: "[--format md|json] [--output <file>]"
---

Score the harness in this project against the Agent Harness Assessment Spec (v1.0).
Each of the six domains — Tool Access, Guardrails, Feedback Loops, Audit Evidence,
Failure Mode, Compliance — is scored on a four-level rubric:

- **Level 0 — Absent** — the control does not exist
- **Level 1 — Partial** — some P0 controls exist; others missing
- **Level 2 — Operating** — all P0 controls present and exercised
- **Level 3 — Operating with continuous evidence** — Level 2 plus tamper-evident logs

The overall score is `MIN(six domains)` per the spec. A passing harness requires every
domain to be at least Operating, with Audit Evidence and Compliance at Operating with
continuous evidence.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
ARGS=("$@")
node ${CLAUDE_PLUGIN_ROOT}/scripts/harness-score.cjs "${ARGS[@]}"
```

## Usage

```bash
/harness-score                                # markdown to stdout
/harness-score --format json                  # machine-readable for CI
/harness-score --output HARNESS_SCORE.md      # write to file
```

## What it checks

For each of the 36 controls in the spec (24 P0 + 12 P1 across six domains), the tool
inspects live project state: plugin manifest, hook configuration, MCP audit log,
HMAC signatures on scan output, fix-history retry budget, available compliance overlays.

Each control returns one of:

- **Present** — implementation exists and is exercisable from the harness
- **Partial** — implementation exists but is incomplete or operates in warn-only mode
- **Absent** — no implementation found

Domains roll up: all P0 present + continuous evidence → Level 3; all P0 present → Level 2;
any P0 present → Level 1; none → Level 0.

## Exit code

`0` if overall ≥ Level 2 (Operating). `1` otherwise. Suitable for CI gating.

## Related

- [`docs/HARNESS_ASSESSMENT_SPEC.md`](../docs/HARNESS_ASSESSMENT_SPEC.md) — the rubric
- [`docs/HARNESS_ASSESSMENT_EVIDENCE.md`](../docs/HARNESS_ASSESSMENT_EVIDENCE.md) — the wire format
- `/compliance-report` — framework-specific attestations (NIST AI 600-1 / OWASP ASVS / OWASP LLM Top 10 / SOC 2 / ISO 27001 / ISO 42001 / EU AI Act)
