---
name: nist-ai-600-1
description: Use when the user asks for NIST AI 600-1 compliance, GAI risk attestation, an audit-ready compliance report, or "how does this codebase satisfy NIST AI 600-1 / AI RMF for generative AI?". Also use before a third-party audit, customer security review, or board-level GenAI risk review. Skip if the user only wants generic AppSec scans (use sast-scan / sca-scan / secret-scan).
---

# NIST AI 600-1 compliance scanning

The `agentic-security` plugin ships a deterministic compliance scanner for the **122 code-testable controls** of [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (the Generative AI Profile of the AI Risk Management Framework). The remaining 90 controls of the 212-control catalog are inherently organizational (legal alignment, contracts, training programs, board oversight) and cannot be evidenced from source — they are listed in the source xlsx with `Code Testable = No`.

## When to invoke

- User asks for "NIST AI 600-1", "AI RMF GenAI compliance", "AI compliance attestation"
- User mentions a third-party audit, vendor risk questionnaire, or customer GenAI review
- User asks "what % of NIST AI 600-1 do we cover with code?"
- User wants a per-control evidence sheet for an auditor

## How to invoke

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/nist-compliance/scan.py [path]
```

Or via the slash command:

```
/agentic-security:nist-ai-600-1 [path]
```

This produces three artifacts in the current directory:

- `nist-ai-600-1-attestation.md` — auditor-ready markdown with per-control evidence
- `nist-ai-600-1-attestation.csv` — same data as a spreadsheet (one row per control)
- `nist-ai-600-1-attestation.json` — machine-readable, suitable for CI gating

## What the scanner does (v0.2 multi-signal)

For each of the 122 testable controls (55 fully code-testable, 67 partially) the scanner runs three passes:

1. **Manifest pass** — parses `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Pipfile`, `go.mod`, `Cargo.toml`, `Gemfile`, and `composer.json`. A library declared as a dependency that maps to a control (e.g. `opacus` → MS-2.2-004 differential privacy) is the strongest, most specific evidence type (`manifest`, weight 5.0).
2. **Per-file pass** — walks the tree and per file:
   - **Detects imports** (Python, JS/TS, Go, Ruby) and matches against the control's `imports` list (`import`, weight 4.0).
   - **Matches paths** against control-specific globs, with bonus weight for files in `tests/` directories (`test_path` 3.0 vs `named_path` 2.5).
   - **Matches keyword terms** with weights tiered by file kind: code files 2.0, config 1.5, docs 1.0, comments 0.5.
3. **Negation filter** — discards keyword matches that occur within "we don't yet implement…", "future work", "planned for", "missing", "lacks" contexts.

**Tiered scoring:**
- *Strong tier* (manifest, import) — explicit capability declaration
- *Medium tier* (test_path, named_path, code_term) — implementation signal
- *Weak tier* (config_term, doc_term, comment) — circumstantial mention

Per-(control, signal-type) hits are capped at 5 to prevent any one broad pattern from dominating.

**Status decision (Yes-bucket controls):**
- **Compliant** — ≥ 2 strong-tier hits AND weight ≥ 8, OR strong + medium/weak mix AND weight ≥ 8, OR ≥ 3 distinct signal types AND weight ≥ 10
- **Partial** — at least 1 strong-tier hit OR weight ≥ 3
- **Not Compliant** — otherwise

**Status decision (Partial-bucket controls)** — code can never make these "Compliant"; the best status is "Partial + External Attestation Required":
- **Partial** — same evidence threshold as Yes-Compliant
- **Partial (limited evidence)** — at least 1 strong-tier hit OR weight ≥ 2
- **Not Compliant** — otherwise

The 90 controls flagged `Code Testable = No` are not scanned; they require external attestation only (signed policies, training records, vendor agreements).

## Status semantics for auditors

| Source `Code Testable` | Best status from scanner | Worst status from scanner |
|---|---|---|
| **Yes** (55 controls) | Compliant | Not Compliant |
| **Partial** (67 controls) | Partial Compliance + External Attestation Required | Not Compliant + External Attestation Required |
| **No** (90 controls) | _not scanned — attestation comes from outside the repo_ | _not scanned_ |

This three-bucket distinction matters: marking an inherently-organizational control as "Not Compliant" because no code matched is misleading. The scanner only opines on what code can show.

## Tuning the rules

Evidence rules live in `scripts/nist-compliance/evidence-rules.json` — one entry per control with `summary`, `paths` (fnmatch globs), and `keywords` (case-insensitive word-boundary). Adjust them to match the project's vocabulary; the file is hand-editable.

## Source data

The 212-control catalog is in `NIST AI 600-1.xlsx` at the repo root, with column F (`Code Testable`) added by this plugin. Re-running with `--xlsx <path>` lets you point at an updated catalog.
