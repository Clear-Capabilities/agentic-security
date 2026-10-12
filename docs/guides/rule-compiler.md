# Self-learning finding-to-rule compiler

**Status: new.** Turns ONE model- or human-discovered vulnerability into a reusable, deterministic detection rule —
evidence promotes rules, never a model. Nothing here calls a model; a model (or a human) may propose a candidate
pattern, and this machinery decides, from executable evidence, whether it is good enough to go live.

## Three similarly-named, different things — read this first

This codebase already has two other features with "synthesize" or "rule" in their name. None of the three
overlaps in what they do:

| Command | Input | Output | What it needs |
|---|---|---|---|
| `labs --synthesize-rule` | sample vulnerable files for one CWE | a **detector spec proposal** for a human to manually copy into a new SAST module | an LLM endpoint |
| `labs claude-audit` / `posture/rule-synthesis.js` | repeated **false-positive** triage verdicts | a **suppression** rule proposal | triage history |
| `rules synthesize` (this guide) | one confirmed **true-positive** finding | a **live, promoted detection rule**, validated against its own corpus | an eligible finding + a candidate pattern |

## The lifecycle

```
DRAFT → CANDIDATE → VALIDATED → PROMOTED → DEPRECATED / ROLLED_BACK
```

Recorded in an append-only, hash-chained ledger (`rule-lifecycle.js`'s idiom, same pattern as the invariants
approval ledger). A rule cannot promote itself: there is no edge from `CANDIDATE` straight to `PROMOTED`, and
nothing in the evaluate/promote split writes the ledger from inside the scoring function.

## Eligibility

A finding may enter synthesis only with: a stable id, a vulnerable span (`file:line`), a CWE or family, code-flow
evidence (an `IR-TAINT`/`MULTI-SINK` parser origin, or a snippet), and deterministic corroboration or exploit proof
— reusing the existing `proofTier` vocabulary and, when available, the [exploit proof fabric](exploit-proof-fabric.md)'s
evidence-state ladder, rather than a third one.

## Worked example — a real, verified miss

The deterministic engine does not recognize `db.rawQuery(...)` as a SQL sink (verified by a real scan in this
session: zero findings on `db.rawQuery("SELECT * FROM users WHERE id = " + userId)`). This is the actual, grounded
case the test suite's killer scenario (`test/cli/rule-compiler-cli.test.js`) walks end to end.

```bash
agentic-security rules synthesize hunt-rawquery-0001 --spec spec.json
```

`spec.json` is exactly what a model (or a human) proposes — this command never invents a pattern:

```json
{
  "id": "orm-raw-query-concat", "title": "ORM rawQuery built from string concatenation",
  "severity": "critical", "cwe": "CWE-89", "family": "sql-injection", "languages": ["javascript"],
  "match": { "pattern": "rawQuery\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+" },
  "remediation": "Bind parameters; never concatenate untrusted input into rawQuery()."
}
```

```bash
agentic-security rules evaluate orm-raw-query-concat --corpus corpus.json
```

`corpus.json` supplies the original code and, optionally, a patched version, nearby clean calls and
sanitizer/guard-carrying variants:

```json
{
  "originalCode": "db.rawQuery(\"SELECT * FROM users WHERE id = \" + userId);",
  "patchedCode": "db.rawQuery(\"SELECT * FROM users WHERE id = ?\", [userId]);",
  "nearbyCleanCode": ["db.rawQuery(\"SELECT * FROM users\");"],
  "protectedVariantsCode": ["db.rawQuery(\"SELECT * FROM users WHERE id = ?\", [userId]);"]
}
```

`evaluate` automatically generates structural siblings of both the positive and negative sides — variable rename,
wrap-in-function, insert-indirection — deterministic and semantics-preserving, so "does this rule generalize"
is answered without needing a second hand-written fixture for every shape. The promotion gate (default: precision
≥95%, recall ≥80%, zero protected-negative failures) must pass before the state can advance to `VALIDATED`, and
only a `VALIDATED` rule can be promoted:

```bash
agentic-security rules promote orm-raw-query-concat
```

This compiles the rule IR into a document the EXISTING custom-rule engine (`posture/custom-rules.js`) already
knows how to run — no second matching engine — and writes it to `.agentic-security/rules/orm-raw-query-concat.yml`.
From the next scan onward, this rule fires deterministically, with no model call, including on an **unseen
sibling** the corpus never contained (different file, renamed identifiers, extra indirection around the same
shape) — the "no model call occurs for B" scenario PRD 3 asks for, and the exact thing
`test/cli/rule-compiler-cli.test.js` asserts against a real spawned CLI and a real `scan`.

```bash
agentic-security rules status orm-raw-query-concat
agentic-security rules rollback orm-raw-query-concat   # un-publishes; ROLLED_BACK, never deleted from the ledger
```

## Anti-cheating

`checkLeakage` reuses the evaluation custodian's own protected-term guard (`posture/evaluation/custody.js` —
`protectedTermsFrom`/`guardPrompt`, QA-002.AC03) rather than a second leakage checker: a corpus or spec containing a
benchmark name or advisory id fails closed, and `gatePromotion` refuses with no leakage check at all as hard as it
refuses a failing score — there is no path where omitting the check reads as "passed".

## What this does not do

- **No automatic pattern proposal.** The candidate regex always comes from the caller (a model, in practice, but
  nothing here calls one). This is the deterministic promotion half, not the proposal half.
- **The mutation generator is intentionally small and syntactic** (three mutators: variable rename, wrap-in-function,
  insert-indirection). It demonstrates "catches a structurally different sibling," not exhaustive adversarial
  coverage — `bench/mutation/` (the engine-wide verdict-flip gate) is a different, much larger thing and is
  untouched by this feature.
- **Regression fixtures are written in the operator's own `.agentic-security/`**, in the existing `vulnerable`/
  `clean` convention `agentic-security rule test` already reads — not into this repository's own `bench/`.

## Reference

- Module: `scanner/src/posture/rule-compiler/` (`ir.js`, `eligibility.js`, `mutation.js`, `corpus.js`,
  `promotion.js`, `lifecycle.js`, `store.js`, `cli.js`)
- Tests: `scanner/test/rule-compiler/core.test.js`, `scanner/test/cli/rule-compiler-cli.test.js` (the killer
  scenario), both in `npm run test:posture`
- Implementation status: [`docs/implementation-status/rule-compiler.md`](../implementation-status/rule-compiler.md)
