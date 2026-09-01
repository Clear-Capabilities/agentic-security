# Milestone 2, Sub-project H scoping: false-protected release gate + corpus

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row H and Decision 2, which defines the gate: evaluated **per
protection dimension** (`transit`, `atRest`, `handling`, never
aggregated); denominator = every labeled-corpus edge the engine asserts
`verdict: 'protected'` on that dimension; numerator = any such edge where
ground truth is unprotected OR `evidenceGrade` overstates the real
evidence; mechanism modeled on `bench/mutation/`'s verdict-flip pattern —
a companion semantics-changing mutation of each `protected`-asserting
fixture must flip that dimension's verdict away from `protected`, scored
as a defect if it doesn't.

**This document CORRECTS Decision 2's own three-dimension framing**, the
same way Sub-project E/my own B/F's scoping did: `handling` is not a
`PROTECTION_VERDICTS`-emitting dimension at all today, and no code path
can make it one without new, separately-scoped work. The gate as literally
specified has a permanently-zero denominator for `handling`.

## What already exists (confirmed by direct read, this session, HEAD `a932f0d1`)

- **`bench/mutation/runner.mjs`** (870 lines, single file, no fixtures
  directory) — the pattern Decision 2 says to model H on. Every case is an
  inline JS object in a `CASES` array: `{id, class: 'baseline' |
  'metamorphic' | 'adversarial', dimension, expectDetected/
  expectSanitized, cwe, parser, file, why, code}`. `class: 'metamorphic'`
  = semantics-preserving rewrite, verdict must NOT move; `class:
  'adversarial'` = semantics-changing near-miss, verdict MUST flip.
  `verdictFor(case)` writes `code` to a temp dir, sets
  `AGENTIC_SECURITY_DEEP=1`/`AGENTIC_SECURITY_DEEP_IN_CI=1`, calls
  `runScan(dir)`, filters `scan.findings` by `parser`/`cwe`. Exit 1 on any
  failure, wired as `"bench:mutation:check": "node
  ../bench/mutation/runner.mjs"` (`package.json`). **No paired base/mutant
  fixture files on disk** — each case IS a self-contained fixture,
  distinguished by `class`, not by a companion file. ~50 cases organized
  by rule family (XSS/SQLi/IaC/concurrency/path-traversal), not by
  protection dimension — `bench/mutation/` has no notion of
  transit/atRest/handling at all; its own two dimensions are
  `sanitization`/`detection`.
- **`bench/data-lineage/`** already carries a real `expectedProtection`
  field per fixture (`expected.json`: `{language, dataClass,
  sourceCategory, sinkCategory, expectedProtection: {handling:
  'protected'}, expectedTransformKind, tier, notes}`), but its own README
  states this field is "recorded and printed, never asserted" — the
  runner (`parseJsFile` → `buildCallGraph` → `buildGraphWithCoverage`)
  does single-graph shape-match scoring, never a paired mutation/flip
  check. **This directory is the right place to anchor positive-case
  labels, not the mutation mechanism itself** — its own scorer has no
  concept of "does the verdict flip when I mutate the fixture," which is
  Decision 2's actual gate mechanism. A genuinely new `bench/
  protection-verdict/` directory, mirroring `bench/mutation/`'s
  paired-case runner shape (not `bench/data-lineage/`'s single-shape
  scorer), is the closer structural fit.
- **Real, confirmed end-to-end invocation shape** for a corpus runner
  (matching both `bench/data-lineage/runner.mjs`'s own pipeline and
  `test/lineage/transit-protection.test.js`/`at-rest-protection.test.js`'s
  real usage):
  ```js
  import { parseJsFile } from '../../src/ir/parser-js.js';
  import { buildCallGraph } from '../../src/ir/callgraph.js';
  import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';

  function irOf(files) {
    const perFile = {};
    for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
    return buildCallGraph(perFile);
  }
  const cg = irOf({ 'a.js': sourceCode });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '...' });
  ```
  Transit cases additionally need `opts.fileContents`/
  `transitEvidenceByFile` for the crypto-protocol correlation to fire —
  `buildLineageGraph`'s own `index.js` wrapper is the scan-facing
  convenience layer that computes this once; a bench runner can call
  either `buildLineageGraph` directly (simpler, one call) or replicate its
  single-scan discipline manually — re-verify which is cleaner at
  implementation time, not decided here.
- **Real, confirmed verdict producers, one per dimension, with one
  critical exception:**
  - **`edge.protection.transit`** — `transit-protection.js`'s
    `resolveTransitProtectionForSite`, wired via `graph-builder.js`'s
    `opts.resolveTransitProtection` hook. Real, scoreable.
  - **`edge.protection.atRest`** — inline in `graph-builder.js`'s
    flow-construction loop (Sub-project C1): `classifyHandling(p,
    callGraph).handling === 'encrypted' && snk.kind === 'store'` →
    `{verdict: 'protected', evidenceGrade: 'code'}`. Real, scoreable, but
    **only for the application-layer slice** — C2 (storage/IaC config)
    and C3 (database column config) are unbuilt, so this dimension's
    corpus can only exercise the encrypt-before-store code pattern, never
    an IaC-declared-encryption or DB-column-config scenario (there is
    nothing yet to assert `protected` from either signal).
  - **`edge.protection.handling` — NOT a real dimension. No code
    anywhere writes it.** `emptyProtection()` leaves it permanently
    `{verdict: 'not_assessed', evidenceGrade: 'none'}`. `flow.handling`
    is a SEPARATE field using a SEPARATE vocabulary
    (`HANDLING_VALUES`: `raw`/`masked`/`redacted`/`hashed`/`tokenized`/
    `encrypted`/`aggregated`/`unknown` — not `PROTECTION_VERDICTS`'s
    `protected`/`unprotected`/`unknown`/`not_applicable`/`not_assessed`).
    `handling-analyzer.js`'s own header is explicit that deciding whether
    a `mask` "earns 'protected'" is a FUTURE analyzer's job, deliberately
    not this one's. **Decision 2's gate, applied literally to
    `handling`, has a permanently-zero denominator** — there is no
    `edge.protection.handling.verdict === 'protected'` for any fixture to
    assert, so no false-positive rate can even be computed, let alone
    gated.

## The resolved scoping decision

**H1 (this document recommends starting here): score `transit` and
`atRest` only — the two dimensions with real `protected`-asserting
producers.** This delivers the literal, otherwise-unowned second half of
the Milestone 2 exit gate's own wording ("...; false-protected release
gate passes") for the two dimensions that can actually be gated today,
without inventing scope Decision 2 didn't ask for and without silently
dropping the third.

**`handling` is EXPLICITLY, DISCLOSED-not-attempted in H1** — not
silently omitted. Two honest options exist for a future increment, named
here but not decided:
- (a) Wait for a real `edge.protection.handling` producer to exist (a
  currently-unstaffed, unscoped future analyzer per
  `handling-analyzer.js`'s own header) before this dimension can be gated
  at all, matching Decision 2's literal text; or
- (b) Reframe `handling`'s own slice of the gate around `flow.handling`'s
  actual vocabulary — e.g., "the engine asserts `masked`; does removing
  the masking call flip it to `raw`?" — a structurally DIFFERENT check
  from "asserts protected, must not overstate," since `HANDLING_VALUES`
  has no `protected`/`unprotected` axis at all. This is a real, disclosed
  design fork, not resolved here — whoever plans a `handling` increment
  must choose (a) or (b) explicitly, and should re-read this section
  before assuming Decision 2's prose settles it (it does not; it was
  written before this gap was discovered).

## Recommended H1 design (grounded in the real code above)

- **New `bench/protection-verdict/runner.mjs`**, mirroring
  `bench/mutation/runner.mjs`'s shape: a `CASES` array of self-contained
  fixtures, `{id, dimension: 'transit' | 'atRest', class: 'baseline' |
  'metamorphic' | 'adversarial', expectVerdict: 'protected' |
  'unprotected' | 'unknown', expectEvidenceGrade, file, why, code}`.
  `class: 'adversarial'` cases are the mutation targets Decision 2 calls
  for: a case whose BASE form the engine marks `protected` on the target
  dimension, paired with the SAME case's adversarial form (TLS-
  verification-disabled variant for transit; missing-encryption variant
  for atRest) that must flip away from `protected`. Given `bench/
  mutation/`'s own precedent has no separate base/mutant FILES (each case
  is self-contained, distinguished by `class`), the cleanest mirror is:
  each transit/atRest scenario contributes TWO cases sharing an `id`
  prefix — a `-base` (`class: 'baseline'`, asserts the real `protected`
  verdict, this is Decision 2's own DENOMINATOR member) and a `-mutant`
  (`class: 'adversarial'`, asserts the verdict is NOT `protected`) —
  confirm this pairing convention against `bench/mutation/`'s own exact
  `id` patterns before implementing, don't invent a new one if theirs
  already has a clean convention.
- **Pass/fail criterion**, directly from Decision 2's own numerator/
  denominator: for every `-base` case (a fixture the engine marks
  `protected`), the paired `-mutant` case's verdict must NOT be
  `protected` — a failure to flip is a false-protected defect, scored and
  reported by name/dimension, exit 1 if any exist. `evidenceGrade`
  overstatement (Decision 2's second numerator clause) needs its own
  explicit cases too — e.g. a `declared`-only transit signal (a manual
  service-map assertion with no code/config backing) must never render
  as `code`/`code_and_config` strength; confirm whether any REAL producer
  today can even emit a `declared`-grade transit/atRest verdict before
  writing this class of case (if none can yet, this half of the gate is
  also honestly empty for now — check, don't assume).
- **Wiring**: `scanner/package.json` gains `"bench:protection-verdict:check":
  "node ../bench/protection-verdict/runner.mjs"`, mirroring
  `bench:mutation:check`'s own entry exactly. `scripts/release-check.mjs`
  gains one `CHECKS` entry (`{id: 'protection-verdict-gate', title, slow:
  true, remedy}`, mirroring `mutation-gate`'s own entry) plus one
  `evaluate('protection-verdict-gate', () =>
  runNpmGate('bench:protection-verdict:check'))` call in `main()` —
  `runNpmGate` is a bare `spawnSync('npm', ['run', script])`, no new
  mechanism needed. **Re-verified directly (correcting the research
  pass that preceded this document): `bench:mutation:check` IS wired
  into BOTH `scripts/release-check.mjs` (`mutation-gate`, line ~822) AND
  `scripts/pre-push-gate.mjs` (`mutation-gate`, `CHECKS` entry at line
  ~154)** — matching the root `CLAUDE.md`'s own documented pre-push-gate
  list. Given H1's own corpus is expected to be small (a handful of
  transit/atRest base+mutant pairs, not `bench:layer-recall`-scale),
  mirroring `mutation-gate` into BOTH gates is the right default —
  `pre-push-gate.mjs` gets its own matching `CHECKS` entry alongside
  `mutation-gate`, `release-check.mjs` gets the entry described above.
  Re-confirm the corpus stays cheap (sub-second to low-seconds) before
  committing to both at implementation time; if it grows large, dropping
  to release-only (matching `layer-recall-gate`/`provenance-accuracy-gate`,
  which are release-only per the root `CLAUDE.md`'s own pre-push-gate
  list) is the fallback.

## What this does NOT do

`handling`'s own dimension (disclosed above, deferred to a future
increment once the (a)/(b) fork is resolved). C2/C3's storage-IaC/
database-column atRest evidence sources (still unbuilt — H1's `atRest`
corpus can only exercise the application-layer encrypt-before-store
pattern C1 actually detects). `flow.policyVerdict`'s own correctness (a
DIFFERENT gate, if one is ever needed — Sub-project G's own territory,
not protection verdicts). Any language beyond JS/TS.

## Recommended next step

Write H1's implementation plan following this scoping's own boundary —
transit + atRest only, gated into both `release-check.mjs` and
`pre-push-gate.mjs` mirroring `mutation-gate`'s own dual wiring, with
`handling` explicitly named as future, disclosed work (the (a)/(b) fork
above, not resolved here).
