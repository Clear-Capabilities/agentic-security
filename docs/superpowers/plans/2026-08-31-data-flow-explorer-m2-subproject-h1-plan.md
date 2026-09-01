# Milestone 2, Sub-project H, increment 1: false-protected release gate for `transit`/`atRest`

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-h-scoping.md`.
That document corrected Decision 2's own three-dimension framing —
`edge.protection.handling` is never written by any code today, so its
slice of the gate is deferred — and recommended H1 score `transit` and
`atRest` only, mirroring `bench/mutation/runner.mjs`'s real, verified
mechanism. This plan implements H1.

## What already exists (confirmed by direct read, this session, HEAD `0de41d82`)

- **`bench/mutation/runner.mjs`'s real scoring mechanism** (re-verified
  directly, correcting the scoping doc's own tentative "-base"/"-mutant"
  pairing guess): there is **no explicit pairing at runtime**. Every case
  is an independent object in one `CASES` array, scored independently
  against its own `expected` value:
  ```js
  for (const c of CASES) {
    const v = await verdictFor(c, tmpRoot);   // writes c.code to a temp dir, runs the real pipeline
    const verdictOk = /* v's actual outcome === c's own expected outcome */;
    if (!verdictOk) failures++;
  }
  // ...
  if (failures) process.exit(1);
  ```
  "Pairing" is achieved only by CONVENTION — a scenario contributes one
  `class: 'baseline'`/`'metamorphic'` case (expects the protected
  verdict) and one or more `class: 'adversarial'` cases (expects it to
  NOT hold), sharing a readable `id` prefix (e.g.
  `adversarial-sanitizer-removed`) for humans, not for the runner. **H1's
  own runner must copy this exact shape — independent per-case scoring,
  no pairing mechanism to build.**
- **Real, confirmed verdict producers and their exact invocation**
  (`test/lineage/transit-protection.test.js`,
  `test/lineage/at-rest-protection.test.js`, `bench/data-lineage/
  runner.mjs`, all re-verify against current files before trusting line
  numbers cited elsewhere in this plan):
  ```js
  import { parseJsFile } from '../../src/ir/parser-js.js';
  import { buildCallGraph } from '../../src/ir/callgraph.js';
  import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';

  function irOf(files) {
    const perFile = {};
    for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
    return buildCallGraph(perFile);
  }
  const cg = irOf({ 'a.js': code });
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '...',
    // transit cases only:
    transitEvidenceByFile: scanTransitEvidence({ 'a.js': code }),
  });
  ```
  `scanTransitEvidence` is exported from `scanner/src/lineage/
  transit-protection.js` — import it directly in the bench runner rather
  than going through `buildLineageGraph`'s scan-facing wrapper, matching
  this plan's own single-file-fixture shape (no `opts.scanRoot`/policy
  file needed here, unlike a full scan).
- **`edge.protection.transit`**: `resolveTransitProtectionForSite(site,
  transitEvidenceByFile)` — `protected`/`code` for a literal `https://`
  with no nearby `crypto-tls-no-verify`/`crypto-tls-version` finding;
  `unprotected`/`code` for `http://` OR a nearby TLS-disable finding
  overriding an `https://` literal; `undefined` (stays default
  `not_assessed`) for a dynamic destination or non-`external-api`
  category — re-verify this exact behavior against
  `transit-protection.js`'s current code before writing case
  expectations, don't rely solely on this citation.
- **`edge.protection.atRest`**: inline in `graph-builder.js`'s
  flow-construction loop — `classifyHandling(p, callGraph).handling ===
  'encrypted' && snk.kind === 'store'` → `{verdict: 'protected',
  evidenceGrade: 'code'}`; default otherwise. Requires a real
  `transform-catalog.js`-recognized `encrypt`-kind call directly on the
  path to a `store`-kind sink (`database`/`file`/`object-storage`/
  `cache`/`client-storage`/`backup`/`export`) — copy a real recognized
  encrypt callee from `transform-catalog.js`'s own `examples[]` (e.g.
  `crypto.createCipheriv`), don't invent an unrecognized name.
- **Release-gate wiring pattern** (`scripts/release-check.mjs`,
  `scripts/pre-push-gate.mjs`, `scanner/package.json` — re-verify exact
  line numbers before editing): `mutation-gate`'s own `CHECKS` entry
  exists in BOTH files (re-confirmed directly, correcting an earlier
  research-pass error), evaluated via `runNpmGate('bench:mutation:check')`
  / the pre-push gate's equivalent helper — a bare `spawnSync('npm',
  ['run', script])`, pass = exit 0. `scanner/package.json` has
  `"bench:mutation:check": "node ../bench/mutation/runner.mjs"`.

## Scope for this increment

1. **New `bench/protection-verdict/runner.mjs`**, structurally mirroring
   `bench/mutation/runner.mjs` as closely as the different domain allows:
   - Header comment explaining the WHY (mirrors `bench/mutation/`'s own
     header structure): this gate measures whether a `protected`
     verdict tracks real evidence, per Decision 2 (§14 of the PRD) —
     score is false-protected RATE among the engine's own `protected`
     claims, not detection count.
   - `CASES` array, each case: `{id, class: 'baseline' | 'metamorphic' |
     'adversarial', dimension: 'transit' | 'atRest', expectVerdict:
     'protected' | 'unprotected' | 'unknown' | 'not_assessed',
     expectEvidenceGrade (optional, only asserted when present — see
     item 3), file (default `'a.js'`), why, code}`.
   - At minimum, cover per dimension: one `baseline` (a real fixture the
     engine correctly marks `protected`), 1-2 `metamorphic` variants
     (semantics-preserving rewrites — rename a variable, reformat the
     call — verdict must NOT move off `protected`), and 2-3
     `adversarial` variants (semantics-changing near-misses — the exact
     failure modes named in the PRD's own §14.1 worked examples: for
     transit, `http://` carrying regulated data, and `https://` with
     certificate verification disabled nearby; for atRest, no encryption
     call at all, AND — this is FR-402's own explicit anti-pattern guard,
     already proven live by `at-rest-protection.test.js`'s own `C1/3`
     test — an `encrypt`-recognized call present in the SAME
     file/function but NOT on the actual flow's path to the store write,
     which must NOT make the gate pass).
   - `verdictFor(c)`: build the graph per the invocation shape above,
     locate the edge the case's own scenario targets (the case can name
     which edge — e.g. by asserting there is exactly one edge of the
     relevant kind in a deliberately minimal single-flow fixture, the
     same "keep the fixture minimal and unambiguous" discipline every
     `test/lineage/*.test.js` file in this package already uses), read
     `edge.protection[c.dimension]`.
   - Scoring: independent per-case, `actual.verdict === c.expectVerdict`
     (mirroring `bench/mutation/`'s own `verdictOk` shape exactly — no
     pairing mechanism). Print a results table (case/class/dimension/
     actual/expected/PASS-FAIL), a per-class summary line
     (metamorphic-must-hold, adversarial-must-flip — mirroring `bench/
     mutation/`'s own two summary lines), `process.exit(1)` on any
     failure.
2. **`scanner/package.json`**: add `"bench:protection-verdict:check":
   "node ../bench/protection-verdict/runner.mjs"`.
3. **`scripts/release-check.mjs`**: one new `CHECKS` entry (`{id:
   'protection-verdict-gate', title: '...', slow: true, remedy: '...'}`,
   mirroring `mutation-gate`'s own entry structure) plus one
   `evaluate('protection-verdict-gate', () =>
   runNpmGate('bench:protection-verdict:check'))` call in `main()`,
   placed near `mutation-gate`'s own call.
4. **`scripts/pre-push-gate.mjs`**: the matching `CHECKS` entry,
   mirroring `mutation-gate`'s own entry in this file exactly (same
   shape, same helper). Confirm the corpus runs fast (sub-second to a
   few seconds — `bench/mutation/`'s own ~50-case corpus runs in
   ~0.85s) before finalizing this; if H1's own corpus is meaningfully
   slower once written, drop this file's entry and keep H1 release-gate-
   only (matching `layer-recall-gate`'s own release-only placement), and
   say so plainly in the final report rather than silently degrading
   pre-push gate performance.
5. **`evidenceGrade`-overstatement cases (Decision 2's second numerator
   clause)** — before writing these, confirm whether any REAL producer
   today can emit a `declared`-grade transit/atRest verdict at all
   (`transit-protection.js`/the inline `atRest` block both currently
   only ever emit `evidenceGrade: 'code'` when they emit `protected` at
   all — re-verify this directly). **If nothing can produce a
   `declared`-grade `protected` verdict yet, this half of the gate has
   the same permanently-zero-denominator problem the scoping doc found
   for `handling` — do not invent a synthetic producer to test against.
   Disclose this explicitly in the new runner's own header comment and
   in this increment's final report, exactly the way `handling`'s own
   gap was disclosed rather than silently worked around**, and skip
   writing evidence-grade-overstatement cases for H1.

## Do NOT touch

`bench/mutation/runner.mjs` (read-only reference/pattern only —
never edit it or add cases to it; this is a NEW, separate corpus).
`bench/data-lineage/` (read-only reference for its `expectedProtection`
field's own documented "recorded, never asserted" status — do not wire
H1's own scoring into that runner; H1 is a paired-mutation mechanism,
`bench/data-lineage/`'s is single-shape scoring, and conflating them was
explicitly rejected in the scoping doc). `edge.protection.handling` /
`flow.handling` (explicitly deferred — the scoping doc's own (a)/(b)
fork remains unresolved, not this increment's to pick). `transit-
protection.js`, the inline `atRest` block in `graph-builder.js`, and
`classifyHandling` itself (read-only — this increment tests their
OUTPUT, never modifies their logic). C2/C3 (storage/IaC and DB-column
at-rest detection — still unbuilt; H1's `atRest` cases can only exercise
the application-layer encrypt-before-store pattern C1 actually detects).

## Test plan

This IS the test — `bench/protection-verdict/runner.mjs` is itself the
deliverable, not a thing with its own separate unit-test file (matching
`bench/mutation/runner.mjs`'s own precedent — no
`test/bench-mutation.test.js` exists for it either, re-verify this by
checking `scanner/package.json`'s `test:*` scripts don't already
reference a `bench/mutation`-adjacent test file before assuming). Verify
by running:
1. `node ../bench/protection-verdict/runner.mjs` from `scanner/` directly
   — confirm real exit 0 with every case passing on the CURRENT engine.
2. A deliberate regression proof: temporarily comment out
   `transit-protection.js`'s TLS-disable-override logic (or the atRest
   `snk.kind === 'store'` guard) and re-run the gate — confirm it now
   exits 1 with the correct case(s) named as failing, then revert the
   temporary change. This is the "prove both directions" discipline the
   root `CLAUDE.md`'s own verification section requires for anything
   that gates.
3. `npm run bench:protection-verdict:check` (from `scanner/`) — confirm
   the npm script wiring itself works, real exit code.
4. `node ../scripts/release-check.mjs` (or its documented fast/full
   invocation — check `package.json`'s own `release:check` script name
   first) — confirm the new `protection-verdict-gate` entry appears and
   passes.
5. If item 4 of "Scope for this increment" is kept: confirm the pre-push
   gate itself still runs and passes with the new check included — the
   coordinator will run a real `git push --dry-run`-equivalent check (or
   simply re-run `scripts/pre-push-gate.mjs` directly) during review.
6. Full `npm run test:lineage` and `npm test`, green, real captured exit
   codes — this increment shouldn't touch any `src/`/test file at all
   (it's bench-only, plus two release-gate scripts and one package.json
   line), so no regression is expected, but confirm anyway.

## Explicitly deferred

`handling`'s own dimension (the scoping doc's (a)/(b) fork — a future
analyzer producing real `edge.protection.handling` verdicts, or a
reframing around `HANDLING_VALUES`' own vocabulary — neither decided
here). `evidenceGrade`-overstatement cases, if item 5 above finds no
real `declared`-grade producer exists yet. C2/C3's own at-rest evidence
sources. Any language beyond JS/TS.
