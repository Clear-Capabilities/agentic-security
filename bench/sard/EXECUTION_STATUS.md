# SARD 80% F1 Execution PRD — Implementation Ledger

Source: `SARD_80_F1_EXECUTION_PRD.md` (repo root, untracked per this repo's PRD
convention — ask the maintainer for the current copy if missing). This ledger
is the persistent execution record for that PRD, maintained by an autonomous
`/loop` session. Status values: `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`,
`IMPLEMENTED_UNVERIFIED`, `VERIFIED`.

**Rule (same as the sibling `IMPLEMENTATION_STATUS.md` ledger's own rule):**
`VERIFIED` means a command was actually run in the current session/turn and
its output was read — never assigned because "the code exists." Every
`VERIFIED` line in this file must be followed by the exact command and the
real number/result it produced.

**Rule:** no answer-key signals, ever. No item in this ledger may be marked
done on the strength of a detector that reads `FLAW` comments, filenames,
case ids, method names, or bench-shape heuristics. See the PRD's own
Section 1 for the full integrity rules — they bind every entry below.

---

## How to read this file

Each workstream (W0-W6) lists its concrete tasks. A task is `VERIFIED` only
once its own acceptance evidence (a real command + real output) is recorded
inline. Milestones (M1-M3) are separate gates run on `--split test`, at most
once per milestone, by the harness — see the PRD Section 6.

---

## W0 — Measurement integrity

| # | Task | Status |
|---|---|---|
| W0.1 | Truncation fail-closed in `bench-realworld.js` + `score-php.mjs` | VERIFIED |
| W0.2 | `scannedFiles`/`expectedFiles` added to `results[0]` | VERIFIED |
| W0.3 | Batch corpus scanning per-CWE-dir / fixed-size, merge via `merge-results.mjs` | VERIFIED |
| W0.4 | Scan surface = gold surface (exclude unscored CWE dirs from scan for scoring) | VERIFIED |
| W0.5 | Performance profiling pass (index-based catalog matching for every match.type) | IN_PROGRESS |
| W0.6 | Per-CWE key hygiene self-test (no tp=fp=fn=0 rows) | VERIFIED |
| W0.7 | Variant-class breakdown in `macro-score.mjs` report | VERIFIED |

**W0 acceptance:** full dev run per language completes with zero truncation,
report shows per-variant recall, reported P/R match a hand-checked 100-entry
sample. Status: IN_PROGRESS — zero-truncation + per-variant recall both real
and verified for Java (`batch-scan.mjs`, see W0.3 log below); C# not yet
independently re-verified with batching (same code path, expected to work
identically, not yet run); the 100-entry hand-check is still a manual
spot-check that has not been done. Not blocking W1 — the measurement
instrument is real and trustworthy for the work ahead.

## W1 — Structural class resolution

| # | Task | Status |
|---|---|---|
| W1.1 | `ir.classes` emission for PHP/Python/Ruby/Go/Kotlin parsers (Java/C#/Rust already emit it) | NOT_STARTED |
| W1.2 | `callgraph.js` `classMethods` from structural class facts, not `[A-Z]` regex | VERIFIED |
| W1.3 | `class-hierarchy.js` `methodOwners`/`typeOfVar` from structural facts | VERIFIED |
| W1.4 | `dataflow/engine.js` `_resolveMemberCalleeViaCHA` handles flat dotted-string callees | NOT_STARTED (analysis below: not on the critical path for Java/C#) |
| W1.5 | Scrambled-name regression suite for every session-landed field/collection/dispatch fix | NOT_STARTED |

**W1 acceptance:** on dev, Java variants 41/42/45/51-54/61-68/81 each move
from current 0-28% recall to >=60%, measured by the W0 variant report; C#
equivalents likewise; holdout and cve-replay gates unchanged. Status: NOT_STARTED.

### 2026-09-15 — W1.2/W1.3 implemented, anti-overfit gates clean, SARD verification in progress

- **The root-cause fix**: `callgraph.js`'s `classMethods` index and
  `class-hierarchy.js`'s `methodOwners` both gated on `/^[A-Z]/` over a
  qid segment or class name to decide "is this a real class" — under
  `--scramble-identifiers`, every Juliet class becomes a lowercase
  `case_<hash>` token, so this NEVER matched and both indexes stayed empty
  for the entire scrambled corpus, even though the parser's own `ir.classes`
  structural output (built independently, from parsing `class X {}`
  declarations, not from capitalization) was correct the whole time.
- Fixed both to check `ir.classes`-derived real class-name sets FIRST
  (`knownClassNamesByFile` in callgraph.js; the pre-existing `classes` Map in
  class-hierarchy.js, which was already built from `ir.classes` earlier in
  the same function) and fall back to the old `/^[A-Z]/` heuristic only for
  languages that don't emit `ir.classes` yet (JS/Python/PHP/Ruby/Go/Kotlin —
  W1.1, still not started) — so nothing regresses ahead of that work.
- **Verified NOT needed (analysis, not a fix)**: W1.4's target,
  `_resolveMemberCalleeViaCHA`, only ever handles the Babel `{kind:'member'}`
  callee shape (JS-only) — hand-rolled parsers (Java/C#) emit a flat
  dotted-string callee instead, which `_resolvableCalleeName` returns
  UNCHANGED before `_resolveMemberCalleeViaCHA` is ever reached. For Java/C#,
  a local-variable-qualified callee like `b.action` is rewritten to
  `RealClass.action` (or, under scrambling, `case_xyz.action`) by
  `_localVarConstructedTypes`/`_rewriteVarTypeCallees` — present in BOTH
  `parser-java.js` and `parser-cs.js`, confirmed to key SOLELY on
  `src.isNew`, no capitalization test anywhere in either. That rewritten
  string then resolves via `classMethods` — the SAME index W1.2 just fixed.
  So W1.4 is real but JS-scoped and not on the Java/C# critical path this
  PRD is measuring; left NOT_STARTED, not blocking.
- Anti-overfit gates, all run this session, all clean: `npm run
  test:dataflow` (1203/1203 pass), `npm run bench:mutation:check` (35/35
  verdict-flip correct), `npm run bench:layer-recall:check` (122/220 taint,
  EXACTLY at baseline — no regression, no unrecorded gain), `npm run
  bench:cve-replay:check` (220/220 baselined entries, no drift).
- Real SARD verification: `node bench/sard/scripts/batch-scan.mjs --app
  sard-juliet-java-strict --blind --scramble-identifiers --deep --split dev
  --json` → tp=1320 (+16), fp=507 (+16), recall=44.3% (+0.5pp), macroF1=36.5%
  (+0.1pp vs the W0.3 baseline). Real but SMALL aggregate movement — far
  short of the PRD's own "variants 41/42/45/51-54/61-68/81 each move to
  >=60% recall" expectation for this workstream alone.
- **Investigated the shortfall directly rather than accepting a
  disappointing number at face value.** Per-variant table showed only
  variant 45 moved (30.4%→47.8% recall, +16 tp — accounting for the ENTIRE
  aggregate delta); every other named variant (41/42/51-54/61-68/81) was
  bit-for-bit identical before and after. Built an isolated, controlled
  fixture reproducing Juliet's exact abstract-dispatch shape (`case_base b =
  new case_bad(); b.action(data);`, scrambled-style names) — **the fix
  correctly resolves it and produces the finding**, confirmed via direct IR/
  callgraph inspection (`case_bad.action` correctly rewritten and present in
  `classMethods`) AND an end-to-end scan. Re-confirmed on ACTUAL, unmodified
  scrambled Juliet source copied out of the corpus cache (a real CWE-90
  variant-81 LDAP file, then a real CWE-89 variant-81 SQLi file that IS in
  the dev split) — **both fire correctly in isolation.**
- **So why doesn't the fix show up in the full-corpus aggregate?** Found the
  real cause: `runTaintEngine`'s per-function analysis loop silently
  `break`s once it has processed `AGENTIC_SECURITY_DEEP_FN_LIMIT` functions
  (default 5000) — and Java CWE-89 ALONE has 3668 files / **17604
  functions**, ~3.5x the cap. Roughly 70% of that one CWE directory's
  functions are never analyzed by the deep engine at all, in either
  direction (pre- or post-W1-fix), regardless of whether resolution would
  succeed. This was completely invisible to every existing truncation signal
  (W0.1 only checked wall-clock budget + per-file skip/timeout counts) — a
  real gap in W0.1's own coverage, found by refusing to accept "the fix
  didn't move the number" without tracing why.
- **Fixed the blind spot**: `dataflow/engine.js`'s `runTaintEngine` now
  pushes an `ir-taint-fn-limit:` info finding (same convention as the
  existing `ir-taint-timeout:` marker) whenever `fnList.length > fnLimit`.
  Threaded into `truncated`/`truncationDetail.fnLimitExceeded` in
  `bench-realworld.js`, `score-php.mjs`, and `batch-scan.mjs`'s aggregation —
  extends W0.1, doesn't replace it. Verified: forcing
  `AGENTIC_SECURITY_DEEP_FN_LIMIT=1` on the real dev-split fixture produces
  the finding (`"analyzed only 1/6 functions"`); real dataflow suite
  (1203/1203), mutation (35/35), layer-recall (122/220, exact baseline), and
  cve-replay (220/220, no drift) all re-run clean after this engine change.
- **W1.2/W1.3 → VERIFIED** (the class-resolution fix itself is real, correct,
  and independently proven on genuine Juliet content — that is what these
  ledger items asked for). **Not yet VERIFIED: the PRD's own >=60%-recall
  target for this workstream** — reaching it requires re-measuring with a
  function limit that doesn't truncate 70% of a large CWE directory, which
  is real follow-up work (raise `AGENTIC_SECURITY_DEEP_FN_LIMIT` for SARD
  runs and/or extend W0.3's batching to sub-split large CWE directories by
  source/sink combination, not just by CWE number) — tracked as the
  immediate next task, not assumed away.

## W2 — Interprocedural completeness

| # | Task | Status |
|---|---|---|
| W2.1 | Control-flow gating: constant-fold static/instance final fields + trivially-constant helper returns | NOT_STARTED |
| W2.2 | Multi-file field/chain taint (51-54, 61, 66-68) depth-aware fixed point | NOT_STARTED |
| W2.3 | Collection element taint verification (71-74) — typed reads, for-each binding | NOT_STARTED |
| W2.4 | Return-value/parameter variants (41, 42, 61, 62) under scrambled names | NOT_STARTED |
| W2.5 | Abstract/interface dispatch via declared base when receiver is a parameter (81, 82) | NOT_STARTED |

**W2 acceptance:** no flow-variant class below 70% recall on dev for Java and
C#. Status: NOT_STARTED. Blocked on W1.

## W3 — Precision: taint authority and validation guards

| # | Task | Status |
|---|---|---|
| W3.1 | Taint-authority rule: regex/structural taint-family findings defer to the taint engine where it ran | NOT_STARTED |
| W3.2 | Guard-predicate narrowing (branch-scoped taint removal after a validating predicate) | NOT_STARTED |
| W3.3 | Proven-clean ledger + `--include-proven-clean` flag | NOT_STARTED |
| W3.4 | PHP FP-by-sanitizer gated metric (<10% unattributed) | NOT_STARTED |

**W3 acceptance:** dev precision >=85% Java, >=75% C#/PHP; mutation gate
grown by >=15 guard/parameterization cases; holdout precision unchanged or
better. Status: NOT_STARTED. Blocked on W1/W2 (needs real recall to measure
precision against).

## W4 — Per-CWE coverage sweep

| # | Task | Status |
|---|---|---|
| W4.J1 | Java CWE-113 header/cookie injection | NOT_STARTED |
| W4.J2 | Java CWE-36/23 file constructors | NOT_STARTED |
| W4.J3 | Java CWE-643 XPath | NOT_STARTED |
| W4.J4 | Java CWE-80/81/83 servlet writer XSS | NOT_STARTED |
| W4.J5 | Java CWE-601, CWE-470, CWE-134 | NOT_STARTED |
| W4.J6 | Java CWE-90 LDAP re-measure (family key already fixed this session) | NOT_STARTED |
| W4.J7 | Java crypto families 319/321/325/327/328/329/330/338 | NOT_STARTED |
| W4.C1 | C# CWE-113, CWE-80/81/83 | NOT_STARTED |
| W4.C2 | C# CWE-89 remaining sinks (SqlDataAdapter etc, already partially landed) | NOT_STARTED |
| W4.C3 | C# CWE-36/23, CWE-643, CWE-470, CWE-134, CWE-601, CWE-78, CWE-90 | NOT_STARTED |
| W4.C4 | C# CWE-313/314/315 cleartext storage | NOT_STARTED |
| W4.C5 | C# CWE-523/539 cookie/transport, CWE-259/321/256/261 credentials | NOT_STARTED |
| W4.Q | Structural/quality CWE triage (decide honest-detector vs exclude-from-scan-surface per family) | NOT_STARTED |

**W4 acceptance:** no scored CWE with support >=20 below 50% F1 on dev.
Status: NOT_STARTED. Blocked on W1/W2/W3.

## W5 — PHP-specific

| # | Task | Status |
|---|---|---|
| W5.1 | Sources: nested fgets/fopen, fread, file_get_contents, shell output, unserialize, $_SERVER, class getters | NOT_STARTED |
| W5.2 | Sinks: ldap_search/list (CWE-90), ->xpath()/DOMXPath (CWE-91), include/require scoring (CWE-98), eval family (CWE-95) | NOT_STARTED |
| W5.3 | CWE-862 detector design (post-W3, needs guard-predicate distinction) | NOT_STARTED |
| W5.4 | Guard matrix (sanitizer x sink x quote-context) test file + FP triage | NOT_STARTED |

**W5 acceptance:** PHP dev macro-F1 >=75% before the milestone test run.
Status: NOT_STARTED. Blocked on W3.

## W6 — Rust (out of SARD scope, tracked for honesty only)

No SARD/Juliet suite exists for Rust. Measured via `bench:cve-replay` and
`bench:layer-recall` only. Nothing in this ledger claims a Rust F1.

---

## Milestone gates (TEST split, run once each, by the harness)

| Gate | Java target | C# target | PHP target | Status |
|---|---|---|---|---|
| M1 (after W0+W1) | >=45 | >=25 | >=25 | NOT_STARTED |
| M2 (after W2+W3) | >=65 | >=50 | >=50 | NOT_STARTED |
| M3 (after W4+W5) | >=80 | >=80 | >=80 | NOT_STARTED |

---

## Baseline (measured 2026-09-14, dev split, commit 4ce6c09e)

Command: `node test/benchmark/realworld/bench-realworld.js --app sard-juliet-{java,csharp}-strict --blind --scramble-identifiers --deep --split dev --json | node ../bench/sard/scripts/macro-score.mjs` (PHP: `node ../bench/sard/scripts/score-php.mjs --deep --split dev --json | node ../bench/sard/scripts/macro-score.mjs`)

| Language | macro-F1 | micro-F1 | P | R |
|---|---|---|---|---|
| Java | 33.5% | 50.3% | 71.7% | 38.8% |
| C# | 15.1% | 17.1% | 39.9% | 10.9% |
| PHP | 21.2% | 17.2% | 24.2% | 13.4% |

## Session log

### 2026-09-14 — loop started

- Ledger created. Status dashboard published (see repo README or ask for the
  URL — recorded in the loop's own session notes, not duplicated here since
  URLs are not durable ledger content).
- Beginning W0.1 (truncation fail-closed).

### 2026-09-15 — W0.1 implemented, verification in progress

- `bench-realworld.js`: added `truncated`/`truncationDetail` to the per-app
  result (from `scan._scanMeta.{filesTimedOut,filesSkipped,filesDenseSkipped}`
  plus a scan for the deep engine's own `ir-taint-timeout:` finding id — none
  of these read any answer-key signal, only the scan's own execution-coverage
  metadata). Added `--allow-truncation` opt-out; default is
  `process.exitCode = 1` when any app truncated, computed only in the process
  that owns the FINAL aggregated result (guarded off in isolated per-app
  children via `AGENTIC_SECURITY_BENCH_CHILD=1`, since the isolation harness
  treats any non-zero child exit as a crash and would otherwise discard the
  truncated-but-informative result instead of surfacing it).
- `score-php.mjs`: same signals, accumulated per-case (this harness scans one
  Juliet case dir at a time, not the whole corpus in one call). Same
  `--allow-truncation` opt-out and fail-closed default.
- `macro-score.mjs`: also fails closed independently on `r.truncated` in its
  input, because a shell pipeline's exit code is the LAST command's by
  default (no `pipefail`) — this is the layer a milestone-gate command
  actually reads, so it can't rely on the upstream producer's exit code alone.
  Verified this turn with synthetic `--input` JSON:
  `node bench/sard/scripts/macro-score.mjs --input /tmp/fake-truncated.json`
  → exit 1, prints `✗ 1 app(s) truncated`; same input + `--allow-truncation`
  → exit 0. Real command run, output read, this session.
- VERIFIED: `node test/benchmark/realworld/bench-realworld.js --app
  sard-juliet-java-strict --blind --scramble-identifiers --split dev --json`
  (non-deep, from `scanner/`) completed exit 0, no leftover process (`ps aux`
  clean afterward), and its JSON result carries `"truncated": false,
  "truncationDetail": {"filesTimedOut": 0, "filesSkipped": 0,
  "filesDenseSkipped": 0, "deepBudgetExceeded": false}` — a real, untruncated
  scan correctly reports itself as such (F1=47.0% P=76.5% R=33.9% on this
  non-deep dev run, not itself a milestone number). Combined with the
  synthetic-input `macro-score.mjs` exit-1/exit-0 check above, both directions
  of W0.1's fail-closed behavior are now real-command-verified this session.
  W0.1 → VERIFIED.

### 2026-09-15 — W0.2 verified

- Added `scannedFiles` (engine's own `scan.filesScanned`) and `expectedFiles`
  (distinct files in the gold set for the current split) to both harnesses'
  result objects — `scanned` stays as-is (findings-kept, in bench-realworld.js;
  case count in score-php.mjs) rather than renamed, to avoid breaking every
  consumer of the existing field; the new fields exist specifically so a file
  count is never again misread from it.
  Verified: `node test/benchmark/realworld/bench-realworld.js --app
  sard-juliet-java-strict --blind --scramble-identifiers --cwe CWE-89 --split
  dev --json` → `scannedFiles: 3669, expectedFiles: 732, scanned: 334,
  expectedTotal: 780` — four visibly different numbers, confirming `scanned`
  was never a file count. `node bench/sard/scripts/score-php.mjs --split dev
  --limit 10 --json` → `scannedFiles: 10, expectedFiles: 10, truncated:
  false`. SARD unit suite (55 tests) still green after this change too.
  W0.2 → VERIFIED.

### 2026-09-15 — W0.6 already satisfied by prior work, verified this session

- The `CWE89` vs `CWE-89` key merge and the "no tp=fp=fn=0 row" self-test the
  PRD asks for were already landed and committed before this ledger existed
  (`test/sard-cwe-key-merge.test.js`, `test/sard-macro-score-support-floor.test.js`
  — the latter's `perCweTable: an entry can never be constructed with
  tp=fn=fp=0` test IS this self-test: `perCwe` entries in both harnesses are
  only ever created via `(perCwe[cwe] ??= {tp:0,fp:0,fn:0})[k]++`, so a
  zero-row can never be constructed from real scan data by construction, and
  the test documents/pins that invariant against a future refactor).
  Re-ran both files this session as part of the 55-test SARD suite (green,
  see W0.1/W0.2 log entries above) — real command, real output, this session.
  No new code needed. W0.6 → VERIFIED.

### 2026-09-15 — W0.7 implemented and verified

- `macro-score.mjs` now classifies every `tps`/`fns` entry by Juliet's public
  filename convention (`variantOfFile`/`variantBucket`/`variantRecallTable`,
  all exported) and adds a per-variant recall table (sorted worst-first) to
  both `latest.json` (`variantRecall` per app) and `latest.md`. Read ONLY by
  the benchmark controller off the gold entry's own filename — the scanner
  never sees or uses a variant number; this is reporting metadata, same
  category as the existing CWE/family grouping. Named buckets are restricted
  to the ranges the PRD itself names (41/42/45, 51-54, 61-75, 81/82); every
  other variant still gets its own exact-number row rather than an invented
  finer taxonomy. Apps with no per-instance `tps[]`/`fns[]` (PHP's scorer)
  report `variantRecall: null` rather than a fabricated table.
  Verified: unit-level with synthetic filenames (correct variant/bucket/
  recall/sort for 01, 22, 53, 81, and a non-Juliet filename correctly
  ignored). End-to-end: `node bench/sard/scripts/macro-score.mjs --input
  /tmp/w02-check.json` (the real CWE-89 dev-split Java result from the W0.2
  verification run) produced a real per-variant table — e.g. variant 15: 0/12
  (0.0%), 54: 14/59 (23.7%), 81: 16/57 (28.1%), 41/45/51/61: 7/24 (29.2%) —
  matching the PRD's own description of the flow-variant recall wall this
  workstream exists to instrument. SARD unit suite (55 tests) still green.
  W0.7 → VERIFIED.

### 2026-09-15 — W0.4 implemented and verified

- `bench-realworld.js`: for Juliet/Juliet-C# apps, the CWE-directory
  exclusion mechanism `--cwe` already used (excludes from BOTH the scan
  surface and GT — see that flag's own header comment) now runs by default,
  keyed off which CWEs the (possibly `--split`-filtered) gold set actually
  covers, not just an explicit `--cwe` list. `--full-corpus` opts out for
  exploratory/W4 work. Findings in a directory with zero gold entries are
  never produced at all, so they can no longer be miscounted as FPs.
  Verified: `node test/benchmark/realworld/bench-realworld.js --app
  sard-juliet-java-strict --blind --scramble-identifiers --split dev --json`
  (same exact command as W0.1/W0.2's baseline, no `--cwe`) now logs
  `gold-surface scoping (PRD W0.4, --full-corpus to disable): excluding
  94/112 CWE directories from the scan itself` and produces `scannedFiles:
  13274, expectedFiles: 2814, tp: 1011, fp: 227, fn: 1967, precision:
  81.66%, recall: 33.95% (unchanged, as expected), f1: 47.96%`. Compared
  against the IDENTICAL command run for W0.1 (before this fix): precision
  76.5% → 81.7% (+5.2pp), F1 47.0% → 48.0%, recall bit-for-bit identical
  (0.33948959032907994 both times) — confirms the fix removes FPs from
  unscored directories without touching real recall. `truncated: false`,
  exit 0. SARD unit suite (55 tests) still green. W0.4 → VERIFIED.

### 2026-09-15 — W0.3 in progress: batch-scan.mjs built, one real bug found and fixed

- Confirmed W0.4 alone is NOT sufficient: `--app sard-juliet-java-strict
  --blind --scramble-identifiers --deep --split dev --json` (the real
  milestone-gate shape) still hit `truncated: true, deepBudgetExceeded: true`
  at 530.7s elapsed against the 300s budget, even after W0.4 cut the scan
  surface to 18/112 CWE directories. W0.3 is genuinely still needed.
- Added `--list-cwes` to `bench-realworld.js` (gold-construction only, no
  scan — prints the distinct CWEs the FULL, possibly `--split`-filtered gold
  set covers) and built `bench/sard/scripts/batch-scan.mjs`, which calls it
  once to discover the CWE list, then runs `bench-realworld.js --cwe <n>`
  once per CWE (its existing `--cwe` flag already scopes both GT and the scan
  surface to one directory), aggregating every batch's result into ONE
  combined result with bench-realworld.js's own result shape.
- **Bug found during verification**: the first aggregation pass used
  `Object.assign(combined.perCwe, r.perCwe)`. `bench-realworld.js` bumps an
  FP's per-CWE row under the FINDING's own claimed CWE (`reportedCwe`), not
  the directory being scanned, so a batch scoped to CWE-643 can still
  contribute FPs under spillover keys like CWE-79/CWE-918/CWE-22 — and more
  than one batch can touch the same spillover key. `Object.assign` silently
  drops every batch's contribution but the last for any shared key, which
  would have corrupted `perCwe` (and therefore macro-F1, which is computed
  from it) while leaving the aggregate tp/fp/fn totals looking fine. Fixed to
  sum `{tp,fp,fn}` per key across batches instead of overwriting.
  Caught by comparing a batch's own logged tp/fp/fn against its perCwe
  breakdown — never shipped as VERIFIED with the bug present.
- Verified: re-ran the non-deep, all-18-CWE batched run with the fix applied.
  `node bench/sard/scripts/macro-score.mjs --input
  /tmp/batch-check-nondeep2.json` → macroF1=35.0%, microF1=48.0%, P=81.7%,
  R=33.9%, CWEs=23 — IDENTICAL to running `macro-score.mjs` against the
  single-shot 18-dir W0.4 baseline (`/tmp/w04-check.json`, same command).
  Aggregate tp/fp/fn (1011/227/1967) also unchanged from the pre-fix run
  (confirming the fix only touched the previously-corrupted perCwe
  breakdown, not the aggregate totals, which were already correct).
  Batched-and-aggregated results are now provably indistinguishable from a
  single-shot scan of the same scope.
- **The actual point of W0.3, verified**: `node bench/sard/scripts/batch-scan.mjs
  --app sard-juliet-java-strict --blind --scramble-identifiers --deep --split
  dev --json` (the real milestone-gate shape, batched) — ALL 18 batches
  completed with `truncated: false` (longest single batch, CWE-89: 154.5s,
  comfortably under the 300s budget; total wall time 517.2s across all 18,
  similar to the single-shot run's 530.7s, but now correctly zero-truncated
  since no INDIVIDUAL batch exceeded its own budget). Real deep-mode numbers
  (first time this session deep mode has run to completion, untruncated, on
  the gold-scoped surface): tp=1304, fp=491, fn=1674, precision=72.6%,
  recall=43.8% (up from 33.9% non-deep — a genuine gain from deep mode
  actually finishing), f1=54.6%. `node bench/sard/scripts/macro-score.mjs
  --input <that file>` → **macroF1=36.4%**, microF1=54.6%, CWEs=24,
  macroF1(support>=5)=55.6%. Per-variant recall table (W0.7) shows real
  signal: variant 15 at 10.4%, 61-75 collection variants at 25%, 51-54
  multi-file at 25-30%, 41/42/45 at 30% — exactly the flow-variant wall
  W1 exists to close. SARD unit suite (55 tests) green. W0.3 → VERIFIED.
- **New fresh Java dev-split macro-F1 baseline (deep, batched, zero
  truncation, commit at time of this run): 36.4%** — supersedes the earlier
  33.5% non-deep/pre-W0.4/pre-W0.3 baseline recorded above. This is the
  number future W1+ work should be measured against for Java.
- W0.5 (performance profiling) downgraded from a hard blocker: W0.3+W0.4
  together already eliminate truncation for the real milestone-gate command
  without any engine-level optimization. A genuine perf win would still cut
  total wall-clock (517s across 18 sequential batches is not fast), but it is
  no longer required for W0's core acceptance. Left IN_PROGRESS/optional
  rather than NOT_STARTED to record that this session's investigation showed
  catalog matching is ALREADY index-based for every match.type (call/member/
  global/annotation all have their own Map-backed index in catalog.js,
  contrary to the PRD's own text at time of writing) — so the PRD's
  suggested lever does not apply; any future perf work here should look
  elsewhere (per-batch IR/deep-engine setup overhead, parallelizing batches)
  rather than re-attempting catalog indexing.
