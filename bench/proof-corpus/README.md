# proof-corpus

Scans large third-party open-source repositories to produce reproducible
evidence about language coverage, detection quality, and operational behaviour
at scale. See the Proof Corpus PRD (removed post-implementation) for the full rationale.

## Running

```bash
cd scanner
npm run build                                          # the bench refuses a stale bundle
node ../bench/proof-corpus/runner.mjs --only ghost,superset
```

Options: `--only <ids>`, `--refresh-pins`, `--no-determinism`, `--out <dir>` (controls only
where `summary.json` is written; raw artifacts always land under the fixed
`bench/proof-corpus/results/raw/`, since that is the only path `.gitignore` covers).

## Pinning

Targets are pinned to full commit SHAs so a re-run months later produces the
same numbers. A target with `"commit": null` is refused; run `--refresh-pins`
to resolve each `ref` to a SHA and rewrite the manifest. Advancing a pin is
therefore always a reviewable diff.

## Clone cache

Clones are blobless (`--filter=blob:none --depth 1`) and live outside the
repository, by default under `~/.claude/agentic-security/proof-corpus-cache`.
Override with `AGENTIC_SECURITY_PROOF_CACHE`. Nothing third-party is ever
committed to this tree.

## What is and is not committed

`results/summary.json` holds aggregate metrics and is committed.
`results/raw/` holds findings and SARIF for live third-party projects and is
gitignored — unreviewed findings against software people run in production are
not ours to publish (PRD §9.1).

## Phase-1 status

Two targets validated end-to-end on 2026-07-25, re-run on 2026-07-25 after a
metric-definition fix (see "Parse-coverage metric correction" below). All
figures below are from that re-run's `results/summary.json`.

| Target | Licence | Parse coverage | Deterministic | Wall | Peak RSS |
|---|---|---|---|---|---|
| ghost | MIT | 94% (javascript 4023/4271, functionless 0) | **no** — see known gaps | 64s | 3315 MB |
| superset | Apache-2.0 | 100% overall — javascript 100% (2613/2616, functionless 0), python 100% (1470/1470, functionless 389) | **no** — see known gaps | 77s | 3487 MB |

All three targets were re-run on 2026-07-25 after the SARIF-capture fix described under
"Determinism was being measured against truncated files" below; the figures in this file are
from that re-run's `results/summary.json`, and the failing-file lists behind the coverage
percentages are enumerated in `GAPS.md`.

Both scans exited with code 3 (per the CLI's exit-code contract: `0` clean,
`1` low/medium, `2` high, `3` critical, `4` error) — a successful scan run
that surfaced critical-severity findings, not a failure.

### Parse-coverage metric correction

The parse-coverage metric originally counted a file as a parse failure if it
declared zero functions, even when the parser returned a valid IR record for
it (an `__init__.py`, a constants module). That is not a parse failure. The
metric now counts `parsed` as "an IR record exists for the file," full stop,
and tracks `functionless` (record exists, zero functions) as a separate,
non-penalized count. See the Proof Corpus PRD §5.4.

**The previously published "Superset Python parse coverage: 74%" was a
measurement artifact, not a parsing problem.** Under the corrected metric,
Superset's Python coverage is **100% (1470/1470)**, with 389 of those files
being function-free (`functionless`) — exactly the kind of file the old
metric miscounted as a failure. There was no Python IR parser bug to
investigate; the earlier "known gap" and its stated follow-up
("investigating the Python IR parser's failure modes") were chasing a number
that measured the wrong thing. Superset now clears the PRD's 85% acceptance
bar (the Proof Corpus PRD §12 acceptance criterion 2) on every language in scope.

### Known gaps surfaced by this run

- **Ghost's JavaScript parse coverage is 94% (4023/4271), and this is a real
  gap, not a metric artifact** (the failing files are listed in `GAPS.md`): `functionless` is 0 for ghost, so the 248
  unparsed files are genuine parse failures under the corrected metric, not
  function-free modules. This is the one figure in this run that the metric
  fix does not explain away.
- **Determinism was being measured against truncated files — fixed, and the
  numbers changed.** The capture path piped the CLI's stdout into a
  `createWriteStream`. The CLI ends every command with `process.exit(code)`,
  and writes to a pipe are asynchronous, so `process.exit` discarded
  everything past the 64 KiB OS pipe buffer. Godot's two SARIFs came out
  **both exactly 65,536 bytes, both ending mid-token**, and the runner
  sha256'd those two identical truncated prefixes and reported
  `identical: true` — a gate that could not fail. Reproduced in isolation
  this session: a child writing 1,000,001 bytes then calling `process.exit`
  yields **65,536** bytes through a pipe and **1,000,001** through a file
  descriptor. `lib/scan.mjs` now hands the child an fd (writes to a regular
  file are synchronous, so exit is flush-safe), and `runner.mjs`'s comparison
  refuses to report determinism from any capture that does not parse as a
  SARIF document with a `runs[]` array. Ghost's captures were never truncated
  (1.36 MB), so only Godot's claim was affected.
- **Neither Ghost nor Superset is byte-deterministic on the re-run.** Ghost:
  1,364,169 vs 1,364,186 bytes. Superset: 1,275,554 vs 1,275,555 bytes —
  Superset's previously reported `identical: true` did **not** reproduce.
  Ghost's diff was previously traced to one finding attributed to
  `apps/admin-x-settings/package.json` in one run and
  `apps/admin-x-framework/package.json` in the other: both manifests declare
  the same dependency, so the scanner has two valid places to attribute the
  same finding and picks non-deterministically between them — consistent with
  unordered iteration over a map or set in the licence-graph code. That a
  target can report `identical: true` on one run and `false` on the next is
  worse than a consistent failure: a `--deterministic` run can pass by
  chance. Nothing in this fix wave touched licence-graph code; this is
  pre-existing scanner behaviour the bench surfaced, not a bench defect. It
  is recorded as an open gap, not fixed here — the determinism check itself
  is not weakened or disabled. Godot, by contrast, IS byte-identical on
  whole, valid captures (183,978 bytes each, 145 results).
- **Call-graph edge resolution is low on both targets**: ghost resolved
  5,819 of 118,356 edges (4.9%); superset resolved 4,004 of 69,959 edges
  (5.7%). This reflects the k=1 monovariant, largely intra-file resolution
  documented in `scanner/src/dataflow/CLAUDE.md`, not a bench defect — a
  genuine finding about cross-file call resolution on large real-world
  repositories.
- **Peak RSS is high on both targets** (~3.32 GB ghost, ~3.49 GB superset),
  reflecting the cost of building IR for parse-coverage measurement across a
  large repository.

The remaining eight targets are in the manifest but unpinned; Phase 2 brings
them online.

## Phase-4 status — Godot (C/C++ IR parser acceptance test)

Godot pinned at commit `159701651ad44335691dcbd632d8074307074c7b` (`master`),
scoped per the manifest to `core, modules, scene, servers, editor` (thirdparty/
and everything else excluded). Deep mode was confirmed active for every run
below — none of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`,
`JENKINS_URL` was set in the shell that ran them, so the CLI's default-on
deep-mode rule applied (`bin/agentic-security.js:385-391`).

**A runner scope bug was found and fixed as part of this run.** The runner
previously scanned only `scope[0]` of a multi-entry `scope` array while
reporting the full array as the declared scope — Godot would have been
measured on `core/` alone (416 C++ files) while the scorecard claimed five
subsystems. `bench/proof-corpus/runner.mjs` now materializes every `scope`
entry as a sibling under one staging root (a real recursive copy, since
`readTree()` does not follow symlinks) so a single scan pass covers the full
declared scope and `scannedPath` names what was actually measured.

**A second, unrelated bug surfaced by running on a real multi-million-line
tree**: `buildProjectIR`/`buildProjectIRAsync` had no per-file exception
guard, so one pathological file (a deeply-nested C# expression tree in
Godot's `editor/` Mono tooling, hitting `parser-cs.js`'s recursive-descent
expression lowerer) threw `RangeError: Maximum call stack size exceeded` and
aborted IR construction for the **entire** project — silently, since the
call site is wrapped in a broad try/catch for instrumentation. `scanner/src/ir/index.js`
now wraps each per-file dispatch branch individually so one file's parse
failure degrades to "unparsed" for that file only, exactly like a parser
returning `null`. This is a general engine fix, not C++-specific, and is
covered by the `test:dataflow` suite (418/418 green after the change).

A bare `catch` makes a *systematic* parser failure indistinguishable from
"this language isn't in the tree" — coverage simply reads 0. So the guard now
counts what it swallows: `irParseFailures()` in `scanner/src/ir/index.js`
returns `{ count, byLanguage, firstError }` for the process, and setting
`AGENTIC_SECURITY_IR_PARSE_DEBUG=1` prints one stderr line per swallowed
failure. This follows the precedent of `parser-py-cst.js`'s
`AGENTIC_SECURITY_PY_PARSER_DEBUG` and `sast/cpp-dataflow.js`'s
`_parseErrorCount`. On the Godot run the 8 C# files that fail (298/306
parsed) are the visible residue of exactly this class of failure; they are
listed in `GAPS.md`.

### Before / after: C++ parse coverage and call-graph resolution

| | Before (dispatch removed) | After (parser enabled) |
|---|---|---|
| C++ files in scope | 3012 | 3012 |
| C++ files parsed | 0 | 3012 |
| C++ parse coverage | **0%** | **100%** |
| Call-graph functions | 1,946 (non-C++ only) | 105,231 |
| Call-graph edges | 227 | 322,871 |
| Resolved edges | 11 (all non-C++) | **131,422** |

("After" is the 2026-07-25 re-run, post parser-fix wave. The pre-fix run of the
same scope measured 104,993 functions / 321,800 edges / 130,692 resolved; the
delta is the functions the digit-separator and raw-string fixes recovered.)

**Denominator note, stated plainly:** the very first baseline attempt scanned
`core/` only (416 files, 0 parsed, 0 edges) before the runner's scope bug
above was found and fixed. The "before" figures in this table are a *clean
re-run* over the same full five-directory scope as "after" (3012 files in
both), so the two rows share a denominator and the delta is directly
comparable. Either way — 416 or 3012 — the "before" parse count is
structurally zero: with the C++ dispatch branch disabled, `buildProjectIR`
never produces a single C++ IR record at any scope, so 0% is not a sampling
artifact.

### Full scan metrics (post-parser, official run — re-measured 2026-07-25)

| Metric | Value |
|---|---|
| Scanned path | `core, modules, scene, servers, editor` (declared == measured) |
| Exit code | 3 (critical-severity findings present — a verdict, not an error) |
| Timed out | **false** (wall 107s of a 3600s budget) |
| Peak RSS | 1176 MB |
| Determinism | **identical: true, now on real evidence** — 183,978 bytes each, both valid SARIF, 145 results. The earlier `identical: true` compared two 65,536-byte truncated prefixes; see "Determinism was being measured against truncated files" above |
| C++ files parsed | 3012/3012 (100%) |
| C++ functionless | 152 (parsed, zero-function files — headers, forward-decl-only, etc.; not a parse failure) |
| C++ functions | 103,285 (up from 103,047 — see the parser fix wave below) |
| C# files parsed | **298/306 (97%)**, 130 functionless — 8 failures, all under `modules/mono/`, enumerated in `GAPS.md` |
| JavaScript / Python in scope | 4/4 and 77/77 parsed |
| Call graph | 105,231 functions, 322,871 edges, **131,422 resolved** (≈40.7%) |

### Parser fix wave (2026-07-25) — three defects found by review, all measured

Godot's tree is multi-million-line, so each of these was an operational risk,
not a nit. All figures below are from runs in the fixing session.

- **C++14 digit separators silently deleted functions.** `'` was
  unconditionally a char-literal opener, so `1'000'000` started a "literal"
  that blanked everything up to the next quote later in the file — while the
  file still counted as parsed, making the loss invisible in the coverage
  metric. Measured on `editor/editor_node.cpp`: **298 functions before, 302
  after** (302 also for a control copy with the separators textually removed).
  Across the measured Godot scope, 13 files contain the pattern.
- **Raw string literals lost whole files.** `R"delim(...)delim"` was not
  modelled, so a raw string containing a quote desynchronised the blanker and
  yielded **zero** functions for the entire translation unit. Now recognised
  and blanked whole, including the `u8R`/`uR`/`UR`/`LR` prefixes; an
  unterminated raw string blanks to EOF (what a compiler sees) rather than
  losing the file's IR.
- **Two performance cliffs.** `_findFunctions` rescanned to EOF for every
  unmatched `(` — 200,000 of them took **32.9 s**, unbounded by
  `_MAX_FUNCTIONS`; a single linear pre-pass that matches all parens brings
  that to **7 ms**. `_lowerExpr` recursed once per binary term, so a
  20,000-term `a-a-a-…` chain threw `RangeError` after **11.4 s** — precisely
  the crash class the new per-file guard in `src/ir/index.js` swallows
  silently; an iterative left fold plus a flat-node cap beyond 32 terms brings
  that to **7 ms**. Both are covered by wall-clock regression tests in
  `scanner/test/parser-cpp.test.js` (bound: 3 s each).

Both blanker defects are now named in `parser-cpp.js`'s not-modelled contract
at the top of the module.

### What this run does and does not prove

The corpus entries added in Task 7 (`bench/cve-replay/capability/cpp-*`, 8
entries, all `pre:TP post:TN`) all pass via **pre-existing syntactic rules**
in `src/sast/cpp.js` — the cve-replay runner never enables deep mode, so none
of those 8 entries exercises the IR parser, call graph, or taint catalog
added in this workstream. **This Godot run is therefore the only evidence in
the repository that the IR/call-graph/taint work does anything at scale.**

A direct check of the interprocedural taint engine on both the Task 6 test
fixture and Godot's live run found **no materialized `ir-taint:` finding**
for a cross-translation-unit source→sink flow, despite the call-graph edge
resolving correctly.

**Root cause, corrected.** An earlier revision of this section attributed it
to the callee summary returning `findings: []`. That was wrong: the blocker
is one step earlier, and nothing is discarded because nothing is computed.
`callGraph.resolve()` (`src/ir/callgraph.js`) returns a **qid string**, but
all three call sites in `src/dataflow/engine.js` — `:235` (assign position),
`:344` (plain-call position), `:795` (higher-order) — do
`const fn = resolved && resolved.qid ? resolved : null`. A string has no
`.qid`, so `fn` is **always null**, and the callee-summary blocks never
execute: `:235`'s lazy compute is guarded by `!sum && fn && fn.cfg`, `:344`'s
whole block by `fn && Array.isArray(fn.params)`, and `:795` hits
`if (!cbFn …) continue` every iteration — which also makes the `findings: []`
line at `:809` unreachable, so the old claim that "only the higher-order path
forwards them" was false for the same reason. Verified by execution:
`resolve('execute', 'main.cpp')` returns the string
`util.cpp::Util.execute@1#…` and `!!(r && r.qid)` is `false`.

This is language-agnostic, not a C++ issue: JS, Python and C++ all show
intraprocedural findings and no interprocedural ones, exactly as one shared
defect predicts. It is deliberately **not** fixed here — see the known-issue
register below. See the Proof Corpus PRD §6.12 for how it affects the
criterion-4 judgement.

## Known issues found on this branch and deliberately not fixed here

Each is a product-wide change that deserves its own tracked issue, its own
fixtures and its own false-positive review — bundling them into a parser fix
wave would make both changes unreviewable.

1. **`engine.js`'s `resolved.qid` bug (most significant finding on this
   branch).** As above: `callGraph.resolve()` returns a qid string while
   `engine.js:235`, `:344` and `:795` expect an object with a `.qid`. **No
   language currently gets an interprocedural taint finding.** Fixing it means
   accepting the string and looking the function record up from it — and then
   re-reviewing the false-positive surface that suddenly appears across every
   language.
2. **`callgraph.js:157-161` `isCrossLanguageUnsafe` is one-directional.** It
   blocks a JS caller from binding to a C++ definition, but not a C++ caller
   from binding to a JS one. Latent only because of (1); it bites the moment
   (1) is fixed.
3. **`engine.js:536` sets `_currentFile` without restoring it** after a nested
   `analyzeFunction`, so a callee's file can leak into the caller's subsequent
   file-scoped decisions.
4. **A `.cpp` `system()` call emits 5 findings**, 4 of them labelled
   `Kernel.system` / `os.system`. The file-scoping fix does not cover them
   because those catalog entries are not `language: 'cpp'` — cross-language
   noise on a genuine finding.
5. **Smaller ones, same disposition:** `sast/cpp.js:77-82` `_isStrcpyGuarded`;
   JS→Python false edges; `dataflow/index.js:175` uses an object as a Map key;
   the IFDS/tabulation path lacks file context.
