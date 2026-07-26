# proof-corpus

Scans large third-party open-source repositories to produce reproducible
evidence about language coverage, detection quality, and operational behaviour
at scale. See `docs/PROOF_CORPUS_PRD.md` for the full rationale.

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
| ghost | MIT | 94% (javascript 4023/4271, functionless 0) | **no** — see known gaps | 62s | 3353 MB |
| superset | Apache-2.0 | 100% overall — javascript 100% (2613/2616, functionless 0), python 100% (1470/1470, functionless 389) | yes | 73s | 2893 MB |

Both scans exited with code 3 (per the CLI's exit-code contract: `0` clean,
`1` low/medium, `2` high, `3` critical, `4` error) — a successful scan run
that surfaced critical-severity findings, not a failure.

### Parse-coverage metric correction

The parse-coverage metric originally counted a file as a parse failure if it
declared zero functions, even when the parser returned a valid IR record for
it (an `__init__.py`, a constants module). That is not a parse failure. The
metric now counts `parsed` as "an IR record exists for the file," full stop,
and tracks `functionless` (record exists, zero functions) as a separate,
non-penalized count. See `docs/PROOF_CORPUS_PRD.md` §5.4.

**The previously published "Superset Python parse coverage: 74%" was a
measurement artifact, not a parsing problem.** Under the corrected metric,
Superset's Python coverage is **100% (1470/1470)**, with 389 of those files
being function-free (`functionless`) — exactly the kind of file the old
metric miscounted as a failure. There was no Python IR parser bug to
investigate; the earlier "known gap" and its stated follow-up
("investigating the Python IR parser's failure modes") were chasing a number
that measured the wrong thing. Superset now clears the PRD's 85% acceptance
bar (`docs/PROOF_CORPUS_PRD.md` §12 acceptance criterion 2) on every language in scope.

### Known gaps surfaced by this run

- **Ghost's JavaScript parse coverage is 94% (4023/4271), and this is a real
  gap, not a metric artifact**: `functionless` is 0 for ghost, so the 248
  unparsed files are genuine parse failures under the corrected metric, not
  function-free modules. This is the one figure in this run that the metric
  fix does not explain away.
- **Ghost's determinism check now fails intermittently.** Two consecutive
  scans of the same commit produced SARIF output that is byte-identical
  except for one finding: a dependency relicensing warning attributed to
  `apps/admin-x-settings/package.json` in the first run and
  `apps/admin-x-framework/package.json` in the second. Both manifests
  declare the same dependency, so the scanner has two valid places to
  attribute the same finding and picks non-deterministically between them —
  consistent with unordered iteration over a map or set in the licence-graph
  code. The prior run (before this fix wave, under the old parse-coverage
  metric) reported `identical: true` for ghost, so the failure is
  intermittent rather than consistent, which is worse, not better — it means
  a `--deterministic` run can pass by chance. Nothing in this fix wave
  touched licence-graph code; this is a pre-existing scanner behavior the
  bench surfaced, not a bench defect. Superset's determinism check passed
  (`identical: true`) on this run. This is recorded as an open gap, not
  fixed here — the determinism check itself is not weakened or disabled.
- **Call-graph edge resolution is low on both targets**: ghost resolved
  5,819 of 118,356 edges (4.9%); superset resolved 4,004 of 69,959 edges
  (5.7%). This reflects the k=1 monovariant, largely intra-file resolution
  documented in `scanner/src/dataflow/CLAUDE.md`, not a bench defect — a
  genuine finding about cross-file call resolution on large real-world
  repositories.
- **Peak RSS is high on both targets** (~3.35 GB ghost, ~2.89 GB superset),
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
covered by the existing `test:dataflow` suite (410/410 green after the change).

### Before / after: C++ parse coverage and call-graph resolution

| | Before (dispatch removed) | After (parser enabled) |
|---|---|---|
| C++ files in scope | 3012 | 3012 |
| C++ files parsed | 0 | 3012 |
| C++ parse coverage | **0%** | **100%** |
| Call-graph functions | 1,946 (non-C++ only) | 104,993 |
| Call-graph edges | 227 | 321,800 |
| Resolved edges | 11 (all non-C++) | **130,692** |

**Denominator note, stated plainly:** the very first baseline attempt scanned
`core/` only (416 files, 0 parsed, 0 edges) before the runner's scope bug
above was found and fixed. The "before" figures in this table are a *clean
re-run* over the same full five-directory scope as "after" (3012 files in
both), so the two rows share a denominator and the delta is directly
comparable. Either way — 416 or 3012 — the "before" parse count is
structurally zero: with the C++ dispatch branch disabled, `buildProjectIR`
never produces a single C++ IR record at any scope, so 0% is not a sampling
artifact.

### Full scan metrics (post-parser, official run)

| Metric | Value |
|---|---|
| Scanned path | `core, modules, scene, servers, editor` (declared == measured) |
| Exit code | 3 (critical-severity findings present — a verdict, not an error) |
| Timed out | **false** (wall 106s of a 3600s budget) |
| Peak RSS | 1179 MB |
| Determinism | **identical: true** — two scans of the same commit produced byte-identical SARIF (contrast with Ghost's pre-existing, unrelated determinism gap above) |
| C++ functionless | 152 (parsed, zero-function files — headers, forward-decl-only, etc.; not a parse failure) |
| C++ functions | 103,047 |

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
resolving correctly. Tracing it: the engine's context-sensitive callee-summary
computation (used at both assign-position and plain-call-position call
sites in `src/dataflow/engine.js`) discards the callee's inner findings —
only the higher-order/callback invocation path forwards them to the caller's
finding list. This reproduces identically on an equivalent JS fixture, so it
is a pre-existing, language-agnostic gap in the shared taint engine, not
something introduced by or specific to the C++ parser. It is out of scope
to fix here; it is recorded as a discovered limitation. See
`docs/PROOF_CORPUS_PRD.md` §6.12 for how this affects the criterion-4
judgement.
