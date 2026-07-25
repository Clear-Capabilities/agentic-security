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
that measured the wrong thing. Superset now clears the plan's 85% acceptance
bar (`docs/PROOF_CORPUS_PRD.md` §11.2) on every language in scope.

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
  large repository, as anticipated in the plan's accepted-cost note.

The remaining eight targets are in the manifest but unpinned; Phase 2 brings
them online.
