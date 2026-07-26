# Engine-reconnect: pre-fix baseline

**Date:** 2026-07-25
**Commit:** `97eebb83cdfbf461a7aafdb334d528e63a589410` (branch `feat/engine-reconnect`, working tree before any Task 2-7 change)

## Command

```
cd scanner
npm run bench:engine-reconnect
```

## Output (verbatim, this session)

```
> @clear-capabilities/agentic-security-scanner@0.128.2 bench:engine-reconnect
> node ../bench/engine-reconnect/measure.mjs

js: total=0 irTaint=0 interprocedural=0
python: total=1 irTaint=0 interprocedural=0
cpp: total=1 irTaint=0 interprocedural=0
sanitizedDemoted=0
```

`--json` form of the same run:

```json
{
  "perLanguage": {
    "js": { "total": 0, "irTaint": 0, "interprocedural": 0 },
    "python": { "total": 1, "irTaint": 0, "interprocedural": 0 },
    "cpp": { "total": 1, "irTaint": 0, "interprocedural": 0 }
  },
  "sanitizedDemoted": 0
}
```

## Per-language figures

| Language | total | irTaint | interprocedural |
|---|---|---|---|
| js | 0 | 0 | 0 |
| python | 1 | 0 | 0 |
| cpp | 1 | 0 | 0 |

`sanitizedDemoted`: 0

## Metric definition (updated post-review)

`interprocedural` counts **distinct flows**, deduplicated by `file:line` (or by
`stableId` when every finding in the set carries one) — not a raw count of
`IR-TAINT` findings. The catalog matches a sink by its bare callee name (e.g.
`exec`), so one call site collides with every same-named catalog entry
(`PDO::exec`, `Kernel.exec`, `Runtime.exec`, ...); that duplication predates
this phase and is unrelated to it. `irTaint` (the raw count) is still reported
alongside `interprocedural` so the duplication stays visible rather than
hidden. This baseline's `interprocedural` figures are unaffected by the
redefinition: `irTaint` was already 0 in every language pre-fix, so 0 distinct
flows and 0 raw findings coincide here. The distinction only matters once
`irTaint` goes non-zero — see `.superpowers/sdd/2026-07-25-engine-reconnect-phase1/task-2-report.md`
for the post-fix figures under both definitions.

## Central claim check

**`interprocedural` is 0 for all three languages before any fix has landed** — consistent with the plan's premise that interprocedural taint currently produces zero findings across languages. This is not contradicted.

## Deep mode confirmation

The harness sets `AGENTIC_SECURITY_DEEP=1` and `AGENTIC_SECURITY_DEEP_IN_CI=1` before calling `runScan()`, which is required for an in-process caller to build IR at all (`scanner/src/engine.js` deep-mode gate: `_deepEnabled = _deepRequested && (!_inCi || _deepInCiAllowed)`).

Deep mode's effect was confirmed independently (not just inferred from the harness output) by running each fixture directory through `runScan()` with `AGENTIC_SECURITY_IR_STATS=<path>` set (an existing opt-in instrumentation flag, no source changes), which writes an IR/call-graph coverage sidecar:

| Language | files parsed | functions | call-graph edges | resolved edges |
|---|---|---|---|---|
| js | 2/2 | 5 | 3 | 0 |
| python | 1/1 | 2 | 0 | 0 |
| cpp | 1/1 | 2 | 3 | 1 |

IR construction and the call graph are demonstrably running (non-zero functions/edges in every language). Despite that — and even in the one case where an edge did resolve (cpp: 1 resolved edge) — zero interprocedural taint findings were produced. This is a stronger signal than "deep mode flag was set": it shows IR/call-graph construction succeeds but the interprocedural taint step downstream still yields nothing, which is exactly the gap the remaining six tasks are meant to close.

## Other observations

- `js` fixture (`app.js`, the `exec(cmd)` sink) produced **zero findings of any kind** (not just zero interprocedural) — no syntactic rule fired either, despite `require('child_process').exec(cmd)` being a classic command-injection shape. This is worth a reviewer's attention: it may mean the syntactic/regex layer also doesn't fire on this exact call shape (destructured member access via `require(...).exec(...)`), which is a second, independent gap from the interprocedural one this phase targets.
- `python` and `cpp` each produced exactly 1 finding (`total=1`), but neither is `parser: 'IR-TAINT'` — i.e. these are single-function/syntactic detections (`os.system`, `system()` sink patterns), not evidence of cross-function taint tracking.
- `sanitized.js` was scanned as part of the same `fixtures/js` directory scan used for the `js` row above (the harness re-scans `fixtures/js` a second time for the `sanitizedDemoted` count); `sanitizedDemoted=0` — no findings were produced for the sanitizer case either, so there is nothing (yet) to demote. This is expected pre-fix and will be meaningful only once Task 2+ makes the engine emit a finding here to demote.

## Concerns for reviewers

- The interprocedural thesis (zero across all three languages) is confirmed, not contradicted — the remaining tasks can proceed as planned.
- The `js` fixture's `total=0` (no findings of any kind, not just no interprocedural ones) is unexpected and should be understood before Task 2+ claims a fix, since a future non-zero `interprocedural` count for `js` needs to be distinguishable from a coincidental improvement in the syntactic layer.
- `.agentic-security/` scan-state directories were generated under `bench/engine-reconnect/` and its fixture subdirectories during measurement; these were deleted before finalizing this baseline and before commit, per the project's benchmarking hygiene rule.
