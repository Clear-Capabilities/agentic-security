# Sub-project H closure: Milestone 1 exit-gate verification

Per the parent scoping doc's §5 table, row H ("Exit-gate closure," depends on
A-G, sized Small): "Runs AC-01, AC-02, AC-07, AC-11, and schema completeness
against the real JS/TS corpus (F); this is verification and cleanup, not new
engine capability — the milestone's actual 'done' checkpoint."

Sub-project G merged (`8091b58c`) as the last dependency; H is unblocked. Its
substance — the AC-07 catalog bridge and the AC-01 direct-unit-test proof —
was already built and merged earlier in this session as dedicated hotfixes,
ahead of the formal H closure step. This document is that formal closure:
re-verifying everything fresh, on the current merged main, in one pass.

## Fresh verification (2026-08-31, on merged main at `8091b58c`)

- `npm run test:lineage`: **550/550 passing.**
- `node bench/data-lineage/runner.mjs`: **17/24 fixtures passing, 0
  regression-tier failures**, 7 honestly disclosed `capability`-tier gaps
  (unmodeled source/sink categories — see `bench/data-lineage/README.md`).
- `node --test test/lineage/ac01-multi-sink.test.js
  test/lineage/sink-registry.test.js test/lineage/coverage.test.js
  test/lineage/registry-real-code.test.js`: **89/89 passing**, including the
  pinned AC-07 reachability proof and the AC-01 multi-sink proof.

## Exit-gate criteria (PRD §26, line 1796)

| AC | Status | Proof |
|---|---|---|
| AC-01 (PCI to multiple sinks) | PASS | `test/lineage/ac01-multi-sink.test.js` |
| AC-02 (masked vs. raw log differ) | PASS | `bench/data-lineage/fixtures/js-api-to-log-{masked,raw}/` |
| AC-07 (AI + regulated data) | PASS | `bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/`, `test/catalog-ai-model-provider-precision.test.js` |
| AC-11 (disconnected sources/sinks stay visible) | PASS | `bench/data-lineage/fixtures/js-api-to-log-disconnected/` |
| Schema completeness | PASS | `validateGraph()` zero-errors across every fixture and `test/lineage/*.test.js` |

Full detail already lives in `scanner/src/lineage/CLAUDE.md`'s "Milestone 1
exit-gate status" section (updated alongside this doc to mark Sub-projects
E-H, and Milestone 1 itself, complete) — this closure doc exists as the
dedicated, dated verification record the sub-project table calls for, not a
duplicate of that write-up.

## Milestone 1: COMPLETE

All eight sub-projects (A-H) are done. What's explicitly NOT included, per
the scoping doc's own out-of-scope table (§1): external destination
resolution, DB/queue field-level mapping beyond "initial," transit/at-rest/
handling analyzers, policy/governance verdicts, any UI, and any language
beyond JS/TS. The §22.2/§22.3 100+/100+-entry corpus floor is a separate,
larger, ongoing target (24/100+ currently) — not part of the exit gate's
literal wording, and not blocking this closure.

Milestones 2 (external destination resolution, transit/at-rest/handling
analyzers), 3 (interactive website), 4 (decision intelligence/exports/
workflow), 5 (simulation/continuous corroboration/remediation/scale) remain
entirely unscoped.
