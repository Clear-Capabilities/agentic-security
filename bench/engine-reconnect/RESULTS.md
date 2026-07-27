# Engine-reconnect Phase 1: before/after and go/no-go call

**Date:** 2026-07-26
**Branch:** `feat/engine-reconnect`

This is Task 7 of the plan at `docs/superpowers/plans/2026-07-25-engine-reconnect-phase1.md`.
Every number below comes from a command run in this session; anything not
re-run this session is marked "not measured" rather than estimated.

## Step 1: harness before/after

Before figures are from `bench/engine-reconnect/BASELINE.md` (`/tmp/engine-before.txt`,
captured pre-Task-2, commit `97eebb8`). After figures are from this session's run of
`npm run bench:engine-reconnect` (`/tmp/engine-after.txt`), on top of a fresh
`npm run build`.

### Verbatim after-run output

```
> @clear-capabilities/agentic-security-scanner@0.128.2 bench:engine-reconnect
> node ../bench/engine-reconnect/measure.mjs

js: total=9 irTaint=8 interprocedural=1
python: total=6 irTaint=4 interprocedural=1
cpp: total=7 irTaint=5 interprocedural=1
sanitizedDemoted=0
```

### Per-language table

| Language | total (before) | total (after) | irTaint (before) | irTaint (after, raw) | interprocedural (before) | interprocedural (after, distinct flows) |
|---|---|---|---|---|---|---|
| js | 0 | 9 | 0 | 8 | 0 | 1 |
| python | 1 | 6 | 0 | 4 | 0 | 1 |
| cpp | 1 | 7 | 0 | 5 | 0 | 1 |

`sanitizedDemoted`: 0 before, 0 after.

**Reading the js/python/cpp discrepancy between `irTaint` (raw) and `interprocedural`
(distinct flows):** as documented in `BASELINE.md`'s metric-definition note, the
catalog matches a sink by bare callee name, so one real call site collides with
several same-named catalog entries (e.g. `exec` matching `PDO::exec`,
`Kernel.exec`, `Runtime.exec`, ...). That duplication predates this phase. Once
`irTaint` went non-zero post-fix, deduplicating by `file:line` collapses each
language's raw count down to exactly 1 distinct flow — the one interprocedural
source-to-sink flow each fixture is designed to exercise. This is the expected
shape, not evidence of partial detection.

**`sanitizedDemoted` staying at 0 is expected, not a regression.** Task 5 wired
`applySanitizerGate` into the pipeline, but per the task-5 brief and report, the
sanitizer-family data the gate needs is not reachable at its call site, so the
gate runs as a documented no-op (fed an empty map). It is wired, not effective.
Making it effective is Phase 2+ work, not part of this phase's claim.

## Step 2: proof-corpus precision check (Ghost, Superset)

Run: `node ../bench/proof-corpus/runner.mjs --only ghost,superset`, from
`scanner/`, against the freshly built bundle (same build as Step 1).

`bench/proof-corpus/results/summary.json` deliberately carries no finding
counts (a disclosure-boundary decision from an earlier branch: report
emitters never see finding content). Counts were instead taken directly from
the local, gitignored raw SARIF this session's run produced:

- ghost: **1124** results (`bench/proof-corpus/results/raw/ghost/run-a.sarif`)
- superset: **860** results (`bench/proof-corpus/results/raw/superset/run-a.sarif`)

Coverage from `summary.json` is unchanged from the pre-Task-7 figures in
`README.md`: ghost 94% (javascript 4023/4271), superset 100% overall.

| Target | Total findings (before) | Total findings (after) | Comparison quality |
|---|---|---|---|
| ghost | 1124 | 1124 | **indicative only** — the before figure was counted from ghost's SARIF during an earlier branch in this same session, on a **different commit** than this session's Task 7 build. It is not a clean same-commit before/after pair, but it is a same-repository, same-scan-scope comparison. |
| superset | not measured | 860 | no reliable before figure exists for superset; recording "not measured" on the before side rather than inventing one. |

**Reading this:** ghost's finding count is unchanged (1124 → 1124) across the
recount, despite `interprocedural` moving from 0 to a positive count in the
engine-reconnect harness. That is a meaningful, if indicative rather than
strictly like-for-like, signal that Phase 1's recall increase did not, on one
large real codebase, produce a finding explosion — the opposite of what a
precision regression would look like. Superset has no before figure to
compare against at all, so its 860 stands alone; it cannot be used to assess
a precision delta this session, only recorded as a data point for a future
before/after once a same-commit baseline exists.

## Step 3: deep-tier corpus

`bench/cve-replay/deep/` contains **4 entries**, not the 5 the plan's Step 4
question (and design spec §7.4) asked for:

- `cpp-interproc-cmdi-shape`
- `js-interproc-cmdi-shape`
- `js-interproc-sqli-shape`
- `py-interproc-cmdi-shape`

This is a published shortfall, not an oversight recovered late: per the
task-6 report, a fifth entry — an inverted sanitizer case ("flow is correctly
sanitized, expect no finding") — could not be written, independent of the
sanitizer gate being a no-op. The corpus format expressed by
`bench/cve-replay/generate-corpus*.mjs` and consumed by `runner.mjs` requires
every entry to declare `pre:TP` (a finding that is expected pre-fix and
expected to be resolved/typed post-fix); it has no vocabulary for "expect no
finding at all," which is what a true-negative sanitizer case needs. Building
that vocabulary is out of scope for this phase.

## Verdict

**1. Did `interprocedural` go from zero to non-zero in JS, Python and C++?**
Yes. All three languages moved from `interprocedural=0` pre-fix to
`interprocedural=1` post-fix (distinct-flow count), with the underlying raw
`irTaint` finding count also moving from 0 to a positive number in all three
(8, 4, 5 respectively). The central thesis of Phase 1 — that a handful of
plumbing defects, not months of new rules, were suppressing interprocedural
findings — held. Three defects were the actual root cause (the callee record
never resolving from a qid string; `engine.js` gating callee-name derivation
on `typeof === 'string'` when the JS parser emits objects; and `exprTaint`
recognising only `member`-shaped sources, so `return getenv(...)` never
tainted a return), one more than the plan's original single-defect framing,
but the shape of the result — zero to non-zero, across all three languages,
from tractable engine fixes — matches the bet the phase was designed to test.

**2. Did the deep tier gain at least 5 entries that are missed deep-off?**
No — it gained 4, not 5. The shortfall is structural (the corpus format
cannot express the fifth entry's "expect no finding" semantics), not a sign
of weaker detection, and is recorded above and in the task-6 report rather
than worked around by weakening the entry's meaning.

**3. Did Ghost or Superset finding counts rise sharply enough to suggest a
precision problem?**
No, on the one comparison available. Ghost's total finding count is unchanged
(1124 → 1124), which is the strongest signal available this session against a
precision blowup on a large real-world codebase — though it must be read as
indicative, not a clean same-commit before/after, since the before count was
taken from a different commit earlier in this session. Superset has no before
figure at all (recorded "not measured"), so it contributes no evidence either
way; its 860-finding after-figure is a baseline for a future comparison, not
a delta. Taken together there is no signal of a sharp rise, but the evidence
is thinner than a same-commit, two-target before/after would be — Phase 2's
precision work should still be treated as the next real priority, just not
because this session's data shows an active fire.

## Overall call

**The thesis held.** `interprocedural` moved from zero to non-zero in JS,
Python and C++ in the same session's harness run, which is the specific,
pre-committed bar Phase 1 set for itself. The mechanism was three engine
defects rather than the one originally hypothesized, and two things fell
short of the original ask: the deep tier has 4 entries instead of 5 (a
corpus-format limitation, not a detection gap), and the sanitizer gate is
wired but inert (`sanitizedDemoted=0`, by design per Task 5). Neither
shortfall touches the central recall claim. The one precision comparison
available (ghost) shows no finding-count increase, so there is no evidence
this session of the noise problem Phase 2 is meant to address, but that
comparison is indicative rather than rigorous (different commit, and
superset has no before figure at all) — Phase 2 should proceed, and its
precision work remains the stated next priority regardless, since Phase 1's
recall increase raises exactly the kind of judgment-harder findings the
design spec's Phase 2 section already anticipates.
