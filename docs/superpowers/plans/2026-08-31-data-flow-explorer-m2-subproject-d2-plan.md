# Milestone 2, Sub-project D, increment 2: FR-307 multi-path control-credit (`transformation.appliesToAllPaths`)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`,
Sub-project D ("Handling analyzer + FR-307 control-credit computation,"
Large). Increment 1 (`05403427`) shipped FR-403's single-path handling
taxonomy and explicitly deferred this rule — see
`scanner/src/lineage/DESIGN_HANDLING_ANALYZER.md`'s own "Explicitly
deferred" section, which names it verbatim: *"FR-307's multi-path
control-credit rule (AC-12) — needs enumerating every path to a sink and
checking a transform applies on ALL of them, not one."*

**PRD text (verbatim):**
- FR-307: *"A transform receives control credit only when the analyzer can
  associate it with the selected field on the selected path and determine
  that it applies on all relevant feasible paths. A nearby call to
  `encrypt()` or `mask()` is insufficient."*
- AC-12: *"Given one branch encrypts a field and another branch reaches the
  same store without encryption, then end-to-end protection is `mixed` or
  `unprotected`; a transform on one branch cannot make the full flow
  green."*

## Scope boundary (read before writing code)

This increment computes **`transformation.appliesToAllPaths`** — the field
`graph-builder.js` already stubs at `null` on every transformation entity
(`src/lineage/graph-builder.js:455`, comment: *"§7.3: honest absences.
`appliesToAllPaths` needs FR-307's all-path proof, which nothing here
does."*) — and nothing else. It does **NOT** compute `flow.protectionSummary`
as `mixed`/`unprotected` (AC-12's own literal end-to-end verdict wording) —
that field stays `'not_assessed'`, exactly as it is today. Populating it for
real needs a real protection-verdict analyzer (Sub-project B/C's transit/
at-rest analyzers, or Sub-project G's policy verdict), none of which exist
yet — `appliesToAllPaths` is the load-bearing SIGNAL those future analyzers
will consume, not the verdict itself. Say this explicitly in the design-doc
addition below; do not attempt to synthesize a `protectionSummary` value
from `appliesToAllPaths` alone in this increment.

## What already exists (confirmed by direct read, this session, current HEAD `05403427`)

- `graph-builder.js`'s flow-construction loop (`buildDataFlowGraph`, lines
  388-533) already groups every reconstructed path into `groupsByFlowKey`,
  keyed on `[src.id, snk.id, de.id, p.shape, g.grade, sortedT.join(',')]`
  (line 488) — **note this key ALREADY includes the transformation-id set**,
  so two paths to the same (source, sink, dataElement) that apply DIFFERENT
  transforms already land in DIFFERENT flow-key groups today, each becoming
  its own `graph.flows` entry with its own `handling` value (increment 1).
  AC-12's "one branch masks, one doesn't" scenario therefore ALREADY
  produces two visible, distinct flows in the graph — that part of AC-12 was
  a side effect of Milestone 1's own flow-key design, not something this
  increment needs to build.
- `transformsById` (line 269, `const transformsById = new Map()`) is a
  SINGLE map across the whole `buildDataFlowGraph` call, keyed on
  `t.id = ids.transformationId(anchor, calleeDisplay(d), [file, line,
  fromPath, toPath])` (line 438) — `anchor` is the SINK node id, not the
  data element id. A transformation entity can in principle (rare, not
  observed in any shipped fixture) be referenced by flows for more than one
  data element if two different fields happen to produce byte-identical
  `(file, line, fromPath, toPath)` at the same sink — name this as a real,
  disclosed edge case (see "Conjunction across coarse groups" below), do not
  silently assume `t.id` is always field-unique.
- `graph.transformations = [...transformsById.values()].sort(byId)` is
  assigned at line 563, `graph.flows = [...flowsById.values()].sort(byId)`
  at line 564 — **both after** the flow-construction loop (which ends at
  line 533) finishes populating `groupsByFlowKey`/`transformsById`/
  `flowsById`. The new aggregation pass this increment adds must run
  strictly between line 533 and line 563 — after every flow group exists,
  before either map is read into the final arrays.
- `test/lineage/graph-builder.test.js`'s `E1/11` (around line 267-299) is
  the ONE existing test that currently asserts `t.appliesToAllPaths === null`
  UNCONDITIONALLY for every transformation entity — **this increment will
  make that assertion false and the test MUST be updated, not left
  broken.** Read that test's fixture directly: it has two sinks
  (`logger.info(masked)` reached via `maskCard(card)`, `logger.warn(shaped)`
  reached via the unrecognized `reshapeForVendor(card)`), with **no
  branching at all** — each sink has exactly one path reaching it. Under
  this increment's rule (below), a transform that is the ONLY path to its
  sink trivially "applies to all paths that exist" — so both
  `byCallee.maskCard.appliesToAllPaths` and
  `byCallee.reshapeForVendor.appliesToAllPaths` become `true`, not `null`.
  Update the assertion at lines 294-295 accordingly (per-callee, not a
  blanket loop assertion) — do not just delete the check.

## The rule this increment implements

For every **coarse key** `[src.id, snk.id, de.id].join('|')` (deliberately
coarser than `groupsByFlowKey`'s own key — it drops `shape`/`grade`/
`sortedT`, so every flow-group reaching the same sink for the same field
from the same source, regardless of which transforms were found on it,
collapses into one coarse group):

1. Collect every DISTINCT flow group (post-dedup — `groupsByFlowKey`'s own
   entries, not raw reconstructed paths; `alternatePathCount` already
   collapsed byte-identical repeats and carries no new information for this
   rule) sharing that coarse key, and each one's `sortedT` (its ordered
   transformation-id array).
2. For every transformation id `tid` appearing in ANY flow group's
   `sortedT` within that coarse group: `tid` "applies to all paths" for
   THIS coarse group iff `sortedT.includes(tid)` is true for **every** flow
   group in the coarse group — not just the ones where it appears.
3. Write the result onto `transformsById.get(tid).appliesToAllPaths`.

**Conjunction across coarse groups (the disclosed rare-collision case
named above):** if the SAME `tid` is relevant to more than one coarse
group (only possible if the same call site's `(file, line, fromPath,
toPath)` was reached via two different data elements or two different
sinks, which no shipped fixture currently produces), the final
`appliesToAllPaths` is the AND of every coarse group's own answer for that
`tid` — `true` only if every coarse group where it is relevant judges it
`true`. This is the conservative (never-overclaim) direction, consistent
with FR-307's own "insufficient" framing and with Milestone 2's own
"false-protected" exit-gate concern (a release must never assert credit it
cannot prove).

**Why a truncated/incomplete path needs no special-case code, and why that
is itself worth a test:** if one path to a sink was cut short by
`path-query.js`'s own budget/depth limits before reaching a transform call
site, that path's own flow-group `sortedT` simply won't contain that
transform's id (the hop was never walked, so `recognizeTransformation`
never ran on it). Under the rule above, that flow group's absence of `tid`
in its own `sortedT` already forces `appliesToAllPaths` to `false` for any
`tid` present in a SIBLING flow group in the same coarse key — the
conservative answer falls out of the existing conjunction, with no
additional "is this path incomplete" branch needed. State this reasoning in
the design-doc addition; add a real fixture proving it (see Test plan).

## Implementation

**File to edit:** `scanner/src/lineage/graph-builder.js` only (no new
module — this is a second pass over data the existing flow-construction
loop already built, not new detection).

Insert a new block immediately after the flow-construction loop closes
(after line 533's closing `}` of `for (const [, group] of
[...groupsByFlowKey.entries()]...)`), before line 563's
`graph.transformations = ...`:

```js
// Milestone 2, Sub-project D, increment 2 (FR-307): appliesToAllPaths.
// Must run AFTER groupsByFlowKey is fully populated (every flow group for
// every sink has been discovered) and BEFORE transformsById is read into
// graph.transformations — see DESIGN_HANDLING_ANALYZER.md §5 for the full
// rule and why no special-casing is needed for a truncated/incomplete path.
const coarseGroups = new Map();
for (const [, group] of groupsByFlowKey) {
  const { src, snk, de, sortedT } = group[0];
  const coarseKey = `${src.id}|${snk.id}|${de.id}`;
  if (!coarseGroups.has(coarseKey)) coarseGroups.set(coarseKey, []);
  coarseGroups.get(coarseKey).push(sortedT);
}
for (const flowsSortedT of coarseGroups.values()) {
  const relevantIds = new Set(flowsSortedT.flat());
  for (const tid of relevantIds) {
    const appliesToAll = flowsSortedT.every((st) => st.includes(tid));
    const t = transformsById.get(tid);
    t.appliesToAllPaths = t.appliesToAllPaths === null ? appliesToAll : (t.appliesToAllPaths && appliesToAll);
  }
}
```

This is close to a complete implementation, not pseudocode — the
implementer's own job is to place it correctly, verify every referenced
variable (`groupsByFlowKey`, `transformsById`, `src`/`snk`/`de`/`sortedT`
destructured from a group's first entry) matches the CURRENT shipped file
exactly (re-read the file first — do not assume this plan's line numbers
are still exact after any earlier edit in the same task), and prove it
against real parsed code per the test plan below. If the real file's
variable names or structure have drifted from what this plan describes,
STOP and report a `NEEDS_CONTEXT`/`BLOCKED` status rather than guessing.

**Do NOT touch:** `handling-analyzer.js` (single-path classifier, unrelated
to this cross-path aggregation), `flow-grade.js`, `path-store.js`,
`path-query.js`, `resolve-destination.js`, `coverage.js`, `validate.js`
(the schema for `appliesToAllPaths` — `boolean | null` — is unchanged; only
its VALUE changes from always-`null` to sometimes-`true`/`false`, and
`validate.js` has no existing structural check on this field to update —
confirm this by reading `_validateTransformation` before assuming so, don't
just trust this sentence).

**Design doc:** add a new `## 5. FR-307 multi-path control-credit
(increment 2)` section to the END of
`scanner/src/lineage/DESIGN_HANDLING_ANALYZER.md`, covering: the coarse-key
rule, the conjunction-across-coarse-groups edge case, and the
truncated-path reasoning — condense the "Implementation" and "The rule this
increment implements" sections above into the design doc's own voice
(binding documentation, not a copy-paste of this plan). Update the
"Explicitly deferred" section's own D2 bullet to say it is now DONE, per
this package's established convention (see how increment 1's own commit
updated `CLAUDE.md`'s stale AC-07/deferred-item text).

## Test plan

Extend `test/lineage/graph-builder.test.js` (do not create a new test
file — this is one cohesive property of the existing `buildDataFlowGraph`
function, tested alongside its other projection properties):

1. **Fix `E1/11`'s now-wrong assertion** (see "What already exists" above):
   `byCallee.maskCard.appliesToAllPaths === true`,
   `byCallee.reshapeForVendor.appliesToAllPaths === true` — both single-path
   sinks, so the transform trivially applies to the only path that exists.
2. **New test, the real AC-12 proof**: a fixture with ONE field reaching
   ONE sink via two DIFFERENT call paths — e.g. an `if`/`else` branch where
   one branch calls `maskCard(card)` before `logger.info(...)` and the
   other branch calls `logger.info(card)` directly (unmasked), both
   branches reaching the same `logger.info` call statement (so it is
   genuinely the same sink NODE, not two different ones — confirm this by
   checking how `sinkNodeFor`/`enumerateSinkSites` key a node, since two
   textually-different call sites in different branches could still
   collide onto one node if they share the same `(kind, subtypeKey,
   coverageStatus, externality)` tuple, which two `logger.info(...)` sites
   should). Assert: `graph.transformations` contains the `maskCard`
   transformation with `appliesToAllPaths === false` (present on one
   branch's flow, absent from the other's) — proving the false-protected
   direction, the one the PRD's own "false-protected release gate" cares
   about most.
3. **New test, the incomplete-path proof**: reuse or adapt an existing
   truncation fixture (search `test/lineage/` for a fixture that already
   forces `path-query.js`'s budget/depth truncation — `graph-builder.test.js`
   or `coverage.test.js` likely has one already, given `p.terminal`/
   `g.complete` are already read at line 507; do not invent a new
   truncation mechanism, reuse the one that exists) where a transform
   applies on one complete path but a SIBLING path to the same sink was cut
   short before the analyzer could see whether it also applied. Assert
   `appliesToAllPaths === false` for that transform — proving the
   conservative-by-construction claim in the design doc is real, not just
   argued in prose.
4. **Full `npm run test:lineage` and `npm test` must stay green**, captured
   exit codes, not inferred — the implementer runs both from inside the
   worktree and reports the real pass counts.

## Explicitly deferred (name it, don't silently drop it)

`flow.protectionSummary` computation (`mixed`/`unprotected`/`protected`) —
AC-12's own literal end-to-end verdict wording — stays `'not_assessed'`.
That needs a real protection-verdict analyzer consuming
`appliesToAllPaths` as one of its inputs (Sub-project B/C/G, none built
yet); this increment produces the SIGNAL, not the verdict. The rare
same-call-site-different-data-element `t.id` collision (see "Conjunction
across coarse groups") is handled conservatively (AND across groups) but
not separately tested with a dedicated collision fixture — flag it as a
known limitation in the design doc rather than manufacturing an artificial
fixture to force the collision, since no real catalog/parser shape
produces it today.
