# M3-UX, sub-project Filters: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the filter rail from 3 to 9 real facets (data class,
source category, sink category, destination externality, transit/at-
rest/handling verdict, policy verdict, AI — the flow-level `protection`
aggregate stays too), deduplicating the two views' own private filter
functions into one shared, tested module along the way.

**Architecture:** New facet values computed the same simple way
`dataClasses` already is (`[...new Set(...)].sort()` over real graph
data). New row properties attached at ROW-COMPUTATION time (matching the
existing `dataClasses`/`protectionSummary`/`isAiRelevant` convention —
`matchesFilters` only ever reads pre-attached row properties, never the
graph). A facet whose property a given row shape doesn't carry (e.g.
Inventory's Fields rows have no flow-level verdict) is SKIPPED for that
row, never treated as a hide — a real, disclosed design property found
while grounding this plan, not assumed.

**Tech Stack:** Plain JS, zero build step. `node --test` + `test/
dom-shim.js`.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-filters-scoping.md`.

## Global Constraints

- `frontend/` only, no `scanner/` changes.
- A filter facet check is SKIPPED (never a hide) when the row doesn't
  carry that property at all — distinct from carrying the property with
  a value that doesn't match (which IS a hide). Verify this for every
  new facet, not just copy the existing `protection` check's own
  defensive `row.protectionSummary &&` guard by reflex.
- **A real, pre-existing inconsistency found while grounding this
  plan**: `privacy-view.js`'s own `rowMatchesFilters` checks `filters.ai`
  (`row.isAiRelevant`); `inventory-view.js`'s own version does NOT check
  `filters.ai` AT ALL — confirmed by reading both files directly. This
  means the AI filter chip currently has literally zero effect anywhere
  in Inventory View, even on tables that plausibly should support it.
  Fix this as part of the dedup (Task 1) — the shared function must
  check `ai` for every row that carries `isAiRelevant`, closing this gap
  for free rather than carrying it forward into the new shared code.
- Every new test file added to `package.json`.

---

### Task 1: `lib/row-filters.js` (shared, deduplicated matcher) + facet computation

**Files:**
- Create: `frontend/src/lib/row-filters.js`
- Modify: `frontend/src/components/filter-rail.js`
- Test: `frontend/test/row-filters.test.js` (new), `frontend/test/
  filter-rail.test.js` (extend)

**Interfaces:**
- Produces: `matchesFilters(row, filters) -> boolean` — the ONE shared
  function both views will call (Task 2), replacing their own private
  `rowMatchesFilters` copies.
- Produces: `computeFilterFacets(graph)` extended to return the 6 new
  value-sets alongside the existing `dataClasses`/`protectionTiers`.

- [ ] **Step 1: Write failing tests for `matchesFilters`**

Read `frontend/src/views/privacy-view.js`'s and `frontend/src/views/
inventory-view.js`'s current `rowMatchesFilters` functions in full first
(re-verify they still match what's quoted in Global Constraints above —
re-confirm the real AI-check gap before relying on it).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesFilters } from '../src/lib/row-filters.js';

test('matchesFilters: dataClass — matches when the row has ANY selected class', () => {
  const row = { dataClasses: ['PCI'] };
  assert.ok(matchesFilters(row, { dataClass: ['PCI', 'PHI'] }));
  assert.ok(!matchesFilters({ dataClasses: ['PII'] }, { dataClass: ['PCI'] }));
});

test('matchesFilters: dataClass — a row with no dataClasses property at all is unaffected (not hidden)', () => {
  assert.ok(matchesFilters({}, { dataClass: ['PCI'] }));
});

test('matchesFilters: protection (flow-level aggregate) — unchanged existing behavior', () => {
  assert.ok(matchesFilters({ protectionSummary: 'unprotected' }, { protection: ['unprotected'] }));
  assert.ok(!matchesFilters({ protectionSummary: 'protected' }, { protection: ['unprotected'] }));
  assert.ok(matchesFilters({}, { protection: ['unprotected'] }), 'a row with no protectionSummary is unaffected, not hidden');
});

test('matchesFilters: ai — now checked consistently for ANY row carrying isAiRelevant (closes the real Inventory gap)', () => {
  assert.ok(matchesFilters({ isAiRelevant: true }, { ai: true }));
  assert.ok(!matchesFilters({ isAiRelevant: false }, { ai: true }));
  assert.ok(matchesFilters({}, { ai: true }), 'a row with no isAiRelevant property at all is unaffected, not hidden');
});

test('matchesFilters: transitVerdict/atRestVerdict/handlingVerdict — each a real, independent facet', () => {
  const row = { transitVerdict: 'unprotected', atRestVerdict: 'protected', handlingVerdict: 'unknown' };
  assert.ok(matchesFilters(row, { transitVerdict: ['unprotected'] }));
  assert.ok(!matchesFilters(row, { transitVerdict: ['protected'] }));
  assert.ok(matchesFilters(row, { atRestVerdict: ['protected'] }));
  assert.ok(matchesFilters(row, { handlingVerdict: ['unknown'] }));
  assert.ok(matchesFilters({}, { transitVerdict: ['unprotected'] }), 'a row with no transitVerdict property is unaffected');
});

test('matchesFilters: sourceCategory / sinkCategory / destinationExternality / policyVerdict', () => {
  const row = { sourceCategory: 'http-body', sinkCategory: 'database', destinationExternality: 'external', policyVerdict: 'permitted' };
  assert.ok(matchesFilters(row, { sourceCategory: ['http-body'] }));
  assert.ok(!matchesFilters(row, { sourceCategory: ['env-value'] }));
  assert.ok(matchesFilters(row, { sinkCategory: ['database'] }));
  assert.ok(matchesFilters(row, { destinationExternality: ['external'] }));
  assert.ok(matchesFilters(row, { policyVerdict: ['permitted'] }));
});

test('matchesFilters: multiple active facets all AND together', () => {
  const row = { dataClasses: ['PCI'], protectionSummary: 'unprotected', policyVerdict: 'not_evaluated' };
  assert.ok(matchesFilters(row, { dataClass: ['PCI'], protection: ['unprotected'] }));
  assert.ok(!matchesFilters(row, { dataClass: ['PCI'], policyVerdict: ['permitted'] }));
});

test('matchesFilters: no active filters at all matches everything', () => {
  assert.ok(matchesFilters({}, {}));
  assert.ok(matchesFilters({ dataClasses: ['PCI'] }, {}));
});
```

- [ ] **Step 2: Implement `matchesFilters`**

```js
// Shared, deduplicated row-vs-active-filters matcher — was previously two
// near-identical private copies (privacy-view.js's and inventory-view.js's
// own rowMatchesFilters). Every check here reads a PRE-ATTACHED row
// property (never the graph directly) — the caller's own row-computation
// step is responsible for attaching whichever of these properties make
// sense for that row's own shape (see lib/filter-rail.js's own facet list
// and each view's own row-building code). A facet whose property the row
// does not carry AT ALL is skipped (never a hide) — this is what makes it
// safe for a single shared function to serve row shapes as different as a
// Privacy flow-row and an Inventory dataElement-row.
const LIST_FACETS = [
  ['dataClass', 'dataClasses', true], // true = row property is itself an array (dataClasses), match if ANY overlaps
  ['protection', 'protectionSummary', false], // false = row property is a single value, match if included in the filter's list
  ['transitVerdict', 'transitVerdict', false],
  ['atRestVerdict', 'atRestVerdict', false],
  ['handlingVerdict', 'handlingVerdict', false],
  ['sourceCategory', 'sourceCategory', false],
  ['sinkCategory', 'sinkCategory', false],
  ['destinationExternality', 'destinationExternality', false],
  ['policyVerdict', 'policyVerdict', false],
];

export function matchesFilters(row, filters) {
  for (const [filterKey, rowProp, rowIsArray] of LIST_FACETS) {
    const activeValues = filters[filterKey];
    if (!activeValues?.length) continue; // this facet isn't active at all
    if (!(rowProp in row)) continue; // row doesn't carry this property — unaffected, not hidden
    if (rowIsArray) {
      if (!(row[rowProp] ?? []).some((v) => activeValues.includes(v))) return false;
    } else {
      if (row[rowProp] !== undefined && !activeValues.includes(row[rowProp])) return false;
    }
  }
  if (filters.ai && 'isAiRelevant' in row && !row.isAiRelevant) return false;
  return true;
}
```

Note the `ai` check's own placement: unlike the other 9 facets (list-of-
selected-values), `ai` is a single boolean toggle, matching its existing
shape in both views — kept as its own explicit check, not folded into
`LIST_FACETS`'s generic loop, since it's structurally different (a
boolean flag, not a multi-select).

- [ ] **Step 3: Run to verify Step 1's tests pass**

Run: `cd frontend && node --test test/row-filters.test.js`

- [ ] **Step 4: Write failing tests for the 6 new `computeFilterFacets` value-sets**

Read `frontend/src/data/flagship-graph.js`'s real committed data first —
ground every expected value-set against the real fixture, not guessed.

```js
import { computeFilterFacets } from '../src/components/filter-rail.js';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';

test('computeFilterFacets: sourceCategories are the real, distinct node.subtype values among kind===source nodes', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  // Ground the expected array against the real fixture (read every
  // kind:'source' node's own subtype) before asserting — do not guess.
  assert.ok(Array.isArray(facets.sourceCategories));
  assert.ok(facets.sourceCategories.length > 0);
});

test('computeFilterFacets: sinkCategories, destinationExternalities, transitVerdicts, atRestVerdicts, handlingVerdicts, policyVerdicts are all real, non-empty, deduplicated, sorted arrays grounded in the real fixture', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  for (const key of ['sinkCategories', 'destinationExternalities', 'transitVerdicts', 'atRestVerdicts', 'handlingVerdicts', 'policyVerdicts']) {
    assert.ok(Array.isArray(facets[key]), `expected facets.${key} to be an array`);
  }
  // Fill in real, specific expected values for each by reading the real
  // fixture's own edges/nodes/flows — e.g. transitVerdicts should include
  // 'not_assessed' and 'unprotected' (confirmed present in Task 2 of
  // M3-UX-Query's own review this session — re-verify, don't just cite).
});
```

- [ ] **Step 5: Implement the 6 new facet computations**

```js
export function computeFilterFacets(graph) {
  const dataClasses = [...new Set((graph.dataElements ?? []).flatMap((d) => d.dataClasses ?? []))].sort();
  const sourceCategories = [...new Set(graph.nodes.filter((n) => n.kind === 'source').map((n) => n.subtype).filter(Boolean))].sort();
  const sinkCategories = [...new Set(graph.nodes.filter((n) => n.kind === 'sink').map((n) => n.subtype).filter(Boolean))].sort();
  const destinationExternalities = [...new Set(graph.nodes.map((n) => n.externality?.value).filter(Boolean))].sort();
  const transitVerdicts = [...new Set(graph.edges.map((e) => e.protection.transit.verdict))].sort();
  const atRestVerdicts = [...new Set(graph.edges.map((e) => e.protection.atRest.verdict))].sort();
  const handlingVerdicts = [...new Set(graph.edges.map((e) => e.protection.handling.verdict))].sort();
  const policyVerdicts = [...new Set(graph.flows.map((f) => f.policyVerdict))].sort();
  return {
    dataClasses, protectionTiers: PROTECTION_TIERS,
    sourceCategories, sinkCategories, destinationExternalities,
    transitVerdicts, atRestVerdicts, handlingVerdicts, policyVerdicts,
  };
}
```

(`PROTECTION_TIERS` is the existing module constant — unchanged, still
exported/used exactly as today.)

- [ ] **Step 6: Run full test files, commit**

Run: `cd frontend && node --test test/row-filters.test.js test/filter-rail.test.js`
Expected: PASS, all tests including the real-fixture-grounded ones you
filled in.

```bash
git add frontend/src/lib/row-filters.js frontend/src/components/filter-rail.js frontend/test/row-filters.test.js frontend/test/filter-rail.test.js
git commit -m "feat(frontend): shared row-filter matcher (dedup + closes a real AI-filter gap in Inventory) + 6 new real filter facets"
```

---

### Task 2: Wire the 7 new chip groups into `renderFilterRail`, attach row properties in both views

**Files:**
- Modify: `frontend/src/components/filter-rail.js` (render half)
- Modify: `frontend/src/views/privacy-view.js`
- Modify: `frontend/src/views/inventory-view.js`
- Test: `frontend/test/filter-rail.test.js` (extend, render-level),
  `frontend/test/privacy-view.test.js` / `frontend/test/
  inventory-view.test.js` (extend)

- [ ] **Step 1: Extend `renderFilterRail`**

Read the current function in full (already shown in this plan's own
scoping doc). Add 7 new chip groups (source category, sink category,
destination externality, transit/atRest/handling verdict, policy
verdict) mirroring the EXISTING `dataClassChips`/`protectionChips`
pattern exactly (`renderChip`/`toggleListFilter`, already generic over
any list-shaped filter key — confirm this by re-reading `toggleListFilter`
before assuming it needs no change; it almost certainly doesn't, since it
already takes `key` as a parameter).

- [ ] **Step 2: Attach new properties to Privacy View's rows**

Read `computePrivacyRow` in full first. Add, alongside the existing
`dataClasses`/`protectionSummary`/`isAiRelevant`:

```js
transitVerdict: worstVerdict(pathEdges.map((e) => e.protection.transit.verdict)),
atRestVerdict: worstVerdict(pathEdges.map((e) => e.protection.atRest.verdict)),
handlingVerdict: worstVerdict(pathEdges.map((e) => e.protection.handling.verdict)),
sourceCategory: graph.nodes.find((n) => n.id === flow.source)?.subtype ?? null,
sinkCategory: graph.nodes.find((n) => n.id === flow.sink)?.subtype ?? null,
destinationExternality: graph.nodes.find((n) => n.id === flow.sink)?.externality?.value ?? null,
policyVerdict: flow.policyVerdict,
```

(`pathEdges` — confirm the exact existing variable name for "this flow's
own resolved edges" in `computePrivacyRow`; it almost certainly already
exists since `protectionSummary`'s own aggregate needs it too — reuse it,
don't recompute. `worstVerdict` is already imported from
`lib/protection-visual.js` in this file for other purposes — confirm,
reuse.) A `null` value (vs. `undefined`) for a genuinely-absent category
still satisfies `matchesFilters`'s own `rowProp in row` check as
PRESENT-but-not-matching — decide here whether that's the right behavior
(a row that explicitly has no source category, vs. one where source
category was never computed) and disclose which you chose; the simpler,
defensible choice is to only set the key when a real, non-null value
exists (`...(subtype ? {sourceCategory: subtype} : {})`), keeping
`matchesFilters`'s own "property absent = unaffected" semantics clean
rather than introducing a third state.

- [ ] **Step 3: Attach new properties to Inventory View's flow-shaped rows**

Read `computeInventoryViewModel`'s `policyPermittedFlows` and
`manualGovernanceGaps` per-category functions in full first (both
already build flow-shaped rows, confirmed in Task 4 of M3-UX-Query's own
review). Attach the SAME set of properties Step 2 adds to Privacy rows,
computed the same way, for these two categories' own flow rows only —
every other category's rows (sources, sinks, stores, fields, etc.)
correctly get none of these new properties, per this whole sub-project's
own "skip, don't hide" design.

- [ ] **Step 4: Replace both views' own private `rowMatchesFilters` with the shared `matchesFilters`**

Delete the two private functions entirely; import and call
`matchesFilters` from `lib/row-filters.js` instead. Confirm via the full
test suite that removing Inventory's own version (which lacked the `ai`
check) and replacing it with the shared version (which has it) doesn't
break any EXISTING inventory test that implicitly relied on the old,
gapped behavior — if one does, that test was pinning the bug, and should
be updated to the correct behavior, disclosed.

- [ ] **Step 5: Full test suite, commit**

Run: `cd frontend && npm test` — PASS, real exit code. Add any new test
files to `package.json`.

```bash
git add frontend/src/components/filter-rail.js frontend/src/views/privacy-view.js frontend/src/views/inventory-view.js frontend/test/filter-rail.test.js frontend/test/privacy-view.test.js frontend/test/inventory-view.test.js frontend/package.json
git commit -m "feat(frontend): wire 7 new filter facets into Privacy/Inventory views, dedup rowMatchesFilters"
```

---

### Task 3: Docs + scanner gate

**Files:**
- Modify: `frontend/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-scoping.md`

- [ ] **Step 1**: Add a "M3-UX, sub-project Filters" section to
  `frontend/CLAUDE.md`, matching every prior section's own voice —
  including the real, disclosed AI-filter gap this sub-project closed,
  and the 5 dimensions (provider/host, application, environment,
  evidence grade/confidence, governance gap) still deferred.
- [ ] **Step 2**: Mark the M3-UX scoping doc's own Filters row COMPLETE.
- [ ] **Step 3**: `cd frontend && npm test` and `cd scanner && npm test`,
  both green, real captured exit codes.
- [ ] **Step 4**: Commit.

## Final integration checklist (coordinator, after all 3 tasks)

- Re-read every changed file in full.
- Both test suites green, real captured exit codes.
- Manually confirm (real browser) that at least one new facet (e.g.
  transit verdict) genuinely narrows Privacy View's visible rows.
