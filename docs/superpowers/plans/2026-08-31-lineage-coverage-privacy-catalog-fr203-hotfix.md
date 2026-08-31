# Lineage Coverage Hotfix: FR-203's Privacy-Catalog Exclusion Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a real, previously-undetected regression in `scanner/src/lineage/coverage.js`'s `resolveSiteDecision`, found while authoring Sub-project F's benchmark corpus: the guard meant to exclude `PRIVACY_SINK_CATALOG` entries from FR-203's destination-unresolved heuristic never actually excludes anything, silently corrupting real `store`/`external`/`queue`-kind privacy-catalog nodes into `process`/`null`/`unsupported` whenever FR-203's receiver/arg0 signal fires on them.

**Architecture:** A one-line guard-condition fix in `coverage.js`, plus correcting the one test that was supposed to guard this exact behavior but was built against a fabricated entry shape that doesn't exist in the real catalog (so it passed while blind to the bug), plus extending the sink-registry completeness guard so the "unreachable fallback" claim `sink-registry.js`'s own `reclassifySink` makes is actually enforced against BOTH catalogs, not just the general one.

**Tech Stack:** Node ≥ 24, ESM.

**Spec:** This plan IS the spec — the bug was found, root-caused, and reproduced during Sub-project F's own review (not from a separate design doc). The exact reproduction:

```js
// coverage.js:155-158, the guard as shipped:
if (site.entry?.vuln?.cwe === undefined) return undefined;
```

Measured: **all 18 of 18** `PRIVACY_SINK_CATALOG` entries (`scanner/src/dataflow/privacy-catalog.js`) carry `vuln.cwe: 'CWE-359'` — the guard's premise ("privacy-catalog entries have no vuln.cwe") is false for every single entry, so it excludes nothing. `'CWE-359'` has no row in `sink-registry.js`'s `CWE_MAP`, so `reclassifySink(site.entry, opts)` falls into its own defensive fallback branch — whose comment claims it is "unreachable from live data" — returning `{kind: 'process', category: null, coverageStatus: 'unsupported', externality: 'internal', reason: 'unmapped CWE CWE-359'}`. A perfectly good privacy-catalog node (e.g. `s3.putObject(...)` → `store`/`object-storage`/`modeled`) silently collapses to `process`/`null`/`unsupported` whenever its call site also triggers FR-203 (a computed, non-literal argument on `external-api`/`file`/`object-storage`, or a computed receiver on any `FR203_ELIGIBLE_KINDS` category).

**Root cause of why nothing caught this:** `coverage.test.js`'s `C1/3a` ("resolveSiteDecision returns undefined for a privacy-catalog site") hand-builds `entry: { id: 'privacy-js-logger-info', category: 'log' }` — a fabricated shape that omits the `vuln` block the REAL `privacy-js-logger-info` catalog entry actually carries. The test passes against a shape that does not exist in the catalog, and is structurally blind to the real bug. `sink-registry.test.js`'s own completeness guard (`completeness/1a`) only walks `CATALOG`, never `PRIVACY_SINK_CATALOG`, so it provides no backstop either.

**The correct distinguishing signal, verified against the live catalogs:** general `CATALOG` sink entries NEVER carry a `category` field (`sink-registry.js`'s own `D1/8b` test already pins this; independently re-confirmed live in this plan's own research: 0 of 194 general sink entries have one). Every `PRIVACY_SINK_CATALOG` entry DOES carry `category` — it's the literal field `reclassifyPrivacySink` keys on. `typeof site.entry?.category === 'string'` is therefore a real, positive, always-true-for-privacy-entries signal, unlike the absent-`vuln.cwe` check it replaces.

## Global Constraints

- This is a hotfix to already-shipped, already-heavily-reviewed code (Sub-project E, increment E4). Treat it with the same care as this session's own prior hotfixes (the two E1-era hotfixes for `engine.js` receiver identity and schema/validator nullability) — additive/corrective only, no unrelated refactoring.
- The fix must not change `resolveSiteDecision`'s behavior for general-catalog sites at all — only the privacy-catalog exclusion path changes. Prove this with a regression test showing FR-203 still fires correctly on a real general-catalog site (e.g. `fetch(url)`) exactly as before.
- `npm run test:lineage` and the full `npm test` gate must stay green.

---

### Task 1: fix the guard, fix the test that missed it, extend the completeness guard

**Files:**
- Modify: `scanner/src/lineage/coverage.js`
- Modify: `scanner/test/lineage/coverage.test.js`
- Modify: `scanner/test/lineage/sink-registry.test.js`

**Interfaces:** None new — `resolveSiteDecision`'s exported signature is unchanged.

- [ ] **Step 1: Fix the guard in `coverage.js`**

Find, in `resolveSiteDecision`:

```js
  // Privacy-catalog entries have no `vuln.cwe` — reclassifySink's `opts`
  // parameter is specified only for the general (CWE-keyed) catalog
  // (sink-registry.js's own disclosed asymmetry). Never applied here.
  if (site.entry?.vuln?.cwe === undefined) return undefined;
```

Replace with:

```js
  // Privacy-catalog entries are identified by carrying their own `category`
  // field — the literal field `reclassifyPrivacySink` keys on, and one no
  // general CATALOG sink entry ever has (sink-registry.js's own `D1/8b`
  // pins this for the general side; independently re-confirmed live: 0 of
  // 194 general sink entries carry `category`). `reclassifySink`'s `opts`
  // parameter is specified only for the general (CWE-keyed) catalog
  // (sink-registry.js's own disclosed asymmetry) — never applied here.
  //
  // CORRECTED (hotfix, 2026-08-31): the original guard checked
  // `site.entry?.vuln?.cwe === undefined`, on the assumption that
  // privacy-catalog entries carry no `vuln.cwe`. Measured, live: ALL 18 of
  // 18 PRIVACY_SINK_CATALOG entries carry `vuln.cwe: 'CWE-359'` — the
  // guard's premise was false for every single entry, so it excluded
  // nothing. Since `'CWE-359'` has no `CWE_MAP` row, every privacy-catalog
  // site that also triggered FR-203's heuristic silently fell through
  // `reclassifySink`'s "unreachable from live data" fallback branch,
  // corrupting a real store/external/queue-kind node into
  // process/null/unsupported. Found and root-caused during Sub-project F's
  // own corpus-authoring review; see
  // docs/superpowers/plans/2026-08-31-lineage-coverage-privacy-catalog-fr203-hotfix.md.
  if (typeof site.entry?.category === 'string') return undefined;
```

- [ ] **Step 2: Run this fixture-shaped regression proof live before touching any test file**

Confirm the fix with a real, throwaway script (not yet a permanent test — Step 3 makes it one): build a callGraph from `function h(s3){ s3.putObject({ Body: computedExpr }); }` where `computedExpr` is a non-literal identifier (so FR-203's arg0 signal fires), run it through `buildGraphWithCoverage`, and confirm the resulting sink node is `store`/`object-storage`/`modeled` — NOT `process`/`null`/`unsupported` — both BEFORE applying Step 1's fix (confirm the bug reproduces) and AFTER (confirm it's fixed). Report the exact before/after JSON in your task report.

- [ ] **Step 3: Fix `C1/3a` in `coverage.test.js` — it was built against a fabricated entry shape**

Find:

```js
test('C1/3a: resolveSiteDecision returns undefined for a privacy-catalog site (no vuln.cwe)', () => {
  const site = { entry: { id: 'privacy-js-logger-info', category: 'log' }, decision: { kind: 'log', category: 'log', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'log' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});
```

Replace with a test built against the REAL catalog entry, imported directly (not a hand-fabricated literal), so this test can never again pass against a shape that doesn't exist in the live catalog:

```js
test('C1/3a: resolveSiteDecision returns undefined for a real privacy-catalog site — using the REAL catalog entry, not a fabricated shape missing its vuln block (hotfix regression guard)', async () => {
  const { PRIVACY_SINK_CATALOG } = await import('../../src/dataflow/privacy-catalog.js');
  const realEntry = PRIVACY_SINK_CATALOG.find((e) => e.id === 'privacy-js-logger-info');
  assert.ok(realEntry, 'privacy-js-logger-info must exist in the live catalog');
  assert.ok(realEntry.vuln && realEntry.vuln.cwe, 'sanity: the real entry DOES carry vuln.cwe — this is exactly what made the original guard wrong');
  assert.equal(typeof realEntry.category, 'string', 'sanity: the real entry carries the category field the fix now keys on');
  const site = { entry: realEntry, decision: { kind: 'log', category: 'log', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'log' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3a-2 (hotfix regression guard): every PRIVACY_SINK_CATALOG entry is excluded by resolveSiteDecision, not just one representative', async () => {
  const { PRIVACY_SINK_CATALOG } = await import('../../src/dataflow/privacy-catalog.js');
  for (const entry of PRIVACY_SINK_CATALOG) {
    const site = { entry, decision: { kind: 'external', category: 'external-api', coverageStatus: 'modeled', externality: 'external', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'call' }, args: [{ kind: 'ident', name: 'computed' }] };
    assert.equal(resolveSiteDecision(site), undefined, `${entry.id} must never be reclassified by FR-203 — it is a privacy-catalog entry`);
  }
});

test('C1/3a-3 (hotfix regression guard): the exact corruption reproduced during Sub-project F is fixed — a real store/object-storage privacy sink with a computed argument stays store/object-storage, never process/null/unsupported', async () => {
  const { buildGraphWithCoverage } = await import('../../src/lineage/coverage.js');
  const { parseJsFile } = await import('../../src/ir/parser-js.js');
  const { buildCallGraph } = await import('../../src/ir/callgraph.js');
  const cg = buildCallGraph({ 'a.js': parseJsFile('a.js', "function h(s3, patientRecord){ s3.putObject({ Body: patientRecord }); }") });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r' });
  const sinkNode = graph.nodes.find((n) => n.kind !== 'source');
  assert.ok(sinkNode, 'a sink node must exist');
  assert.equal(sinkNode.kind, 'store');
  assert.equal(sinkNode.subtype, 'object-storage');
  assert.equal(sinkNode.coverageStatus, 'modeled');
});
```

- [ ] **Step 4: Extend the completeness guard so the "unreachable" fallback claim is actually enforced against BOTH catalogs**

In `scanner/test/lineage/sink-registry.test.js`, find the `completeness/1a` test (the one asserting `CWE_MAP`'s key set matches the general `CATALOG`'s actual distinct CWE values). Add an adjacent test proving `PRIVACY_SINK_CATALOG`'s CWE values are NEVER present in `CWE_MAP` — since privacy entries are deliberately routed by `category`, not by CWE, a future accidental `CWE_MAP` row for `'CWE-359'` (or any other CWE a privacy entry might someday carry) would silently re-open this exact bug class from the other direction:

```js
test('completeness/1c (hotfix regression guard): no PRIVACY_SINK_CATALOG CWE value is ever present in CWE_MAP — privacy entries must stay routed by category, never accidentally picked up by CWE-keyed reclassification', async () => {
  const { PRIVACY_SINK_CATALOG } = await import('../../src/dataflow/privacy-catalog.js');
  const privacyCwes = new Set(PRIVACY_SINK_CATALOG.map((e) => e.vuln?.cwe).filter(Boolean));
  assert.ok(privacyCwes.size > 0, 'sanity: privacy entries really do carry CWE values worth checking');
  for (const cwe of privacyCwes) {
    assert.equal(CWE_MAP[cwe], undefined, `CWE_MAP must never map ${cwe} — it is a privacy-catalog CWE, and mapping it would let reclassifySink silently reclassify a privacy-catalog entry as if it were a general-catalog one`);
  }
});
```

Confirm `CWE_MAP` is already imported/accessible in this test file's scope (it likely is, as an internal detail — check whether it needs a new export from `sink-registry.js` or is already reachable; if it needs exporting, export it additively, matching the module's existing export style).

- [ ] **Step 5: Run the full lineage suite and the full gate**

Run: `cd scanner && npm run test:lineage`
Expected: prior count + 4 new tests (`C1/3a` rewritten counts as the same test still, `C1/3a-2`, `C1/3a-3`, `completeness/1c` — net +3 new test() calls, all passing).

Run: `cd scanner && npm test`
Expected: full gate green, exit 0.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/coverage.js scanner/test/lineage/coverage.test.js scanner/test/lineage/sink-registry.test.js
git commit -m "fix(lineage): correct FR-203's privacy-catalog exclusion guard — it never actually excluded anything

Found during Sub-project F's corpus-authoring review: every
PRIVACY_SINK_CATALOG entry carries vuln.cwe ('CWE-359'), so the guard's
'no vuln.cwe' check excluded nothing, and any privacy-catalog site
triggering FR-203 silently corrupted to process/null/unsupported via
reclassifySink's 'unreachable' fallback branch. Fixed by keying the
exclusion on the entry's own category field (something only privacy
entries carry), which general CATALOG sink entries never have."
```

---

## Self-review notes

- **Spec coverage:** the fix (Step 1), the reproduction proof (Step 2), the corrected unit test (Step 3, both the fabricated-shape fix and the exhaustive all-18-entries check plus the exact-corruption-reproduced end-to-end check), and the completeness backstop against the bug recurring from the other direction (Step 4) are all covered.
- **Placeholder scan:** every step has literal, complete code.
- **Type consistency:** `resolveSiteDecision(site)`'s signature and return contract (`decision | undefined`) are unchanged — only the internal guard condition changes.
