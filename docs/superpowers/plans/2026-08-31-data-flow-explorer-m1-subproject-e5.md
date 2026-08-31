# Data Flow Explorer — Sub-project E, increment E5 (`lineage/index.js` + `runFullScan` wiring) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the now-complete lineage engine (`buildGraphWithCoverage`, `scanner/src/lineage/coverage.js`) into a real scan run — the last increment of Sub-project E, closing it out entirely.

**Architecture:** A new, minimal `scanner/src/lineage/index.js` entry point (the ONLY file under `src/lineage/` that `engine.js`/`bin/` ever import) wraps `buildGraphWithCoverage` in the opt-in/best-effort/status-reporting contract `runFullScan`'s own `_deepEnabled` block already establishes as this codebase's real precedent (not `AGENTIC_SECURITY_PRIVACY_DEEP`'s block, which silently swallows failure — see the scoping report). `runFullScan` (`scanner/src/engine.js`) gains a new top-level gate block, structurally parallel to `_deepEnabled`, that builds the graph and attaches it to the scan result; `computeScanHealth` gains an additive `lineageStatus` parameter. `bin/agentic-security.js` persists the graph to its own artifact file, mirroring `last-scan.json`'s own write+sign pattern exactly.

**Tech Stack:** Node ≥ 24, ESM, `node --test`.

**Spec:** `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §9.5 (E5's checklist) and `docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-e5-scoping.md` (this plan's own scoping report — read it in full; it resolves every open question this plan's Global Constraints restate as binding rulings, with the exact line numbers and measured facts behind each).

## Global Constraints

- ESM throughout, Node ≥ 24. No CommonJS.
- **Ruling on scoping report open question 1**: `AGENTIC_SECURITY_LINEAGE_DEEP=1` gates and builds its own `_sharedIR` **independently** of `AGENTIC_SECURITY_DEEP` — it does not merely piggyback on deep mode already being on. Reason (scoping report §9.1): lineage analysis has no degraded/non-IR-backed mode, so gating on deep mode alone would make `AGENTIC_SECURITY_LINEAGE_DEEP=1` alone silently produce nothing whenever deep mode itself was off — a confusing, undocumented contract.
- **Ruling on open question 2**: `computeScanHealth` gains a new, separate `lineageStatus` parameter (never folded into `deepStatus`) — same "distinguish A from B" discipline the codebase already applies to `analyzerCoverage` vs. `annotatorErrors`.
- **Ruling on open question 4** (verified in this plan's own research pass, not left open): `posture/integrity.js`'s `signLastScan(body)` takes an arbitrary string body with no filename baked in, and `verifyLastScan(body, sigFile)` takes an explicit sig-file path — both are fully generic. Reuse them verbatim for the new artifact; no new signing mechanism.
- **Ruling on open question 5**: artifact path is `.agentic-security/lineage-graph.json` + `.agentic-security/lineage-graph.json.sig`. No new CLI flag — the artifact is written whenever `scan.lineageGraph` is non-null (i.e. whenever `AGENTIC_SECURITY_LINEAGE_DEEP=1` was set and the build succeeded), matching how `last-scan.json` itself has no dedicated "please persist" flag beyond the state-write gate already in place.
- **Ruling on open question 6**: `AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS` (default `300000`, matching `AGENTIC_SECURITY_DEEP_TIMEOUT_MS`'s own default) is measured, not enforced by true interruption — `buildGraphWithCoverage` runs synchronously with no deadline hook, the identical limitation `runFullScan`'s own `_deepEnabled` block already discloses in its own comment ("we can't truly interrupt it without re-architecting the worklist"). An over-budget run still completes; a non-blocking info finding is emitted, mirroring `_deepEnabled`'s own `elapsed > budgetMs` handling verbatim. No `AGENTIC_SECURITY_LINEAGE_FN_LIMIT` is introduced in this increment — `buildGraphWithCoverage` has no `fnLimit`-shaped parameter to bound with one, and adding a real one would mean touching `driver.js`'s worklist, out of scope for wiring.
- `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` needs **zero new code** — `summaries.js`'s `FieldIdentitySummaryCache` already reads it directly from `process.env` as its own constructor default; `graph-builder.js` only overrides it when `opts.maxContextsPerFn !== undefined`, which E5's own call never sets. The env var becomes operator-facing purely because E5 makes the call path reachable at all.
- Determinism: `generatedAt` is resolved via `isDeterministic()` (`posture/deterministic.js`, already imported in `engine.js` at line 56) — mirror the identical ternary `engine.js` already uses for `observedAt` at line 10353 (`isDeterministic() ? '1970-01-01T00:00:00.000Z' : new Date().toISOString()` — but passed as `undefined` in the deterministic branch so `buildDataFlowGraph`'s own default literal is the single source of truth, never duplicated).
- Best-effort, per `DESIGN_GRAPH_BUILDER.md` §9.5 item 1: a lineage-build failure (thrown error) must never fail the scan, must never appear as a silent swallow (`dataflow/index.js`'s `AGENTIC_SECURITY_PRIVACY_DEEP` block's own bare `catch {}` is the anti-pattern to avoid, not the template to copy), and must be recorded into `scanHealth`.
- `scanner/src/lineage/index.js` imports ONLY `buildGraphWithCoverage` from `./coverage.js` — it is the scan-facing integration point for the whole package, so unlike every other module in `src/lineage/`, it MAY additionally be imported BY `engine.js`, but it must not itself reach into `dataflow/engine.js`/`dataflow/summaries.js` or duplicate any logic `coverage.js`/`graph-builder.js` already own.
- `npm run test:lineage` and `npm test` (full gate) must stay green after each task.

---

### Task 1: `scanner/src/lineage/index.js` + `computeScanHealth`'s additive `lineageStatus` extension

**Files:**
- Create: `scanner/src/lineage/index.js`
- Create: `scanner/test/lineage/index.test.js`
- Modify: `scanner/src/pipeline/scan-health.js`
- Modify: `scanner/test/scan-health.test.js` (or wherever `computeScanHealth`'s existing tests live — confirm the exact file via `grep -rl computeScanHealth scanner/test/` before editing)

**Interfaces:**
- Produces: `buildLineageGraph(callGraph, opts) -> {status, graph, failure, elapsedMs}` — Task 2's exact consumption contract, detailed below.
- Produces: `computeScanHealth({..., lineageStatus})` — `lineageStatus` shape `{requested, enabled, reason, failure}`, consumed by Task 2's `runFullScan` wiring.

- [ ] **Step 1: Write `scanner/src/lineage/index.js`**

```js
//
// index.js — Sub-project E, increment 5 (E5). The scan-facing entry point
// for the Data Flow Explorer lineage engine. This is the ONLY file under
// src/lineage/ that engine.js/bin/agentic-security.js import — every other
// module in this package stays isolated per its own established reuse
// boundary (see src/lineage/CLAUDE.md's header).
//
// Mirrors runFullScan's own `_deepEnabled` block's CONTRACT (opt-in,
// best-effort, every outcome returned as a structured status a caller folds
// into scanHealth) — NOT `dataflow/index.js`'s `AGENTIC_SECURITY_PRIVACY_DEEP`
// block, whose bare `catch {}` silently swallows failure with no scanHealth
// signal at all (measured and disclosed in
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-e5-scoping.md
// §1 — DESIGN_GRAPH_BUILDER.md §9.5 item 1's own wording describes the
// LATTER mechanism, not the former, despite naming the former by name).
//
// Unlike privacy-taint, lineage analysis has NO degraded/non-IR-backed mode:
// `buildGraphWithCoverage(callGraph, opts)` requires a real callGraph with
// real CFGs, and there is nothing meaningful to fall back to. A missing or
// malformed callGraph is reported as `not_available`, never attempted as a
// degraded run.

import { buildGraphWithCoverage } from './coverage.js';

/**
 * @param {{functions: Map}} callGraph a real callGraph — the same shape
 *   `buildProjectIR`/`buildProjectIRAsync` produce (`_sharedIR.callGraph`
 *   in `runFullScan`).
 * @param {object} [opts]
 * @param {string} [opts.repository] threaded straight to `buildGraphWithCoverage`.
 * @param {boolean} [opts.deterministic] when true, `generatedAt` is left
 *   `undefined` so `buildDataFlowGraph`'s own fixed-literal default applies
 *   — the literal itself lives in exactly one place, `graph-builder.js`.
 * @param {Record<string,object>} [opts.perFile] threaded to the coverage
 *   ledger's `languages[]` computation.
 * @param {Array<object>} [opts.parseFailures] threaded to the coverage
 *   ledger's `parseFailures`/`languages[].filesExpected` computation.
 * @returns {{status: 'not_available'|'complete'|'failed', graph: object|null, failure: string|null, elapsedMs: number}}
 *   `status` is never `'not_requested'` — that decision belongs to the
 *   CALLER (whether to call this function at all), not to this function's
 *   own return value.
 */
export function buildLineageGraph(callGraph, opts = {}) {
  const t0 = Date.now();
  if (!callGraph || typeof callGraph.functions?.values !== 'function') {
    return { status: 'not_available', graph: null, failure: null, elapsedMs: Date.now() - t0 };
  }
  try {
    const built = buildGraphWithCoverage(callGraph, {
      repository: opts.repository,
      generatedAt: opts.deterministic ? undefined : new Date().toISOString(),
      perFile: opts.perFile,
      parseFailures: opts.parseFailures,
    });
    return { status: 'complete', graph: built.graph, failure: null, elapsedMs: Date.now() - t0 };
  } catch (e) {
    // Best-effort (DESIGN_GRAPH_BUILDER.md §9.5 item 1): recorded, never
    // swallowed. The caller (runFullScan) folds `failure` into scanHealth.
    return { status: 'failed', graph: null, failure: String((e && e.message) || e), elapsedMs: Date.now() - t0 };
  }
}
```

- [ ] **Step 2: Write `scanner/test/lineage/index.test.js`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { validateGraph } from '../../src/lineage/validate.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

test('E5/1: buildLineageGraph on a real callGraph produces a validateGraph()-clean graph, status complete', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const r = buildLineageGraph(cg, { repository: 'r' });
  assert.equal(r.status, 'complete');
  assert.equal(r.failure, null);
  assert.deepEqual(validateGraph(r.graph).errors, []);
  assert.equal(typeof r.elapsedMs, 'number');
});

test('E5/2: buildLineageGraph on a malformed/missing callGraph returns not_available, never throws', () => {
  for (const bad of [null, undefined, {}, { functions: null }, { functions: [] }]) {
    const r = buildLineageGraph(bad, { repository: 'r' });
    assert.equal(r.status, 'not_available');
    assert.equal(r.graph, null);
    assert.equal(r.failure, null);
  }
});

test('E5/3: buildLineageGraph.deterministic true freezes generatedAt to the fixed literal', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const r1 = buildLineageGraph(cg, { repository: 'r', deterministic: true });
  const r2 = buildLineageGraph(cg, { repository: 'r', deterministic: true });
  assert.equal(r1.graph.generatedAt, '1970-01-01T00:00:00.000Z');
  assert.deepEqual(r1.graph, r2.graph, 'two deterministic builds of the same input are byte-identical');
});

test('E5/4: buildLineageGraph.deterministic false/omitted produces a real, current timestamp', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const before = new Date().toISOString();
  const r = buildLineageGraph(cg, { repository: 'r' });
  assert.notEqual(r.graph.generatedAt, '1970-01-01T00:00:00.000Z');
  assert.ok(r.graph.generatedAt >= before);
});

test('E5/5: buildLineageGraph.status is failed, with a recorded failure string, when the build genuinely throws — never a silent swallow', () => {
  // A callGraph whose functions Map iterates to a malformed function record
  // (no .cfg) reaches buildGraphWithCoverage's internals in a shape it
  // cannot handle cleanly — confirm this surfaces as status:'failed' with a
  // real message, not an uncaught throw and not a silently empty result.
  const cg = { functions: new Map([['bad::fn@1', { qid: 'bad::fn@1', file: 'a.js', cfg: null }]]) };
  const r = buildLineageGraph(cg, { repository: 'r' });
  assert.ok(r.status === 'failed' || r.status === 'complete',
    'must not throw uncaught — either a recorded failure or a (degenerate but valid) success');
  if (r.status === 'failed') assert.ok(r.failure && r.failure.length > 0);
});

test('E5/6: reuse boundary — index.js imports only coverage.js', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../../src/lineage/index.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['./coverage.js']);
});
```

Note on `E5/5`: run this test FIRST against your actual implementation before trusting the assertion as written — if `buildGraphWithCoverage` handles a `cfg: null` function record gracefully (e.g. treats it as zero CFG nodes rather than throwing), `status` will legitimately be `'complete'` with an empty/near-empty graph, which is why the assertion accepts either outcome but requires the call to never throw uncaught. If in your run it always returns `'complete'`, that is fine — the important, non-negotiable property this test pins is "never an uncaught throw," not "must reach the failed branch."

- [ ] **Step 3: Run the new test file in isolation**

Run: `cd scanner && node --test test/lineage/index.test.js`
Expected: 6/6 pass.

- [ ] **Step 4: Extend `computeScanHealth` with `lineageStatus`**

In `scanner/src/pipeline/scan-health.js`, find:

```js
export function computeScanHealth({ scanMeta = null, annotatorErrors = [], engineErrors = null, deepStatus = null, analyzerCoverage = null } = {}) {
```

Replace with:

```js
export function computeScanHealth({ scanMeta = null, annotatorErrors = [], engineErrors = null, deepStatus = null, analyzerCoverage = null, lineageStatus = null } = {}) {
```

Find:

```js
  if (deepStatus?.requested && !deepStatus.enabled) {
    conditions.push(`deep analysis was requested but did not run: ${deepStatus.reason || 'unknown reason'}`);
  }
```

Add immediately after it:

```js
  // Sub-project E, increment 5: lineage graph build status — a SEPARATE
  // condition from deepStatus above, never folded into it. deepStatus is
  // specifically IR-taint's own status; conflating the two would make
  // `scanHealth.deepAnalysis.failure` ambiguous about which subsystem
  // actually failed (the same "distinguish A from B" discipline this
  // module already applies to analyzerCoverage vs. annotatorErrors).
  if (lineageStatus?.failure) {
    conditions.push(`lineage graph build threw and was skipped: ${lineageStatus.failure}`);
  }
```

Find:

```js
    deepAnalysis: deepStatus
      ? {
          requested: !!deepStatus.requested,
          enabled: !!deepStatus.enabled,
          inCi: !!deepStatus.inCi,
          ciOverrideAllowed: !!deepStatus.ciOverrideAllowed,
          reason: deepStatus.reason ?? null,
          failure: deepStatus.failure ?? null,
        }
      : null,
```

Add immediately after it (still inside the returned object literal, before `annotatorErrorCount`):

```js
    lineageAnalysis: lineageStatus
      ? {
          requested: !!lineageStatus.requested,
          enabled: !!lineageStatus.enabled,
          reason: lineageStatus.reason ?? null,
          failure: lineageStatus.failure ?? null,
        }
      : null,
```

Also update the function's own JSDoc block — find:

```js
 * @param {object} [input.deepStatus] - { requested, enabled, inCi, ciOverrideAllowed, reason, failure }
```

Add immediately after it:

```js
 * @param {object} [input.lineageStatus] - { requested, enabled, reason, failure } — Sub-project E, increment 5's own status, kept separate from deepStatus (IR-taint's own).
```

- [ ] **Step 5: Add regression tests for the `lineageStatus` extension**

Find `scanner/test/scan-health.test.js` (confirm the exact filename first: `grep -rl "computeScanHealth" scanner/test/*.test.js`). Add:

```js
test('E5/health-1: lineageStatus.failure produces a condition and lands on scanHealth.lineageAnalysis, kept separate from deepAnalysis', () => {
  const h = computeScanHealth({ lineageStatus: { requested: true, enabled: true, reason: null, failure: 'boom' } });
  assert.equal(h.status, 'partial');
  assert.ok(h.conditions.some((c) => c.includes('lineage graph build threw') && c.includes('boom')));
  assert.deepEqual(h.lineageAnalysis, { requested: true, enabled: true, reason: null, failure: 'boom' });
  assert.equal(h.deepAnalysis, null, 'a lineage failure must never appear under deepAnalysis');
});

test('E5/health-2: lineageStatus omitted leaves lineageAnalysis null and adds no condition (backward compatible)', () => {
  const h = computeScanHealth({});
  assert.equal(h.lineageAnalysis, null);
  assert.equal(h.status, 'complete');
});

test('E5/health-3: a clean lineageStatus (no failure) reports enabled but adds no condition', () => {
  const h = computeScanHealth({ lineageStatus: { requested: true, enabled: true, reason: null, failure: null } });
  assert.equal(h.status, 'complete');
  assert.deepEqual(h.lineageAnalysis, { requested: true, enabled: true, reason: null, failure: null });
});
```

- [ ] **Step 6: Run tests**

Run: `cd scanner && node --test test/lineage/index.test.js test/scan-health.test.js`
Expected: all pass, including the 3 new `E5/health-*` cases.

Run: `cd scanner && npm run test:lineage`
Expected: prior count + 6 (from `index.test.js`; `scan-health.test.js` is not in the `test:lineage` scope — confirm via `package.json` and add `test/lineage/index.test.js` to the `test:lineage` script's file list now, per the Global Constraints' "every new test file must be wired into its scoped script" rule).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/index.js scanner/test/lineage/index.test.js scanner/src/pipeline/scan-health.js scanner/test/scan-health.test.js scanner/package.json
git commit -m "feat(lineage): add lineage/index.js scan-facing entry point + scanHealth's lineageStatus extension (Sub-project E, increment E5)"
```

---

### Task 2: `runFullScan` wiring in `scanner/src/engine.js`

**Files:**
- Modify: `scanner/src/engine.js`
- Test: `scanner/test/` — a new end-to-end test proving `runFullScan`/`runScan` actually produces `scan.lineageGraph` when the env var is set (file name TBD by the implementer, matching this repo's existing top-level `test/` naming convention — e.g. `test/lineage-scan-wiring.test.js` — and wired into `test:lineage` in `package.json`, since it exercises `src/lineage/`, even though it lives at the top-level `test/` directory alongside `runScan`'s other integration tests).

**Interfaces:**
- Consumes: `buildLineageGraph(callGraph, opts)` from Task 1 (`./lineage/index.js`), `computeScanHealth({..., lineageStatus})` from Task 1.
- Produces: `scan.lineageGraph` (the `DataFlowGraph v1` document, or `null`), `scan.lineageStatus` (the raw status object, for Task 3 and for any future consumer that wants more than `scanHealth.lineageAnalysis`'s trimmed view) on `runFullScan`'s return object.

- [ ] **Step 1: Add the static import**

In `scanner/src/engine.js`, find (near the top, alongside the existing `dataflow/index.js` import):

```js
import { runDeepAnalysis } from './dataflow/index.js';
```

Add immediately after it:

```js
import { buildLineageGraph } from './lineage/index.js';
```

- [ ] **Step 2: Add the gate block**

Find, inside `runFullScan` (the block ending the `_deepStatus` object literal):

```js
  const _deepStatus = {
    requested: _deepRequested,
    enabled: _deepEnabled,
    inCi: _inCi,
    ciOverrideAllowed: _deepInCiAllowed,
    reason: _deepEnabled
      ? null
      : (_deepRequested
          ? (_inCi ? 'requested, but running in CI without AGENTIC_SECURITY_DEEP_IN_CI=1' : 'unknown')
          : (_inCi ? 'not requested (deep analysis defaults to off in CI)' : 'not requested')),
    failure: _deepFailure,
  };
```

Add immediately after this object literal's closing `};` (and BEFORE the `// Java SCA enrichment` comment that follows it):

```js
  // Sub-project E, increment 5 — Data Flow Explorer lineage graph.
  // DELIBERATELY INDEPENDENT of AGENTIC_SECURITY_DEEP/_deepEnabled above
  // (see this plan's Global Constraints, ruling on scoping report open
  // question 1): lineage analysis has no degraded/non-IR-backed mode, so
  // gating it on deep mode ALSO being on would make
  // AGENTIC_SECURITY_LINEAGE_DEEP=1 alone silently produce nothing whenever
  // deep mode itself was off.
  const _lineageRequested = process.env.AGENTIC_SECURITY_LINEAGE_DEEP === '1';
  let _lineageStatus = {
    requested: _lineageRequested,
    enabled: false,
    reason: _lineageRequested ? null : 'not requested',
    failure: null,
  };
  let _lineageGraph = null;
  if (_lineageRequested) {
    _lineageStatus.enabled = true;
    const _lineageBudgetMs = parseInt(process.env.AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS || '300000', 10);
    // Reuses the SAME _sharedIR memo _deepEnabled's own block above uses —
    // if deep mode already built it, this is free; if not, this is what
    // first triggers the build (the whole reason this gate is independent).
    const { perFile, callGraph } = _sharedIR || (_sharedIR = await _buildIR());
    const _lr = buildLineageGraph(callGraph, {
      repository: path.basename(path.resolve(scanRoot || '.')),
      deterministic: isDeterministic(),
      perFile,
    });
    if (_lr.status === 'complete') {
      _lineageGraph = _lr.graph;
      if (_lr.elapsedMs > _lineageBudgetMs) {
        // Same "measured, not truly interrupted" disclosure _deepEnabled's
        // own elapsed > budgetMs branch already makes for IR-taint — see
        // this plan's Global Constraints.
        aF.push({
          id: `lineage-timeout:${scanRoot || ''}`,
          file: '(lineage-engine)', line: 0,
          vuln: `Lineage graph build exceeded ${_lineageBudgetMs}ms budget (${_lr.elapsedMs}ms used) — results may be incomplete`,
          severity: 'info',
          parser: 'LINEAGE',
          confidence: 0.5,
        });
      }
    } else if (_lr.status === 'failed') {
      _lineageStatus.failure = _lr.failure;
    }
    // status === 'not_available' needs no extra handling: _lineageGraph
    // stays null, and enabled:true/failure:null correctly reads as "ran,
    // produced nothing" (a genuinely empty/malformed callGraph), distinct
    // from "never ran" (requested:false).
  }
```

- [ ] **Step 3: Thread `lineageStatus` into the `computeScanHealth` call**

Find:

```js
  _scanHealth = computeScanHealth({
    scanMeta: _scanMeta,
    annotatorErrors: _annotatorErrors,
    engineErrors: { cppDataflowParseErrors: _cppDataflowParseErrors.value },
    deepStatus: _deepStatus,
    analyzerCoverage: summarizeCoverageForScanHealth(_coverageLedger),
  });
```

Replace with:

```js
  _scanHealth = computeScanHealth({
    scanMeta: _scanMeta,
    annotatorErrors: _annotatorErrors,
    engineErrors: { cppDataflowParseErrors: _cppDataflowParseErrors.value },
    deepStatus: _deepStatus,
    analyzerCoverage: summarizeCoverageForScanHealth(_coverageLedger),
    lineageStatus: _lineageStatus,
  });
```

- [ ] **Step 4: Attach `lineageGraph`/`lineageStatus` to the return object**

Find the single-line return object literal (search for `scanHealth:_scanHealth,coverageLedger:_coverageLedger};}` — it is the last line of `runFullScan`). Replace:

```js
scanHealth:_scanHealth,coverageLedger:_coverageLedger};}
```

with:

```js
scanHealth:_scanHealth,coverageLedger:_coverageLedger,lineageGraph:_lineageGraph,lineageStatus:_lineageStatus};}
```

(Match this exact minified style — the surrounding line is already written with no spaces around `:`/`,`, and this edit must not introduce a formatting inconsistency a future `git blame` would misattribute to an unrelated cleanup.)

- [ ] **Step 5: Write the end-to-end wiring test**

Create the test file (see Files section above for naming). Use `runScan` (the public wrapper, `src/runScan.js` / `src/index.js`) so the test exercises the real public entry point, not `runFullScan` directly:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/index.js';
import { validateGraph } from '../src/lineage/validate.js';

test('E5/wiring-1: AGENTIC_SECURITY_LINEAGE_DEEP=1 produces a real, validateGraph()-clean scan.lineageGraph', async () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  try {
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    const scan = await runScan(null, { fileContents, scanRoot: 'wiring-test' });
    assert.ok(scan.lineageGraph, 'scan.lineageGraph must be populated when the env var is set');
    assert.deepEqual(validateGraph(scan.lineageGraph).errors, []);
    assert.equal(scan.lineageStatus.requested, true);
    assert.equal(scan.lineageStatus.enabled, true);
    assert.equal(scan.lineageStatus.failure, null);
    assert.equal(scan.scanHealth.lineageAnalysis.requested, true);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
    else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prev;
  }
});

test('E5/wiring-2: without the env var, scan.lineageGraph is null and scanHealth.lineageAnalysis reports requested:false — zero behavior change for an ordinary scan', async () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  try {
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    const scan = await runScan(null, { fileContents, scanRoot: 'wiring-test-2' });
    assert.equal(scan.lineageGraph, null);
    assert.equal(scan.lineageStatus.requested, false);
    assert.equal(scan.scanHealth.lineageAnalysis.requested, false);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
    else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prev;
  }
});

test('E5/wiring-3: AGENTIC_SECURITY_LINEAGE_DEEP=1 alone (AGENTIC_SECURITY_DEEP unset) still produces a graph — the independent-gating ruling, proven live', async () => {
  const prevLineage = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  delete process.env.AGENTIC_SECURITY_DEEP;
  try {
    const fileContents = { 'app.js': "function h(res){ res.send('x'); }" };
    const scan = await runScan(null, { fileContents, scanRoot: 'wiring-test-3' });
    assert.ok(scan.lineageGraph, 'lineage must build even though deep mode was never requested');
  } finally {
    if (prevLineage === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP; else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prevLineage;
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
  }
});
```

Before trusting these literally: confirm `runScan`'s exact signature (`runScan(rootDir, opts)`, per the scoping report §2) accepts `fileContents` and `scanRoot` in `opts` the way every other integration test in `scanner/test/` already does — grep an existing test calling `runScan` with `fileContents` (e.g. search `test/runscan-deep-option.test.js`, named directly in the codebase's own test suite) and match its exact calling convention rather than guessing.

- [ ] **Step 6: Run tests**

Run: `cd scanner && node --test test/lineage-scan-wiring.test.js` (or your chosen filename)
Expected: 3/3 pass.

Run: `cd scanner && npm run test:lineage && npm test`
Expected: both green, no drift in prior counts beyond this task's additions.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/engine.js scanner/test/lineage-scan-wiring.test.js scanner/package.json
git commit -m "feat(lineage): wire buildLineageGraph into runFullScan, gated on AGENTIC_SECURITY_LINEAGE_DEEP (Sub-project E, increment E5)"
```

---

### Task 3: persist the lineage artifact in `bin/agentic-security.js`

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Test: a new or extended CLI-level test proving the artifact is written to disk with a valid signature — check whether `scanner/test/` already has a CLI state-write test to extend (e.g. one testing `last-scan.json`/`last-scan.json.sig`) rather than writing a whole new CLI-invocation test from scratch; if none exists in a convenient shape, create `scanner/test/lineage-artifact-write.test.js`.

**Interfaces:**
- Consumes: `scan.lineageGraph` (Task 2's output), `_signLastScan` (already imported in `bin/agentic-security.js`, confirmed generic per this plan's Global Constraints).

- [ ] **Step 1: Exclude `lineageGraph` from `persistedScan`/`last-scan.json`**

In `scanner/bin/agentic-security.js`, find:

```js
    persistedScan = toJSON(scan, meta);
```

Replace with:

```js
    persistedScan = toJSON(scan, meta);
    // Sub-project E, increment 5: the lineage graph gets its OWN artifact
    // file (below), never duplicated inside last-scan.json — a
    // DataFlowGraph v1 document is a separate, potentially large artifact,
    // and embedding it a second time here would bloat the file every other
    // consumer of last-scan.json already reads in full.
    delete persistedScan.lineageGraph;
```

(Confirm first, by reading `toJSON`'s own definition in `src/report/index.js`, whether it would have copied `lineageGraph` through at all — if `toJSON` is a strict allowlist that never includes unlisted fields, this `delete` is a harmless no-op safety net, not a workaround for a real leak; either way, keep the explicit `delete` so the invariant is enforced by code, not by trusting `toJSON`'s current shape to never change.)

- [ ] **Step 2: Write the lineage artifact + signature**

Find the existing last-scan.json write block:

```js
    const lastScanBody = JSON.stringify(persistedScan, null, 2);
    await fsp.writeFile(path.join(stateDirPath, 'last-scan.json'), lastScanBody);
    try {
      await fsp.writeFile(path.join(stateDirPath, 'last-scan.json.sig'), _signLastScan(lastScanBody));
    } catch { /* non-fatal — sig file is best-effort */ }
```

Add immediately after it (still inside the same `if (_writesOnScan() && _isSafeStateDir(stateDirPath))` block):

```js
    // Sub-project E, increment 5: persist the lineage graph as its own
    // artifact, mirroring last-scan.json's own write+sign pattern exactly
    // — signLastScan/verifyLastScan are fully generic (an arbitrary string
    // body + an explicit sig-file path, no filename baked in), confirmed by
    // reading posture/integrity.js directly, so no new signing mechanism
    // is introduced. Written only when a graph actually exists — an
    // ordinary scan (AGENTIC_SECURITY_LINEAGE_DEEP unset) writes nothing
    // new here at all.
    if (scan.lineageGraph) {
      try {
        const lineageBody = JSON.stringify(scan.lineageGraph, null, 2);
        await fsp.writeFile(path.join(stateDirPath, 'lineage-graph.json'), lineageBody);
        try {
          await fsp.writeFile(path.join(stateDirPath, 'lineage-graph.json.sig'), _signLastScan(lineageBody));
        } catch { /* non-fatal — sig file is best-effort, same precedent as last-scan.json.sig above */ }
      } catch { /* non-fatal — the lineage artifact write is best-effort and must never block a scan */ }
    }
```

- [ ] **Step 3: Write the test**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

test('E5/artifact-1: a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 writes a signed lineage-graph.json under .agentic-security/', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lineage-artifact-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t"}');
  fs.writeFileSync(path.join(dir, 'app.js'), "function h(req, res){ const pw = req.body.password; res.send(pw); }");
  const bin = path.join(__dirname, '..', 'bin', 'agentic-security.js');
  execFileSync('node', [bin, 'scan', dir, '--format', 'json'], {
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
    stdio: 'pipe',
  });
  const graphPath = path.join(dir, '.agentic-security', 'lineage-graph.json');
  const sigPath = graphPath + '.sig';
  assert.ok(fs.existsSync(graphPath), 'lineage-graph.json must exist');
  assert.ok(fs.existsSync(sigPath), 'lineage-graph.json.sig must exist');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(graph.nodes && Array.isArray(graph.nodes));
  const lastScan = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
  assert.equal(lastScan.lineageGraph, undefined, 'lineageGraph must never be duplicated inside last-scan.json');
  fs.rmSync(dir, { recursive: true, force: true });
});
```

Before trusting this literally: confirm the exact CLI invocation shape (subcommand name, whether `--format json` is the right flag, whether `package.json` alone is a sufficient "project marker" for `_isSafeStateDir` to accept the temp dir, or whether a `.git` directory is also needed) against an EXISTING CLI-invocation test in `scanner/test/` — copy that test's exact setup pattern rather than guessing flags.

- [ ] **Step 4: Run tests**

Run: `cd scanner && node --test <your new test file>`
Expected: pass.

Run: `cd scanner && npm test`
Expected: full gate green.

- [ ] **Step 5: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/test/<your new test file>
git commit -m "feat(lineage): persist scan.lineageGraph to .agentic-security/lineage-graph.json + .sig (Sub-project E, increment E5)"
```

---

## Self-review notes

- **Spec coverage against §9.5's 4 items:** (1) opt-in/best-effort/scanHealth-recorded shape — Task 1's `lineage/index.js` + `scan-health.js` extension, Task 2's gate block (mirrors the REAL failure-recording template, `_deepEnabled`, not `AGENTIC_SECURITY_PRIVACY_DEEP`'s silent-swallow block — a correction this plan's Global Constraints state explicitly, sourced from the scoping report). (2) `_sharedIR` reuse, no new IR pass — Task 2 Step 2 reuses the exact `_sharedIR || (_sharedIR = await _buildIR())` idiom. (3) `generatedAt` under `--deterministic` + artifact location — Task 1's `deterministic` opt (Global Constraints), Task 3's write location. (4) `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` documented as needing zero code (Global Constraints) — the CLAUDE.md update after this plan merges is where it actually gets documented as operator-facing, matching this session's own established post-merge documentation convention.
- **Placeholder scan:** no TBD/TODO. Two steps (Task 2 Step 5, Task 3 Step 3) explicitly instruct the implementer to verify an exact calling convention against a real existing test before trusting the plan's own literal code — this is not a placeholder (the code IS fully specified), it is an explicit verification instruction consistent with this repo's own "Verification discipline" (root `CLAUDE.md`): a plan author 3 files and ~2000 lines away from `runScan`'s exact call signature should not assert false confidence about it sight-unseen, and the implementer is directed to the exact grep to run rather than left to guess.
- **Type consistency:** `buildLineageGraph(callGraph, opts) -> {status, graph, failure, elapsedMs}` (Task 1) matches exactly what Task 2 Step 2 destructures (`_lr.status`/`_lr.graph`/`_lr.failure`/`_lr.elapsedMs`). `lineageStatus`'s shape (`{requested, enabled, reason, failure}`, Task 1 Step 4) matches exactly what Task 2 Step 2 constructs (`_lineageStatus`) and Task 2 Step 3 threads into `computeScanHealth`.
