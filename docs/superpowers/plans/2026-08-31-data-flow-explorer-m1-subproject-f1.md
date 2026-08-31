# Data Flow Explorer — Sub-project F, increment F1 (`bench/data-lineage/runner.mjs` — the corpus scoring contract) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the scoring runner for the lineage benchmark corpus (`bench/data-lineage/runner.mjs`), formalizing the shape-match scoring contract sketched in the Sub-project F scoping report, and absorb the 3 existing seed fixtures as its first proof that the runner actually works end-to-end against real `buildGraphWithCoverage` output.

**Architecture:** A pure, `bench/cve-replay/runner.mjs`-adjacent CLI script — same exit-code/CLI-flag SHAPE (0 clean, 1 gate failure, 2 setup error; `--check` for the gating mode), but a **structurally different scorer**: cve-replay asks "is this vulnerable, yes/no" (binary presence/absence of a matching finding); this corpus asks "does the built graph correctly REPRESENT this flow's category/transform/coverage" (a shape-match against a hand-labeled `expected.json`, per fixture). No `corpus-baseline.json` is introduced — unlike cve-replay, `expected.json` already IS the full ground truth per entry, so there is nothing a separate baseline file would add; gating is purely a function of each entry's own `tier` field (`regression` entries must pass; `capability` entries are scored and reported but never fail the gate).

**Tech Stack:** Node ≥ 24, ESM.

**Spec:** `docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-f-scoping.md` §3 (the scoring contract sketch), §4 (AC-01/AC-02/AC-11 as concrete assertions — this increment's own regression fixtures prove AC-02 and AC-11 directly), and `bench/data-lineage/README.md` (the existing fixture-shape design, which this increment extends, not replaces).

## Global Constraints

- ESM throughout, Node ≥ 24. No CommonJS.
- The runner imports ONLY already-shipped `src/lineage/`/`src/ir/` modules: `buildGraphWithCoverage` from `../../scanner/src/lineage/coverage.js`, `parseJsFile` from `../../scanner/src/ir/parser-js.js`, `buildCallGraph` from `../../scanner/src/ir/callgraph.js`. Never `dataflow/engine.js`, never `dataflow/summaries.js` — this corpus measures the LINEAGE engine, not the taint engine.
- Determinism: every fixture is built with `generatedAt: '1970-01-01T00:00:00.000Z'` and a fixed `repository` (the fixture's own directory name) — the runner's own output must be byte-identical run-to-run for the same corpus state.
- **Milestone-2-deferred fields are recorded but never scored.** `expected.json`'s `expectedProtection` field is read and displayed but never asserted against `flow.protectionSummary`/`edge.protection` — per the scoping report §2's finding, those fields are unconditionally `not_assessed`/empty in every graph Milestone 1 can produce, so scoring them now would either always fail or force the corpus to lie about what's provable today. This is a load-bearing rule, not an oversight — do not "fix" it by asserting the placeholder value.
- **A fixture's `tier` field determines gating, not fixture content.** `tier: 'regression'` (or the field absent, defaulting to `'regression'` — matches the 3 existing seed fixtures, which predate this field and are all fully achievable per the scoping report) must pass for `--check` to exit 0. `tier: 'capability'` entries are always scored and reported, and a failure there is visible in the report, but never flips the gate's exit code.
- New/changed `expected.json` fields this increment introduces: `tier` (`'regression'` | `'capability'`, optional, default `'regression'`) and `expectedConnected` (`boolean`, optional, default `true` — `false` marks a deliberately-disconnected AC-11-shaped fixture, where the runner must assert NO connecting flow exists rather than one). Both are purely additive to the existing 3 fixtures' shape — no existing field is renamed or removed.
- `npm run test:lifecycle`/`test/no-orphan-scripts.test.js`-style gates in this repo require every new script to be wired into `package.json`; add `bench:data-lineage` and `bench:data-lineage:check` mirroring `bench:cve-replay`'s own naming convention exactly (`scanner/package.json:85-88`).

---

### Task 1: `bench/data-lineage/runner.mjs` + tier fields on the 3 seed fixtures

**Files:**
- Create: `bench/data-lineage/runner.mjs`
- Modify: `bench/data-lineage/fixtures/js-api-to-log-masked/expected.json`
- Modify: `bench/data-lineage/fixtures/js-api-to-log-raw/expected.json`
- Modify: `bench/data-lineage/fixtures/js-api-to-external-http-cleartext/expected.json`
- Create: `bench/data-lineage/fixtures/js-api-to-log-disconnected/{source.js,expected.json}` (a new, 4th seed fixture — AC-11's own disconnected-node shape has no existing proof fixture; this increment adds one so the runner's `expectedConnected: false` path is exercised by something real, not just unit-tested in isolation)
- Modify: `bench/data-lineage/README.md` (update to describe the runner + the new fields, replacing its "runner lands with Milestone 1" forward-reference — that milestone is now here)
- Modify: `scanner/package.json` (wire the two new scripts)
- Test: `scanner/test/bench-data-lineage-runner.test.js` (a `node:test` suite proving the runner's own scoring logic directly, independent of the CLI — see Step 2)

**Interfaces:**
- Produces: `bench/data-lineage/runner.mjs`'s exported (for direct testing) `scoreFixture(graph, expected)` → `{pass: boolean, errors: string[]}`, and its CLI entry point (`node bench/data-lineage/runner.mjs [--check]`).

- [ ] **Step 1: Add the tier/expectedConnected fields to the 3 existing fixtures, and write the 4th seed fixture**

In `bench/data-lineage/fixtures/js-api-to-log-masked/expected.json`, add `"tier": "regression"` (all three existing fixtures are fully achievable per the scoping report §2, so all three are `regression`-tier):

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": { "handling": "protected" },
  "expectedTransformKind": "mask",
  "tier": "regression",
  "notes": "maskCard() applied to every feasible path before logger.info()"
}
```

Apply the same `"tier": "regression"` addition to `js-api-to-log-raw/expected.json` and `js-api-to-external-http-cleartext/expected.json`, changing nothing else in either file.

Create `bench/data-lineage/fixtures/js-api-to-log-disconnected/source.js`:

```js
function handleCheckout(req, res) {
  const cardNumber = req.body.card_number;
  res.send('ok');
}

function unrelatedLogging(logger, status) {
  logger.info('checkout finished', { status });
}
```

Create `bench/data-lineage/fixtures/js-api-to-log-disconnected/expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "expectedConnected": false,
  "tier": "regression",
  "notes": "AC-11: card_number never reaches the logger (logger.info logs a different variable, `status`) — the log sink node must still be visible in graph.nodes with a coverage reason, not silently absent, even though no flow connects it to the PCI source."
}
```

- [ ] **Step 2: Write `bench/data-lineage/runner.mjs`**

```js
#!/usr/bin/env node
//
// bench/data-lineage/runner.mjs — Sub-project F, increment F1.
//
// Scores every fixture under bench/data-lineage/fixtures/ against its own
// expected.json, by building a real DataFlowGraph v1 document
// (buildGraphWithCoverage) from the fixture's source.js and checking that
// the graph correctly REPRESENTS the labeled flow — a shape-match, not the
// binary vulnerable/clean presence check bench/cve-replay/runner.mjs uses.
// See docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-f-scoping.md
// §3 for why this corpus needs a different scorer, not a copy of cve-replay's.
//
// Milestone-2-deferred fields (expectedProtection) are recorded and printed,
// never asserted — graph.limitations already discloses that protection
// verdicts are not_assessed in Milestone 1; scoring them now would either
// always fail or force the corpus to lie about what's provable today.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../scanner/src/ir/parser-js.js';
import { buildCallGraph } from '../../scanner/src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../scanner/src/lineage/coverage.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, 'fixtures');

/** Builds a deterministic DataFlowGraph v1 document from one fixture's source.js. */
export function buildFixtureGraph(fixtureId, sourceCode) {
  const perFile = { 'source.js': parseJsFile('source.js', sourceCode) };
  const callGraph = buildCallGraph(perFile);
  const { graph } = buildGraphWithCoverage(callGraph, {
    repository: fixtureId,
    generatedAt: '1970-01-01T00:00:00.000Z',
  });
  return graph;
}

/**
 * The shape-match scoring contract (scoping report §3). Never throws —
 * returns {pass, errors}, errors always populated when pass is false.
 */
export function scoreFixture(graph, expected) {
  const errors = [];
  const sourceNodes = graph.nodes.filter((n) => n.subtype === expected.sourceCategory);
  const sinkNodes = graph.nodes.filter((n) => n.subtype === expected.sinkCategory);
  if (sourceNodes.length === 0) errors.push(`no node with subtype '${expected.sourceCategory}' (source category)`);
  if (sinkNodes.length === 0) errors.push(`no node with subtype '${expected.sinkCategory}' (sink category)`);
  if (errors.length > 0) return { pass: false, errors };

  const sourceIds = new Set(sourceNodes.map((n) => n.id));
  const sinkIds = new Set(sinkNodes.map((n) => n.id));
  const dataElById = new Map(graph.dataElements.map((d) => [d.id, d]));
  const dataClasses = expected.dataClass ?? [];

  const matchingFlows = graph.flows.filter((f) =>
    sourceIds.has(f.source) && sinkIds.has(f.sink) &&
    f.dataElementIds.some((id) => {
      const de = dataElById.get(id);
      return de && (de.dataClasses ?? []).some((c) => dataClasses.includes(c));
    }));

  const expectConnected = expected.expectedConnected !== false; // default true

  if (!expectConnected) {
    if (matchingFlows.length > 0) {
      errors.push(`expected NO connecting flow (expectedConnected: false) but found ${matchingFlows.length}`);
    }
    // AC-11: a disconnected node must still be VISIBLE with a coverage
    // reason, never silently absent — assert this on every candidate sink
    // node (the one AC-11 actually cares about for this fixture shape).
    for (const n of sinkNodes) {
      if (!n.coverageReason) errors.push(`sink node ${n.id} (subtype ${n.subtype}) has no coverageReason — AC-11 requires a disconnected node to still disclose why`);
    }
    return { pass: errors.length === 0, errors };
  }

  if (matchingFlows.length === 0) {
    errors.push('expected a connecting flow (matching source/sink category AND a shared dataClass) but found none');
    return { pass: false, errors };
  }

  if (expected.expectedTransformKind) {
    const transformById = new Map(graph.transformations.map((t) => [t.id, t]));
    const hasKind = matchingFlows.some((f) =>
      f.transformationIds.some((tid) => transformById.get(tid)?.kind === expected.expectedTransformKind));
    if (!hasKind) errors.push(`expected a transformation of kind '${expected.expectedTransformKind}' on the matching flow, found none`);
  } else if (expected.expectedTransformKind === null) {
    const hasUntransformed = matchingFlows.some((f) => f.transformationIds.length === 0);
    if (!hasUntransformed) errors.push('expected an UNtransformed flow (expectedTransformKind: null) but every matching flow carries a transformation');
  }

  return { pass: errors.length === 0, errors };
}

function loadFixtures() {
  const ids = fs.readdirSync(FIXTURES_DIR).filter((f) => fs.statSync(path.join(FIXTURES_DIR, f)).isDirectory());
  return ids.sort().map((id) => {
    const dir = path.join(FIXTURES_DIR, id);
    const sourceFile = fs.readdirSync(dir).find((f) => f.startsWith('source.'));
    const source = fs.readFileSync(path.join(dir, sourceFile), 'utf8');
    const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
    return { id, source, expected, tier: expected.tier ?? 'regression' };
  });
}

async function main() {
  const args = process.argv.slice(2);
  const checkMode = args.includes('--check');

  let fixtures;
  try {
    fixtures = loadFixtures();
  } catch (e) {
    console.error(`bench/data-lineage: failed to load fixtures: ${e.message}`);
    process.exit(2);
  }
  if (fixtures.length === 0) {
    console.error('bench/data-lineage: no fixtures found under fixtures/ — nothing to check');
    process.exit(2);
  }

  let regressionFail = 0;
  let capabilityFail = 0;
  let pass = 0;

  for (const fx of fixtures) {
    let result;
    try {
      const graph = buildFixtureGraph(fx.id, fx.source);
      result = scoreFixture(graph, fx.expected);
    } catch (e) {
      result = { pass: false, errors: [`threw while building/scoring: ${e.message}`] };
    }
    if (result.pass) {
      pass++;
      console.log(`  ok  [${fx.tier}] ${fx.id}`);
    } else {
      if (fx.tier === 'regression') regressionFail++; else capabilityFail++;
      console.log(`FAIL  [${fx.tier}] ${fx.id}`);
      for (const err of result.errors) console.log(`        - ${err}`);
    }
  }

  console.log('');
  console.log(`bench/data-lineage: ${pass}/${fixtures.length} passed (${regressionFail} regression-tier failure(s), ${capabilityFail} capability-tier failure(s))`);

  if (checkMode && regressionFail > 0) {
    console.error(`bench/data-lineage: CHECK FAILED — ${regressionFail} regression-tier fixture(s) did not score correctly`);
    process.exit(1);
  }
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
```

- [ ] **Step 2b: Run the runner directly and confirm all 4 fixtures pass**

Run: `cd /Users/ross/code/agentic-security && node bench/data-lineage/runner.mjs`
Expected: `4/4 passed (0 regression-tier failure(s), 0 capability-tier failure(s))`, exit 0. If any of the 4 fixtures fails, read the printed errors — they name exactly which assertion failed — and determine whether the fixture's `source.js`/`expected.json` needs adjustment (the scoping report's contract was designed but never run against real code before this task; a real discrepancy here is expected work, not a sign the plan is wrong) or whether `scoreFixture`'s own logic has a bug. Do not force a fixture to "pass" by loosening `scoreFixture` beyond what §3's contract specifies without flagging it — if the contract itself needs a correction, make it explicitly and document why, the same way this session's own prior increments have corrected a plan's draft assertions against measured reality.

Run: `cd /Users/ross/code/agentic-security && node bench/data-lineage/runner.mjs --check; echo "exit: $?"`
Expected: same output, `exit: 0`.

- [ ] **Step 3: Write `scanner/test/bench-data-lineage-runner.test.js`**

This proves `scoreFixture`'s own logic directly, independent of the CLI, with hand-built graph objects (not full `buildGraphWithCoverage` runs — those are already covered by Step 2b's real end-to-end proof) so each assertion branch is independently testable:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFixture, buildFixtureGraph } from '../../bench/data-lineage/runner.mjs';

function minimalGraph({ nodes = [], flows = [], dataElements = [], transformations = [] } = {}) {
  return { nodes, flows, dataElements, transformations };
}

test('F1/1: a connected flow with the right category/dataClass/transform scores pass', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log' }],
    dataElements: [{ id: 'd:1', dataClasses: ['PCI'] }],
    transformations: [{ id: 't:1', kind: 'mask' }],
    flows: [{ source: 'n:src', sink: 'n:snk', dataElementIds: ['d:1'], transformationIds: ['t:1'] }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'], expectedTransformKind: 'mask' });
  assert.equal(r.pass, true, JSON.stringify(r.errors));
});

test('F1/2: a missing source/sink node fails with a specific error', () => {
  const graph = minimalGraph();
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'] });
  assert.equal(r.pass, false);
  assert.ok(r.errors.some((e) => e.includes('http-body')));
  assert.ok(r.errors.some((e) => e.includes('log')));
});

test('F1/3: right nodes but no flow connecting them fails with "expected a connecting flow"', () => {
  const graph = minimalGraph({ nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log' }] });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'] });
  assert.equal(r.pass, false);
  assert.ok(r.errors.some((e) => e.includes('connecting flow')));
});

test('F1/4: a flow exists but its dataElement carries the WRONG dataClass fails (not a false positive)', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log' }],
    dataElements: [{ id: 'd:1', dataClasses: ['PII'] }],
    flows: [{ source: 'n:src', sink: 'n:snk', dataElementIds: ['d:1'], transformationIds: [] }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'] });
  assert.equal(r.pass, false, 'a PII flow must not satisfy a PCI-labeled fixture');
});

test('F1/5: expectedTransformKind: null requires an UNtransformed matching flow', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log' }],
    dataElements: [{ id: 'd:1', dataClasses: ['PCI'] }],
    transformations: [{ id: 't:1', kind: 'mask' }],
    flows: [{ source: 'n:src', sink: 'n:snk', dataElementIds: ['d:1'], transformationIds: ['t:1'] }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'], expectedTransformKind: null });
  assert.equal(r.pass, false, 'every matching flow is transformed, but expectedTransformKind:null requires an untransformed one');
});

test('F1/6: expectedConnected:false passes when no flow connects AND the sink node discloses a coverage reason', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log', coverageReason: 'nothing seeded reached this sink' }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'], expectedConnected: false });
  assert.equal(r.pass, true, JSON.stringify(r.errors));
});

test('F1/7: expectedConnected:false FAILS if a matching flow actually exists (the fixture claim was wrong)', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log', coverageReason: 'x' }],
    dataElements: [{ id: 'd:1', dataClasses: ['PCI'] }],
    flows: [{ source: 'n:src', sink: 'n:snk', dataElementIds: ['d:1'], transformationIds: [] }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'], expectedConnected: false });
  assert.equal(r.pass, false, 'a fixture claiming disconnection must fail loudly if a real flow connects the two nodes');
});

test('F1/8: expectedConnected:false FAILS if the sink node has no coverageReason (AC-11 violation)', () => {
  const graph = minimalGraph({
    nodes: [{ id: 'n:src', subtype: 'http-body' }, { id: 'n:snk', subtype: 'log' }],
  });
  const r = scoreFixture(graph, { sourceCategory: 'http-body', sinkCategory: 'log', dataClass: ['PCI'], expectedConnected: false });
  assert.equal(r.pass, false);
  assert.ok(r.errors.some((e) => e.includes('coverageReason')));
});

test('F1/9: scoreFixture never throws on a malformed expected object', () => {
  const graph = minimalGraph();
  for (const bad of [{}, { sourceCategory: null, sinkCategory: null }, { dataClass: undefined }]) {
    assert.doesNotThrow(() => scoreFixture(graph, bad));
  }
});

test('F1/10: buildFixtureGraph produces a real, validateGraph()-clean graph end to end', async () => {
  const { validateGraph } = await import('../../scanner/src/lineage/validate.js');
  const graph = buildFixtureGraph('t', "function h(req, res){ res.send(req.body.x); }");
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('F1/11: the real seed corpus (all 4 fixtures) scores clean end to end — the actual regression pin', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bench', 'data-lineage', 'fixtures');
  const ids = fs.readdirSync(dir).filter((f) => fs.statSync(path.join(dir, f)).isDirectory());
  assert.ok(ids.length >= 4, 'the 4 seed fixtures from Task 1 Step 1 must all exist');
  for (const id of ids) {
    const fxDir = path.join(dir, id);
    const sourceFile = fs.readdirSync(fxDir).find((f) => f.startsWith('source.'));
    const source = fs.readFileSync(path.join(fxDir, sourceFile), 'utf8');
    const expected = JSON.parse(fs.readFileSync(path.join(fxDir, 'expected.json'), 'utf8'));
    const graph = buildFixtureGraph(id, source);
    const r = scoreFixture(graph, expected);
    assert.equal(r.pass, true, `${id}: ${JSON.stringify(r.errors)}`);
  }
});
```

- [ ] **Step 4: Wire into `scanner/package.json`**

Add, mirroring `bench:cve-replay`'s own convention (`scanner/package.json:85-88`) and using a relative path from `scanner/` up to the repo-root `bench/` directory (matching `bench:cve-replay`'s own `../bench/cve-replay/runner.mjs` pattern exactly):

```
    "bench:data-lineage": "node ../bench/data-lineage/runner.mjs",
    "bench:data-lineage:check": "node ../bench/data-lineage/runner.mjs --check",
```

Add `scanner/test/bench-data-lineage-runner.test.js` to `test:lineage`'s file list (it directly tests a `src/lineage/` consumer and belongs in that scope, matching this session's own established convention for every other lineage-adjacent test file).

- [ ] **Step 5: Update `bench/data-lineage/README.md`**

Replace the closing paragraph (currently: *"Milestone 1's DFG-018 mass-authors the remaining ~194+ entries against it, plus the runner/checker script... once the lineage engine exists to score against."*) with a description of what now exists: the runner (`runner.mjs`, `npm run bench:data-lineage` / `:check` from `scanner/`), the scoring contract (a shape-match against `buildGraphWithCoverage` output, not cve-replay's binary presence/absence check — link to `DESIGN_GRAPH_BUILDER.md` or this plan's own spec doc for the full reasoning), the two new `expected.json` fields (`tier`, `expectedConnected`) with their default values, and the current fixture count (4, up from 3) with a note that Sub-project F's remaining increments (F2+) mass-author the rest of the ~200-entry floor. Also add one sentence recording the scoping report's own finding that 2 of §22.2's 9 corpus dimensions (transport-protection states, policy-permitted/prohibited flows) are unscoreable until Milestone 2 ships the relevant analyzers — fixtures for those can be authored now as `capability`-tier but will not pass `--check` until then.

- [ ] **Step 6: Run the full test suite**

Run: `cd scanner && npm run test:lineage`
Expected: prior count + 11 (the new `F1/*` tests).

Run: `cd /Users/ross/code/agentic-security && node bench/data-lineage/runner.mjs --check; echo "exit: $?"`
Expected: `exit: 0`.

Run: `cd scanner && npm test`
Expected: full gate green, exit 0.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/data-lineage/runner.mjs bench/data-lineage/README.md \
  bench/data-lineage/fixtures/js-api-to-log-masked/expected.json \
  bench/data-lineage/fixtures/js-api-to-log-raw/expected.json \
  bench/data-lineage/fixtures/js-api-to-external-http-cleartext/expected.json \
  bench/data-lineage/fixtures/js-api-to-log-disconnected/ \
  scanner/package.json scanner/test/bench-data-lineage-runner.test.js
git commit -m "feat(lineage): ship the data-lineage corpus scoring runner (Sub-project F, increment F1)"
```

---

## Self-review notes

- **Spec coverage:** the scoping report's §3 scoring contract (5 checks) is implemented in full in `scoreFixture` — node existence, dataClass-tagged flow connection, transform-kind assertion (both directions: required kind present, or explicitly required ABSENT), and the `expectedConnected: false` / AC-11 coverage-reason branch. §4's AC-02 and AC-11 both get a real, scored regression fixture (the pre-existing masked/raw pair for AC-02; the new `js-api-to-log-disconnected` fixture for AC-11) — AC-01 and AC-07 are explicitly NOT this increment's job (AC-01 needs a 3-sink fixture, reasonable for F2+; AC-07 is blocked on Sub-project H's catalog-bridging work per the scoping report §5).
- **Placeholder scan:** no TBD/TODO. Every code block is complete, runnable code, not a sketch.
- **Type consistency:** `scoreFixture(graph, expected) -> {pass, errors}` is used identically by both the CLI (`main()`) and the test suite. `buildFixtureGraph(fixtureId, sourceCode) -> graph` matches what `main()`'s per-fixture loop and `F1/10`/`F1/11` both call.
