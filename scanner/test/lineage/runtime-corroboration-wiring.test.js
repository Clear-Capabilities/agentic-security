//
// runtime-corroboration-wiring.test.js — M5 deliverable #7 (Runtime-
// Corroborated Digital Twin, "7b"; FR-505 §7.12, AC-29), Task 5: proves
// `opts.correlateObservations` is wired through `graph-builder.js`,
// `coverage.js`, and `index.js` as the FIFTH additive hook of the
// identical shape `resolveDestination`/`resolveTransitProtection`/
// `buildRecipientProfile` already established — byte-identical when
// omitted, proven the same way `M2A1/hook-1` proved it for
// `resolveDestination`.
//
// Builds real graphs with `buildGraphWithCoverage` over parsed JS/TS
// (`parseJsFile` + `buildCallGraph`), following `test/lineage/coverage
// .test.js`'s own fixture shape — this is wiring proof, not a re-test of
// `correlateObservations`'s own internal logic (Task 2's own job,
// `test/lineage/observation-correlation.test.js`).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fsp from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';

import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { matchObservationToGraph } from '../../src/lineage/observation-correlation.js';
import { observationId, observationImportId } from '../../src/lineage/ids.js';
import { RUNTIME_OBSERVATION_VERSION } from '../../src/lineage/runtime-observation.js';
import { OBSERVATION_IMPORT_VERSION, persistObservationImport } from '../../src/lineage/observation-store.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// A single-flow fixture (matches coverage.test.js's own established
// "smallest real thing that produces a real graph" style): one seeded
// PII field reaching one sink call statement.
const SIMPLE_CODE = "function h(req, res){ const pw = req.body.password; res.send(pw); }";

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-runtime-corrob-wiring-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

// ── WIRE/1-7: buildGraphWithCoverage-level wiring ──────────────────────

test('WIRE/1: the hook fires exactly once per build, and receives a graph whose nodes/edges/flows/dataElements are already populated', () => {
  const cg = irOf({ 'a.js': SIMPLE_CODE });
  let calls = 0;
  let seenGraph = null;
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z',
    correlateObservations: (g) => { calls += 1; seenGraph = g; return undefined; },
  });
  assert.equal(calls, 1);
  assert.ok(seenGraph.nodes.length > 0, 'nodes must be populated inside the hook');
  assert.ok(seenGraph.edges.length > 0, 'edges must be populated inside the hook');
  assert.ok(seenGraph.flows.length > 0, 'flows must be populated inside the hook');
  assert.ok(seenGraph.dataElements.length > 0, 'dataElements must be populated inside the hook');
  // The hook returned undefined -> genuinely absent, not a side-effect of
  // this particular test's own assertions above.
  assert.equal('runtimeCorroboration' in graph, false);
});

test('WIRE/2: the hook\'s return value lands verbatim on graph.runtimeCorroboration', () => {
  const cg = irOf({ 'a.js': SIMPLE_CODE });
  const sentinel = { evaluated: true, sentinel: 'wire-2', nested: { a: [1, 2, 3] } };
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z',
    correlateObservations: () => sentinel,
  });
  assert.deepEqual(graph.runtimeCorroboration, sentinel);
});

test('WIRE/3: byte-identical when omitted (Correction 10) — no hook/no opts vs. a hook returning undefined produce identical JSON, and the key is genuinely ABSENT (not null) in both', () => {
  const cgA = irOf({ 'a.js': SIMPLE_CODE });
  const cgB = irOf({ 'a.js': SIMPLE_CODE });
  const a = buildGraphWithCoverage(cgA, { repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z' }).graph;
  const b = buildGraphWithCoverage(cgB, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z',
    correlateObservations: () => undefined,
  }).graph;
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.equal('runtimeCorroboration' in a, false, 'key must be genuinely absent, not null, when no hook is supplied');
  assert.equal('runtimeCorroboration' in b, false, 'key must be genuinely absent, not null, when the hook returns undefined');
});

test('WIRE/4: opts.runtimeObservations undefined installs no default hook; opts.runtimeObservations = [] produces evaluated:true with every flow not_observed_in_window', () => {
  const cg1 = irOf({ 'a.js': SIMPLE_CODE });
  const r1 = buildGraphWithCoverage(cg1, { repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z' });
  assert.equal('runtimeCorroboration' in r1.graph, false);

  const cg2 = irOf({ 'a.js': SIMPLE_CODE });
  const r2 = buildGraphWithCoverage(cg2, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z', runtimeObservations: [],
  });
  assert.ok('runtimeCorroboration' in r2.graph);
  assert.equal(r2.graph.runtimeCorroboration.evaluated, true);
  assert.ok(r2.graph.flows.length > 0, 'sanity: this fixture has at least one real flow');
  for (const f of r2.graph.flows) {
    assert.equal(r2.graph.runtimeCorroboration.byFlow[f.id].layer, 'not_observed_in_window');
  }
});

test('WIRE/5: a caller-supplied opts.correlateObservations always wins over the default built from opts.runtimeObservations', () => {
  const cg = irOf({ 'a.js': SIMPLE_CODE });
  const sentinel = { won: 'caller' };
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z',
    runtimeObservations: [],
    correlateObservations: () => sentinel,
  });
  assert.deepEqual(graph.runtimeCorroboration, sentinel);
});

test('WIRE/6: opts.environment/opts.observationWindowStart/opts.observationWindowEnd reach correlateObservations\'s opts verbatim', () => {
  const cg = irOf({ 'a.js': SIMPLE_CODE });
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z',
    runtimeObservations: [],
    environment: 'production',
    observationWindowStart: '2026-01-01T00:00:00.000Z',
    observationWindowEnd: '2026-02-01T00:00:00.000Z',
  });
  assert.equal(graph.runtimeCorroboration.environment, 'production');
  assert.equal(graph.runtimeCorroboration.windowStart, '2026-01-01T00:00:00.000Z');
  assert.equal(graph.runtimeCorroboration.windowEnd, '2026-02-01T00:00:00.000Z');
});

test('WIRE/7: validateGraph(graph) returns zero errors with runtimeCorroboration present — the extension is never routed through the validator, exactly like graph.recipientProfiles', () => {
  const cg = irOf({ 'a.js': SIMPLE_CODE });
  const { graph } = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z', runtimeObservations: [],
  });
  assert.ok('runtimeCorroboration' in graph);
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
});

// ── WIRE/8: index.js's single-load discipline, proven live ─────────────

test('WIRE/8: coverage.js and graph-builder.js never import the observation store directly', () => {
  const gbSrc = fs.readFileSync(new URL('../../src/lineage/graph-builder.js', import.meta.url), 'utf8');
  const covSrc = fs.readFileSync(new URL('../../src/lineage/coverage.js', import.meta.url), 'utf8');
  assert.ok(!gbSrc.includes('observation-store.js'), 'graph-builder.js must never read the observation store itself');
  assert.ok(!covSrc.includes('observation-store.js'), 'coverage.js must never read the observation store itself — only observation-correlation.js (pure) is imported');
});

test('WIRE/8: loadObservations (and therefore the underlying store read) is called EXACTLY ONCE per buildLineageGraph call, measured live via a monkey-patched fs.readdirSync call counter', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security', 'runtime-observations'), { recursive: true });
    const cg = irOf({ 'a.js': SIMPLE_CODE });

    // `node:fs`'s CJS module.exports object (reached via `createRequire`) is
    // the SAME underlying object every `import * as fs from 'node:fs'`
    // binding is ultimately backed by — but a plain reassignment on it does
    // not retroactively update an ESM namespace that was already
    // instantiated (a real, measured Node behavior, not a guess: confirmed
    // both ways while writing this test). `syncBuiltinESMExports()`
    // (`node:module`) is the documented, public API for exactly this case —
    // it re-syncs every core module's ESM named exports to the current CJS
    // state, regardless of load order, so calling it after the reassignment
    // makes the patch visible to `observation-store.js`'s own `import * as
    // fs from 'node:fs'` without any module-mocking flag/machinery this
    // codebase does not otherwise depend on (`--experimental-test-module-
    // mocks` was tried and rejected: `scripts/run-unit-tests.mjs`'s combined
    // `npm test` invocation spawns a single flag-less `node --test`, so a
    // mock requiring that flag would silently break under the full gate
    // even though it passes standalone).
    const require = createRequire(import.meta.url);
    const cjsFs = require('node:fs');
    const orig = cjsFs.readdirSync;
    const calls = [];
    cjsFs.readdirSync = (...args) => { calls.push(String(args[0])); return orig(...args); };
    syncBuiltinESMExports();
    let result;
    try {
      result = buildLineageGraph(cg, { repository: 'r', scanRoot: dir });
    } finally {
      cjsFs.readdirSync = orig;
      syncBuiltinESMExports();
    }
    assert.equal(result.status, 'complete');
    const obsDirReads = calls.filter((p) => p.endsWith('runtime-observations'));
    assert.deepEqual(obsDirReads.length, 1, `expected exactly one readdirSync of the observations directory; got ${obsDirReads.length} (${JSON.stringify(calls)})`);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── WIRE/9: buildLineageGraph's own existsSync gate ─────────────────────

test('WIRE/9: buildLineageGraph with no .agentic-security/runtime-observations/ directory on disk produces a graph with runtimeCorroboration genuinely absent; with an EMPTY store directory present, a real evaluated:true result is produced', async () => {
  const dir = await tmpProject();
  try {
    const cg1 = irOf({ 'a.js': SIMPLE_CODE });
    const r1 = buildLineageGraph(cg1, { repository: 'r', scanRoot: dir });
    assert.equal(r1.status, 'complete');
    assert.equal('runtimeCorroboration' in r1.graph, false, 'not_evaluated expressed by absence — no store directory exists at all');

    await fsp.mkdir(path.join(dir, '.agentic-security', 'runtime-observations'), { recursive: true });
    const cg2 = irOf({ 'a.js': SIMPLE_CODE });
    const r2 = buildLineageGraph(cg2, { repository: 'r', scanRoot: dir });
    assert.equal(r2.status, 'complete');
    assert.ok('runtimeCorroboration' in r2.graph, 'a genuinely present (even if empty) store directory must produce a real, evaluated correlation result');
    assert.equal(r2.graph.runtimeCorroboration.evaluated, true);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── WIRE/10: end-to-end AC-29 scenario over real parsed code ───────────
//
// `OC/6a` promoted from a hand-built graph (observation-correlation.test.js)
// to real scanned code. Two distinct external sink nodes are needed for
// this scenario to be provable at all: node identity in this package is
// `(kind, subtypeKey, coverageStatus, externality)` — it deliberately does
// NOT include `destination` (graph-builder.js's own header, "destination,
// always null in M1" note) — so two plain `fetch(...)` calls to two
// different literal URLs collide onto ONE shared node (measured directly
// against the real pipeline while writing this test), which would make
// the two-different-answers scenario this test needs unprovable: an
// observation matching that ONE shared node would correlate BOTH flows
// sharing it (Correction 4's own node-granularity boundary), not just one.
// The fixture below uses one `fetch(...)` sink (category `external-api`,
// a real literal destination) and one `analytics.track(...)` sink
// (category `analytics`, `policy-verdict.test.js`'s own established real
// fixture shape) — two genuinely distinct SINK_CATEGORIES, so two
// genuinely distinct graph nodes, each the endpoint of exactly one flow.
test('WIRE/10: end-to-end AC-29 scenario over real parsed code — one flow reads runtime_observed, the other not_observed_in_window, both sink nodes stay visible, every flow appears in byFlow', async () => {
  const dir = await tmpProject();
  try {
    const code = `
function h1(req) {
  const cardNumber = req.body.card_number;
  fetch('https://api.stripe.com/v1/charges', { method: 'POST', body: cardNumber });
}
function h2(req, analytics) {
  const other = req.body.other_field;
  analytics.track('signup', { other });
}
`;
    // Probe build (no scanRoot, no observations) — discovers this
    // fixture's own real, content-hashed node/flow ids. Ids never depend
    // on `generatedAt`, so these ids are identical to the ones the later,
    // scanRoot-backed build below produces from the same source.
    const probeCg = irOf({ 'a.js': code });
    const { graph: probeGraph } = buildGraphWithCoverage(probeCg, { repository: 'r', generatedAt: '2026-01-01T00:00:00.000Z' });
    const externalNodes = probeGraph.nodes.filter((n) => n.kind === 'external');
    assert.equal(externalNodes.length, 2, 'two distinct external sink nodes (fetch/external-api and analytics.track/analytics)');
    const stripeNode = probeGraph.nodes.find((n) => n.destination?.literalValue === 'https://api.stripe.com/v1/charges');
    assert.ok(stripeNode, 'the fetch() site must resolve a literal destination');
    const otherNode = externalNodes.find((n) => n.id !== stripeNode.id);
    assert.ok(otherNode);
    const stripeFlow = probeGraph.flows.find((f) => f.sink === stripeNode.id);
    const otherFlow = probeGraph.flows.find((f) => f.sink === otherNode.id);
    assert.ok(stripeFlow);
    assert.ok(otherFlow);
    assert.notEqual(stripeFlow.id, otherFlow.id);

    // One observation, matched (via the real match ladder, at "import
    // time") to the stripe destination only.
    const draft = {
      version: RUNTIME_OBSERVATION_VERSION, adapter: 'native-jsonl',
      source: 'native.jsonl:wire-10', environment: 'production',
      windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-02T00:00:00.000Z',
      importedAt: '2026-01-02T00:00:00.000Z', retention: { expiresAt: null },
      attributes: { 'destination.host': 'api.stripe.com' },
      eventCountBand: '2-10',
      firstObservedAt: '2026-01-01T05:00:00.000Z', lastObservedAt: '2026-01-01T06:00:00.000Z',
    };
    const observation = {
      ...draft,
      id: observationId(draft, [JSON.stringify(draft.attributes)]),
      ...matchObservationToGraph(probeGraph, draft),
    };
    assert.deepEqual(observation.matchedFlowIds, [stripeFlow.id], 'sanity: the observation matches only the stripe flow');

    const importRecord = {
      id: observationImportId(draft, ['wire-10']),
      version: OBSERVATION_IMPORT_VERSION, adapter: 'native-jsonl', source: draft.source,
      environment: 'production', windowStart: draft.windowStart, windowEnd: draft.windowEnd,
      importedAt: draft.importedAt, retention: { expiresAt: null },
      observations: [observation],
    };
    const persisted = persistObservationImport(dir, importRecord);
    assert.ok(persisted.ok, `persistObservationImport failed: ${JSON.stringify(persisted)}`);

    const cg2 = irOf({ 'a.js': code });
    const r = buildLineageGraph(cg2, { repository: 'r', scanRoot: dir, environment: 'production' });
    assert.equal(r.status, 'complete');
    const rc = r.graph.runtimeCorroboration;
    assert.ok(rc, 'a real correlation result must be attached');
    assert.equal(rc.evaluated, true);

    assert.equal(rc.byFlow[stripeFlow.id].layer, 'runtime_observed');
    assert.equal(rc.byFlow[otherFlow.id].layer, 'not_observed_in_window');

    // Every flow appears in byFlow, exactly once each.
    assert.equal(r.graph.flows.length, 2);
    for (const f of r.graph.flows) assert.ok(f.id in rc.byFlow, `flow ${f.id} missing from byFlow`);

    // Both static paths remain visible (AC-29 clause 3) — neither sink
    // node was filtered, removed, or reordered out of the built graph.
    assert.ok(r.graph.nodes.some((n) => n.id === stripeNode.id));
    assert.ok(r.graph.nodes.some((n) => n.id === otherNode.id));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});
