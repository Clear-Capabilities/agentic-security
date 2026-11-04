//
// GA-03.1 (0.195.24): the three lineage-engine capabilities that moved the
// data-lineage corpus's last seven fixtures from capability-tier to
// regression-tier, each proven in both directions against the real parser:
//
//   1. the lineage-only source catalog (`lineage-source-catalog.js`): four
//      JavaScript collection points that are lineage sources but NOT taint
//      sources, and the proof that the main taint matcher never sees them;
//   2. seeding across an alias hop and after a call-shaped assignment
//      (`source-seeding.js`: `extendThroughAliases`, `after-node` seeds);
//   3. a callee's own seeds under every call context (`summaries.js`,
//      `createCallSummaryResolver`), which is what connects an
//      interprocedural flow end to end.
//
// Everything below goes through `buildGraphWithCoverage`, the same entry
// point the corpus runner uses, so a passing assertion here is the same
// evidence the corpus records.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildProjectIR } from '../../src/ir/index.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { matchSource } from '../../src/dataflow/catalog.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { planSeeds, seedEntryStateFactory, seedAfterNodeFactory, SEED_KINDS } from '../../src/lineage/source-seeding.js';
import { LINEAGE_SOURCE_CATALOG, LINEAGE_SOURCE_DECISIONS, matchLineageSource } from '../../src/lineage/lineage-source-catalog.js';
import { SOURCE_CATEGORIES } from '../../src/lineage/schema.js';
import { PROVENANCE_MAP } from '../../src/lineage/source-registry.js';

function graphOf(files) {
  const { callGraph } = buildProjectIR(files);
  const { graph } = buildGraphWithCoverage(callGraph, { repository: 't', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(validateGraph(graph).errors, []);
  return graph;
}

function flowsBetween(graph, sourceCategory, sinkCategory) {
  const src = new Set(graph.nodes.filter((n) => n.subtype === sourceCategory).map((n) => n.id));
  const snk = new Set(graph.nodes.filter((n) => n.subtype === sinkCategory).map((n) => n.id));
  const deById = new Map(graph.dataElements.map((d) => [d.id, d]));
  return graph.flows
    .filter((f) => src.has(f.source) && snk.has(f.sink))
    .map((f) => ({ flow: f, elements: f.dataElementIds.map((id) => deById.get(id)) }));
}

// ── 1. the lineage-only catalog ────────────────────────────────────────────

test('LC/1: every lineage-only entry classifies to one of the four categories the main catalog has no JavaScript entry for, through the registry\'s own provenance map', () => {
  assert.equal(LINEAGE_SOURCE_CATALOG.length, 6);
  const cats = new Set();
  for (const e of LINEAGE_SOURCE_CATALOG) {
    assert.equal(e.kind, 'source');
    assert.equal(e.language, 'js');
    assert.equal(e.lineageOnly, true);
    assert.ok(Object.hasOwn(PROVENANCE_MAP, e.provenance), `${e.id}: provenance ${e.provenance} is not in PROVENANCE_MAP`);
    const d = LINEAGE_SOURCE_DECISIONS[e.id];
    assert.ok(SOURCE_CATEGORIES.includes(d.category), `${e.id}: ${d.category} is not a SOURCE_CATEGORIES value`);
    assert.notEqual(d.coverageStatus, 'unsupported');
    cats.add(d.category);
  }
  assert.deepEqual([...cats].sort(), ['cli-argument', 'http-upload', 'storage-read', 'user-input']);
});

test('LC/2: the matcher fires on the real JavaScript shapes and only on them (receiver, bare-global and language gates)', () => {
  const ir = parseJsFile('a.js', [
    'function f(fs, req) {',
    '  const a = process.argv;',
    '  const b = req.file;',
    '  const c = req.files;',
    '  const d = fs.readFileSync("/x");',
    '  const e = readFileSync("/x");',
    '  const g = prompt("q");',
    '  const h = readlineSync.question("q");',
    '  const n1 = inquirer.prompt(["q"]);',
    '  const n2 = rl.question("q");',
    '  const n3 = fs.truncate("/x");',
    '  const n4 = req.body;',
    '}',
  ].join('\n'));
  const fn = ir.functions.find((f) => f.name === 'f');
  const byTarget = Object.fromEntries(Object.values(fn.cfg.nodes).filter((n) => n.kind === 'assign').map((n) => [n.target, n.source]));
  const id = (t, file = 'a.js') => matchLineageSource(byTarget[t], file)?.id ?? null;
  assert.equal(id('a'), 'js-process-argv');
  assert.equal(id('b'), 'js-multer-req-file');
  assert.equal(id('c'), 'js-multer-req-files');
  assert.equal(id('d'), 'js-fs-readFileSync');
  assert.equal(id('e'), 'js-fs-readFileSync', 'a directly imported readFileSync matches too');
  assert.equal(id('g'), 'js-window-prompt');
  assert.equal(id('h'), 'js-readline-sync-question');
  assert.equal(id('n1'), null, 'inquirer.prompt is not the browser prompt: the entry is bare-global only');
  assert.equal(id('n2'), null, 'rl.question delivers its answer to a callback; only readlineSync.question returns it');
  assert.equal(id('n3'), null);
  assert.equal(id('n4'), null, 'req.body belongs to the main catalog, not this one');
  assert.equal(id('a', 'a.py'), null, 'a Python file never matches a JavaScript-only entry');
  assert.equal(id('a', 'a.ts'), 'js-process-argv');
  assert.equal(matchLineageSource(null, 'a.js'), null);
  assert.equal(matchLineageSource({ kind: 'call' }, 'a.js'), null, 'a malformed call never throws');
});

test('LC/3: the main taint catalog\'s matcher returns null for every lineage-only shape, so the taint engine gained no source (the "without broadening the main taint catalog" rule)', () => {
  const ir = parseJsFile('a.js', 'function f(fs, req) { const a = process.argv; const b = req.file; const c = req.files; const d = fs.readFileSync("/x"); const g = prompt("q"); const h = readlineSync.question("q"); }');
  const fn = ir.functions.find((f) => f.name === 'f');
  for (const n of Object.values(fn.cfg.nodes).filter((n) => n.kind === 'assign')) {
    assert.ok(matchLineageSource(n.source, 'a.js'), `${n.target}: the lineage catalog matches it`);
    assert.equal(matchSource(n.source, 'a.js'), null, `${n.target}: the main catalog must NOT match it`);
  }
});

// ── 2. seeding: alias hop and call-shaped assignment ───────────────────────

test('SA/1: a container aliased to a local and then read field by field mints the field seed on the ORIGINAL path, and the graph carries a classified flow through the alias', () => {
  const files = { 'a.js': 'function handleCheckout(req, logger) { const body = req.body; const cardNumber = body.card_number; logger.info("checkout", cardNumber); }' };
  const { callGraph } = buildProjectIR(files);
  const { seeds } = planSeeds(callGraph, { repository: 't' });
  const paths = seeds.map((s) => s.seedPath).sort();
  assert.deepEqual(paths, ['req.body', 'req.body.card_number'], 'the container seed stays (honest for the container itself) and the field seed is added');
  const field = seeds.find((s) => s.seedPath === 'req.body.card_number');
  assert.equal(field.seedKind, 'entry');
  assert.deepEqual(field.dataClasses, ['PCI']);
  assert.equal(field.nodeId, seeds.find((s) => s.seedPath === 'req.body').nodeId, 'the field seed is sited where the data entered, not where the alias was read');
  const graph = graphOf(files);
  const pci = flowsBetween(graph, 'http-body', 'log').filter((f) => f.elements.some((d) => d.dataClasses.includes('PCI')));
  assert.equal(pci.length, 1, 'one PCI-tagged flow from the http-body node to the log node');
});

test('SA/2: the alias extension follows a chain, stops at a wildcard and never follows a parameter that is not an alias', () => {
  const chain = buildProjectIR({ 'a.js': 'function h(req, db) { const b = req.body; const c = b.card; db.query(c.number); }' }).callGraph;
  assert.deepEqual(planSeeds(chain, { repository: 't' }).seeds.map((s) => s.seedPath).sort(), ['req.body', 'req.body.card', 'req.body.card.number']);
  const wild = buildProjectIR({ 'a.js': 'function h(req, k, db) { const b = req.body; db.query(b[k]); }' }).callGraph;
  assert.deepEqual(planSeeds(wild, { repository: 't' }).seeds.map((s) => s.seedPath), ['req.body'], 'a dynamic key is never seeded as a field');
  const param = buildProjectIR({ 'a.js': 'function h(req, body, db) { const x = req.body; db.query(body.card_number); }' }).callGraph;
  assert.deepEqual(planSeeds(param, { repository: 't' }).seeds.map((s) => s.seedPath), ['req.body'], 'a parameter named like an alias is not one');
});

test('SA/3: a call-shaped source assigned to a variable is seeded AFTER the assignment and reaches a sink; nested in another call it stays unseedable', () => {
  const files = { 'a.js': 'function mailRecord(fs, sendMail) { const record = fs.readFileSync("/var/records/patient.json"); sendMail({ body: record }); }' };
  const { callGraph } = buildProjectIR(files);
  const { seeds, unseedable } = planSeeds(callGraph, { repository: 't' });
  assert.equal(unseedable.length, 0);
  assert.equal(seeds.length, 1);
  assert.equal(seeds[0].seedKind, 'after-node');
  assert.ok(SEED_KINDS.includes(seeds[0].seedKind));
  assert.equal(seeds[0].seedPath, 'record');
  const fn = [...callGraph.functions.values()].find((f) => f.name === 'mailRecord');
  assert.equal(seedEntryStateFactory(seeds)(fn), undefined, 'not an entry seed');
  const after = seedAfterNodeFactory(seeds);
  assert.deepEqual(after(fn.qid, seeds[0].nodeId), [{ path: 'record', id: seeds[0].dataElementId }]);
  assert.equal(after(fn.qid, 'n999'), undefined);
  assert.equal(seedAfterNodeFactory([]), undefined, 'no after-node seeds, no hook');
  const graph = graphOf(files);
  assert.equal(flowsBetween(graph, 'storage-read', 'email').length, 1, 'the file contents reach the email sink');

  const nested = buildProjectIR({ 'a.js': 'function m(fs, sendMail) { sendMail({ body: fs.readFileSync("/x") }); }' }).callGraph;
  const r = planSeeds(nested, { repository: 't' });
  assert.equal(r.seeds.length, 0);
  assert.equal(r.unseedable.length, 1, 'a call-shaped source with neither a path nor an assignment target is still recorded as unseedable');
});

test('SA/4: a prompt answer named after personal data is classified from the target variable', () => {
  const graph = graphOf({ 'a.js': 'function promptForSsn() { const ssn = prompt("Enter your SSN"); console.log("collected", ssn); }' });
  const flows = flowsBetween(graph, 'user-input', 'log');
  assert.equal(flows.length, 1);
  assert.ok(flows[0].elements.some((d) => d.name === 'ssn' && d.dataClasses.includes('PII')));
  const src = graph.nodes.find((n) => n.subtype === 'user-input');
  assert.equal(src.coverageStatus, 'partial', 'the stdin provenance broadens to the generic category and says so');
});

// ── 3. the callee's own seeds under every call context ─────────────────────

test('IP/1: a field read in a helper and returned to the caller connects end to end: one PCI flow from the http-body node to the caller\'s log sink', () => {
  const graph = graphOf({ 'a.js': 'function extractCard(req) { return req.body.card_number; }\nfunction handleCheckout(req, logger) { const cardNumber = extractCard(req); logger.info("checkout", cardNumber); }' });
  const flows = flowsBetween(graph, 'http-body', 'log').filter((f) => f.elements.some((d) => d.dataClasses.includes('PCI')));
  assert.equal(flows.length, 1);
  assert.ok(flows[0].flow.limitations.some((l) => /cross-scope/.test(l)), 'the flow discloses that it crossed a function boundary');
});

test('IP/2 (disclosed gap, pinned): a sink INSIDE the callee does not see an argument\'s identity, because a bare call statement is never resolved through the summary', () => {
  // engine.js, step()'s bare `call` case, says why: resolving it consumes
  // a summary context per call site and under a tight cap degrades a later
  // resolution (tried and reverted in 0.195.24). This pin exists so the
  // gap is measured, not assumed; when it closes, flip the assertion.
  const graph = graphOf({ 'a.js': 'function emit(logger, v) { logger.info("x", v); }\nfunction handle(req, logger) { emit(logger, req.body.card_number); }' });
  assert.equal(flowsBetween(graph, 'http-body', 'log').length, 0);
  assert.ok(graph.nodes.some((n) => n.subtype === 'http-body'), 'the source is still minted');
  assert.ok(graph.nodes.some((n) => n.subtype === 'log' && n.coverageReason), 'and the sink stays visible with a reason (AC-11)');
});

test('IP/3: a helper whose source read does not reach its return value contributes nothing to the caller (the seed join adds facts, never flows)', () => {
  const graph = graphOf({ 'a.js': 'function audit(req) { const n = req.body.card_number; return 1; }\nfunction handle(req, logger) { const v = audit(req); logger.info("x", v); }' });
  assert.equal(flowsBetween(graph, 'http-body', 'log').length, 0);
});

test('IP/4: the seeded callee is analysed under one key for the driver and for a clean call site; the empty-entry key is never written for it', async () => {
  const { runFieldIdentityAnalysis } = await import('../../src/lineage/driver.js');
  const { emptyState } = await import('../../src/lineage/field-identity.js');
  const { callGraph } = buildProjectIR({
    'aaa.js': 'function helper(req) { return req.body.secret; }',
    'zzz.js': 'function caller(o, logger) { const v = helper(o); logger.info(v); }',
  });
  const { seeds } = planSeeds(callGraph, { repository: 't' });
  const seedEntryState = seedEntryStateFactory(seeds);
  const consulted = [];
  const { results, cache } = runFieldIdentityAnalysis(callGraph, { seedEntryState: (fn) => { consulted.push(fn.qid); return seedEntryState(fn); } });
  const helper = [...callGraph.functions.values()].find((f) => f.name === 'helper');
  const caller = [...callGraph.functions.values()].find((f) => f.name === 'caller');
  assert.equal(consulted.filter((q) => q === helper.qid).length, 1, 'the hook is consulted once per function (memoised for the resolver)');
  assert.equal(cache.get(helper.qid, emptyState()), undefined);
  assert.ok(cache.has(helper.qid, seedEntryState(helper)));
  assert.deepEqual([...(results.get(caller.qid).exitState.get('v') ?? [])], [seeds[0].dataElementId]);
});
