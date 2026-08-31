//
// source-seeding.test.js — Sub-project E, increment 2 (E2).
//
// The permanent test suite for `src/lineage/source-seeding.js`, absorbing
// the seeding-half tests from `test/lineage/graph-builder-poc.test.js`
// (E1/1-E1/5, plus E1/14 — the escalated engine limitation, which is about
// seeding reaching a sink, not about projection), re-pointed at the SHIPPED
// module + the shipped `driver.js`, per `DESIGN_GRAPH_BUILDER.md` §9.1's
// absorption protocol.
//
// All numbers in this file were re-measured against the live tree in this
// increment (2026-08-31), not copied forward from the PoC's own comments —
// see this task's report for the harness used to confirm they are still
// current after the `lineage-engine-receiver-identity-hotfix` and the
// schema/validator hotfix that landed on top of Sub-project E1's own work.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildProjectIR } from '../../src/ir/index.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths } from '../../src/lineage/path-query.js';
import { gradePath } from '../../src/lineage/flow-grade.js';
import { COVERAGE_STATUS_VALUES } from '../../src/lineage/schema.js';
import * as ids from '../../src/lineage/ids.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULN_JS_DIR = path.join(__dirname, '..', 'fixtures', 'vulnerable-js');

function irOf(fileContents) {
  const { callGraph } = buildProjectIR(fileContents);
  return callGraph;
}

function vulnerableJs() {
  return { 'app.js': fs.readFileSync(path.join(VULN_JS_DIR, 'app.js'), 'utf8') };
}

// =========================================================================
// E2/1 (absorbs E1/1 + E1/4): the "0 becomes N" proof
// =========================================================================

test('E2/1a (absorbs E1/1): the SHIPPED driver still emits exactly ZERO hops on real code with no seeding hook — the measured gap this increment closes', () => {
  const callGraph = irOf(vulnerableJs());
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h) });
  const store = new PathStore();
  store.addHops(hops);
  assert.equal(hops.length, 0, 'no seeding hook => no identity can enter the analysis => no hop can fire');
  assert.equal(store.stats().nodes, 0);
  assert.equal(store.stats().edges, 0);
});

test('E2/1b (absorbs E1/4): source-seeding.js\'s real seeding, wired through opts.seedEntryState into the SHIPPED driver, produces real hops on vulnerable-js — 0 becomes 23, re-measured in this task', () => {
  const callGraph = irOf(vulnerableJs());
  const { seeds } = planSeeds(callGraph, { repository: 'vuln' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);

  // Re-measured in this task (2026-08-31), not copied from the PoC's own
  // comments: post `lineage-engine-receiver-identity-hotfix`, seeding
  // vulnerable-js through the SHIPPED source-seeding.js + driver.js
  // produces 23 hops / 15 pnodes / 9 pedges — confirmed current.
  assert.equal(hops.length, 23, 'measured: real seeding emits 23 hops where the shipped driver emits 0');
  const st = store.stats();
  assert.equal(st.nodes, 15);
  assert.equal(st.edges, 9);
  assert.deepEqual(store.diagnostics().malformed, [], 'no malformed hop reaches the store');
  assert.deepEqual(store.diagnostics().unclassified, [], 'every out-half matches one of §14.3\'s rules');

  // A real seed is still a strict subset of "one identity per parameter"'s
  // node count (the synthetic per-parameter seed measures 16 pnodes,
  // unaffected by the hotfix — §3.7's own re-measurement).
  assert.ok(st.nodes < 16, 'a real seed still produces a strict subset of "one identity per parameter"\'s pnode count');

  const kinds = [...new Set(store.nodes().map((n) => n.kind))].sort();
  assert.deepEqual(kinds, ['escape', 'path'],
    'real code reaches `path` and `escape` only — still zero `loss`, zero `origin`, zero `return`');
});

// =========================================================================
// E2/2 (absorbs E1/2): the field-vs-container seed-path rule
// =========================================================================

test('E2/2: matchSource/reclassifySource/accessPathOf compose into real seeds via planSeeds() on real parsed code — 9 call-site matches, 3 distinct catalog entries, 6 data elements', () => {
  const callGraph = irOf(vulnerableJs());
  const { seeds, unseedable } = planSeeds(callGraph, { repository: 'vuln' });

  assert.equal(seeds.length, 9, 'nine matched source call sites');
  assert.equal(unseedable.length, 0, 'every matched source expression in this fixture has an access path');
  assert.deepEqual([...new Set(seeds.map((s) => s.entryId))].sort(), ['js-req-body', 'js-req-params', 'js-req-query']);
  assert.deepEqual([...new Set(seeds.map((s) => s.category))].sort(), ['http-body', 'http-query', 'http-route']);
  assert.ok(seeds.every((s) => COVERAGE_STATUS_VALUES.includes(s.coverageStatus)));

  // §3.2's seed-path rule lands on the FIELD, not the container: the
  // matched expression is `req.body`, the seeded path is `req.body.host`.
  const paths = [...new Set(seeds.map((s) => s.seedPath))].sort();
  assert.deepEqual(paths, [
    'req.body', 'req.body.expr', 'req.body.host', 'req.body.password', 'req.params.id', 'req.query.name',
  ], 'the seed path is the longest enclosing pure-member chain, so a field keeps its own identity');

  // Field-level naming is what makes classification possible at all.
  const pw = seeds.find((s) => s.canonicalName === 'password');
  assert.ok(pw, 'req.body.password mints a data element literally named "password"');
  assert.deepEqual(pw.dataClasses, ['CREDENTIALS'],
    'classifyDataElementName only works because the seed path reaches the field — a container-level "body" seed classifies as nothing');

  assert.equal(new Set(seeds.map((s) => s.dataElementId)).size, 6,
    'nine call sites collapse to six data elements: two reads of req.params.id in one function are ONE element');
});

// =========================================================================
// E2/3 (absorbs E1/3): dataElementId discriminator correctness
// =========================================================================

test('E2/3: the dataElementId discriminator satisfies PRD §10.4 — same field name in two files/services is two elements, and the id is never a function of the name alone', () => {
  const same = 'function h(req){ sink(req.body.email); }';
  const cgA = irOf({ 'serviceA/api.js': same });
  const cgB = irOf({ 'serviceB/api.js': same });
  const a = planSeeds(cgA, { repository: 'r' }).seeds;
  const b = planSeeds(cgB, { repository: 'r' }).seeds;
  assert.equal(a.length, 1);
  assert.equal(b.length, 1);
  assert.equal(a[0].canonicalName, 'email');
  assert.equal(b[0].canonicalName, 'email');
  assert.notEqual(a[0].dataElementId, b[0].dataElementId,
    'PRD §10.4: `email` in two unrelated services must remain TWO data elements');

  // Two DIFFERENT fields in ONE file are also two elements...
  const cgC = irOf({ 'one.js': 'function h(req){ sink(req.body.email); sink(req.body.ssn); }' });
  const c = planSeeds(cgC, { repository: 'r' }).seeds;
  assert.equal(new Set(c.map((s) => s.dataElementId)).size, 2);
  // ...and the SAME field read twice in one file is ONE element.
  const cgD = irOf({ 'one.js': 'function h(req){ sink(req.body.email); log(req.body.email); }' });
  const d = planSeeds(cgD, { repository: 'r' }).seeds;
  assert.equal(d.length, 2, 'two matched call sites');
  assert.equal(new Set(d.map((s) => s.dataElementId)).size, 1, 'one logical field => one data element');

  // Function scope (qid) is deliberately NOT in the discriminator: two
  // handlers in one file reading the same field are one logical field.
  const cgE = irOf({ 'one.js': 'function h1(req){ sink(req.body.email); } function h2(req){ log(req.body.email); }' });
  const e = planSeeds(cgE, { repository: 'r' }).seeds;
  assert.equal(e.length, 2, 'two matched call sites, in two different functions');
  assert.notEqual(e[0].qid, e[1].qid, 'confirm they really are in two different functions');
  assert.equal(new Set(e.map((s) => s.dataElementId)).size, 1,
    'qid is not in the discriminator: two handlers reading the same field in one file are still ONE data element');

  // The same repository+file+path+category always mints the same id, and
  // the id is a content hash, never a counter.
  assert.equal(
    ids.dataElementId('email', ['r', 'serviceA/api.js', 'req.body.email', 'http-body']),
    a[0].dataElementId,
  );
  assert.notEqual(ids.dataElementId('email', []), a[0].dataElementId,
    'the bare name alone must never produce this id');
});

// =========================================================================
// E2/4: unseedable[] — a matched expression with no access path is
// recorded, never silently dropped (§3.3)
// =========================================================================

test('E2/4: a matched source expression with no access path is recorded in unseedable[], never silently dropped', () => {
  // `js-fetch-json` matches the CALL expression `res.json()` itself (a
  // CALL-shaped source, R3), not a member read. Assigned straight to a
  // variable, that call expression is its own exprRoot — there is no
  // enclosing pure-member access to extend outward through, so
  // accessPathOf(callExpr) is null (accessPathOf only resolves ident/member
  // chains) and the match is recorded as unseedable, never dropped.
  const callGraph = irOf({ 'fetcher.js': 'function h(res){ const data = res.json(); sink(data); }' });
  const { seeds, unseedable } = planSeeds(callGraph, { repository: 'u' });
  assert.equal(seeds.length, 0, 'the CALL-shaped match itself has no field-level access path to seed');
  assert.equal(unseedable.length, 1, 'the match is recorded, not dropped');
  assert.equal(unseedable[0].entryId, 'js-fetch-json');
  assert.equal(unseedable[0].reason, 'accessPathOf returned null for the matched expression');
  assert.equal(unseedable[0].file, 'fetcher.js');
  assert.ok(typeof unseedable[0].qid === 'string' && unseedable[0].qid.length > 0);
});

// =========================================================================
// E2/5 (adapted from E1/5): field precision survives seeding + the field-
// identity analysis end to end. E1/5's own version additionally proved this
// through the PROJECTION half (buildDataFlowGraph, minting nodes/edges/
// flows) — that machinery is E3's, not this increment's, to ship. This
// adaptation proves the SAME FR-301 property (two distinct fields of one
// container reach two distinct sinks without merging) using only modules
// already shipped before this task: source-seeding.js + driver.js +
// path-store.js + path-query.js + flow-grade.js.
// =========================================================================

test('E2/5 (adapted from E1/5): a seeded flow is field-precise through seeding + analysis — two distinct fields of the SAME container reach two different sinks without merging (FR-301)', () => {
  const code = 'function h(req, db, logger){ const a = req.body.card_number; const b = req.body.nickname; db.query(a); logger.info(b); }';
  const callGraph = irOf({ 'r.js': code });
  const { seeds } = planSeeds(callGraph, { repository: 'fp' });
  assert.equal(seeds.length, 2, 'two matched fields of the same container');
  const cardSeed = seeds.find((s) => s.canonicalName === 'card_number');
  const nickSeed = seeds.find((s) => s.canonicalName === 'nickname');
  assert.ok(cardSeed && nickSeed);
  assert.notEqual(cardSeed.dataElementId, nickSeed.dataElementId, 'two distinct fields mint two distinct data elements');

  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);

  // Two independent CFG call-statement sites (`db.query(a)`, `logger.info(b)`)
  // each produce their own `escape` provenance node. Reconstruct backward
  // from each and confirm each connects to exactly the ONE field that
  // reached it — never both, and never the wrong one.
  const escapeNodes = store.nodes().filter((n) => n.kind === 'escape');
  assert.equal(escapeNodes.length, 2, 'both sink call sites are reached by the store');

  const dataElementIdsBySite = escapeNodes.map((esc) => {
    const r = reconstructPaths(store, esc.id, {});
    const des = new Set(r.paths.map((p) => p.dataElementId));
    return { siteNodeId: esc.siteNodeId, dataElementIds: [...des] };
  });
  for (const site of dataElementIdsBySite) {
    assert.equal(site.dataElementIds.length, 1, `sink site ${site.siteNodeId} must be reached by exactly one field, never a merge of both`);
  }
  const reachedIds = dataElementIdsBySite.map((s) => s.dataElementIds[0]).sort();
  assert.deepEqual(reachedIds, [cardSeed.dataElementId, nickSeed.dataElementId].sort(),
    'the two sink sites are together reached by exactly the two seeded fields, one each, never merged');
});

// =========================================================================
// E2/6 (absorbs E1/14): the escalated engine limitation, now resolved
// =========================================================================

test('E2/6a (absorbs E1/14): lineage/engine.js now keeps RECEIVER-borne identity through a method call, so the bench corpus\'s own masked-log flow connects through seeding + analysis', () => {
  // `pan + 'x'` and `String(pan)` always kept the identity; `pan.slice(0,4)`
  // used to lose it, because engine.js's unresolved-`call` branch unioned
  // only `expr.args`, never `expr.callee.object`. Fixed by the
  // `lineage-engine-receiver-identity-hotfix`: the unresolved-`call` branch
  // now also unions the receiver's own resolved identities.
  const masked = 'function maskCard(pan){ return pan.slice(0, 4) + \'********\' + pan.slice(-4); }\n'
    + 'function handleCheckout(req, logger){\n'
    + '  const cardNumber = req.body.card_number;\n'
    + '  const maskedPan = maskCard(cardNumber);\n'
    + '  logger.info(\'processing payment\', { pan: maskedPan });\n'
    + '}';
  const callGraph = irOf({ 'source.js': masked });
  const { seeds } = planSeeds(callGraph, { repository: 'm' });
  assert.equal(seeds.length, 1, 'the source IS matched and seeded');

  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);

  const escapeNodes = store.nodes().filter((n) => n.kind === 'escape');
  assert.equal(escapeNodes.length, 1, 'the logger.info sink call site IS reached by the store');

  const grades = [];
  for (const esc of escapeNodes) {
    const r = reconstructPaths(store, esc.id, {});
    for (const p of r.paths) {
      if (p.dataElementId !== seeds[0].dataElementId) continue;
      grades.push(gradePath(p).grade);
    }
  }
  // Post-fix: the identity now survives `pan.slice(...)` inside maskCard,
  // producing TWO reconstructed paths to the sink — the real cross-scope
  // path through maskCard (graded `widened`, since the call itself stays
  // unresolved even though the receiver's identity is recovered) and the
  // caller-side bypass FR-305/§14.7 correctly marks `ambiguousCorrelation`.
  assert.deepEqual(grades.sort(), ['ambiguous', 'widened'],
    'the identity now survives pan.slice(...): two reconstructed paths reach the sink, matching the corpus fixture bench/data-lineage/fixtures/js-api-to-log-masked');
});

test('E2/6b (absorbs E1/14, receiver-free control): the same shape with a receiver-free transform connects identically, isolating the fix to receiver-borne identity specifically', () => {
  const ok = 'function maskCard(pan){ return \'****\' + pan; }\n'
    + 'function handleCheckout(req, logger){\n'
    + '  const cardNumber = req.body.card_number;\n'
    + '  const maskedPan = maskCard(cardNumber);\n'
    + '  logger.info(\'processing payment\', { pan: maskedPan });\n'
    + '}';
  const callGraph = irOf({ 'source.js': ok });
  const { seeds } = planSeeds(callGraph, { repository: 'm' });
  assert.equal(seeds.length, 1);

  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);

  const escapeNodes = store.nodes().filter((n) => n.kind === 'escape');
  assert.equal(escapeNodes.length, 1);

  const grades = [];
  for (const esc of escapeNodes) {
    const r = reconstructPaths(store, esc.id, {});
    for (const p of r.paths) {
      if (p.dataElementId !== seeds[0].dataElementId) continue;
      grades.push(gradePath(p).grade);
    }
  }
  // TWO paths, not one, and that is FR-305 working rather than a defect:
  // the real cross-scope path through maskCard (now `explicit`, since
  // there's no unresolved call left in this receiver-free variant) and the
  // caller-side bypass §14.7 marks `ambiguousCorrelation`.
  assert.deepEqual(grades.sort(), ['ambiguous', 'explicit']);
});
