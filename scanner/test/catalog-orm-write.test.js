// Precision + isolation proof for Milestone 2, Sub-project E, increment 1
// (ORM-write sink recognition — an isolated catalog for the Data Flow
// Explorer only, per
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e1-plan.md).
//
// Mirrors test/catalog-ai-model-provider-precision.test.js's own structure
// and naming — same class of test (precision proof for a new catalog
// family) — but adds a fourth section that file doesn't need: a live proof
// that this new catalog is genuinely inert to the general SAST/taint
// pipeline, since `orm-write-catalog.js` is (unlike the AI-provider
// entries that file guards) never merged into `dataflow/catalog.js`'s
// `CATALOG` at all.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../src/ir/parser-js.js';
import { buildCallGraph } from '../src/ir/callgraph.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { matchSinkOrSanitizer, CATALOG } from '../src/dataflow/catalog.js';
import { ORM_WRITE_CATALOG, matchOrmWrite } from '../src/dataflow/orm-write-catalog.js';
import { enumerateSinkSites, buildDataFlowGraph } from '../src/lineage/graph-builder.js';
import { validateGraph } from '../src/lineage/validate.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

function ormSites(src) {
  const cg = irOf({ 'a.js': `function h(req) { ${src} }` });
  const { sites } = enumerateSinkSites(cg);
  return sites.filter((s) => s.entry.id.startsWith('orm-write-js-'));
}

// ── 1. Real ORM shapes match ────────────────────────────────────────────

test('ORM-write: User.create({...}) matches with coverageStatus candidate', () => {
  const sites = ormSites('User.create({ email: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'orm-write-js-create');
  assert.equal(sites[0].decision.coverageStatus, 'candidate');
  assert.equal(sites[0].decision.category, 'database');
});

test('ORM-write: Order.save({...}) matches with coverageStatus candidate', () => {
  const sites = ormSites('Order.save({ total: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'orm-write-js-save');
  assert.equal(sites[0].decision.coverageStatus, 'candidate');
});

test('ORM-write: Payment.update({...}) matches with coverageStatus candidate', () => {
  const sites = ormSites('Payment.update({ status: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'orm-write-js-update');
  assert.equal(sites[0].decision.coverageStatus, 'candidate');
});

test('ORM-write: Account.upsert({...}) matches with coverageStatus candidate', () => {
  const sites = ormSites('Account.upsert({ balance: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'orm-write-js-upsert');
  assert.equal(sites[0].decision.coverageStatus, 'candidate');
});

// ── 1b. Milestone 2, Sub-project E, increment 2: node.storeDetail
//         extraction (table/operation/columns) ─────────────────────────

test('storeDetail: User.create({ email: x, password: y }) extracts table/operation/columns', () => {
  const sites = ormSites('User.create({ email: x, password: y });');
  assert.equal(sites.length, 1);
  const { storeDetail } = sites[0];
  assert.equal(storeDetail.table, 'User');
  assert.equal(storeDetail.operation, 'create');
  assert.deepEqual([...storeDetail.columns].sort(), ['email', 'password']);
  // FR-204's own "unknown portions remain unknown" clause — this
  // increment never populates these four fields, in every case it
  // produces (DESIGN_STORE_DETAIL.md §2).
  assert.equal(storeDetail.provider, null);
  assert.equal(storeDetail.host, null);
  assert.equal(storeDetail.database, null);
  assert.equal(storeDetail.schema, null);
});

test('storeDetail: Order.save({...}) maps operation to "upsert", never "create" — save is genuinely undecidable statically (INSERT on a new document, UPDATE on one loaded from the database), so "upsert" is the honest umbrella, not a guess at which one', () => {
  const sites = ormSites('Order.save({ total: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].storeDetail.operation, 'upsert');
});

test('storeDetail: a spread argument mixed with real keys never fabricates a column name for the spread', () => {
  const sites = ormSites('User.create({ email: x, ...extra });');
  assert.equal(sites.length, 1);
  assert.deepEqual(sites[0].storeDetail.columns, ['email']);
});

test('storeDetail: a computed, non-literal key never reports "*" as a column name', () => {
  const sites = ormSites('User.create({ [dynamicKey]: x, email: y });');
  assert.equal(sites.length, 1);
  assert.deepEqual(sites[0].storeDetail.columns, ['email']);
  assert.ok(!sites[0].storeDetail.columns.includes('*'));
});

test('storeDetail: duplicate-value properties sharing a key are deduplicated', () => {
  const sites = ormSites('User.create({ email: a, email: b });');
  assert.equal(sites.length, 1);
  assert.deepEqual(sites[0].storeDetail.columns, ['email']);
});

test('storeDetail: validateGraph() stays clean on a real graph containing an ORM-write node with a populated storeDetail', () => {
  const cg = irOf({ 'a.js': `function h(req) { User.create({ email: req.body.email, password: req.body.password }); }` });
  const r = buildDataFlowGraph(cg, { repository: 'orm-store-detail' });
  assert.deepEqual(validateGraph(r.graph).errors, []);
  const ormNode = r.graph.nodes.find((n) => n.storeDetail && n.storeDetail.table === 'User');
  assert.ok(ormNode, 'expected an ORM-write sink node carrying storeDetail');
  assert.equal(ormNode.storeDetail.operation, 'create');
  assert.deepEqual([...ormNode.storeDetail.columns].sort(), ['email', 'password']);
});

// ── 2. The object-literal gate rejects non-literal arguments ───────────
//
// `User.create(req.body)` — a bare identifier, not an object literal —
// must NOT produce a sink site at all. This is the exact shape
// `mass-assignment.js`'s OWN detector treats as its positive case (its
// pattern requires the first argument to be `req|request` followed by
// `.body|.params|.query`, i.e. a bare property read, never an object
// literal wrapping one). This increment recognizing FEWER shapes than
// `mass-assignment.js` here is not a regression — the two modules answer
// different questions at different confidence tiers (a full-confidence
// SAST finding vs. a disclosed `candidate`-tier Data Flow Explorer node),
// and this catalog's whole reason for existing is the object-literal
// precision gate `mass-assignment.js` does not need.

test('ORM-write: a bare-identifier first argument (req.body) is a hard exclusion, not a downgrade', () => {
  assert.equal(ormSites('User.create(req.body);').length, 0);
});

test('ORM-write: a spread first argument is a hard exclusion', () => {
  assert.equal(ormSites('User.create(...args);').length, 0);
});

test('ORM-write: a positional-string first argument is a hard exclusion', () => {
  assert.equal(ormSites("User.create('literal-string');").length, 0);
});

test('ORM-write: matchOrmWrite itself never receives the call arguments, so the gate must live at the call site — proven directly', () => {
  // matchOrmWrite's own signature mirrors matchPrivacySink's: (calleeExpr, file).
  // It cannot see arg0 at all, so it matches on callee shape alone, even
  // for a call whose real argument would fail the object-literal gate.
  // The gate is enforced by graph-builder.js's resolveOrmWriteAtCallSite,
  // proven in the sibling tests above and not duplicated here.
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'User' }, prop: 'create' };
  assert.ok(matchOrmWrite(calleeExpr, 'a.js'));
});

// ── 3. Non-ORM receivers do not match (the receiver-shape gate, proven
//        independently of the argument-shape gate) ─────────────────────

test('ORM-write: a lowercase receiver does not match, even with an object-literal argument', () => {
  assert.equal(ormSites('widget.create({ a: x });').length, 0);
});

test('ORM-write: a non-capitalized, non-ident receiver (member chain) does not match', () => {
  assert.equal(ormSites('db.models.User.create({ a: x });').length, 0);
});

test('ORM-write: a bare call with no receiver at all does not match', () => {
  assert.equal(ormSites('create({ a: x });').length, 0);
});

// ── 4. Isolation: dataflow/engine.js / runTaintEngine is genuinely
//        unaffected — proven live, not just asserted in a comment ───────

test('ORM-write: ORM_WRITE_CATALOG entries never appear in the general CATALOG (structural isolation check)', () => {
  const catalogIds = new Set(CATALOG.filter((e) => e.kind === 'sink').map((e) => e.id));
  for (const e of ORM_WRITE_CATALOG) {
    assert.ok(!catalogIds.has(e.id), `${e.id} must not appear in dataflow/catalog.js's CATALOG`);
  }
});

test('ORM-write: matchSinkOrSanitizer (the general engine matcher) never returns an orm-write-catalog entry for an ORM-write call shape', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'User' }, prop: 'create' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', undefined) ?? [];
  assert.ok(!hits.some((h) => h.id.startsWith('orm-write-js-')));
});

test('ORM-write: a real scan through runTaintEngine over a fixture containing an ORM-write call site produces NO finding attributable to orm-write-catalog.js', () => {
  // The exact worked shape the plan names: a tainted field reaching a
  // recognized ORM-write call. If the general taint engine ever surfaced
  // a finding for this, the isolation this whole increment depends on
  // would be broken — this is the load-bearing proof, not the structural
  // check above alone (a structural check proves the catalogs don't
  // SHARE ids; this proves the ENGINE never independently discovers the
  // ORM shape some other way).
  const src = `
    function express() {}
    function handler(req, res) {
      User.create({ email: req.body.email });
    }
  `;
  const { perFile, callGraph } = buildProjectIR({ 'a.js': src });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  assert.ok(Array.isArray(findings));
  const ormAttributable = findings.filter((f) =>
    /orm-write/i.test(String(f.id ?? '')) ||
    /orm write/i.test(String(f.vuln ?? '')) ||
    (f.parser === 'IR-TAINT' && /\bcreate\b/i.test(String(f.vuln ?? '')) && /orm/i.test(String(f.vuln ?? ''))),
  );
  assert.equal(ormAttributable.length, 0, `expected zero ORM-write-attributable findings, got: ${JSON.stringify(ormAttributable)}`);
});

test('ORM-write: enumerateSinkSites is the only place that can ever see an ORM-write site — buildProjectIR/runTaintEngine\'s own call graph never consults dataflow/orm-write-catalog.js at all (import-boundary check)', async () => {
  // A direct, textual confirmation that dataflow/engine.js never imports
  // orm-write-catalog.js — the same reuse-boundary test style this
  // package already uses elsewhere (e.g. graph-builder.test.js's own
  // reuse-boundary check).
  const fs = await import('node:fs');
  const path = await import('node:path');
  const engineSrc = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'dataflow', 'engine.js'), 'utf8');
  assert.ok(!engineSrc.includes('orm-write-catalog'), 'dataflow/engine.js must never import orm-write-catalog.js');
});
