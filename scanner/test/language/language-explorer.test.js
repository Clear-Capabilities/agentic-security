// X-005: Haskell and Nix graphs through the real explorer server, exports and graph workflows. Tagged [X-005.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { exportGraphJSON } from '../../src/lineage/export-json.js';
import { exportFlowsCSV } from '../../src/lineage/export-csv.js';
import { buildGraphSnapshot } from '../../src/lineage/graph-snapshot.js';
import { computeGraphDiff } from '../../src/lineage/graph-diff.js';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { diffScenarioGraph } from '../../src/lineage/scenario-diff.js';
import { computeImpactAssessment } from '../../src/lineage/impact-engine.js';
import { correlateObservations } from '../../src/lineage/observation-correlation.js';
import { createExploreServer, TOKEN_HEADER } from '../../src/server/http-server.js';
import { generateSessionToken } from '../../src/server/security.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures');

function readTree(dir, ext) {
  const out = {};
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (ext.test(e.name)) out[path.relative(dir, p)] = fs.readFileSync(p, 'utf8'); } };
  walk(dir);
  return out;
}
function build(files) {
  const { perFile, callGraph } = buildProjectIR(files);
  const r = buildLineageGraph(callGraph, { perFile, fileContents: files, repository: 'demo', deterministic: true });
  assert.equal(r.status, 'complete', JSON.stringify(r.failure));
  return r.graph;
}
const haskell = () => build(readTree(path.join(FIX, 'language-privacy', 'haskell'), /\.hs$/));
const nix = () => build(readTree(path.join(FIX, 'nix-secrets', 'store'), /\.nix$/));

function get(port, token, p) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path: p, headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: token } }, (res) => {
      const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => { const raw = Buffer.concat(c).toString('utf8'); let body = raw; try { body = JSON.parse(raw); } catch { /* raw */ } resolve({ status: res.statusCode, body }); });
    }).on('error', reject);
  });
}

for (const [label, make] of [['haskell', haskell], ['nix', nix]]) {
  test(`[X-005.AC01] ${label} golden graph is schema-valid and serves through the real explorer`, async () => {
    const graph = make();
    assert.deepEqual(validateGraph(graph).errors, []);
    assert.ok(graph.flows.length > 0 && graph.nodes.length > 0);
    const token = generateSessionToken();
    const { server, port } = await createExploreServer({ graph, port: 0, sessionToken: token, keepOpen: false });
    try {
      const g = await get(port, token, '/api/v1/graph');
      assert.equal(g.status, 200);
      assert.equal(g.body.data.flows.length, graph.flows.length);
      const f = await get(port, token, `/api/v1/flows/${encodeURIComponent(graph.flows[0].id)}`);
      assert.equal(f.status, 200);
      assert.equal(f.body.data.id, graph.flows[0].id);
    } finally { server.close(); }
  });

  test(`[X-005.AC01] ${label} exports (JSON, CSV) carry flows with evidence grades`, () => {
    const graph = make();
    const json = exportGraphJSON(graph);
    assert.equal(json.graph.flows.length, graph.flows.length);
    const csv = exportFlowsCSV(graph);
    assert.equal(csv.trim().split('\n').length, graph.flows.length + 1);
    for (const f of graph.flows) assert.ok(typeof f.evidenceGrade === 'string' && f.evidenceGrade.length, 'every flow keeps an evidence grade');
  });

  test(`[X-005.AC03] ${label} ids are deterministic across rebuilds and unique`, () => {
    const a = make(); const b = make();
    assert.deepEqual(a.nodes.map((n) => n.id), b.nodes.map((n) => n.id));
    assert.deepEqual(a.flows.map((n) => n.id), b.flows.map((n) => n.id));
    assert.equal(new Set(a.flows.map((f) => f.id)).size, a.flows.length);
  });
}

test('[X-005.AC01] Nix nodes keep static-configuration provenance, locations stay original', () => {
  const g = nix();
  const cfg = g.nodes.filter((n) => n.analysis && n.analysis.language === 'nix');
  assert.ok(cfg.length > 0);
  for (const n of cfg) { assert.equal(n.analysis.scope, 'static-configuration'); assert.equal(n.analysis.runtime, false); }
  const ev = g.evidence.filter((e) => e.evidenceType === 'configuration');
  assert.ok(ev.length > 0);
  for (const e of ev) { assert.match(e.location.file, /\.nix$/); assert.ok(Number.isInteger(e.location.line)); assert.ok(e.limitations.some((l) => /not proven|static/.test(l))); }
  // a storage fact is never proven protected from configuration alone
  for (const f of g.flows) assert.notEqual(f.protectionSummary, 'protected');
});

test('[X-005.AC01] unknown values stay unknown (no invented destination or protection)', () => {
  for (const g of [haskell(), nix()]) for (const n of g.nodes) { assert.ok(['internal', 'external', 'unknown'].includes(n.externality.value)); }
});

test('[X-005.AC02] diff, scenario and impact preserve scope; a hypothetical control never becomes static evidence', () => {
  const g = haskell();
  const before = buildGraphSnapshot(g, os.tmpdir(), { capturedAt: '2026-01-01T00:00:00.000Z' });
  const edge = g.edges.find((e) => e.protection.transit.verdict !== 'protected');
  assert.ok(edge, 'an unprotected-transit edge exists');
  const { graph: hypo, appliedOperations } = applyScenario(g, { operations: [{ kind: 'require_transit_protection', targetEdgeId: edge.id }] });
  assert.equal(appliedOperations.length, 1);
  const hypoEdge = hypo.edges.find((e) => e.id === edge.id);
  assert.equal(hypoEdge.protection.transit.evidenceGrade, 'assumed', 'a hypothetical control is graded assumed');
  assert.notEqual(g.edges.find((e) => e.id === edge.id).protection.transit.evidenceGrade, 'assumed', 'the base graph is never mutated');
  assert.ok(diffScenarioGraph(g, hypo));
  const after = buildGraphSnapshot(g, os.tmpdir(), { capturedAt: '2026-01-02T00:00:00.000Z' });
  const d = computeGraphDiff(before, after);
  assert.deepEqual(Object.values(d.added).flat(), []);
  const imp = computeImpactAssessment(g, g.flows[0].id);
  assert.equal(imp.scope, 'possible');
  assert.ok(imp.affectedNodeIds.length >= 2);
});

test('[X-005.AC02] an imported observation never rewrites static evidence; absence is not non-occurrence', () => {
  const g = haskell();
  const unevaluated = correlateObservations(g, null, {});
  for (const k of Object.keys(unevaluated.byFlow)) assert.equal(unevaluated.byFlow[k].layer, 'not_evaluated');
  const empty = correlateObservations(g, [], {});
  for (const k of Object.keys(empty.byFlow)) assert.equal(empty.byFlow[k].layer, 'not_observed_in_window');
  assert.equal(JSON.stringify(g).includes('runtime_observed'), false, 'the static graph has no runtime layer of its own');
  for (const e of g.edges) assert.equal(e.provenance, 'code');
});

test('[X-005.AC03] redaction: default export never carries a secret literal from a Haskell or Nix source', () => {
  const files = { 'S.hs': 'module S where\nimport Network.HTTP.Simple\n\ngo :: IO ()\ngo = do\n  r <- parseRequest "POST https://svc.example.test/x?token=sk-live-abcdefghijklmnopqrstuvwx"\n  _ <- httpLBS r\n  pure ()\n' };
  const g = build(files);
  assert.ok(!JSON.stringify(exportGraphJSON(g)).includes('sk-live-abcdefghijklmnopqrstuvwx'));
});

test('[X-005.AC03] XSS: hostile labels render as text, never as elements, in the privacy view', async () => {
  const { createDomShim } = await import('../../../frontend/test/dom-shim.js');
  const { document } = createDomShim();
  globalThis.document = document;
  const { computePrivacyViewModel, renderPrivacyView } = await import('../../../frontend/src/views/privacy-view.js');
  const g = JSON.parse(JSON.stringify(haskell()));
  for (const n of g.nodes) n.label = '<script>window.__xss=1</script><img src=x onerror=alert(1)>';
  for (const d of g.dataElements) d.name = '<svg onload=alert(1)>';
  const canvas = document.createElement('div');
  renderPrivacyView(computePrivacyViewModel(g, { selectedId: null, filters: {} }), canvas, () => {});
  const tags = [];
  const walk = (n) => { for (const c of n.childNodes || []) { if (c.nodeType === 'element') { tags.push(c.tagName); walk(c); } } };
  walk(canvas);
  for (const bad of ['SCRIPT', 'IMG', 'SVG']) assert.ok(!tags.includes(bad), `${bad} element created from hostile text`);
  delete globalThis.document;
});
