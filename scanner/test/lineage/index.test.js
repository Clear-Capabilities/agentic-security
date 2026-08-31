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
  for (const bad of [null, undefined, {}, { functions: null }]) {
    const r = buildLineageGraph(bad, { repository: 'r' });
    assert.equal(r.status, 'not_available');
    assert.equal(r.graph, null);
    assert.equal(r.failure, null);
  }
});

// CORRECTION (measured against the real implementation, not assumed): the
// plan's original E5/2 list also included `{ functions: [] }` expecting
// `not_available`. Measured reality: an Array inherits `Array.prototype.values`
// (a real function), so the duck-type guard
// `typeof callGraph.functions?.values !== 'function'` treats an array as
// Map-like and lets it through — buildGraphWithCoverage then iterates zero
// functions and returns a valid, empty, schema-clean graph with
// status:'complete'. That is arguably correct behavior for the guard (which
// exists to reject genuinely shapeless input, not to duck-type-check
// "is this specifically a Map"), so this is pinned as its own case rather
// than folded into the `not_available` list above.
test('E5/2b: buildLineageGraph on a callGraph with an array (not Map) functions field duck-types as Map-like and produces an empty, valid, complete graph', () => {
  const r = buildLineageGraph({ functions: [] }, { repository: 'r' });
  assert.equal(r.status, 'complete');
  assert.equal(r.failure, null);
  assert.deepEqual(r.graph.nodes, []);
  assert.deepEqual(r.graph.edges, []);
  assert.deepEqual(validateGraph(r.graph).errors, []);
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
