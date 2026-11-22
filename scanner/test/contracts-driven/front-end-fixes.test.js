// Three defects the contract-driven verification slice surfaced in the front ends, each pinned in both directions.
//   1. A call that is the right-hand side of a declaration or an assignment was left out of the function's call summary, so the
//      cross-file call graph and the context-intelligence symbol graph never followed `const r = helper(x)`.
//   2. Two anonymous functions on one line collided in the symbol graph and the whole context build was refused.
//   3. A database read inside the authentication middleware's own chain counted as the first sensitive operation at the middleware's
//      position, so the guard was judged "same-step" and ineffective.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProjectIRAsync } from '../../src/ir/index.js';
import { graphFromSource } from '../../src/context-intelligence/adapters/existing-ir.js';
import { validateGraph } from '../../src/context-intelligence/graph-schema.js';
import { buildContext } from '../../src/context-intelligence/build.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';

setStateWritesEnabled(false);
const HERE = path.dirname(fileURLToPath(import.meta.url));

test('an assignment-side call is in the call summary with the assignment node as its site, and the call graph follows it through an import', async () => {
  const files = {
    'svc.js': 'export function helper(v) { return v; }\n',
    'app.js': "import { helper } from './svc.js';\nexport function a(x) { const r = helper(x); return r; }\nexport function b(x) { let r; r = helper(x); return r; }\nexport function c(x) { const r = helper(other(x)); return r; }\nfunction other(v) { return v; }\n",
  };
  const ir = await buildProjectIRAsync(files);
  const fns = Object.fromEntries(ir.perFile['app.js'].functions.map((f) => [f.name, f]));
  for (const name of ['a', 'b']) {
    const calls = fns[name].calls;
    assert.equal(calls.length, 1, `${name} records its one call`);
    assert.equal(calls[0].callee, 'helper');
    const nodes = fns[name].cfg.nodes; const list = nodes instanceof Map ? [...nodes.values()] : Array.isArray(nodes) ? nodes : Object.values(nodes || {});
    assert.ok(list.some((n) => n.id === calls[0].site && n.kind === 'assign'), `${name}: the site is the assignment node`);
  }
  assert.deepEqual(fns.c.calls.map((x) => x.callee).sort(), ['helper', 'other'], 'a nested call keeps its own site; the outer one gains the assignment site');
  assert.ok(!Object.keys(fns.a).some((k) => k.startsWith('_')), 'no bookkeeping property leaks onto the cached function record');
  const edges = ir.callGraph.edges.filter((e) => /app\.js/.test(e.caller) && e.calleeName === 'helper');
  assert.equal(edges.length, 3);
  assert.ok(edges.every((e) => e.callee && e.callee.includes('svc.js')), 'every one resolves through the import');
});

test('a second anonymous function on one line gets its own symbol id and the graph validates', () => {
  const files = { 'a.js': 'export function f(xs) { return xs.map((x) => [x].map((y) => y + 1)); }\n' };
  const { graph } = graphFromSource(files);
  assert.deepEqual(validateGraph(graph, files), []);
  const anon = graph.symbols.filter((s) => s.id.includes('::<anon>@1')).map((s) => s.id).sort();
  assert.deepEqual(anon, ['a.js::<anon>@1', 'a.js::<anon>@1#2']);
});

test('a session lookup inside the authentication middleware is the control\'s own work: the guard stays present before the handler\'s operation', async () => {
  const { config } = normalizeConfig({});
  const built = await buildContext(path.join(HERE, '..', 'fixtures', 'context-intelligence', 'js-app'), { config });
  assert.equal(built.ok, true);
  const archive = built.bundles.find((b) => b.entrypoint.label.includes('/docs/:id/archive'));
  const auth = archive.manifest.protection.authentication;
  assert.equal(auth.state, 'present');
  assert.equal(auth.firstSensitiveLine, 23, 'the first sensitive operation is the handler\'s own write, not the middleware\'s session read');
  assert.ok(archive.reach.facts.some((f) => f.file === 'src/auth.js' && f.category === 'sensitive' && f.effLine === -1), 'the middleware\'s read is still recorded, at the chain\'s position');
  assert.equal(archive.manifest.protection.ownership.state, 'evaluated_and_ineffective', 'the check after the write is still ineffective');
});
