import { test } from 'node:test';
import assert from 'node:assert/strict';
import { focusAreaId, partitionCallGraph } from '../src/discovery/partition.js';

function graph(fns, edges) {
  return { functions: new Map(fns.map(f => [f.qid, f])), edges };
}

test('focusAreaId is deterministic and order-independent', () => {
  assert.equal(focusAreaId(['b.js', 'a.js']), focusAreaId(['a.js', 'b.js']));
  assert.notEqual(focusAreaId(['a.js']), focusAreaId(['b.js']));
  assert.match(focusAreaId(['a.js']), /^[0-9a-f]{12}$/);
});

test('partitionCallGraph splits disconnected components into separate areas', () => {
  const cg = graph(
    [
      { qid: 'auth.js::login@1', name: 'login', file: 'auth.js' },
      { qid: 'auth.js::check@9', name: 'check', file: 'auth.js' },
      { qid: 'bill.js::charge@1', name: 'charge', file: 'bill.js' },
    ],
    [{ caller: 'auth.js::login@1', callee: 'auth.js::check@9' }],
  );
  const areas = partitionCallGraph(cg);
  assert.equal(areas.length, 2);
  const byFile = Object.fromEntries(areas.map(a => [a.files.join(','), a]));
  assert.ok(byFile['auth.js']);
  assert.equal(byFile['auth.js'].functions.length, 2);
  assert.equal(byFile['bill.js'].size, 1);
});

test('partitionCallGraph merges components that share a file', () => {
  // Two unconnected functions in one file still belong to one area:
  // a hunter reads whole files, so splitting a file across areas would
  // hand the same source to two hunters and reintroduce convergence.
  const cg = graph(
    [
      { qid: 'a.js::x@1', name: 'x', file: 'a.js' },
      { qid: 'a.js::y@5', name: 'y', file: 'a.js' },
    ],
    [],
  );
  const areas = partitionCallGraph(cg);
  assert.equal(areas.length, 1);
  assert.deepEqual(areas[0].files, ['a.js']);
});

test('partitionCallGraph caps area count and folds the remainder into misc', () => {
  const fns = [];
  for (let i = 0; i < 10; i++) fns.push({ qid: `f${i}.js::m@1`, name: 'm', file: `f${i}.js` });
  const areas = partitionCallGraph(graph(fns, []), { maxAreas: 3 });
  assert.equal(areas.length, 3);
  const misc = areas.find(a => a.label === 'misc');
  assert.ok(misc, 'expected a misc area');
  assert.ok(misc.files.length > 1);
  // Every input file appears in exactly one area.
  const all = areas.flatMap(a => a.files).sort();
  assert.equal(new Set(all).size, 10);
  assert.equal(all.length, 10);
});

test('partitionCallGraph returns [] for an empty or missing graph', () => {
  assert.deepEqual(partitionCallGraph(null), []);
  assert.deepEqual(partitionCallGraph({ functions: new Map(), edges: [] }), []);
});
