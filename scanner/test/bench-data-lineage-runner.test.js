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
