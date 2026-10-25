// DAG-07 R07.7: the lineage build wired through the owned worker.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildLineageGraphOwned, resolveLineageDeadlineMs } from '../../src/lineage/owned-build.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures', 'owned-worker-fixtures.mjs');
const vulnerableJs = { 'app.js': fs.readFileSync(path.join(HERE, '..', 'fixtures', 'vulnerable-js', 'app.js'), 'utf8') };

function largeFixture(files = 150, fns = 6) {
  const fc = {};
  for (let f = 0; f < files; f++) {
    let src = '';
    for (let i = 0; i < fns; i++) {
      src += `function h${f}_${i}(req, res) {\n  const a = req.body.f${i};\n  const b = a + 'x';\n  return h${f}_${(i + 1) % fns}({ body: { f${i}: b } }, res);\n}\n`;
    }
    src += `module.exports = { h${f}_0 };\n`;
    fc[`src/m${f}.js`] = src;
  }
  return fc;
}

test('owned-build/1: deadline parsing; unset means off', () => {
  assert.equal(resolveLineageDeadlineMs({}, {}), null);
  assert.equal(resolveLineageDeadlineMs({}, { AGENTIC_SECURITY_LINEAGE_DEADLINE_MS: '250' }), 250);
  assert.equal(resolveLineageDeadlineMs({ deadlineMs: 10 }, { AGENTIC_SECURITY_LINEAGE_DEADLINE_MS: '250' }), 10);
  assert.equal(resolveLineageDeadlineMs({ deadlineMs: 0 }, {}), null);
  assert.equal(resolveLineageDeadlineMs({}, { AGENTIC_SECURITY_LINEAGE_DEADLINE_MS: 'abc' }), null);
});

test('owned-build/2: no deadline completes and matches the in-process build byte for byte', async () => {
  const { buildProjectIR } = await import('../../src/ir/index.js');
  const { buildLineageGraph } = await import('../../src/lineage/index.js');
  const { perFile, callGraph } = buildProjectIR(vulnerableJs);
  const direct = buildLineageGraph(callGraph, { deterministic: true, perFile, fileContents: vulnerableJs, repository: 'r' });
  const { done, exited } = buildLineageGraphOwned(vulnerableJs, { deterministic: true, repository: 'r' });
  const owned = await done;
  await exited;
  assert.equal(owned.status, 'complete');
  assert.equal(owned.cancelled, false);
  assert.equal(JSON.stringify(owned.graph), JSON.stringify(direct.graph));
});

test('owned-build/3: a tiny deadline on a large fixture returns a cancelled graph, acknowledged in under 1000 ms', async () => {
  const fc = largeFixture();
  const t0 = Date.now();
  const { done, exited } = buildLineageGraphOwned(fc, { deterministic: true, deadlineMs: 1, ackGraceMs: 900 });
  const r = await done;
  const wall = Date.now() - t0;
  await exited;
  assert.equal(r.status, 'complete', JSON.stringify({ status: r.status, failure: r.failure }));
  assert.equal(r.cancelled, true);
  assert.equal(r.graph.scanHealth.status, 'cancelled');
  assert.ok(!r.terminatedByWatchdog);
  assert.ok(wall < 1000, `returned in ${wall}ms`);
  console.log(`# cancelled lineage graph returned in ${wall}ms (large fixture ${Object.keys(fc).length} files)`);
});

test('owned-build/4: an unresponsive worker is terminated by the watchdog and the thread is gone', async () => {
  const t0 = Date.now();
  const { done, exited } = buildLineageGraphOwned({ 'a.js': 'x' }, { deadlineMs: 100, ackGraceMs: 300, worker: { modulePath: FIX, exportName: 'lineageUnresponsive' } });
  const r = await done;
  const ms = Date.now() - t0;
  assert.equal(r.status, 'cancelled');
  assert.equal(r.terminatedByWatchdog, true);
  assert.equal(r.graph, null);
  assert.ok(ms < 1000, `released in ${ms}ms`);
  await exited;
  console.log(`# watchdog released the lineage build in ${ms}ms`);
});

test('owned-build/6: runScan honours AGENTIC_SECURITY_LINEAGE_DEADLINE_MS and reports a cancelled graph in scan health', async () => {
  const { runScan } = await import('../../src/runScan.js');
  const dir = path.join(HERE, '..', 'fixtures', 'vulnerable-js');
  const saved = { d: process.env.AGENTIC_SECURITY_LINEAGE_DEEP, m: process.env.AGENTIC_SECURITY_LINEAGE_DEADLINE_MS };
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  process.env.AGENTIC_SECURITY_LINEAGE_DEADLINE_MS = '1';
  try {
    const { scan } = await runScan(dir, { deterministic: true });
    assert.equal(scan.lineageGraph.scanHealth.status, 'cancelled');
    assert.equal(scan.lineageStatus.completion.status, 'cancelled');
  } finally {
    for (const [k, v] of [['AGENTIC_SECURITY_LINEAGE_DEEP', saved.d], ['AGENTIC_SECURITY_LINEAGE_DEADLINE_MS', saved.m]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});

test('owned-build/5: an AbortSignal cancels the same way', async () => {
  const ac = new AbortController();
  const { done, exited } = buildLineageGraphOwned({ 'a.js': 'x' }, { signal: ac.signal, ackGraceMs: 200, worker: { modulePath: FIX, exportName: 'lineageUnresponsive' } });
  setTimeout(() => ac.abort(), 50);
  const r = await done;
  assert.equal(r.terminatedByWatchdog, true);
  await exited;
});
