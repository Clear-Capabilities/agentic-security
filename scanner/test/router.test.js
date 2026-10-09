import { test } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { decide, computeScanTrend, explain } from '../src/posture/router.js';
import { mkTestTmp } from './helpers/tmp.js';

function tmpRoot() {
  const root = mkTestTmp('as-router-');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

function writeState(root, name, obj) {
  fs.writeFileSync(path.join(root, '.agentic-security', name), JSON.stringify(obj));
}

test('decide: no prior scan -> first-scan', () => {
  const root = tmpRoot();
  const d = decide({ scanRoot: root, intent: null });
  assert.equal(d.action, 'first-scan');
});

test('decide: criticals open -> fix-critical', () => {
  const root = tmpRoot();
  writeState(root, 'last-scan.json', { findings: [{ severity: 'critical' }] });
  const d = decide({ scanRoot: root, intent: null });
  assert.equal(d.action, 'fix-critical');
});

test('computeScanTrend: needs >=2 history points', () => {
  const root = tmpRoot();
  assert.deepEqual(computeScanTrend(root), {});
  writeState(root, 'scan-history.json', [{ critical: 1, high: 1 }]);
  assert.deepEqual(computeScanTrend(root), {});
});

test('computeScanTrend: improving when critical+high drop', () => {
  const root = tmpRoot();
  writeState(root, 'scan-history.json', [
    { critical: 2, high: 3 },
    { critical: 0, high: 1 },
  ]);
  const t = computeScanTrend(root);
  assert.equal(t.trend, 'improving');
  assert.match(t.whatChanged, /4 fewer/);
});

test('computeScanTrend: regressing when critical+high rise', () => {
  const root = tmpRoot();
  writeState(root, 'scan-history.json', [
    { critical: 0, high: 0 },
    { critical: 1, high: 1 },
  ]);
  assert.equal(computeScanTrend(root).trend, 'regressing');
});

test('decide: merges trend into decision and explain renders it', () => {
  const root = tmpRoot();
  writeState(root, 'last-scan.json', { findings: [{ severity: 'medium' }] });
  writeState(root, 'scan-history.json', [
    { critical: 3, high: 2 },
    { critical: 1, high: 1 },
  ]);
  const d = decide({ scanRoot: root, intent: null });
  assert.equal(d.trend, 'improving');
  assert.match(explain(d), /Trend:\s+↓/);
});
