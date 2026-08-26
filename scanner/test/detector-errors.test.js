// Detector-error surface test (assurance-hardening PRD FR-201), mirroring
// test/annotator-errors.test.js's own established shape for the sibling
// FR-106/annotatorErrors surface.
//
// Real fault-injection into a real 128-call-site scan (proving isolation
// itself, not just presence of the field) lives in
// test/detector-fault-injection.test.js, which needs --experimental-test-
// module-mocks and its own process per that file's header. This file only
// proves the two cheap, always-run regressions: a clean scan reports
// detectorErrors: [], and a pre-populated scan.detectorErrors round-trips
// through toJSON().

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { toJSON } from '../src/report/index.js';

test('clean scan emits detectorErrors: []', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan, meta } = await runScan(root, { network: false });
  const out = toJSON(scan, meta);
  assert.ok(Array.isArray(out.detectorErrors), 'detectorErrors must be an array');
  assert.equal(out.detectorErrors.length, 0, `expected clean run, got: ${JSON.stringify(out.detectorErrors)}`);
});

test('detectorErrors surfaces when pre-populated on the scan object', () => {
  const fakeScan = {
    findings: [], routes: [], components: [], suppressions: [],
    detectorErrors: [
      { file: 'a.js', analyzer: 'scanFoo', err: 'simulated failure for test' },
    ],
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.detectorErrors.length, 1);
  assert.equal(out.detectorErrors[0].analyzer, 'scanFoo');
  assert.equal(out.detectorErrors[0].file, 'a.js');
  assert.match(out.detectorErrors[0].err, /simulated/);
});

test('toJSON defaults detectorErrors to [] when the engine did not compute one', () => {
  const out = toJSON({ findings: [], routes: [], components: [], suppressions: [] },
    { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(out.detectorErrors, []);
});
