// End-to-end fault-injection gate (assurance-hardening PRD FR-201/FR-203).
//
// FR-203 grounding (auditing which detector call sites are gated by what,
// to build a per-analyzer coverage ledger) found a real, previously-missed
// gap in D-0028 step (b)'s otherwise-complete 128-call-site migration:
// scanWeb3Advanced and scanK8sAdmission were called directly
// (`_aF.push(...scanK8sAdmission(p,cc))`), NOT wrapped in runDetector — an
// exception from EITHER would propagate out of _runFileCascade entirely,
// silently discarding every OTHER detector's results for that same file
// (everything sequenced after it in the cascade), which is exactly the
// failure mode FR-201's own acceptance criterion exists to prevent. Fixed
// by wrapping both the same way as the other 128+ call sites. This test
// proves the fix for scanK8sAdmission specifically, mirroring
// test/detector-fault-injection.test.js's exact technique.
//
// DELIBERATELY ITS OWN FILE — mock.module() registrations bind at first
// resolution; a second mock.module() call in an already-mocked test file
// has nothing left to intercept (see detector-fault-injection.test.js's own
// header for the same constraint).

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const FIXTURE = path.join(SCANNER, 'test', 'fixtures', 'vulnerable-js');

test('scanK8sAdmission throwing does not crash the scan or discard sibling detectors\' findings for the same file', async () => {
  const modPath = path.join(SCANNER, 'src', 'sast', 'k8s-admission.js');
  const real = await import(modPath);
  mock.module(modPath, {
    exports: {
      ...real,
      scanK8sAdmission: () => { throw new Error('FR-201/FR-203 injected fault — scanK8sAdmission should never actually throw in production'); },
    },
  });

  setStateWritesEnabled(false);
  let scan;
  try {
    const { runScan } = await import(path.join(SCANNER, 'src', 'runScan.js'));
    ({ scan } = await runScan(FIXTURE, { network: false }));
  } finally {
    setStateWritesEnabled(true);
  }

  assert.ok((scan.findings || []).length > 0,
    'a fault in scanK8sAdmission must not suppress findings every OTHER independent detector already produced for the same file');
  assert.ok(Array.isArray(scan.detectorErrors), 'detectorErrors must be an array even when a fault was injected');
  const captured = scan.detectorErrors.find(e => /FR-201\/FR-203 injected fault/.test(e.err));
  assert.ok(captured, `expected the injected fault to be captured in detectorErrors, got: ${JSON.stringify(scan.detectorErrors)}`);
  assert.equal(captured.analyzer, 'scanK8sAdmission', 'the captured error must name the failing detector');
});
