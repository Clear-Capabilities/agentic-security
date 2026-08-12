// S7 (Stage 2 measurement-completeness audit): _snapshotFromScan keyed its
// finding-identity Set on f.id — the engine's default id embeds file path
// and line number (posture/stable-id.js's own docstring: "any refactor that
// moves code rotates the IDs"). A finding that only shifted line between two
// scans registered as one finding "fixed" and a different one "introduced,"
// producing false churn in computeTrend()'s introduced/fixed/delta numbers.
// stableId (annotated well before appendScanSnapshot runs, per runScan.js's
// call order) omits the exact line by design and must be preferred.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { appendScanSnapshot, computeTrend } from '../src/posture/security-trend.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-trend-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"trend-test"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('computeTrend does not double-count a finding that only shifted line (same stableId)', async () => {
  setStateWritesEnabled(true);
  const p = await mkProject();
  try {
    const scanA = { findings: [{ id: 'struct:app.js:20:SQLi', stableId: 'stable-abc', severity: 'critical' }] };
    const scanB = { findings: [{ id: 'struct:app.js:21:SQLi', stableId: 'stable-abc', severity: 'critical' }] };
    appendScanSnapshot(scanA, p.dir, 'scan-a');
    appendScanSnapshot(scanB, p.dir, 'scan-b');
    const trend = computeTrend(p.dir);
    assert.equal(trend.hasTrend, true);
    assert.equal(trend.introduced, 0, `expected no introduced findings from a pure line shift, got ${trend.introduced}`);
    assert.equal(trend.fixed, 0, `expected no fixed findings from a pure line shift, got ${trend.fixed}`);
  } finally {
    setStateWritesEnabled(true);
    await p.cleanup();
  }
});

test('computeTrend still detects a genuinely new finding (different stableId)', async () => {
  setStateWritesEnabled(true);
  const p = await mkProject();
  try {
    const scanA = { findings: [{ id: 'struct:app.js:20:SQLi', stableId: 'stable-abc', severity: 'critical' }] };
    const scanB = {
      findings: [
        { id: 'struct:app.js:20:SQLi', stableId: 'stable-abc', severity: 'critical' },
        { id: 'struct:app.js:40:XSS', stableId: 'stable-xyz', severity: 'high' },
      ],
    };
    appendScanSnapshot(scanA, p.dir, 'scan-a');
    appendScanSnapshot(scanB, p.dir, 'scan-b');
    const trend = computeTrend(p.dir);
    assert.equal(trend.introduced, 1);
    assert.equal(trend.fixed, 0);
  } finally {
    setStateWritesEnabled(true);
    await p.cleanup();
  }
});

test('computeTrend falls back to id for findings with no stableId', async () => {
  setStateWritesEnabled(true);
  const p = await mkProject();
  try {
    const scanA = { findings: [{ id: 'legacy-id-1', severity: 'high' }] };
    const scanB = { findings: [] };
    appendScanSnapshot(scanA, p.dir, 'scan-a');
    appendScanSnapshot(scanB, p.dir, 'scan-b');
    const trend = computeTrend(p.dir);
    assert.equal(trend.fixed, 1);
  } finally {
    setStateWritesEnabled(true);
    await p.cleanup();
  }
});
