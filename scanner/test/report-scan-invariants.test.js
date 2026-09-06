// Report-consistency invariants — customer-reported inconsistencies between
// what a scan actually did and what the report/scanMeta claimed it did.
//
// Both bugs below are single-field wiring defects, not the annotators being
// wrong: `linesScanned` was read in report/index.js but never assigned
// anywhere in the engine, and `annotateWhyFired` was called with a hardcoded
// `{}` context even though the engine already computes the real ruleset
// version two other places in the same function. Both are pinned end-to-end
// via a real `runScan()`, not by calling the annotator directly with a
// hand-supplied context — that's exactly the gap that let the wiring defect
// through: the annotator itself was already unit-tested and correct.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '../src/runScan.js';
import { toJSON } from '../src/report/index.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

async function scanOneFile(name, src) {
  setStateWritesEnabled(false);
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'report-inv-'));
  try {
    fs.writeFileSync(path.join(d, name), src);
    return await runScan(d);
  } finally { setStateWritesEnabled(true); fs.rmSync(d, { recursive: true, force: true }); }
}

test('toJSON scanned.lines reflects the real file, not zero', async () => {
  const src = Array.from({ length: 42 }, (_, i) => `# line ${i}`).join('\n');
  const { scan } = await scanOneFile('a.py', src);
  const out = toJSON(scan, {});
  assert.ok(out.scanned.files >= 1, 'at least the one file scanned');
  assert.equal(out.scanned.lines, 42, 'scanned.lines must count the real source, not fall back to 0');
});

test('scan._scanMeta.findingsBySeverity sums to scan.findings.length', async () => {
  // A mix of severities from real detectors, so this is not a single-bucket
  // coincidence: critical (SQL injection) + critical (shell=True command
  // injection). The invariant this pins: the severity breakdown the report
  // shows and the finding count the report shows must never be able to
  // disagree, because a reader compares them directly.
  const src = [
    'import subprocess',
    'def get_user(cursor, user_id):',
    '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    'def run_cmd(host):',
    '    subprocess.run(f"ping {host}", shell=True)',
  ].join('\n');
  const { scan } = await scanOneFile('a.py', src);
  const bySev = scan._scanMeta.findingsBySeverity;
  const summed = Object.values(bySev).reduce((a, b) => a + b, 0);
  assert.ok((scan.findings || []).length > 0, 'the fixture must actually produce findings, or this test proves nothing');
  assert.equal(summed, scan.findings.length,
    `findingsBySeverity (${JSON.stringify(bySev)}) must sum to findings.length (${scan.findings.length})`);
});

test('a finding\'s whyFired.scanner.rulesetVersion is populated, not null', async () => {
  const src = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n';
  const { scan } = await scanOneFile('a.py', src);
  const f = (scan.findings || []).find(x => x.whyFired);
  assert.ok(f, 'expected at least one finding with whyFired attached');
  assert.ok(f.whyFired.scanner.rulesetVersion,
    'rulesetVersion must be the real engine version, not the ctx={} default of null');
});
