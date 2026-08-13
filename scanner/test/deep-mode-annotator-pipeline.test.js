// PRD R3 — deep-mode (IR-TAINT) findings must flow through the same
// dedup/annotator pipeline as pattern-layer findings, not be appended
// afterward as unscored orphans.
//
// Fixture: a same-function SQLi shape (source and sink in one handler) is
// detectable by BOTH the regex/structural SAST layer and the IR-TAINT deep
// engine independently. Before the fix, the two findings for the identical
// sink survived as two entries (deep mode was appended after dedup) and the
// IR-TAINT one carried no family/calibration. After the fix, dedup collapses
// them to one, and that one has gone through family backfill + calibration.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-deep-pipeline-'));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('deep-mode SQLi finding dedupes against the pattern-layer duplicate and carries family + calibration', async () => {
  const dir = mkTmp({
    'app.js': `
const express = require('express');
const app = express();
app.get('/users', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id);
});
module.exports = app;
`.trim() + '\n',
  });

  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
  const hits = all.filter(f => /sql injection/i.test(f.vuln || ''));

  assert.equal(hits.length, 1,
    `expected exactly one deduped finding for the shared sink, got ${hits.length}: ${JSON.stringify(hits.map(h => ({ vuln: h.vuln, parser: h.parser })))}`);

  const f = hits[0];
  assert.ok(f.family, `expected a non-null family, got ${f.family}`);
  assert.notEqual(f.calibration_reason, 'no-family',
    'finding never reached the calibration annotator with a family set — deep mode is still bypassing the pipeline');
});
