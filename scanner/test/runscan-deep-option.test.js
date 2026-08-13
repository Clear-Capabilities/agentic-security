// Stage 3 correctness audit (detection depth): runScan(dir, {deep:true}) was
// a silent no-op. runFullScan destructured its single options object as
// {fileContents, depFileContents, scanRoot, resume} only — `deep` was
// dropped on the floor before engine.js's `_deepRequested` gate, which read
// ONLY `process.env.AGENTIC_SECURITY_DEEP === '1'`. Several interprocedural
// test files (interproc-k2.test.js, parser-cs-kt.test.js, points-to.test.js)
// pass exactly this option believing it enables deep mode; it never did —
// those tests were exercising whatever non-deep detector coincidentally
// fired, not the interprocedural taint engine they're named for.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-deepopt-'));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('runScan(dir, {deep:true}) actually enables deep mode (IR-TAINT findings appear)', async () => {
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  cp.exec(req.body.cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  // PRD R3: IR-TAINT findings now dedupe against a pattern-layer duplicate of
  // the same sink before the rest of the pipeline runs, so the survivor's own
  // `parser` field may be the winning non-IR-TAINT detector (e.g. STRUCTURAL)
  // with IR-TAINT recorded as corroborating `evidence` — this is the correct,
  // intended outcome (see test/deep-mode-annotator-pipeline.test.js), not a
  // sign the deep engine didn't run. Check either shape.
  const irContribution = (scan.findings || []).filter(f =>
    f.parser === 'IR-TAINT' || (Array.isArray(f.evidence) && f.evidence.includes('IR-TAINT')));
  assert.ok(irContribution.length >= 1,
    `expected {deep:true} to enable the IR-TAINT engine and contribute a finding, got: ${JSON.stringify((scan.findings || []).map(f => ({ parser: f.parser, evidence: f.evidence })))}`);
});

test('runScan(dir, {}) (no deep option) leaves deep mode off, matching prior default behavior', async () => {
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  cp.exec(req.body.cmd);
});
`,
  });
  const { scan } = await runScan(dir, {});
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.equal(irFindings.length, 0,
    'deep mode must stay off by default when {deep:true} is not passed and AGENTIC_SECURITY_DEEP is unset');
});
