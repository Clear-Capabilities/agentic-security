// PRD R14(b) (docs/DETECTION_GAP_REMEDIATION_PRD.md): Tasks 1-4 taught the
// IR layer to synthesize a <module> function for top-level statements in
// Python (CST + regex fallback), PHP, and Ruby, giving flat vulnerable
// scripts in these languages the same Layer-2 taint-analysis CFG shape JS
// already had. Those tasks' own tests confirm IR *shape* (correct CFG nodes)
// but never exercise the full taint engine end to end. This file proves the
// PRD's actual success metric: a flat script with source->sink on the same
// top-level statement list (no function/def wrapping it) is detected by a
// real runScan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14b-e2e-'));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('R14(b) success metric: a flat PHP script (source+sink on the top-level statement list, no function) is detected', async () => {
  const dir = mkTmp({
    'index.php': `<?php
system($_GET['cmd']);
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat PHP script, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  // Finding 4 of the final whole-branch review: prove Task 5's dead-code
  // severity exemption actually applies to these new <module> findings —
  // not just that a finding exists at all.
  assert.ok(irFindings.every((f) => f.severity === 'critical'), `expected full, non-demoted severity, got: ${JSON.stringify(irFindings.map((f) => f.severity))}`);
});

test('R14(b) success metric: a flat Ruby script (source+sink on the top-level statement list, no def) is detected', async () => {
  const dir = mkTmp({
    'app.rb': `system(params[:cmd])
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Ruby script, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  assert.ok(irFindings.every((f) => f.severity === 'critical'), `expected full, non-demoted severity, got: ${JSON.stringify(irFindings.map((f) => f.severity))}`);
});

test('R14(b) success metric: a flat Python script (source+sink on the top-level statement list, no def) is detected — CST/auto path', async () => {
  const dir = mkTmp({
    'app.py': `import os

os.system(request.args)
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Python script (CST path), got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  assert.ok(irFindings.every((f) => f.severity === 'critical'), `expected full, non-demoted severity, got: ${JSON.stringify(irFindings.map((f) => f.severity))}`);
});

test('R14(b) success metric: a flat Python script is detected via the regex-fallback path too', async () => {
  const dir = mkTmp({
    'app.py': `import os

os.system(request.args)
`,
  });
  const prevParser = process.env.AGENTIC_SECURITY_PY_PARSER;
  process.env.AGENTIC_SECURITY_PY_PARSER = 'regex';
  try {
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
    assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Python script (regex path), got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
    assert.ok(irFindings.every((f) => f.severity === 'critical'), `expected full, non-demoted severity, got: ${JSON.stringify(irFindings.map((f) => f.severity))}`);
  } finally {
    if (prevParser === undefined) delete process.env.AGENTIC_SECURITY_PY_PARSER;
    else process.env.AGENTIC_SECURITY_PY_PARSER = prevParser;
  }
});

// --- Finding 2 (final whole-branch review): the line-scoped suppression
// pragma must work for module-level PHP/Ruby findings ------------------------
//
// Both parsers previously mis-tracked line numbers for module-level CFG
// nodes, so a pragma placed on the real sink line did nothing (the finding
// was reported at a different, wrong line). These place the sink several
// lines past a function/def declaration — proving the fix generally, not
// just for a first-line special case — and pin BOTH directions: the pragma
// suppresses the finding, and a positive control (no pragma) confirms the
// finding fires in the first place.

test('R14(b) Finding 2 regression: agentic-security-ignore on the exact source line of a module-level PHP sink suppresses it', async () => {
  const phpFile = (pragma = '') => `<?php
function helper($x) {
    return $x;
}

$cmd = $_GET['cmd'];
system($cmd);${pragma}
`;
  const controlDir = mkTmp({ 'index.php': phpFile() });
  const { scan: control } = await runScan(controlDir, { deep: true, deepInCi: true });
  const controlTaint = (control.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(controlTaint.length >= 1, 'positive control: deep mode must produce an IR-TAINT finding without the pragma');

  const suppressedDir = mkTmp({ 'index.php': phpFile(' // agentic-security-ignore') });
  const { scan: suppressed } = await runScan(suppressedDir, { deep: true, deepInCi: true });
  const suppressedTaint = (suppressed.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.equal(suppressedTaint.length, 0,
    'the pragma on the real sink line (line 7) must suppress the module-level IR finding — ' +
    'before the line-tracking fix, the finding was reported at the wrong line and the pragma was inert');
});

test('R14(b) Finding 2 regression: agentic-security-ignore on the exact source line of a module-level Ruby sink suppresses it', async () => {
  const rubyFile = (pragma = '') => `def helper(x)
  return x
end

cmd = params[:cmd]
system(cmd)${pragma}
`;
  const controlDir = mkTmp({ 'app.rb': rubyFile() });
  const { scan: control } = await runScan(controlDir, { deep: true, deepInCi: true });
  const controlTaint = (control.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(controlTaint.length >= 1, 'positive control: deep mode must produce an IR-TAINT finding without the pragma');

  const suppressedDir = mkTmp({ 'app.rb': rubyFile(' # agentic-security-ignore') });
  const { scan: suppressed } = await runScan(suppressedDir, { deep: true, deepInCi: true });
  const suppressedTaint = (suppressed.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.equal(suppressedTaint.length, 0,
    'the pragma on the real sink line (line 6) must suppress the module-level IR finding — ' +
    'before the line-tracking fix, the finding was reported at the wrong line and the pragma was inert');
});
