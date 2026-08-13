// PRD R15 (docs/DETECTION_GAP_REMEDIATION_PRD.md): annotateReachability
// (engine.js) computes reachability from a call graph that `buildCallGraph`
// only ever populates for .js/.jsx/.ts/.tsx/.mjs/.cjs files. For every other
// language, `callGraph[file]` is simply absent — but the code read that as
// `{}` (an empty-but-present graph) and fell through to `reachable=false`,
// which `demoteUnreachable` (posture/reachability-filter.js) then treats as
// real evidence of unreachability and demotes severity on. In a routed
// project, this silently demoted EVERY non-JS finding not lucky enough to be
// route-rooted (within 60 lines of a route declaration in the same file) —
// an absence of evidence scored identically to evidence of absence.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

test('a non-JS finding in a routed project is not severity-demoted purely for lacking call-graph data', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-reach-nocg-'));
  fs.writeFileSync(path.join(dir, 'app.js'), `
const express = require('express');
const app = express();
app.get('/x', (req, res) => { res.send('ok'); });
`);
  fs.writeFileSync(path.join(dir, 'worker.py'), `
import subprocess
import os
def process(cmd):
    subprocess.call(cmd, shell=True)
process(os.environ.get('CMD'))
`);
  const { scan } = await runScan(dir);
  const py = (scan.findings || []).filter((f) => f.file === 'worker.py' && f.parser === 'PY-SAST');
  assert.ok(py.length >= 1, 'expected the Python command-injection finding to be present');
  const f = py[0];
  assert.equal(f.unreachable, undefined,
    `Python has no call graph at all — absence of evidence must not be treated as unreachability. Got: reachable=${f.reachable} unreachable=${f.unreachable} severity=${f.severity}`);
  assert.equal(f.severity, 'critical', `severity must not be demoted, got ${f.severity}`);
});

test('a genuinely-unreachable JS finding (real call-graph data says so) is still demoted (mechanism still works)', async () => {
  // helper.js is a JS file (buildCallGraph DOES process it — real data
  // exists), has no route of its own, so routeRooted is always false there,
  // and nothing in it is ever called near a route. This is the case the
  // demotion is SUPPOSED to catch — distinct from the Python case above,
  // where no call-graph data exists for the language at all.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-reach-jsdead-'));
  fs.writeFileSync(path.join(dir, 'app.js'), `
const express = require('express');
const app = express();
app.get('/x', (req, res) => { res.send('ok'); });
`);
  fs.writeFileSync(path.join(dir, 'helper.js'), `
const cp = require('child_process');
function neverCalledHelper(req) { cp.exec(req.query.cmd); }
`);
  const { scan } = await runScan(dir);
  const findings = (scan.findings || []).filter((f) => f.file === 'helper.js' && /Command Injection|exec/i.test(f.vuln || ''));
  assert.ok(findings.length >= 1, `expected a command-injection finding in helper.js, got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
  assert.equal(findings[0].unreachable, true, 'a JS finding with real (empty) call-graph evidence should still be demoted');
});
