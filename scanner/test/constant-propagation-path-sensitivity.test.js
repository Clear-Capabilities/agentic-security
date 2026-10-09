// A real, general (not language-specific) bug found via the SARD PHP work:
// `_activeConstantVars` (dataflow/engine.js) was a single, function-scoped
// Map, written destructively by EVERY 'assign' step regardless of which CFG
// branch produced it, and consulted by `exprTaint` as an unconditional
// short-circuit ahead of the real, properly branch-merged access-path
// lattice (`state`). A variable assigned a LITERAL on one branch of an
// if/else and a TAINTED SOURCE on the other branch is exactly Juliet's
// dominant control-flow-gating idiom (flow variants 02-22 across every
// language this engine supports) — and whichever branch the worklist
// happened to visit LAST silently overrode the correct, merged taint state
// at the join point, regardless of which branch's value could actually
// reach the sink. This is the taint-engine analogue of forgetting that two
// branches of an if/else are not sequential statements.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

async function scanSource(name, body) {
  const dir = mkTestTmp('as-const-path-sens-');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', name), body);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const taintOnly = (findings) => findings.filter((f) => f.parser === 'IR-TAINT');

test('a variable tainted on one if/else branch and constant on the other still fires at the merge point (branch order: tainted-then-literal)', async () => {
  const findings = await scanSource('a.js', `const { exec } = require('child_process');
module.exports = (req) => {
  let cmd;
  if (req.query.useDefault) {
    cmd = "ping localhost";
  } else {
    cmd = req.query.host;
  }
  exec(cmd);
};
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-78'),
    `expected a CWE-78 finding (else-branch taints cmd), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('the same shape with branches SWAPPED (literal first, tainted second in source order) still fires', async () => {
  const findings = await scanSource('b.js', `const { exec } = require('child_process');
module.exports = (req) => {
  let cmd;
  if (req.query.custom) {
    cmd = req.query.host;
  } else {
    cmd = "ping localhost";
  }
  exec(cmd);
};
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-78'),
    `expected a CWE-78 finding (if-branch taints cmd), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sanity: BOTH branches constant genuinely does not fire', async () => {
  const findings = await scanSource('c.js', `const { exec } = require('child_process');
module.exports = (req) => {
  let cmd;
  if (req.query.useDefault) {
    cmd = "ping localhost";
  } else {
    cmd = "ping 127.0.0.1";
  }
  exec(cmd);
};
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-78').length, 0,
    `both branches constant must not fire, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a variable reassigned to a literal AFTER a tainted branch merge is still correctly cleared (no false positive from removing the shortcut)', async () => {
  const findings = await scanSource('d.js', `const { exec } = require('child_process');
module.exports = (req) => {
  let cmd;
  if (req.query.custom) {
    cmd = req.query.host;
  } else {
    cmd = "ping localhost";
  }
  cmd = "ping 127.0.0.1";
  exec(cmd);
};
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-78').length, 0,
    `a literal reassignment AFTER the merge must still clear taint, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});
