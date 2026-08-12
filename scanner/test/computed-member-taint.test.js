// Stage 3 correctness audit (detection depth, path-feasibility): a
// computed-member WRITE with a literal key (`obj['secret'] = tainted`)
// collapsed straight to the wildcard access path "obj.*" — lhsPath never
// tried to extract the literal key, unlike exprOf's MemberExpression case,
// which DOES extract it for reads. access-paths.js has no wildcard
// semantics ('*' is a literal property name, not a match-anything token),
// so a write via bracket notation with a literal key and a later read of
// that same key (`obj.secret` or `obj['secret']`) computed DIFFERENT
// access paths and never matched — the taint was silently unreachable.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-computed-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a computed (bracket-notation) write with a literal key, read back via dot notation, propagates taint', async () => {
  const dir = mkTmp('write-computed-read-dot', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const data = {};
  data['cmd'] = req.body.cmd;
  cp.exec(data.cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected a bracket-notation write with a literal key to propagate taint to a dot-notation read, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('a computed write with a literal key, read back via the same computed literal key, propagates taint', async () => {
  const dir = mkTmp('write-computed-read-computed', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const data = {};
  data['cmd'] = req.body.cmd;
  cp.exec(data['cmd']);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected a bracket-notation write with a literal key to propagate taint to a matching bracket-notation read, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('a computed write to a DIFFERENT clean key does not fire (control)', async () => {
  const dir = mkTmp('control', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const data = {};
  data['other'] = req.body.cmd;
  data['cmd'] = 'echo hello';
  cp.exec(data.cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0,
    'a clean key must not be conflated with a tainted write to a DIFFERENT key');
});
