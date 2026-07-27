// Regression tests for the two engine recall gaps.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

async function scanJs(src) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recall-test-'));
  try {
    fs.writeFileSync(path.join(dir, 'app.js'), src);
    const { scan } = await runScan(dir);
    const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
    return all.filter(f => /^IR-TAINT/.test(f.parser || ''));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const HEAD = `const { exec } = require('child_process');\nfunction h(req) { return req.query.c; }\n`;

test('assign-sink: a sink call in statement position is found (control)', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); exec(c); }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1, 'the control case must still be detected');
});

test('assign-sink: the same sink call on an assignment RHS is found', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); const out = exec(c); return out; }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1,
    `an assignment-position sink must be detected; got ${hits.length} IR-TAINT findings`);
});

test('assign-sink: a clean assignment RHS produces no finding', async () => {
  const hits = await scanJs(`const { exec } = require('child_process');\nfunction f() { const out = exec('ls -la'); return out; }\nmodule.exports={f};\n`);
  assert.equal(hits.length, 0, 'a literal argument must not be reported as tainted');
});
