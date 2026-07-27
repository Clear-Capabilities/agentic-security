// Regression tests for the two engine recall gaps.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { CATALOG, matchSource } from '../src/dataflow/catalog.js';

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

test('global sources: every global entry is reachable from matchSource', () => {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  assert.ok(globals.length >= 10, `expected at least 10 global entries, got ${globals.length}`);
  const unreachable = [];
  for (const e of globals) {
    const file = e.language === 'php' ? 'a.php' : e.language === 'rb' ? 'a.rb' : 'a.js';
    const hit = matchSource({ kind: 'ident', name: e.match.name }, file);
    if (!hit || hit.id !== e.id) unreachable.push(`${e.id}(${e.match.name})`);
  }
  assert.deepEqual(unreachable, [], `these global sources are unreachable: ${unreachable.join(', ')}`);
});

test('global sources: a global is language-scoped like every other entry', () => {
  const phpOnJs = matchSource({ kind: 'ident', name: '_GET' }, 'a.js');
  assert.ok(!phpOnJs || phpOnJs.language !== 'php',
    'a php superglobal must not match a .js file');
});

test('global sources: an unrelated identifier does not match', () => {
  assert.equal(matchSource({ kind: 'ident', name: 'notAGlobalAnywhere' }, 'a.php'), null);
});
