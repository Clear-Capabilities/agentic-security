// RX-EXEC: RegExp.exec() is not child_process.exec().
//
// The `js-exec` sink matches by bare method name, so a regex's own `.exec()` on
// request data was reported as high-severity command injection. The sink is now
// gated on the receiver's type. Both directions are pinned: a provable RegExp
// receiver is not a sink, and every real child_process spelling (plus any
// receiver the engine cannot resolve) still is.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';
import { mkTestTmp } from './helpers/tmp.js';

async function cmdInjection(code) {
  const dir = mkTestTmp('as-rx-exec-');
  fs.writeFileSync(path.join(dir, 'app.js'), code);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter((f) => f.parser === 'IR-TAINT' && /CWE-78/.test(f.cwe || ''));
}

const ROUTE = (body, pre = '') => `${pre}
app.get('/v', (req, res) => {
${body}
  res.send('ok');
});
`;

test('RX-EXEC-1: module-scope regex const .exec(request data) is not command injection', async () => {
  const f = await cmdInjection(ROUTE('  const m = SEMVER.exec(req.query.v);', 'const SEMVER = /^(\\d+)\\.(\\d+)$/;'));
  assert.equal(f.length, 0, f.map((x) => x.vuln).join(', '));
});

test('RX-EXEC-2: inline regex literal .exec(request data) is not command injection', async () => {
  const f = await cmdInjection(ROUTE('  const n = /^(\\d+)/.exec(req.query.w);'));
  assert.equal(f.length, 0, f.map((x) => x.vuln).join(', '));
});

test('RX-EXEC-3: a local built with new RegExp(...) is not command injection', async () => {
  const f = await cmdInjection(ROUTE("  const re = new RegExp('^v(\\\\d+)');\n  const m = re.exec(req.query.v);"));
  assert.equal(f.length, 0, f.map((x) => x.vuln).join(', '));
});

test('RX-EXEC-4: child_process exec, destructured and member forms, still fires', async () => {
  const a = await cmdInjection(ROUTE("  exec('ls ' + req.query.d);", "const { exec } = require('child_process');"));
  assert.ok(a.length > 0, 'destructured exec must still be a sink');
  const b = await cmdInjection(ROUTE("  cp.exec('ls ' + req.query.d);", "const cp = require('child_process');"));
  assert.ok(b.length > 0, 'cp.exec must still be a sink');
});

test('RX-EXEC-5: an unresolved receiver and a name rebound to a non-regex both keep firing', async () => {
  const a = await cmdInjection(ROUTE("  runner.exec('ls ' + req.query.d);", 'const runner = makeRunner();'));
  assert.ok(a.length > 0, 'unresolved receiver must stay conservative');
  const b = await cmdInjection(`
app.get('/a', (req, res) => {
  const runner = require('child_process');
  runner.exec('ls ' + req.query.d);
  res.send('ok');
});
app.get('/b', (req, res) => {
  const runner = /^a/;
  res.send(String(runner.test('a')));
});
`);
  assert.ok(b.length > 0, 'a name also bound to a non-regex must not be treated as a RegExp');
});

test('RX-EXEC-6: catalog level, receiver type RegExp removes js-exec, other types and null keep it', () => {
  const callee = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'exec' };
  const ids = (t) => (matchSinkOrSanitizer(callee, 'a.js', t) || []).map((e) => e.id);
  assert.ok(ids(null).includes('js-exec'));
  assert.ok(ids('ChildProcess').includes('js-exec'));
  assert.ok(!ids('RegExp').includes('js-exec'));
  const lit = { kind: 'member', object: { kind: 'literal', value: /a/, isRegex: true }, prop: 'exec' };
  assert.ok(!(matchSinkOrSanitizer(lit, 'a.js') || []).some((e) => e.id === 'js-exec'));
});
