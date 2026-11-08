import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { readTree } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

function mk() {
  const dir = mkTestTmp('as-rt-');
  cp.execFileSync('git', ['init', '-q'], { cwd: dir });
  const w = (rel, c) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); };
  w('.gitignore', 'buck-out/\n');
  w('src/App.js', 'x');
  w('buck-out/gen/Gen.js', 'x');
  w('test/keep.js', 'x');
  w('.github/workflows/buck2.yml', 'on: push\n');
  return dir;
}

test('git scope: ignored file is never opened', async () => {
  const dir = mk();
  const target = path.join(dir, 'buck-out/gen/Gen.js');
  const opened = [];
  const orig = fs.promises.readFile;
  const origStat = fs.promises.stat;
  // readTree imports node:fs/promises; patch the shared namespace object's methods.
  const fsp = await import('node:fs/promises');
  const patch = (k, o) => { fsp.default[k] = async (p, ...a) => { opened.push(String(p)); return o(p, ...a); }; };
  patch('readFile', orig); patch('stat', origStat);
  try {
    const { fileContents, inventory } = await readTree(dir, { gitScope: true });
    assert.ok('src/App.js' in fileContents);
    // The inventory keeps it; engine.js shouldScan()/IGNORE_DIRS is a second,
    // folder-name gate that still runs downstream (known gap, not changed here).
    assert.ok(inventory.included.includes('test/keep.js'), 'inventory does not drop code by folder name');
    assert.ok(inventory.included.includes('.github/workflows/buck2.yml'));
    assert.ok(!('buck-out/gen/Gen.js' in fileContents));
  } finally { fsp.default.readFile = orig; fsp.default.stat = origStat; }
  assert.ok(!opened.some((p) => p === target || p.includes('buck-out')), 'zero reads of ignored source');
});

test('legacy mode unchanged: test/ is still ignored', async () => {
  const dir = mk();
  const { fileContents } = await readTree(dir, { gitScope: false });
  assert.ok(!('test/keep.js' in fileContents));
});

test('in Git scope a tracked file under test, vendor or bin is scanned, and the default walk still skips them', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const cp = await import('node:child_process');
  const { runScan } = await import('../../src/runScan.js');
  const { mkTestTmp } = await import('../helpers/tmp.js');
  const d = mkTestTmp('agsec-scope-tests-');
  const body = "const cp = require('child_process');\nmodule.exports = (r) => cp.exec('ls ' + r.query.d);\n";
  fs.writeFileSync(path.join(d, 'package.json'), '{}');
  for (const rel of ['src/app.js', 'vendor/lib.js', 'bin/run.js', 'test/helper.js']) { fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true }); fs.writeFileSync(path.join(d, rel), body); }
  cp.spawnSync('git', ['init', '-q'], { cwd: d });
  const files = (scan) => [...new Set(scan.findings.filter((f) => f.kind !== 'sca').map((f) => f.file))].sort();
  const scoped = await runScan(d, { gitScope: true });
  assert.deepEqual(files(scoped.scan), ['bin/run.js', 'src/app.js', 'test/helper.js', 'vendor/lib.js']);
  const legacy = await runScan(d, {});
  assert.deepEqual(files(legacy.scan), ['src/app.js']);
});

test('a Git-ignored file is never opened by the scan, whatever opens files (PRD FR 01 acceptance)', async () => {
  const { createRequire, syncBuiltinESMExports } = await import('node:module');
  const req = createRequire(import.meta.url);
  const fs = req('node:fs');
  const fsp = req('node:fs/promises');
  const path = await import('node:path');
  const cp = await import('node:child_process');
  const { runScan } = await import('../../src/runScan.js');
  const { mkTestTmp } = await import('../helpers/tmp.js');
  const d = mkTestTmp('agsec-scope-reads-');
  fs.writeFileSync(path.join(d, '.gitignore'), 'secret-out/\n*.private.hs\n');
  fs.writeFileSync(path.join(d, 'package.json'), '{}');
  fs.mkdirSync(path.join(d, 'secret-out', 'deep'), { recursive: true });
  fs.writeFileSync(path.join(d, 'secret-out', 'deep', 'a.js'), "require('child_process').exec(process.argv[2])\n");
  fs.writeFileSync(path.join(d, 'x.private.hs'), 'module X where\n');
  fs.writeFileSync(path.join(d, 'ok.js'), 'module.exports = 1\n');
  cp.spawnSync('git', ['init', '-q'], { cwd: d });
  const opened = [];
  const real = { rfs: fs.readFileSync, ofs: fs.openSync, rp: fsp.readFile, op: fsp.open };
  const note = (p) => { if (typeof p === 'string') opened.push(p); };
  fs.readFileSync = function (p, ...a) { note(p); return real.rfs.call(this, p, ...a); };
  fs.openSync = function (p, ...a) { note(p); return real.ofs.call(this, p, ...a); };
  fsp.readFile = function (p, ...a) { note(p); return real.rp.call(this, p, ...a); };
  fsp.open = function (p, ...a) { note(p); return real.op.call(this, p, ...a); };
  syncBuiltinESMExports();
  try { await runScan(d, { gitScope: true }); }
  finally { fs.readFileSync = real.rfs; fs.openSync = real.ofs; fsp.readFile = real.rp; fsp.open = real.op; syncBuiltinESMExports(); }
  const touched = opened.filter((p) => p.startsWith(d) && /secret-out|\.private\.hs/.test(p));
  assert.deepEqual(touched, [], 'an ignored path was opened');
  assert.ok(opened.some((p) => p.endsWith('ok.js')), 'the instrumentation sees ordinary reads');
});
