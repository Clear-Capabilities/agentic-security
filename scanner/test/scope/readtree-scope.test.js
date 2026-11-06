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
