// Regression guard: tests must not leave directories behind in the OS temp folder.
//
// A full run used to leave thousands of directories (gigabytes at one point) in the
// machine's temp folder, which also slowed later runs. Two halves:
//   1. the measuring harness (test/helpers/temp-leak.js) really detects a leak, and
//      really reports none for a file that cleans up with the mkTestTmp helper. Without
//      this, a harness that silently measured nothing would make half 2 pass vacuously;
//   2. the worst former offenders, run for real, leave nothing behind.
// Each measured run gets a PRIVATE temp root, so other processes cannot cause a false
// positive and nothing here touches the real temp folder.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { measureTempLeaks } from './helpers/temp-leak.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HELPER_TMP = path.join(HERE, 'helpers', 'tmp.js');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'leakguard-'));
after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function probeFile(name, body) {
  const f = path.join(scratch, name);
  fs.writeFileSync(f, `import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mkTestTmp } from ${JSON.stringify(HELPER_TMP)};
${body}
`);
  return f;
}

test('the harness detects a test that leaks a temp directory', () => {
  const f = probeFile('leaky.test.js', `test('leaks', () => { fs.writeFileSync(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'leaky-')), 'f'), 'x'); });`);
  const m = measureTempLeaks(f, { timeoutMs: 120_000 });
  assert.equal(m.status, 0);
  assert.equal(m.leaked.length, 1, `expected exactly the one leaked directory, got ${JSON.stringify(m.leaked)}`);
  assert.match(m.leaked[0], /^leaky-/);
  assert.ok(m.bytes > 0);
});

test('mkTestTmp removes its directories at exit, even when the test fails or leaves a read-only tree', () => {
  const f = probeFile('tidy.test.js', `test('tidy', () => {
  const a = mkTestTmp('tidy-a-');
  fs.mkdirSync(path.join(a, 'ro'));
  fs.writeFileSync(path.join(a, 'ro', 'f'), 'x');
  fs.chmodSync(path.join(a, 'ro'), 0o500);
  mkTestTmp('tidy-b-');
  throw new Error('a failing test must still be cleaned up after');
});`);
  const m = measureTempLeaks(f, { timeoutMs: 120_000 });
  assert.notEqual(m.status, 0, 'the probe test is meant to fail');
  assert.deepEqual(m.leaked, [], 'nothing may remain');
});

// Worst former offenders (counts measured before the fix, in parentheses): each created
// directories under the OS temp folder and never removed them.
const FIXED_OFFENDERS = [
  'test/compliance-evidence-signing.test.js', // 10
  'test/sandbox-escape.test.js',              // 2
  'test/pre-bash-guard.test.js',              // its scratch dirs
];

for (const file of FIXED_OFFENDERS) {
  test(`${file} leaves no temp directories behind`, () => {
    const m = measureTempLeaks(file, { timeoutMs: 300_000 });
    assert.equal(m.status, 0, `${file} itself must pass for the measurement to mean anything`);
    assert.deepEqual(m.leaked, [], `${file} left ${m.leaked.length} entr(ies) (${m.bytes} bytes) in the temp folder`);
  });
}
