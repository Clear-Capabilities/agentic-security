// scripts/run-unit-tests.mjs is what `npm test` now runs instead of chaining
// eleven `npm run test:<scope>` invocations (258s sequential -> ~115s in one
// `node --test` call over the union of files — see that file's header for
// why). This pins the derivation logic itself: the file list must track
// package.json, not drift from it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCOPES, extractFiles, unionFiles, assertAllTestFilesCovered } from '../../scripts/run-unit-tests.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');

function readPkg() {
  return JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
}

test('every test:* script that runs `node --test` is covered by SCOPES or explicitly excluded', () => {
  // This is the drift guard itself, exercised as a visible test rather than
  // only as a side effect of running the script — a THIRTEENTH scoped script
  // added to package.json without being added here would otherwise only be
  // caught the next time someone runs `npm test` and reads stderr closely.
  const missing = assertAllTestFilesCovered(readPkg());
  assert.deepEqual(missing, [], `these test:* files are not covered by the combined run: ${JSON.stringify(missing)}`);
});

test('a scope missing from package.json is a hard error, not a silent skip', () => {
  // SCOPES names 'foo', but package.json has no test:foo. This is what
  // happens after a scoped script is renamed or removed without updating
  // SCOPES — the combined run must refuse to quietly cover less than it did
  // yesterday.
  const pkg = readPkg();
  assert.throws(() => unionFiles({ scripts: { ...pkg.scripts, 'test:sast': undefined } }),
    /has no "test:sast" script/);
});

test('the derived file list matches a hand-count of every scoped script', () => {
  const pkg = readPkg();
  const files = unionFiles(pkg);
  const bySet = new Set(files);
  assert.equal(bySet.size, files.length, 'unionFiles must not return duplicates');

  let expected = new Set();
  for (const scope of SCOPES) {
    for (const f of extractFiles(pkg.scripts[`test:${scope}`])) expected.add(f);
  }
  assert.deepEqual([...bySet].sort(), [...expected].sort());
});

test('cpp-dataflow and python are deliberately excluded, and still run in `npm test`', () => {
  // Not covered by run-unit-tests.mjs's combined invocation (see its header:
  // cpp-dataflow.test.js silently contributed zero results when folded into a
  // multi-file run, for a reason not chased down; python is a different
  // runtime). Both must still be reachable from `npm test` as separate steps,
  // or this exclusion silently drops coverage instead of just declining to
  // batch it.
  const pkg = readPkg();
  assert.ok(!SCOPES.includes('cpp-dataflow'));
  assert.match(pkg.scripts.test, /cpp-dataflow\.test\.js/, 'cpp-dataflow.test.js must still run somewhere in `npm test`');
  assert.match(pkg.scripts.test, /run-unit-tests\.mjs/, '`npm test` must invoke the combined runner');
  assert.match(pkg.scripts.test, /test:python\b/, 'test:python must still run in `npm test`');
});

test('extractFiles finds every file reference and nothing else', () => {
  assert.deepEqual(
    extractFiles('node --test test/a.test.js test/b/c.test.js test/a.test.js'),
    ['test/a.test.js', 'test/b/c.test.js'],
    'must dedupe and ignore non-file tokens',
  );
  assert.deepEqual(extractFiles(''), []);
  assert.deepEqual(extractFiles(undefined), []);
});
