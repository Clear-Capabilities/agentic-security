// scripts/vendor-java-parser.mjs runs from the "prepare" lifecycle, which `npm pack` and `npm ci` both trigger. It used to delete
// vendor/java-parser and copy it again every time, so a test importing "#java-parser" at that moment lost the Java parser: on the hosted
// test-shard (3/8) a test that runs `npm pack` made the Java static-field taint tests lose every finding (reproduced locally: 4 failing runs
// in 6 with the script running beside the test). A current copy is now left untouched; a stale one is rebuilt in a staging directory and swapped
// in. Residual limit, stated: the swap is two renames, so a reader can still miss the directory for an instant while a STALE copy is replaced.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = path.join(SCANNER, 'scripts', 'vendor-java-parser.mjs');
const FINAL = path.join(SCANNER, 'vendor', 'java-parser');
const run = () => spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
const ident = () => ['entry.mjs', 'node_modules', path.join('node_modules', 'java-parser')].map((p) => { const s = fs.statSync(path.join(FINAL, p)); return `${s.ino}:${s.mtimeMs}`; });

test('a current vendored copy is left untouched (same inodes and times), and the run says so', () => {
  assert.equal(run().status, 0);                      // make sure a copy exists and is current
  const before = ident();
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /already current/);
  assert.deepEqual(ident(), before, 'nothing under vendor/java-parser was rewritten');
});

test('a stale copy is rebuilt and left complete, with no staging directory behind', () => {
  fs.appendFileSync(path.join(FINAL, 'entry.mjs'), '// stale\n');
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /vendored java-parser/);
  assert.ok(fs.existsSync(path.join(FINAL, 'node_modules', 'java-parser', 'package.json')));
  assert.doesNotMatch(fs.readFileSync(path.join(FINAL, 'entry.mjs'), 'utf8'), /stale/);
  // Only this child's own directories are checked: other test processes (npm pack, npm ci) run the same script at the same time and
  // may legitimately have a staging directory of their own for an instant.
  const own = fs.readdirSync(path.join(SCANNER, 'vendor')).filter((n) => n === `.java-parser-stage-${r.pid}` || n === `.java-parser-old-${r.pid}`);
  assert.deepEqual(own, [], 'the run left no staging or old directory behind');
});
