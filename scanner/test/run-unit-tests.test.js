// scripts/run-unit-tests.mjs is what `npm test` now runs instead of chaining
// eleven `npm run test:<scope>` invocations (258s sequential -> ~115s in one
// `node --test` call over the union of files — see that file's header for
// why). This pins the derivation logic itself: the file list must track
// package.json, not drift from it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  SCOPES, extractFiles, unionFiles, assertAllTestFilesCovered,
  parseShard, assignShard, extraStepsForShard, resolveShard, EXTRA_STEPS, makeRunTemp, writeThenExit,  testConcurrencyFor,
} from '../../scripts/run-unit-tests.mjs';

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
  // The extras moved into `test:extras`, which run-unit-tests.mjs runs after the main list
  // (in shard 1 only when sharded), so `npm test` still reaches every one of them.
  assert.match(pkg.scripts['test:extras'], /cpp-dataflow\.test\.js/, 'cpp-dataflow.test.js must still run in test:extras');
  assert.match(pkg.scripts['test:extras'], /test:python\b/, 'test:python must still run in test:extras');
  assert.match(pkg.scripts.test, /run-unit-tests\.mjs/, '`npm test` must invoke the combined runner');
  assert.deepEqual(EXTRA_STEPS.map((e) => e.script), ['test:extras'], 'the runner must run test:extras after the main list');
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

// ------------------------------------------------------------------ sharding
test('parseShard accepts i/N and rejects everything else', () => {
  assert.deepEqual(parseShard('2/4'), { index: 2, total: 4 });
  for (const bad of ['', '0/4', '5/4', '1/0', 'a/b', '1-4', '1/4/2', '-1/4', '1.5/4', undefined]) {
    assert.throws(() => parseShard(bad), /invalid shard/, `must reject ${JSON.stringify(bad)}`);
  }
});

test('resolveShard: flag wins over the variable, neither means unsharded', () => {
  assert.equal(resolveShard([], {}), null);
  assert.deepEqual(resolveShard([], { AGENTIC_SECURITY_TEST_SHARD: '3/4' }), { index: 3, total: 4 });
  assert.deepEqual(resolveShard(['--shard', '1/2'], { AGENTIC_SECURITY_TEST_SHARD: '3/4' }), { index: 1, total: 2 });
  assert.throws(() => resolveShard(['--shard'], {}), /needs a value/);
});

for (const total of [1, 2, 3, 4, 5, 8]) {
  test(`across shards 1..${total} every test file runs exactly once and the extra steps run once`, () => {
    const files = unionFiles(readPkg());
    const seen = new Map();
    let extraRuns = 0;
    for (let index = 1; index <= total; index++) {
      const shard = { index, total };
      for (const f of assignShard(files, shard)) seen.set(f, (seen.get(f) || 0) + 1);
      extraRuns += extraStepsForShard(shard).length;
    }
    assert.deepEqual([...seen.keys()].sort(), [...files].sort(), 'no file may be skipped');
    for (const [f, n] of seen) assert.equal(n, 1, `${f} ran ${n} times`);
    assert.equal(extraRuns, EXTRA_STEPS.length, 'the extra steps must run in exactly one shard');
    assert.equal(extraStepsForShard(null).length, EXTRA_STEPS.length, 'unsharded runs the extras');
    assert.equal(extraStepsForShard({ index: 1, total }).length, EXTRA_STEPS.length, 'shard 1 owns the extras');
  });
}

test('every shard of 4 is non-empty and within one file of balanced', () => {
  const files = unionFiles(readPkg());
  const sizes = [1, 2, 3, 4].map((index) => assignShard(files, { index, total: 4 }).length);
  assert.ok(sizes.every((n) => n > 0));
  assert.ok(Math.max(...sizes) - Math.min(...sizes) <= 1, `sizes ${sizes}`);
});

test('writeThenExit exits only after the write has completed, never straight after write()', () => {
  const events = [];
  let flush;
  const stream = { write: (text, cb) => { events.push(`write ${text.length}`); flush = cb; } };
  writeThenExit('abc', 0, { stream, exit: (c) => events.push(`exit ${c}`) });
  assert.deepEqual(events, ['write 3'], 'no exit while the write is still pending');
  flush();
  assert.deepEqual(events, ['write 3', 'exit 0'], 'exit follows the completed write');
});

test('--list-shard never ends the process with a synchronous exit right after writing (the cause of lost output on a pipe)', () => {
  const src = fs.readFileSync(path.resolve(HERE, '..', '..', 'scripts', 'run-unit-tests.mjs'), 'utf8');
  const branch = src.slice(src.indexOf("const li = argv.indexOf('--list-shard')"), src.indexOf('const shard = resolveShard(argv)'));
  assert.match(branch, /writeThenExit\(/);
  assert.doesNotMatch(branch, /process\.exit\(/, 'a synchronous exit after a pipe write can drop buffered output');
});

test('--list-shard prints the assignment through the real CLI and runs nothing', () => {
  const files = unionFiles(readPkg());
  const script = path.resolve(HERE, '..', '..', 'scripts', 'run-unit-tests.mjs');
  const printed = [];
  let stepLines = 0;
  for (let i = 1; i <= 4; i++) {
    const r = spawnSync(process.execPath, [script, '--list-shard', `${i}/4`], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const line of r.stdout.split('\n').filter(Boolean)) {
      if (line.startsWith('step: ')) stepLines++; else printed.push(line);
    }
  }
  assert.deepEqual(printed.sort(), [...files].sort());
  assert.equal(stepLines, 1, 'the extra step is listed under exactly one shard');
  const bad = spawnSync(process.execPath, [script, '--list-shard', '9/4'], { encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
});

test('the run gets a private temp root: test processes see it as their temp dir, and cleanup removes whatever they left in it', () => {
  const { root, env, cleanup } = makeRunTemp();
  try {
    assert.ok(path.basename(root).startsWith('as-run-'));
    assert.equal(env.TMPDIR, root); assert.equal(env.TEMP, root); assert.equal(env.TMP, root);
    // a child that forgets to clean up after itself, like the tests used to
    const r = spawnSync(process.execPath, ['-e', "const fs=require('fs'),os=require('os'),p=require('path');fs.writeFileSync(p.join(fs.mkdtempSync(p.join(os.tmpdir(),'leak-')),'f'),'x');console.log(os.tmpdir())"], { env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.realpathSync(r.stdout.trim()), fs.realpathSync(root), 'the child resolved os.tmpdir() to the private root');
    assert.equal(fs.readdirSync(root).length, 1, 'the leak landed inside the private root, not the machine temp folder');
  } finally { cleanup(); }
  assert.equal(fs.existsSync(root), false, 'cleanup removed the root and everything in it');
});

test('the local runner uses half the CPUs (at least two), the hosted runner keeps the default, and an explicit value always wins', () => {
  assert.equal(testConcurrencyFor({}, 12), 6);
  assert.equal(testConcurrencyFor({}, 2), 2, 'never below two');
  assert.equal(testConcurrencyFor({}, 1), 2);
  assert.equal(testConcurrencyFor({ GITHUB_ACTIONS: 'true' }, 12), null, 'dedicated hosted runners keep the default');
  assert.equal(testConcurrencyFor({ AGENTIC_SECURITY_TEST_CONCURRENCY: '3' }, 12), 3);
  assert.equal(testConcurrencyFor({ AGENTIC_SECURITY_TEST_CONCURRENCY: '3', GITHUB_ACTIONS: 'true' }, 12), 3, 'the override wins on the hosted runner too');
  assert.equal(testConcurrencyFor({ AGENTIC_SECURITY_TEST_CONCURRENCY: 'abc' }, 12), 6, 'an invalid override is ignored');
  assert.equal(testConcurrencyFor({ AGENTIC_SECURITY_TEST_CONCURRENCY: '0' }, 12), 6, 'zero is not a concurrency');
});
