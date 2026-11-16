// FR-02 / GAP-02 (T-04, T-05): per-test outcomes compared between the original and the patched tree, on real Node test-runner projects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runTestsOnPatchedCopy } from '../../src/fix/test-commands.js';
import { compareTestRuns, parseNodeTestReport, parseJestReport, exitCodeUnit, testSurfaceChanges, adapterFor } from '../../src/fix/test-results.js';

function project(files, script = 'node --test') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tr-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', scripts: { test: script } }));
  for (const [rel, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); }
  return root;
}
const TESTS = "const test = require('node:test'); const assert = require('assert'); const app = require('../app.js');\n" +
  "test('A', () => assert.equal(app.a(), 'a'));\ntest('B', () => assert.equal(app.b(), 'b'));\nif (app.c) test('C', () => assert.equal(app.c(), 'c'));\n";
const APP = (a, b, extra = "exports.c = () => 'c';\n") => `exports.a = () => ${a};\nexports.b = () => ${b};\n${extra}`;

test('AC-02.1 / T-04: original A fails, the patch makes B newly fail: rejected, not excused', async () => {
  const root = project({ 'app.js': APP("'x'", "'b'"), 'test/t.test.js': TESTS });
  try {
    const r = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("'x'", "'y'") } });
    assert.equal(r.adapter, 'node-test');
    assert.equal(r.status, 'failed');
    assert.equal(r.preExistingFailure, false);
    assert.deepEqual(r.testDelta.newlyFailing.map((x) => x.id), ['test/t.test.js::B']);
    assert.deepEqual(r.testDelta.preExisting.map((x) => x.id), ['test/t.test.js::A']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('AC-02.2: the same test fails before and after for a different reason: a failure, never pre-existing', async () => {
  const root = project({ 'app.js': APP("'x'", "'b'"), 'test/t.test.js': TESTS });
  try {
    const r = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("(() => { throw new TypeError('boom'); })()", "'b'") } });
    assert.equal(r.status, 'failed');
    assert.deepEqual(r.testDelta.changedFailure.map((x) => x.id), ['test/t.test.js::A']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('AC-02.3 / T-05: a test the patch makes disappear, or a test file it edits, blocks the result', async () => {
  const root = project({ 'app.js': APP("'a'", "'b'"), 'test/t.test.js': TESTS });
  try {
    const removed = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("'a'", "'b'", '') } });
    assert.equal(removed.status, 'failed');
    assert.deepEqual(removed.testDelta.removed.map((x) => x.id), ['test/t.test.js::C']);
    const edited = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'test/t.test.js': TESTS.replace("test('B'", "test.skip('B'") } });
    assert.equal(edited.status, 'failed');
    assert.match(edited.reason, /protected-test-surface.*modifies an existing test file/);
    const script = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'package.json': JSON.stringify({ name: 'p', version: '1.0.0', scripts: { test: 'true' } }) } });
    assert.equal(script.status, 'failed');
    assert.match(script.reason, /changes the test script/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('AC-02.4 / AC-02.6: an unchanged, unrelated baseline failure is recorded and does not refuse a good patch', async () => {
  const root = project({ 'app.js': APP("'x'", "'bb'"), 'test/t.test.js': TESTS });
  try {
    const r = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("'x'", "'b'") } });
    assert.equal(r.status, 'passed');
    assert.equal(r.passed, true);
    assert.deepEqual(r.testDelta.preExisting.map((x) => x.id), ['test/t.test.js::A']);
    assert.deepEqual(r.testDelta.fixed.map((x) => x.id), ['test/t.test.js::B']);
    assert.match(r.reason, /1 unchanged pre-existing failure/);
    // the same failure is NOT excused when the test is required
    const req = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("'x'", "'b'") }, required: ['test/t.test.js::A'] });
    assert.equal(req.status, 'skipped');
    assert.match(req.reason, /required test\(s\) already fail/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('AC-02.5: zero discovered tests, a missing runner, a timeout and a malformed report stay explicit', async () => {
  const empty = project({ 'app.js': APP("'a'", "'b'") }, 'node --test test/');
  try {
    fs.mkdirSync(path.join(empty, 'test'));
    const r = await runTestsOnPatchedCopy({ scanRoot: empty, files: { 'app.js': APP("'a'", "'c'") } });
    assert.notEqual(r.status, 'passed');
  } finally { fs.rmSync(empty, { recursive: true, force: true }); }
  const root = project({ 'app.js': APP("'a'", "'b'"), 'test/t.test.js': TESTS });
  try {
    const missing = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': APP("'a'", "'b'") }, command: ['definitely-not-a-runner-xyz'] });
    assert.equal(missing.status, 'skipped'); assert.match(missing.reason, /not-installed/);
    const hang = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': 'while (true) {}\n' }, timeoutMs: 1500 });
    assert.notEqual(hang.status, 'passed');
    assert.equal(hang.timedOut, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
  const bad = parseNodeTestReport('{"k":"test","type":"test:pass","path":["x"]}\nnot json\n');
  assert.equal(bad.complete, false); assert.equal(bad.malformed, 1);
  const d = compareTestRuns(bad, bad);
  assert.equal(d.verdict, 'inconclusive');
});

test('GAP-02 on an exit-code-only suite: a different failure after the patch is a failure, an identical one is the only "already failing"', async () => {
  const root = project({ 'app.js': "module.exports = 1;\n", 'test.js': "const v = require('./app'); if (v !== 2) { console.error('value is ' + v); process.exit(1); }\n" }, 'node test.js');
  try {
    const diff = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': "throw new Error('the module no longer loads');\n" } });
    assert.equal(diff.adapter, 'exit-code');
    assert.equal(diff.status, 'failed');
    assert.equal(diff.preExistingFailure, false, 'a different failure is never excused as already failing');
    const same = await runTestsOnPatchedCopy({ scanRoot: root, files: { 'app.js': "module.exports = 1; // comment\n" } });
    assert.equal(same.preExistingFailure, true);
    assert.equal(same.attribution, 'suite-only');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('signatures ignore paths, durations and positions; outcomes compare by identity', async () => {
  const a = exitCodeUnit({ exitCode: 1, output: 'Error at /tmp/x-1/app.js:3:9 after 12ms', roots: [] });
  const b = exitCodeUnit({ exitCode: 1, output: 'Error at /tmp/x-2/app.js:4:1 after 40ms', roots: [] });
  assert.equal(a.tests[0].signature, b.tests[0].signature);
});

test('AC-02.7: adapter selection and the jest/vitest report parser (parser-level only, stated)', async () => {
  assert.equal(adapterFor({ cmd: 'npm', args: ['test'], kind: 'npm' }, 'node --test'), 'node-test');
  assert.equal(adapterFor({ cmd: 'npm', args: ['test'], kind: 'npm' }, 'jest --ci'), 'jest');
  assert.equal(adapterFor({ cmd: 'npm', args: ['test'], kind: 'npm' }, 'vitest run'), 'vitest');
  assert.equal(adapterFor({ cmd: 'npm', args: ['test'], kind: 'npm' }, 'node test.js'), 'exit-code');
  assert.equal(adapterFor({ cmd: 'npm', args: ['test'], kind: 'npm' }, 'jest && eslint .'), 'exit-code', 'a compound script cannot take appended reporter arguments');
  const rep = parseJestReport({ numTotalTests: 2, testResults: [{ name: '/r/a.test.js', status: 'failed', assertionResults: [{ ancestorTitles: ['g'], title: 'x', status: 'passed' }, { ancestorTitles: [], title: 'y', status: 'failed', failureMessages: ['Expected 1'] }] }] }, { root: '/r' });
  assert.deepEqual(rep.tests.map((t) => [t.id, t.outcome]), [['a.test.js::g > x', 'passed'], ['a.test.js::y', 'failed']]);
});

test('a new test file is allowed but recorded as not independent; a runner config change is blocked', async () => {
  const s = testSurfaceChanges({ 'test/new.test.js': 'x', 'jest.config.js': 'module.exports={}', 'src/app.js': 'y' }, (rel) => (rel === 'jest.config.js' ? 'module.exports={a:1}' : null));
  assert.deepEqual(s.addedTests, ['test/new.test.js']);
  assert.deepEqual(s.blocked.map((b) => b.file), ['jest.config.js']);
});
