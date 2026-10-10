// The protected suite wrappers (PRD 11.1 step 4): every registered suite is runnable by the controller, and a
// wrapper reports the real child results under their own names without ever upgrading a failure, a skip or an
// empty run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG } from '../helpers/closure-fixtures.js';
import { FOUNDATION_FILES } from '../../../scripts/release-closure.mjs';
import { parseTap } from '../../../scripts/loop-engineering/lib/tap.mjs';
import { suiteLaunchBlockers, loadProfile } from '../../../scripts/loop-engineering/lib/profile.mjs';
import { protectedFiles } from '../../../scripts/loop-engineering/lib/drift.mjs';

const WRAP = path.join(REPO, 'scripts', 'assurance-differentiation', 'test');
const RELAY = path.join(WRAP, 'relay.mjs');
const SCANNER = path.join(REPO, 'scanner');
const PROFILE = path.join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json');
// This file itself runs inside a test context; a nested `node --test` must start clean, as the controller's does.
const cleanEnv = () => { const e = { ...process.env }; delete e.NODE_TEST_CONTEXT; return e; };
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

const EXPECTED_SCOPE = {
  evaluation: 'evaluation', verification: 'verification', 'deployment-graph': 'deployment', invariants: 'invariants',
  capabilities: 'capabilities', routing: 'routing', portfolio: 'portfolio', documentation: 'documentation', release: 'release-closure',
};

/** Run relaySuite over `childSources` (name -> file text) in a subprocess exactly as the controller would run a wrapper. */
function relay(childSources, { expectHelper } = {}) {
  const dir = mkTestTmp('relay-');
  const files = Object.entries(childSources).map(([name, text]) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, text);
    return path.relative(SCANNER, f);
  });
  const harness = path.join(dir, 'wrapper.test.js');
  fs.writeFileSync(harness, `import { relaySuite, helperSha256 } from ${JSON.stringify(pathToFileURL(RELAY).href)};
await relaySuite({ suite: 'fixture', files: ${JSON.stringify(files)}, expectHelper: ${expectHelper ? JSON.stringify(expectHelper) : 'helperSha256()'} });
`);
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', harness], { cwd: dir, encoding: 'utf8', env: cleanEnv() });
  return { code: r.status, tap: parseTap(r.stdout), stdout: r.stdout };
}
const T = (body) => `import test from 'node:test';\nimport assert from 'node:assert/strict';\n${body}\n`;
const byName = (tap, re) => tap.tests.find((t) => re.test(t.name));

test('[wrappers] every registered suite other than loop is runnable: wrapper present, not declared blocked, no launch blockers', () => {
  const { profile } = loadProfile(PROFILE);
  assert.deepEqual(suiteLaunchBlockers(profile, REPO), []);
  for (const [name, s] of Object.entries(profile.suites)) {
    assert.equal(s.notYetRunnable, undefined, `${name} is not declared blocked`);
    for (const f of s.files) assert.ok(fs.existsSync(path.join(REPO, f)), `${name}: ${f} exists`);
  }
  assert.equal(Object.keys(profile.suites).length, 11);
  const frozen = protectedFiles(profile);
  for (const k of Object.keys(EXPECTED_SCOPE)) assert.ok(frozen.includes(`scripts/assurance-differentiation/test/${k}.test.js`), `${k} wrapper is frozen at init`);
});

test('[wrappers] each wrapper pins the current helper digest and names the scoped script its suite is defined by', () => {
  const helper = sha(RELAY);
  for (const [suite, scope] of Object.entries(EXPECTED_SCOPE)) {
    const text = fs.readFileSync(path.join(WRAP, `${suite}.test.js`), 'utf8');
    assert.ok(text.includes(`expectHelper: '${helper}'`), `${suite}: pinned helper digest is current`);
    assert.ok(text.includes(`suite: '${suite}'`));
    assert.ok(text.includes(`scope: '${scope}'`), `${suite}: runs test:${scope}`);
    const script = PKG.scripts[`test:${scope}`];
    assert.ok(typeof script === 'string' && /node --test/.test(script), `test:${scope} exists`);
    const files = script.match(/test\/[\w.\-/]+\.test\.js/g);
    assert.ok(files.length >= 5, `${suite}: the scope names real files`);
    for (const f of files) assert.ok(fs.existsSync(path.join(SCANNER, f)), `${suite}: scanner/${f}`);
  }
  const found = fs.readFileSync(path.join(WRAP, 'foundation.test.js'), 'utf8');
  assert.deepEqual(JSON.parse(/files: (\[.*\]),/.exec(found)[1]), FOUNDATION_FILES, 'foundation runs the same files the closure plan names');
  for (const f of FOUNDATION_FILES) assert.ok(fs.existsSync(path.join(SCANNER, f)));
});

test('[wrappers] a passing child is re-emitted under its own names with an exit-0 witness', () => {
  const r = relay({ 'a.test.js': T("test('[X-1.AC01] works', () => assert.equal(1, 1));\ntest('[X-1.AC02] also works', () => {});") });
  assert.equal(r.code, 0, r.stdout);
  assert.equal(byName(r.tap, /\[X-1\.AC01\] works/).ok, true);
  assert.equal(byName(r.tap, /\[X-1\.AC02\] also works/).ok, true);
  assert.equal(byName(r.tap, /the child run exited 0, ran tests/).ok, true);
  assert.match(r.stdout, /child run: 1 file\(s\), exit 0, signal null, 2 test line\(s\), output sha256 [0-9a-f]{64}/);
});

test('[wrappers] a failing child test fails under its own name and fails the run', () => {
  const r = relay({ 'a.test.js': T("test('[X-1.AC01] passes', () => {});\ntest('[X-1.AC03] breaks', () => assert.equal(1, 2));") });
  assert.notEqual(r.code, 0);
  assert.equal(byName(r.tap, /\[X-1\.AC01\] passes/).ok, true);
  assert.equal(byName(r.tap, /\[X-1\.AC03\] breaks/).ok, false);
  assert.equal(byName(r.tap, /the child run exited 0/).ok, false, 'the untagged witness fails too, so a lost child line cannot hide it');
});

test('[wrappers] a skipped or todo child test stays skipped or todo, so the controller counts it as a failed criterion', () => {
  const r = relay({ 'a.test.js': T("test('[X-1.AC01] real', () => {});\ntest('[X-1.AC02] skipped', { skip: 'no backend' }, () => {});\ntest('[X-1.AC03] todo', { todo: true }, () => {});") });
  assert.equal(byName(r.tap, /\[X-1\.AC02\] skipped/).skip, true);
  assert.equal(byName(r.tap, /\[X-1\.AC03\] todo/).todo, true);
  assert.equal(byName(r.tap, /\[X-1\.AC01\] real/).ok, true);
});

test('[wrappers] a child that runs no tests, or a missing file, fails instead of selecting nothing', () => {
  const empty = relay({ 'a.test.js': T('// no tests here') });
  assert.notEqual(empty.code, 0);
  assert.equal(byName(empty.tap, /the child run exited 0, ran tests/).ok, false);
  // one good file does not excuse a file beside it that registered nothing
  const mixed = relay({ 'good.test.js': T("test('[X-1.AC01] real', () => {});"), 'empty.test.js': T('// no tests here') });
  assert.notEqual(mixed.code, 0);
  assert.equal(byName(mixed.tap, /\[X-1\.AC01\] real/).ok, true);
  assert.equal(byName(mixed.tap, /empty\.test\.js registered at least one test/).ok, false);
  const missingDir = mkTestTmp('relay-missing-');
  const harness = path.join(missingDir, 'wrapper.test.js');
  fs.writeFileSync(harness, `import { relaySuite, helperSha256 } from ${JSON.stringify(pathToFileURL(RELAY).href)};\nawait relaySuite({ suite: 'fixture', files: ['test/does-not-exist.test.js'], expectHelper: helperSha256() });\n`);
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', harness], { cwd: missingDir, encoding: 'utf8', env: cleanEnv() });
  assert.notEqual(r.status, 0);
  assert.equal(byName(parseTap(r.stdout), /names at least one real test file/).ok, false);
  const noScope = spawnSync(process.execPath, ['--test', '--test-reporter=tap', harness.replace('wrapper', 'w2')], { cwd: missingDir, encoding: 'utf8', env: cleanEnv() });
  assert.notEqual(noScope.status, 0, 'a harness that does not exist cannot pass either');
});

test('[wrappers] a helper that changed after the wrapper was frozen makes the wrapper fail and run nothing', () => {
  const r = relay({ 'a.test.js': T("test('[X-1.AC01] would pass', () => {});") }, { expectHelper: '0'.repeat(64) });
  assert.notEqual(r.code, 0);
  assert.equal(byName(r.tap, /\[X-1\.AC01\]/), undefined, 'the child never ran');
  assert.ok(byName(r.tap, /helper matches the digest this wrapper was frozen against/));
  assert.equal(byName(r.tap, /helper matches/).ok, false);
});

test('[wrappers] the child is not run inside the wrapper\'s own test context, so it really runs its tests', () => {
  // the runner sets NODE_TEST_CONTEXT inside the wrapper process, exactly as it does when the controller runs one
  const r = relay({ 'a.test.js': T("test('[X-1.AC01] ran', () => {});") });
  assert.equal(r.code, 0);
  assert.ok(byName(r.tap, /\[X-1\.AC01\] ran/), 'a child that inherited the context would report zero tests');
});
