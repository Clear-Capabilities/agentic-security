// Background gate warm-up and pre-commit preparation: the decisions in isolation, and the real scripts against a throwaway repository with a
// stub gate. Nothing here runs the real pre-push gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decide, parseFailed, cleanEnv, skipReason, start, readStatus, describe as describeWarm, EXIT } from '../../scripts/gate-warm.mjs';
import { plan } from '../../scripts/pre-commit-prepare.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const GIT = (dir, ...args) => spawnSync('git', args, { cwd: dir, encoding: 'utf8' });

function tmpRepo(stubGate) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-warm-'));
  GIT(dir, 'init', '-q');
  GIT(dir, 'config', 'user.email', 't@example.com'); GIT(dir, 'config', 'user.name', 't'); GIT(dir, 'config', 'commit.gpgsign', 'false');
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  fs.copyFileSync(path.join(REPO, 'scripts', 'gate-warm.mjs'), path.join(dir, 'scripts', 'gate-warm.mjs'));
  fs.writeFileSync(path.join(dir, 'scripts', 'pre-push-gate.mjs'), stubGate);
  fs.writeFileSync(path.join(dir, '.gitignore'), '.agentic-security/\n');
  fs.writeFileSync(path.join(dir, 'a.txt'), '1\n');
  GIT(dir, 'add', '-A'); GIT(dir, 'commit', '-q', '-m', 'one');
  return dir;
}
const PASS_GATE = "console.error('PASS  Everything'); process.exit(0);\n";
const FAIL_GATE = "console.error('PASS  Bundle\\nFAIL  Full test suite passes\\nFAIL  Self-scan precision baseline holds\\nSKIP  rest'); process.exit(1);\n";
// a child node started from inside `node --test` inherits NODE_TEST_CONTEXT and would report as a subtest, hiding its output
const childEnv = () => { const e = { ...process.env, AGENTIC_SECURITY_NO_GATE_WARM: '', CI: '', GITHUB_ACTIONS: '' }; delete e.NODE_TEST_CONTEXT; return e; };
const run = (dir, ...args) => spawnSync(process.execPath, [path.join(dir, 'scripts', 'gate-warm.mjs'), ...args], { cwd: dir, encoding: 'utf8', env: childEnv() });

// ── decisions ──────────────────────────────────────────────────────────────────────────────────────────────

test('decide: passed and failed count only for the exact commit and tree; a dead run is not "running"', () => {
  const base = { commit: 'c1', tree: 't1' };
  assert.equal(decide({ status: { ...base, state: 'passed' }, ...base }).state, 'passed');
  assert.deepEqual(decide({ status: { ...base, state: 'failed', failed: ['x'] }, ...base }).failed, ['x']);
  assert.equal(decide({ status: { ...base, state: 'passed' }, commit: 'c2', tree: 't1' }).state, 'none', 'an amended or new commit is not covered');
  assert.equal(decide({ status: { ...base, state: 'passed' }, commit: 'c1', tree: 't2' }).state, 'none');
  assert.equal(decide({ status: null, ...base }).state, 'none');
  assert.equal(decide({ status: { ...base, state: 'running', pid: 1 }, ...base, alive: () => true }).state, 'running');
  const dead = decide({ status: { ...base, state: 'running', pid: 1 }, ...base, alive: () => false });
  assert.equal(dead.state, 'none');
  assert.match(dead.why, /stopped without recording/);
  assert.equal(decide({ status: { ...base, state: 'weird' }, ...base }).state, 'none');
});

test('failed checks are read from the gate output, once each; the child environment drops the hook\'s git variables', () => {
  assert.deepEqual(parseFailed('PASS  a\nFAIL  Full test suite passes  (12s)\nFAIL  Full test suite passes  (12s)\nFAIL  Self-scan\nSKIP  b'), ['Full test suite passes  (12s)', 'Self-scan']);
  assert.deepEqual(parseFailed('all good'), []);
  const e = cleanEnv({ GIT_DIR: 'x', GIT_INDEX_FILE: 'y', GIT_WORK_TREE: 'z', KEEP: '1' });
  assert.deepEqual(Object.keys(e), ['KEEP']);
});

test('skip reasons: the opt-out, CI, and a rebase in progress', () => {
  const dir = tmpRepo(PASS_GATE);
  assert.equal(skipReason({ env: {}, repo: dir }), null);
  assert.match(skipReason({ env: { AGENTIC_SECURITY_NO_GATE_WARM: '1' }, repo: dir }), /NO_GATE_WARM/);
  assert.match(skipReason({ env: { CI: 'true' }, repo: dir }), /CI/);
  fs.mkdirSync(path.join(dir, '.git', 'rebase-merge'));
  assert.match(skipReason({ env: {}, repo: dir }), /rebase-merge is in progress/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('describe: says plainly what a push will do in each state', () => {
  const st = { commit: 'abcdef123456', startedAt: 't', log: 'l', seconds: 7 };
  assert.match(describeWarm({ state: 'passed' }, st)[0], /PASSED.*reuse the cached verdicts/);
  assert.match(describeWarm({ state: 'failed', failed: ['x', 'y'] }, st)[0], /FAILED.*x; y/);
  assert.match(describeWarm({ state: 'running' }, st)[0], /RUNNING/);
  assert.match(describeWarm({ state: 'none', why: 'w' }, null)[0], /run the gate in full/);
  assert.deepEqual([EXIT.passed, EXIT.failed, EXIT.running, EXIT.none], [0, 1, 2, 3]);
});

// ── the real script against a throwaway repository with a stub gate ─────────────────────────────────────────────

test('start records a running status for HEAD and does not start a second run for the same commit', () => {
  const dir = tmpRepo(PASS_GATE);
  const spawned = [];
  const fake = (cmd, args, opts) => { spawned.push({ cmd, args, detached: opts.detached }); return { pid: process.pid, unref() {} }; };
  const r = start({ repo: dir, env: {}, spawnFn: fake });
  assert.equal(r.started, true);
  assert.equal(spawned.length, 1); assert.equal(spawned[0].detached, true, 'detached: the commit never waits for it');
  assert.equal(readStatus(dir).state, 'running');
  const again = start({ repo: dir, env: {}, spawnFn: fake });
  assert.equal(again.started, false); assert.match(again.reason, /already running/);
  assert.equal(spawned.length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('end to end: a passing gate is recorded as passed for HEAD (exit 0) and a new commit makes it "nothing usable" (exit 3)', () => {
  const dir = tmpRepo(PASS_GATE);
  assert.equal(run(dir, '--start', '--quiet').status, 0);
  const waited = run(dir, '--wait', '--json');
  assert.equal(waited.status, 0, waited.stdout + waited.stderr);
  assert.equal(JSON.parse(waited.stdout.trim().split('\n').pop()).state, 'passed');
  assert.equal(run(dir, '--status').status, 0);
  fs.writeFileSync(path.join(dir, 'a.txt'), '2\n'); GIT(dir, 'commit', '-qam', 'two');
  const s = run(dir, '--status', '--json');
  assert.equal(s.status, 3);
  assert.equal(JSON.parse(s.stdout.trim()).state, 'none');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('end to end: a failing gate is recorded as failed with the check names (exit 1), and nothing is marked green', () => {
  const dir = tmpRepo(FAIL_GATE);
  run(dir, '--start', '--quiet');
  const waited = run(dir, '--wait', '--json');
  assert.equal(waited.status, 1, waited.stdout + waited.stderr);
  const d = JSON.parse(waited.stdout.trim().split('\n').pop());
  assert.equal(d.state, 'failed');
  assert.deepEqual(d.failed, ['Full test suite passes', 'Self-scan precision baseline holds']);
  assert.match(run(dir, '--status').stdout, /FAILED.*Full test suite passes/);
  assert.ok(fs.readFileSync(path.join(dir, '.agentic-security', 'gate-warm', 'gate.log'), 'utf8').includes('FAIL  Full test suite passes'), 'the log keeps the gate output');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a run that dies without recording a result is "nothing usable", never a pass', () => {
  const dir = tmpRepo(PASS_GATE);
  const commit = GIT(dir, 'rev-parse', 'HEAD').stdout.trim(); const tree = GIT(dir, 'rev-parse', 'HEAD^{tree}').stdout.trim();
  fs.mkdirSync(path.join(dir, '.agentic-security', 'gate-warm'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'gate-warm', 'status.json'), JSON.stringify({ state: 'running', commit, tree, pid: 2147483646 }));
  const s = run(dir, '--status', '--json');
  assert.equal(s.status, 3);
  assert.match(JSON.parse(s.stdout.trim()).why, /stopped without recording/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── pre-commit preparation ────────────────────────────────────────────────────────────────────────────────────

test('pre-commit plan: a build input rebuilds, a docs page regenerates tables, unrelated files do nothing', () => {
  assert.deepEqual(plan({ staged: ['scanner/src/engine.js'], unstaged: [] }), { build: true, docs: false, blockers: [] });
  assert.equal(plan({ staged: ['scanner/package.json'], unstaged: [] }).build, true, 'the bundle embeds package.json');
  assert.equal(plan({ staged: ['frontend/app.js'], unstaged: [] }).build, true);
  assert.deepEqual(plan({ staged: ['docs/guides/x.md'], unstaged: [] }), { build: false, docs: true, blockers: [] });
  assert.equal(plan({ staged: ['docs/capabilities.yaml'], unstaged: [] }).docs, true);
  assert.deepEqual(plan({ staged: ['scanner/test/a.test.js', 'scripts/x.mjs', 'CHANGELOG.md'], unstaged: [] }), { build: false, docs: false, blockers: [] });
});

test('pre-commit plan: a partial commit of build inputs is refused instead of building content the commit does not hold', () => {
  const p = plan({ staged: ['scanner/src/a.js'], unstaged: ['scanner/src/b.js'] });
  assert.equal(p.blockers.length, 1);
  assert.match(p.blockers[0], /unstaged changes \(scanner\/src\/b\.js\)/);
  assert.deepEqual(plan({ staged: ['docs/a.md'], unstaged: ['scanner/src/b.js'] }).blockers, [], 'unstaged source does not matter when no build input is staged');
});

test('pre-commit hook shim and post-commit hook shim exist, are executable and never fail a commit', () => {
  for (const [name, mustContain] of [['pre-commit', 'pre-commit-prepare.mjs'], ['post-commit', 'gate-warm.mjs']]) {
    const f = path.join(REPO, '.githooks', name);
    const text = fs.readFileSync(f, 'utf8');
    assert.ok(text.startsWith('#!/bin/sh'));
    assert.ok(text.includes(mustContain));
    assert.ok((fs.statSync(f).mode & 0o111) !== 0, `${name} is executable`);
  }
  assert.match(fs.readFileSync(path.join(REPO, '.githooks', 'post-commit'), 'utf8'), /\|\| true\nexit 0/, 'a failing warm-up can never fail a commit');
});
