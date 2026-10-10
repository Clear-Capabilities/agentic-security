// REL-001: three properties of the closure runner that its first real run exposed. A step's process tree cannot outlive the step; the
// bench runners' own history files are not "a dirty tree" (and nothing else is excused); a step that needs libraries is unsupported where
// they are absent, not failed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, ALL_PRESENT, fakeExec } from '../helpers/closure-fixtures.js';
import { runClosure, defaultExec, gitFacts, GENERATED_OUTPUTS, applicability, CLOSURE_STEPS, CLOSURE_SCHEMA, planDigest, evaluateClosureRecord } from '../../../scripts/release-closure.mjs';

const porcelainExec = (porcelain) => (cmd, args) => {
  const a = args.join(' ');
  const out = a.startsWith('rev-parse HEAD^') ? 'tree0\n' : a.startsWith('rev-parse HEAD') ? 'commit0\n' : a.startsWith('status') ? porcelain : '';
  return { status: 0, signal: null, timedOut: false, error: null, stdout: Buffer.from(out), stderr: Buffer.alloc(0) };
};

test('[REL-001.AC02] the bench runners\' own history files are disclosed but are not a dirty tree', () => {
  const f = gitFacts('/repo', porcelainExec(' M bench/memory/history.jsonl\n M bench/ttff/history.jsonl\n M bench/provenance/history.jsonl\n'));
  assert.deepEqual(f.dirtyPaths, []);
  assert.deepEqual([...f.ignoredGeneratedOutputs].sort(), [...GENERATED_OUTPUTS].sort());
});

test('[REL-001.AC02] nothing else is excused: a source edit, an untracked file, a deleted or replaced history file all still make the tree dirty', () => {
  const f = gitFacts('/repo', porcelainExec(' M bench/memory/history.jsonl\n M scanner/src/engine.js\n?? bench/ttff/history.jsonl\n D bench/provenance/history.jsonl\n?? notes.txt\n'));
  assert.deepEqual(f.dirtyPaths.sort(), ['bench/provenance/history.jsonl', 'bench/ttff/history.jsonl', 'notes.txt', 'scanner/src/engine.js']);
  assert.deepEqual(f.ignoredGeneratedOutputs, ['bench/memory/history.jsonl']);
});

test('[REL-001.AC02] a record that was dirty only through those history files still judges clean, and one dirty through a source file does not', () => {
  const rec = { schema: CLOSURE_SCHEMA, commit: 'c', tree: 't', treeClean: true, dirtyPaths: [], stable: true, planDigest: planDigest([]), partial: false, steps: [] };
  const clean = evaluateClosureRecord(rec, { commit: 'c', tree: 't', dirtyPaths: [] }, { steps: [], readLog: () => null });
  assert.ok(!clean.reasons.some((r) => /dirty/.test(r)), JSON.stringify(clean.reasons));
  const dirty = evaluateClosureRecord(rec, { commit: 'c', tree: 't', dirtyPaths: ['scanner/src/engine.js'] }, { steps: [], readLog: () => null });
  assert.ok(dirty.reasons.some((r) => /dirty/.test(r)));
});

test('[REL-001.AC02] a step that times out leaves no process behind, including its descendants', { timeout: 120000 }, () => {
  // A unique duration names exactly this test's processes, so other tests running at the same time cannot be mistaken for leftovers.
  const dur = `300.${process.pid}${Date.now() % 1000}`;
  const r = defaultExec('/bin/sh', ['-c', `sleep ${dur} & sleep ${dur}`], { cwd: process.cwd(), timeoutMs: 1500, env: process.env });
  assert.equal(r.timedOut, true);
  assert.equal(r.status, null);
  const left = spawnSync('ps', ['-eo', 'command'], { encoding: 'utf8' }).stdout.split('\n').filter((l) => l.includes(`sleep ${dur}`));
  assert.deepEqual(left, [], 'a descendant of the timed-out step is still running');
});

test('[REL-001.AC02] output and the exit status of a step that finishes normally are passed through', () => {
  const ok = defaultExec(process.execPath, ['-e', 'console.log("out-line"); console.error("err-line")'], { cwd: process.cwd(), timeoutMs: 20000, env: process.env });
  assert.equal(ok.status, 0); assert.equal(ok.timedOut, false);
  assert.match(ok.stdout.toString(), /out-line/); assert.match(ok.stderr.toString(), /err-line/);
  const bad = defaultExec(process.execPath, ['-e', 'process.exit(3)'], { cwd: process.cwd(), timeoutMs: 20000, env: process.env });
  assert.equal(bad.status, 3); assert.equal(bad.timedOut, false);
  const missing = defaultExec('/no/such/command', [], { cwd: process.cwd(), timeoutMs: 20000, env: process.env });
  assert.notEqual(missing.status, 0);
});

test('[REL-001.AC03] the Haskell toolchain step is unsupported where the fixture libraries cannot be imported, and runs where they can', () => {
  const step = CLOSURE_STEPS.find((s) => s.id === 'remote-haskell-toolchain');
  assert.ok(step.needs.haskellModules.length >= 4);
  const env = (can) => ({ platform: 'darwin', hasTool: () => true, exists: () => true, canImportHaskell: can });
  const without = applicability(step, env(() => false));
  assert.equal(without.applicable, false);
  assert.match(without.reason, /Haskell module 'Web\.Scotty'/);
  assert.equal(applicability(step, env((m) => m !== 'Servant')).applicable, false, 'one missing library is enough');
  assert.deepEqual(applicability(step, env(() => true)), { applicable: true });
  assert.equal(applicability(step, { platform: 'darwin', hasTool: () => true, exists: () => true }).applicable, false, 'an environment that cannot probe is treated as lacking the module');
});

test('[REL-001.AC02] a step that times out writes the process table of its group into its log before it is killed, so an unreproducible hang leaves evidence', { timeout: 60000 }, () => {
  const dur = `301.${process.pid}${Date.now() % 1000}`;
  const r = defaultExec('/bin/sh', ['-c', `sleep ${dur}`], { cwd: process.cwd(), timeoutMs: 2500, env: process.env });
  assert.equal(r.timedOut, true);
  const err = r.stderr.toString();
  assert.match(err, /the step timed out; processes in its group/);
  assert.ok(err.includes(`sleep ${dur}`), 'the table names the stuck command');
  const gone = spawnSync('ps', ['-eo', 'command'], { encoding: 'utf8' }).stdout.split('\n').filter((l) => l.includes(`sleep ${dur}`));
  assert.deepEqual(gone, [], 'and the group is still killed afterwards');
});

test('[REL-001.AC02] a failing or incomplete step prints the tail of its own log, so a hosted failure is readable without the runner\'s files', () => {
  const lines = [];
  runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-tail-'), env: ALL_PRESENT, exec: fakeExec({ fail: ['smoke'], skipped: ['verification'] }), log: (l) => lines.push(l) });
  const text = lines.join('');
  assert.match(text, /--- smoke: /);
  assert.match(text, /--- verification: /);
  assert.ok(!/--- foundation: /.test(text), 'a passing step prints no tail');
});
