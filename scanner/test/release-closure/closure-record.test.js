// REL-001.AC02: authoritative verification records bind suite versions and logs to the commit; dirty or
// unrecorded inputs invalidate publishable release evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  CLOSURE_STEPS, runClosure, evaluateClosureRecord, suiteVersionOf, readLogFor, planDigest, gitFacts,
} from '../../../scripts/release-closure.mjs';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG, COMMIT, TREE, ALL_PRESENT, fakeExec } from '../helpers/closure-fixtures.js';

const CLEAN = { commit: COMMIT, tree: TREE, dirtyPaths: [] };

function made(opts = {}) {
  const outDir = mkTestTmp('closure-rec-');
  const { record, base } = runClosure({ repoRoot: REPO, outDir, env: ALL_PRESENT, exec: fakeExec(opts) });
  return { record: JSON.parse(JSON.stringify(record)), base, outDir };
}
const judge = (record, current = CLEAN, extra = {}) => evaluateClosureRecord(record, current, { pkg: PKG, ...extra });

test('[REL-001.AC02] a record binds the commit, the tree, each suite version and each log, and verifies against that commit', () => {
  const { record, base } = made();
  assert.equal(record.commit, COMMIT);
  assert.equal(record.tree, TREE);
  assert.equal(record.treeClean, true);
  assert.equal(record.planDigest, planDigest());
  for (const s of record.steps) {
    const step = CLOSURE_STEPS.find((x) => x.id === s.id);
    assert.equal(s.suiteVersion, suiteVersionOf(step, { pkg: PKG, repoRoot: REPO }), `${s.id}: suite version recomputes`);
    assert.ok(fs.existsSync(path.join(base, s.log.path)), `${s.id}: log retained`);
  }
  const v = judge(record, CLEAN, { readLog: readLogFor(base) });
  assert.deepEqual(v.reasons, []);
  assert.equal(v.localOk, true);
  assert.ok(fs.existsSync(path.join(base, `${COMMIT.slice(0, 12)}.json`)), 'the record file is written next to its logs');
});

test('[REL-001.AC02] a different commit or tree invalidates the record', () => {
  const { record } = made();
  assert.match(judge(record, { ...CLEAN, commit: 'c'.repeat(40) }).reasons.join('\n'), /bound to commit aaaaaaaaaaaa, not the current cccccccccccc/);
  assert.match(judge(record, { ...CLEAN, tree: 'd'.repeat(40) }).reasons.join('\n'), /different tree/);
  assert.match(judge(record, { commit: null, tree: null, dirtyPaths: [] }).reasons.join('\n'), /cannot be determined/);
});

test('[REL-001.AC02] dirty inputs invalidate publishable evidence, both when the record was made dirty and when the tree is dirty now', () => {
  const dirtyRun = made({ dirty: ' M scanner/src/x.js\n?? new.txt\n' });
  assert.equal(dirtyRun.record.treeClean, false);
  assert.deepEqual(dirtyRun.record.dirtyPaths, ['scanner/src/x.js', 'new.txt']);
  const a = judge(dirtyRun.record);
  assert.equal(a.localOk, false);
  assert.match(a.reasons.join('\n'), /dirty or unverifiable tree/);
  const clean = made();
  const b = judge(clean.record, { ...CLEAN, dirtyPaths: ['scanner/src/y.js'] });
  assert.equal(b.localOk, false);
  assert.equal(b.publishable, false);
  assert.match(b.reasons.join('\n'), /working tree is dirty \(1 path/);
  assert.equal(judge(clean.record).localOk, true, 'control: the same record on a clean tree holds');
});

test('[REL-001.AC02] a suite whose script or test file changed after it ran invalidates its result', () => {
  const { record } = made();
  const edited = (match) => (p) => (match.test(p) ? Buffer.from('// edited after the run') : fs.readFileSync(p));
  const v = judge(record, CLEAN, { readFile: edited(/test\/evidence-issuer\.test\.js$/) });
  assert.match(v.reasons.join('\n'), /step 'foundation': its suite changed since it ran/);
  assert.equal(v.localOk, false);
  const w = judge(record, CLEAN, { readFile: edited(/test\/release-closure\/closure-plan\.test\.js$/) });
  assert.match(w.reasons.join('\n'), /step 'release-closure-suite': its suite changed/);
  const scripts = { ...PKG.scripts, 'test:routing': `${PKG.scripts['test:routing']} test/routing/extra.test.js` };
  const x = judge(record, CLEAN, { pkg: { ...PKG, scripts } });
  assert.match(x.reasons.join('\n'), /step 'routing': its suite changed/);
});

test('[REL-001.AC02] unrecorded inputs invalidate: a planned step with no result, a recorded step the plan lacks, a changed plan', () => {
  const { record } = made();
  const missing = { ...record, steps: record.steps.filter((s) => s.id !== 'scorecard') };
  assert.match(judge(missing).reasons.join('\n'), /step 'scorecard' is in the plan but has no recorded result/);
  const extra = { ...record, steps: [...record.steps, { ...record.steps[0], id: 'smuggled' }] };
  assert.match(judge(extra).reasons.join('\n'), /names step 'smuggled', which is not in the plan/);
  assert.match(judge(record, CLEAN, { steps: CLOSURE_STEPS.slice(1) }).reasons.join('\n'), /plan changed/);
  assert.match(judge({ ...record, schema: 'other' }).reasons.join('\n'), /not a agentic-security\/release-closure@1 record/);
  assert.match(judge({ ...record, stable: false }).reasons.join('\n'), /changed while the closure ran/);
});

test('[REL-001.AC02] the commit changing under the run makes the record unstable and unusable', () => {
  const outDir = mkTestTmp('closure-rec-');
  const { record } = runClosure({ repoRoot: REPO, outDir, env: ALL_PRESENT, exec: fakeExec({ head: [COMMIT, 'e'.repeat(40)] }) });
  assert.equal(record.stable, false);
  assert.equal(judge(record).localOk, false);
});

test('[REL-001.AC02] a log that changed or went missing no longer supports its result', () => {
  const { record, base } = made();
  const first = record.steps.find((s) => s.state === 'pass');
  fs.appendFileSync(path.join(base, first.log.path), 'tampered');
  assert.match(judge(record, CLEAN, { readLog: readLogFor(base) }).reasons.join('\n'), new RegExp(`step '${first.id}': its log no longer matches`));
  fs.rmSync(path.join(base, first.log.path));
  assert.match(judge(record, CLEAN, { readLog: readLogFor(base) }).reasons.join('\n'), /its log is not retained/);
  assert.equal(judge(record, CLEAN, { readLog: readLogFor(base), requireLogs: false }).reasons.some((r) => /not retained/.test(r)), false, 'retention can be waived only by an explicit option');
  const noDigest = { ...record, steps: record.steps.map((s) => (s.id === first.id ? { ...s, log: { ...s.log, sha256: 'x' } } : s)) };
  assert.match(judge(noDigest).reasons.join('\n'), /passed but has no recorded log digest/);
});

test('[REL-001.AC02] gitFacts reads the commit, tree and dirty paths of a real repository and treats an unreadable repository as dirty', () => {
  const facts = gitFacts(REPO);
  assert.match(facts.commit, /^[0-9a-f]{40}$/);
  assert.match(facts.tree, /^[0-9a-f]{40}$/);
  const broken = gitFacts(mkTestTmp('not-a-repo-'));
  assert.equal(broken.commit, null);
  assert.deepEqual(broken.dirtyPaths, ['(git status failed)']);
});
