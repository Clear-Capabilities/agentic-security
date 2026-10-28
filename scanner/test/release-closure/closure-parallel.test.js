// The closure can run steps side by side (`--jobs N`) without changing what it records: same steps, plan order, the same verdicts, and a
// step marked `serial` finishes before any other starts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runClosure, runClosureParallel, evaluateClosureRecord, readLogFor } from '../../../scripts/release-closure.mjs';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG, COMMIT, TREE, ALL_PRESENT, fakeExec } from '../helpers/closure-fixtures.js';

const sync = fakeExec();
const asyncExec = (spy) => async (cmd, args, o) => {
  spy.live++; spy.max = Math.max(spy.max, spy.live); spy.order.push(`${cmd} ${args.join(' ')}`);
  await new Promise((r) => setTimeout(r, 15));
  spy.live--;
  return sync(cmd, args, o);
};

test('[REL-001.AC02] a parallel closure records the same steps in plan order, with the same verdicts, as a serial one', async () => {
  const a = runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-ser-'), env: ALL_PRESENT, exec: sync });
  const spy = { live: 0, max: 0, order: [] };
  const b = await runClosureParallel({ repoRoot: REPO, outDir: mkTestTmp('closure-par-'), env: ALL_PRESENT, exec: sync }, { jobs: 4, execAsync: asyncExec(spy) });
  assert.deepEqual(b.record.steps.map((s) => [s.id, s.state]), a.record.steps.map((s) => [s.id, s.state]));
  assert.ok(spy.max > 1 && spy.max <= 4, `ran ${spy.max} at once`);
  assert.equal(b.record.planDigest, a.record.planDigest);
  const v = evaluateClosureRecord(JSON.parse(JSON.stringify(b.record)), { commit: COMMIT, tree: TREE, dirtyPaths: [] }, { pkg: PKG, readLog: readLogFor(b.base) });
  assert.deepEqual(v.reasons, []);
});

test('[REL-001.AC02] the serial step (it rebuilds dist in place) runs alone, before any other', async () => {
  const spy = { live: 0, max: 0, order: [] };
  await runClosureParallel({ repoRoot: REPO, outDir: mkTestTmp('closure-par-'), env: ALL_PRESENT, exec: sync }, { jobs: 4, execAsync: asyncExec(spy) });
  assert.match(spy.order[0], /check:bundle-source/);
});
