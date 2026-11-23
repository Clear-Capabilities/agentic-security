// C-AC06: a configuration that loses a protected baseline defect fails the registered policy, even when its aggregate improves,
// unless an adjudicated exception covers exactly that arm and defect. Run records are synthetic (they test the gate, not a model).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { protectedDefectGate, PROTECTED_POLICY_SCHEMA } from '../../src/posture/evaluation/lab/protected.js';
import { saveRun } from '../../src/posture/evaluation/lab/store.js';
import { cmdEval } from '../../src/posture/evaluation/lab/cli.js';
import { setStateWritesEnabled, statePath } from '../../src/posture/state-dir.js';

const HASH = 'sha256:' + 'a'.repeat(64);
const defect = (entryId, detected, scheduled = 10, need = 7) => ({ entryId, cwe: 'CWE-639', scheduled, detected, stable: detected >= need });
const run = (runId, perDefect, { startedAt = '2026-11-20T10:00:00.000Z', hash = HASH } = {}) => ({
  runId, startedAt, dataset: { hash },
  stability: { arms: [{ armId: 'model-a', kind: 'model', perDefect, stableRecall: perDefect.filter((d) => d.stable).length / perDefect.length }] },
});
const policy = (o = {}) => ({ schema: PROTECTED_POLICY_SCHEMA, id: 'protect-baseline', version: 1, registeredAt: '2026-11-19T00:00:00.000Z', exceptions: [], ...o });
const baseline = run('elab-base', [defect('d1', 10), defect('d2', 8), defect('d3', 2), defect('d4', 0)]);
// d2 drops to 6/10 (lost); d3 and d4 become stable: the aggregate goes from 2/4 to 3/4
const current = run('elab-cur', [defect('d1', 10), defect('d2', 6), defect('d3', 9), defect('d4', 7)]);

test('C-AC06: a lost protected defect fails the gate although the aggregate improved', () => {
  const g = protectedDefectGate({ baseline, current, policy: policy(), reviewers: ['dana'], now: '2026-11-21T00:00:00.000Z' });
  assert.equal(g.status, 'fail');
  assert.deepEqual(g.lost.map((l) => [l.entryId, l.baseline, l.current, l.why, l.excused]), [['d2', '8/10', '6/10', 'no-longer-stable', false]]);
  assert.equal(g.aggregate[0].improved, true);
  assert.equal(g.protected['model-a'], 2);
  assert.match(g.aggregateNote, /never excuses/);
});

test('C-AC06: only an adjudicated exception for exactly that arm and defect excuses it; every other exception is rejected with its reason', () => {
  const good = { armId: 'model-a', entryId: 'd2', reason: 'the reference fix for d2 was relabelled after review', adjudicatedBy: 'dana', datasetHash: HASH, expires: '2027-01-01T00:00:00.000Z' };
  const now = '2026-11-21T00:00:00.000Z';
  const ok = protectedDefectGate({ baseline, current, policy: policy({ exceptions: [good] }), reviewers: ['dana'], now });
  assert.equal(ok.status, 'pass'); assert.equal(ok.lost[0].excused, true); assert.equal(ok.exceptions.accepted.length, 1);
  const cases = [
    [{ ...good, adjudicatedBy: 'mallory' }, /not a reviewer/],
    [{ ...good, reason: 'ok' }, /shorter than/],
    [{ ...good, datasetHash: 'sha256:' + 'b'.repeat(64) }, /different population/],
    [{ ...good, expires: '2026-11-20T00:00:00.000Z' }, /expired/],
    [{ ...good, entryId: 'd1' }, /unused/],
  ];
  for (const [e, why] of cases) {
    const g = protectedDefectGate({ baseline, current, policy: policy({ exceptions: [e] }), reviewers: ['dana'], now });
    assert.equal(g.status, 'fail', JSON.stringify(e)); assert.match(g.exceptions.rejected[0].why, why);
  }
});

test('C-AC06: a policy registered after the run started is not a registered policy; different populations are unmeasured', () => {
  assert.equal(protectedDefectGate({ baseline, current, policy: policy({ registeredAt: '2026-11-20T11:00:00.000Z' }) }).status, 'fail');
  assert.equal(protectedDefectGate({ baseline, current: run('elab-x', current.stability.arms[0].perDefect, { hash: 'sha256:' + 'c'.repeat(64) }), policy: policy() }).status, 'unmeasured');
  assert.equal(protectedDefectGate({ baseline, current: { ...current, stability: null }, policy: policy() }).status, 'unmeasured');
  assert.equal(protectedDefectGate({ baseline, current, policy: { ...policy(), schema: 'x' } }).status, 'fail');
  const noLoss = run('elab-same', baseline.stability.arms[0].perDefect);
  assert.equal(protectedDefectGate({ baseline, current: noLoss, policy: policy() }).status, 'pass');
  const armGone = { ...current, stability: { arms: [] } };
  const g = protectedDefectGate({ baseline, current: armGone, policy: policy() });
  assert.equal(g.status, 'fail'); assert.ok(g.lost.every((l) => l.why === 'arm-missing'));
});

test('C-AC06 through the CLI: exit 1 on a loss, 0 with the adjudicated exception, 3 when unmeasured', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-gate-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"g","private":true}\n');
  setStateWritesEnabled(true);
  try {
    for (const r of [baseline, current, run('elab-other', current.stability.arms[0].perDefect, { hash: 'sha256:' + 'c'.repeat(64) })]) assert.equal(saveRun(dir, r).ok, true);
    fs.mkdirSync(path.dirname(statePath(dir, 'reviewer-policy.json')), { recursive: true });
    fs.writeFileSync(statePath(dir, 'reviewer-policy.json'), JSON.stringify({ id: 'local', reviewers: ['dana'] }));
    const pfile = path.join(dir, 'policy.json');
    fs.writeFileSync(pfile, JSON.stringify(policy()));
    const quiet = async (fn) => { const o = console.log; const e = console.error; console.log = () => {}; console.error = () => {}; try { return await fn(); } finally { console.log = o; console.error = e; } };
    const gate = (cur) => quiet(() => cmdEval({ _: ['eval', 'gate', cur], flags: { baseline: 'elab-base', policy: pfile } }, dir));
    assert.equal(await gate('elab-cur'), 1);
    fs.writeFileSync(pfile, JSON.stringify(policy({ exceptions: [{ armId: 'model-a', entryId: 'd2', reason: 'the reference fix for d2 was relabelled after review', adjudicatedBy: 'dana', datasetHash: HASH, expires: '2099-01-01T00:00:00.000Z' }] })));
    assert.equal(await gate('elab-cur'), 0);
    assert.equal(await gate('elab-other'), 3);
    assert.equal(await quiet(() => cmdEval({ _: ['eval', 'gate', 'elab-cur'], flags: {} }, dir)), 4);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
