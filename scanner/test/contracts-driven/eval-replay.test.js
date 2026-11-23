// C-AC05: a stored run replays to the degree its arms permit. The deterministic arm (the shipped scanner) reproduces exactly on the
// same dataset; a model arm is reported `limited` with the reasons, with agreement shown as a description; a changed dataset or arm
// is refused before anything runs. The model arm is a scripted function (plumbing, not a model).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDatasetFile } from '../../src/posture/evaluation/lab/dataset.js';
import { runEval } from '../../src/posture/evaluation/lab/run.js';
import { runArmTask as realRunArmTask } from '../../src/posture/evaluation/lab/arms.js';
import { replayPlan, compareReplay } from '../../src/posture/evaluation/lab/replay.js';
import { saveRun } from '../../src/posture/evaluation/lab/store.js';
import { cmdEval } from '../../src/posture/evaluation/lab/cli.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'eval-lab', 'detect', 'dataset.json');
const baseline = { id: 'baseline', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner' } };
const model = { id: 'm-scripted', kind: 'model', tasks: ['detect'], model: { id: 'scripted', provider: 'fake', local: true }, adapter: { type: 'command', argv: [process.execPath, '-e', '0'] } };
// the scripted model answers differently on every call, as a sampled model may: the replay must not call that a divergence
let calls = 0;
const deps = { runArmTask: async (o) => (o.arm.kind === 'model' ? { status: 'completed', output: { findings: (calls++ % 2) ? [] : [{ file: 'x.js', line: 1, cwe: 'CWE-78' }] }, usage: { usd: null, latencyMs: 1 } } : realRunArmTask(o)) };

test('C-AC05: the deterministic arm reproduces, the model arm is limited with reasons, and a changed input is refused', { timeout: 600_000 }, async () => {
  const ds = loadDatasetFile(FX); assert.equal(ds.ok, true);
  const frozen = await runEval({ dataset: ds, arms: [baseline, model], tasks: ['detect'], repeats: 2, concurrency: 1, deps });
  assert.equal(frozen.ok, true, JSON.stringify(frozen.errors));
  const plan = replayPlan(frozen.run, { dataset: ds, arms: [baseline, model] });
  assert.equal(plan.ok, true, plan.reasons.join('; '));
  assert.deepEqual(plan.config.tasks, ['detect']); assert.equal(plan.config.repeats, 2);
  const again = await runEval({ dataset: ds, arms: [baseline, model], ...plan.config, deps });
  const cmp = compareReplay(frozen.run, again.run);
  const det = cmp.arms.find((a) => a.armId === 'baseline'); const mod = cmp.arms.find((a) => a.armId === 'm-scripted');
  assert.equal(det.status, 'reproduced', JSON.stringify(det.differing));
  assert.equal(det.sameScores, true);
  assert.equal(mod.status, 'limited');
  assert.ok(mod.why.some((w) => /no immutable model version/.test(w)) && mod.why.some((w) => /sampling/.test(w)));
  assert.match(mod.note, /descriptive only/);
  assert.equal(cmp.status, 'reproduced-deterministic-limited-model');
  assert.deepEqual(cmp.configDifferences, []);

  // refused before running: another arm configuration, a missing arm, another dataset
  assert.match(replayPlan(frozen.run, { dataset: ds, arms: [{ ...baseline, tasks: ['detect'], extra: 1 }, model] }).reasons.join(), /configured differently/);
  assert.match(replayPlan(frozen.run, { dataset: ds, arms: [baseline] }).reasons.join(), /not in the arms file/);
  assert.match(replayPlan(frozen.run, { dataset: { ...ds, hash: 'sha256:' + '0'.repeat(64) }, arms: [baseline, model] }).reasons.join(), /dataset hash/);

  // a deterministic difference is a divergence and names the defect
  const tampered = JSON.parse(JSON.stringify(again.run));
  const arm = tampered.stability.arms.find((a) => a.armId === 'baseline');
  arm.perDefect[0].detected = arm.perDefect[0].detected ? 0 : 1;
  const d = compareReplay(frozen.run, tampered);
  assert.equal(d.status, 'diverged'); assert.equal(d.arms.find((a) => a.armId === 'baseline').differing[0].entryId, arm.perDefect[0].entryId);
  // a different scanner is disclosed
  const other = { ...again.run, scanner: { ...again.run.scanner, commit: 'f'.repeat(40) } };
  assert.ok(compareReplay(frozen.run, other).environmentDifferences.some((e) => e.field === 'scanner.commit'));
});

test('C-AC05 through the CLI: a stored deterministic run replays (exit 0) and an edited arms file is refused (exit 4)', { timeout: 600_000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-replay-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"r","private":true}\n');
  setStateWritesEnabled(true);
  try {
    const ds = loadDatasetFile(FX);
    const frozen = await runEval({ dataset: ds, arms: [baseline], tasks: ['detect'], repeats: 1, concurrency: 1, scanRoot: dir });
    assert.equal(saveRun(dir, frozen.run).ok, true);
    const arms = path.join(dir, 'arms.json'); fs.writeFileSync(arms, JSON.stringify({ arms: [baseline] }));
    const quiet = async (fn) => { const o = console.log; const e = console.error; console.log = () => {}; console.error = () => {}; try { return await fn(); } finally { console.log = o; console.error = e; } };
    assert.equal(await quiet(() => cmdEval({ _: ['eval', 'replay', frozen.run.runId], flags: { dataset: FX, arms } }, dir)), 0);
    fs.writeFileSync(arms, JSON.stringify({ arms: [{ ...baseline, id: 'baseline', tasks: ['detect'], note: 'edited' }] }));
    assert.equal(await quiet(() => cmdEval({ _: ['eval', 'replay', frozen.run.runId], flags: { dataset: FX, arms } }, dir)), 4);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
