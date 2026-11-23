// Epic C of the contract-driven verification programme: per-defect stability over scheduled repetitions, failed and cancelled trials
// kept in the denominators, no learning across repetitions, the semantic view kept apart from the localized score, the population
// label, and the router refusing synthetic scores. C-AC01, C-AC02, C-AC03, C-AC04, C-AC07.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDatasetFile } from '../../src/posture/evaluation/lab/dataset.js';
import { runEval } from '../../src/posture/evaluation/lab/run.js';
import { summarizeRun, toMarkdown } from '../../src/posture/evaluation/lab/report.js';
import { stabilityReport, stableThreshold } from '../../src/posture/evaluation/lab/stability.js';
import { semanticView } from '../../src/posture/evaluation/lab/semantic.js';
import { scoreboardFromRun } from '../../src/posture/evaluation/lab/scoreboard.js';
import { routeTask } from '../../src/posture/routing/policy-router.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'eval-lab', 'detect', 'dataset.json');
const model = { id: 'm-scripted', kind: 'model', tasks: ['detect'], model: { id: 'scripted', provider: 'fake', local: true }, adapter: { type: 'command', argv: [process.execPath, '-e', '0'] } };

test('C-AC01: 1/10 is union-detected and not stable; 7/10 and 10/10 are stable and stay distinguishable', () => {
  assert.equal(stableThreshold(10), 7); assert.equal(stableThreshold(3), 3);
  const usable = ['a', 'b', 'c'].map((id) => ({ id, kind: 'vulnerable', cwe: 'CWE-78', expectedSpan: { file: 'x.js', startLine: 1, endLine: 1 } }));
  const hits = { a: 1, b: 7, c: 10 };
  const attempts = [];
  for (let r = 0; r < 10; r++) for (const e of usable) attempts.push({ armId: 'm', repeat: r, task: 'detect', entryId: e.id, status: 'completed', output: { findings: r < hits[e.id] ? [{ file: 'x.js', line: 1, cwe: 'CWE-78' }] : [] } });
  const rep = stabilityReport({ armPlans: [{ arm: { id: 'm', kind: 'model' }, repeats: 10, tasks: ['detect'] }], usable, attempts, mapFile: (id, f) => f });
  const a = rep.arms[0];
  assert.deepEqual(a.perDefect.map((d) => [d.entryId, d.detected, d.stable]), [['a', 1, false], ['b', 7, true], ['c', 10, true]]);
  assert.equal(a.unionRecall, 1); assert.equal(Number(a.stableRecall.toFixed(3)), 0.667);
  assert.ok(a.perDefect[1].interval.low < a.perDefect[2].interval.low, '7/10 and 10/10 carry different intervals');
  assert.equal(a.claim, 'descriptive-at-preregistered-repeats');
});

test('C-AC02: a timed-out, blocked or cancelled repetition is a scheduled non-detection; the valid-run view is labelled and never replaces it', () => {
  const usable = [{ id: 'a', kind: 'vulnerable', cwe: 'CWE-78', expectedSpan: { file: 'x.js', startLine: 1, endLine: 1 } }];
  const hit = { status: 'completed', output: { findings: [{ file: 'x.js', line: 1, cwe: 'CWE-78' }] } };
  const attempts = [
    { armId: 'm', repeat: 0, task: 'detect', entryId: 'a', ...hit },
    { armId: 'm', repeat: 1, task: 'detect', entryId: 'a', ...hit },
    { armId: 'm', repeat: 2, task: 'detect', entryId: 'a', status: 'timeout' },
    { armId: 'm', repeat: 3, task: 'detect', entryId: 'a', status: 'blocked' },
    // repeat 4 never started: no attempt record at all
  ];
  const d = stabilityReport({ armPlans: [{ arm: { id: 'm', kind: 'model' }, repeats: 5, tasks: ['detect'] }], usable, attempts, mapFile: (id, f) => f }).arms[0].perDefect[0];
  assert.equal(d.scheduled, 5); assert.equal(d.detected, 2); assert.equal(d.frequency, 0.4);
  assert.equal(d.validRunOnly.frequency, 1, 'completed-only would say 2/2');
  assert.deepEqual([d.statuses.timeout, d.statuses.blocked, d.statuses.cancelled, d.statuses.completed], [1, 1, 1, 2]);
  assert.equal(d.stable, false, '2 of 5 scheduled is below the threshold even though every completed run detected it');
});

test('C-AC02/C-AC03/C-AC07 through runEval: repetitions are independent, a cancelled run records its unstarted attempts, the run says synthetic', async () => {
  const ds = loadDatasetFile(FX);
  assert.equal(ds.ok, true);
  ds.manifest.dataset.population = 'synthetic'; // the fixture is authored; declare it so the run labels it
  const seen = [];
  // the scripted arm finds cmdi-1 on even repeats only, and records what each call was given: no repeat sees another's findings
  const runArmTask = async ({ request }) => { seen.push(Object.keys(request).sort().join(',')); const repeat = seen.length; return { status: 'completed', output: { findings: [] }, usage: { usd: null, latencyMs: 1 }, repeat }; };
  const res = await runEval({ dataset: ds, arms: [model], tasks: ['detect'], repeats: 4, concurrency: 1, deps: { runArmTask } });
  assert.equal(res.ok, true);
  assert.ok(seen.every((k) => k === 'language,schema,task,workspace'), 'every request carries the workspace and the task, never findings, labels or a prior verdict');
  assert.equal(res.run.measurement.population, 'synthetic');
  assert.equal(res.run.stability.arms[0].scheduledRepeats, 4);
  assert.equal(res.run.config.matcherVersion, 'localized-file-cwe-line/1');
  assert.ok(Object.hasOwn(res.run.scanner, 'dirty'));
  const ac = new AbortController();
  let calls = 0;
  const cancelling = async () => { calls += 1; if (calls === 2) ac.abort(); return { status: 'completed', output: { findings: [] }, usage: { usd: null, latencyMs: 1 } }; };
  const cancelled = await runEval({ dataset: ds, arms: [model], tasks: ['detect'], repeats: 3, concurrency: 1, signal: ac.signal, deps: { runArmTask: cancelling } });
  const statuses = cancelled.run.attempts.map((a) => a.status);
  assert.ok(statuses.includes('cancelled'), 'the unstarted attempts are recorded');
  assert.equal(cancelled.run.attempts.length, 3 * ds.manifest.entries.length, 'every scheduled attempt has a record');
  assert.equal(cancelled.run.complete, false);
  const md = toMarkdown(summarizeRun(cancelled.run));
  assert.match(md, /Population: synthetic/); assert.match(md, /## Stability/); assert.match(md, /INCOMPLETE/);
});

test('C-AC04: the semantic view needs a source anchor and an independent adjudication; a model proposal is ambiguous; duplicates count once; the localized figure is unchanged', () => {
  const references = [
    { id: 'r1', cwe: 'CWE-639', expectedSpan: { file: 'svc.js', startLine: 14, endLine: 14 }, semantic: { rootCause: { file: 'svc.js', startLine: 12, endLine: 16 }, entryFile: 'server.js' } },
    { id: 'r2', cwe: 'CWE-639', expectedSpan: { file: 'other.js', startLine: 40, endLine: 40 }, semantic: { rootCause: { file: 'other.js', startLine: 38, endLine: 42 } } },
    { id: 'r3', cwe: 'CWE-79', expectedSpan: { file: 'view.js', startLine: 5, endLine: 5 } },
  ];
  const findings = [
    { id: 'f1', file: 'svc.js', line: 14, cwe: 'CWE-639' }, { id: 'f2', file: 'svc.js', line: 15, cwe: 'CWE-639' },
    { id: 'f3', file: 'other.js', line: 39, cwe: 'CWE-284' },
    { id: 'f4', file: 'elsewhere.js', line: 1, cwe: 'CWE-79' },
  ];
  const v1 = semanticView({ references, findings, adjudications: [{ referenceId: 'r2', findingId: 'f3', verdict: 'same-defect', kind: 'model-proposal' }] });
  assert.deepEqual(v1.references.map((r) => [r.referenceId, r.outcome]), [['r1', 'exact-localized'], ['r2', 'ambiguous'], ['r3', 'unmatched']]);
  assert.equal(v1.duplicateDescriptions, 1, 'two findings on r1 count it once');
  assert.deepEqual(v1.unlabelled, [{ findingId: 'f4', status: 'unlabelled-needs-review' }], 'a CWE-79 finding in the wrong file is not matched by its class and is not called a false positive');
  const v2 = semanticView({ references, findings, adjudications: [{ referenceId: 'r2', findingId: 'f3', verdict: 'same-defect', kind: 'independent-human', reviewer: 'dana' }] });
  assert.equal(v2.references[1].outcome, 'semantic-adjudicated');
  assert.equal(v2.localizedRecall, v1.localizedRecall, 'the localized figure does not move');
  assert.ok(v2.semanticRecall > v2.localizedRecall);
});

test('the router refuses a synthetic-population score and keeps routing on a labelled real one', () => {
  const entry = (population) => ({ model: 'fake/scripted', armId: 'm', local: true, endpoint: null, routerTask: 'hunt', evalTask: 'detect', datasetHash: 'sha256:x', datasetId: 'd', quality: { mean: 0.8, stdev: 0, ci95: null, n: 3, representative: true, metric: 'f1' }, medianCostUsd: 0, costKnown: true, medianLatencyMs: 1, failures: 0, calls: 3, evidence: { runId: 'r' }, population });
  const synthetic = routeTask({ task: 'hunt', policy: 'local-only', scoreboard: { entries: [entry('synthetic')] }, scanRoot: process.cwd() });
  assert.equal(synthetic.ok, false); assert.ok(synthetic.excluded[0].reasons.some((r) => /synthetic/.test(r)));
  const real = routeTask({ task: 'hunt', policy: 'local-only', scoreboard: { entries: [entry('real-code')] }, scanRoot: process.cwd() });
  assert.equal(real.ok, true);
  assert.equal(scoreboardFromRun({ arms: [], results: [], attempts: [], dataset: { hash: 'h', id: 'd' }, measurement: { population: 'synthetic' } }).length, 0);
});
