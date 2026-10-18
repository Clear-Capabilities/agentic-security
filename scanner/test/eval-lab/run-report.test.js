// The Eval Lab run end to end (in-process): leakage in front, scoring behind, repeats, budgets, cancellation, and the reports.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { loadDatasetFile } from '../../src/posture/evaluation/lab/dataset.js';
import { runEval } from '../../src/posture/evaluation/lab/run.js';
import { summarizeRun, renderReport, toChartData, REPORT_FORMATS, PRIMARY } from '../../src/posture/evaluation/lab/report.js';
import { scoreboardFromRun, mergeScoreboard } from '../../src/posture/evaluation/lab/scoreboard.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/eval-lab');
const ARM = path.join(FX, 'fake-arm.mjs');
const sandbox = sandboxAvailable() ? false : 'no confinement backend on this host';
const price = { inputPerMTok: 3, outputPerMTok: 15 };
const model = (profile, tasks, over = {}) => ({ id: `m-${profile}`, kind: 'model', tasks, model: { id: profile, provider: 'fake', local: true }, adapter: { type: 'command', argv: [process.execPath, ARM, profile, ...(over.argvExtra ?? [])], timeoutMs: 8000 }, price, ...over });
const baseline = { id: 'baseline', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner', layer: 'deep-taint' } };
// the deterministic baseline with a stubbed scan, so these tests do not depend on the engine's current findings
const stubScan = async (dir) => {
  const out = [];
  for (const f of fs.readdirSync(dir)) fs.readFileSync(path.join(dir, f), 'utf8').split('\n').forEach((l, i) => { if (/exec\('ping/.test(l)) out.push({ file: f, line: i + 1, cwe: 'CWE-78' }); if (/\.query\("SELECT/.test(l)) out.push({ file: f, line: i + 1, cwe: 'CWE-89' }); });
  return { findings: out };
};
const detectDs = () => loadDatasetFile(path.join(FX, 'detect/dataset.json'));
const quiet = { concurrency: 4, timeoutMs: 20000 };

test('detect + falsify across a baseline and four model behaviours: scores follow behaviour, failures are visible, repeats follow the arm kind', async () => {
  const arms = [baseline, model('good', ['detect', 'falsify']), model('noisy', ['detect', 'falsify']), model('lazy', ['detect', 'falsify']), model('garbage', ['detect', 'falsify'])];
  const res = await runEval({ dataset: detectDs(), arms, tasks: ['detect', 'falsify'], repeats: 3, ...quiet, deps: { scanFn: stubScan } });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  const run = res.run;
  assert.equal(run.complete, true); assert.equal(run.leakageAudit.status, 'clean');
  assert.deepEqual(run.arms.map((a) => [a.id, a.repeats]), [['baseline', 1], ['m-good', 3], ['m-noisy', 3], ['m-lazy', 3], ['m-garbage', 3]]);
  const rep = summarizeRun(run);
  const by = Object.fromEntries(rep.arms.map((a) => [a.id, a]));
  assert.equal(by['m-good'].tasks.detect.f1.mean, 1); assert.equal(by['m-good'].tasks.detect.f1.representative, true);
  assert.equal(by['m-good'].tasks.falsify.balancedAccuracy.mean, 1);
  assert.equal(by['m-noisy'].tasks.detect.recall.mean, 1); assert.ok(by['m-noisy'].tasks.detect.precision.mean < 0.5, 'flagging every call to a sink is noise');
  assert.equal(by['m-noisy'].tasks.falsify.falseConfirmationRate.mean, 1);
  assert.equal(by['m-lazy'].tasks.detect.recall.mean, 0); assert.equal(by['m-lazy'].tasks.detect.f1.mean, 0);
  assert.equal(by['m-garbage'].tasks.detect.recall.mean, 0); assert.equal(by['m-garbage'].tasks.detect.completion.mean, 0);
  assert.equal(by['m-garbage'].economics.failures, 36, 'every garbage answer is a recorded failure (12 attempts x 3 runs)');
  assert.equal(by['m-garbage'].economics.unknownCostAttempts, 36);
  assert.equal(by.baseline.tasks.detect.f1.mean, 1); assert.equal(by.baseline.tasks.detect.f1.representative, false, 'one deterministic run is not "representative"');
  assert.equal(by.baseline.economics.usd.mean, 0);
  assert.ok(Math.abs(by['m-good'].economics.usd.mean - 0.0972) < 1e-9, '12 attempts x (1200 in x $3 + 300 out x $15) per million');
  assert.equal(rep.header.models.length, 4);
});

test('no request an arm receives contains a label: not the entry id, kind, category, expected span or the dataset name', async () => {
  const seen = [];
  const spy = async (args) => { seen.push(JSON.stringify(args.request)); return { status: 'completed', output: { findings: [], verdicts: { c1: 'uncertain' } }, usage: { usd: null, latencyMs: 1 } }; };
  const arms = [model('lazy', ['detect', 'falsify'])];
  await runEval({ dataset: detectDs(), arms, tasks: ['detect', 'falsify'], repeats: 1, ...quiet, deps: { runArmTask: spy } });
  assert.ok(seen.length >= 12);
  const banned = [/cmdi-\d/, /sqli-\d/, /hn-\d/, /"kind"\s*:\s*"(?:vulnerable|fixed|hard-negative)"/, /hard-negative/, /expectedSpan/, /lookalike/, /sanitization/, /authorization/, /eval-lab-detect/, /answer/i, /cases[\\/]/];
  for (const r of seen) for (const re of banned) assert.doesNotMatch(r, re, `a request contained ${re}: ${r.slice(0, 200)}`);
  for (const r of seen) assert.doesNotMatch(JSON.parse(r).workspace, /cmdi|sqli|vuln|fixed|hn-/i, 'even the workspace path is neutral');
});

test('leakage: a tainted entry is quarantined and named, the run is marked incomplete, and the rest is still scored', async () => {
  const dir = mkTestTmp('lab-run-leak-');
  fs.cpSync(path.join(FX, 'detect'), dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'cases/hn-sanitize/expected.json'), '{"answer":"CWE-79"}');
  const res = await runEval({ dataset: loadDatasetFile(path.join(dir, 'dataset.json')), arms: [model('good', ['detect'])], tasks: ['detect'], repeats: 3, ...quiet });
  const { run } = res;
  assert.equal(run.complete, false);
  assert.equal(run.leakageAudit.status, 'entries-excluded');
  assert.deepEqual(run.leakageAudit.quarantined.map((q) => q.entryId), ['hn-1']);
  assert.ok(run.incompleteReasons.some((r) => /leakage audit/.test(r)));
  assert.equal(run.attempts.filter((a) => a.entryId === 'hn-1').length, 0, 'a quarantined entry is never given to an arm');
  assert.equal(summarizeRun(run).arms[0].tasks.detect.f1.mean, 1);
  assert.match(renderReport(summarizeRun(run), 'md'), /INCOMPLETE.*leakage audit/);
});

test('a dataset with nothing usable runs nothing and says so', async () => {
  const dir = mkTestTmp('lab-run-none-');
  fs.cpSync(path.join(FX, 'detect'), dir, { recursive: true });
  for (const c of fs.readdirSync(path.join(dir, 'cases'))) fs.writeFileSync(path.join(dir, 'cases', c, 'ground-truth.json'), '{}');
  const { run } = await runEval({ dataset: loadDatasetFile(path.join(dir, 'dataset.json')), arms: [model('good', ['detect'])], tasks: ['detect'], repeats: 1, ...quiet });
  assert.equal(run.leakageAudit.status, 'no-entries-usable'); assert.equal(run.attempts.length, 0); assert.equal(run.complete, false);
});

test('a budget stops new attempts, records the skipped ones, and marks the run incomplete', async () => {
  const { run } = await runEval({ dataset: detectDs(), arms: [model('good', ['detect'], { price: { inputPerMTok: 3000, outputPerMTok: 15000 } })], tasks: ['detect'], repeats: 3, budgetUsd: 5, concurrency: 1, timeoutMs: 20000 });
  assert.ok(run.attempts.some((a) => a.status === 'skipped-budget'));
  assert.equal(run.complete, false); assert.ok(run.incompleteReasons.some((r) => /budget/.test(r)));
  assert.equal(run.attempts.length, 18, 'nothing is dropped: every planned attempt is recorded');
});

test('cancellation stops the run and says so', async () => {
  const ac = new AbortController(); ac.abort();
  const { run } = await runEval({ dataset: detectDs(), arms: [model('good', ['detect'])], tasks: ['detect'], repeats: 3, ...quiet, signal: ac.signal });
  assert.equal(run.complete, false); assert.ok(run.incompleteReasons.includes('cancelled'));
});

test('input is validated up front: bad arms, tasks and repeats are refused without running anything', async () => {
  const ds = detectDs();
  const bad = async (o, re) => { const r = await runEval({ dataset: ds, arms: [model('good', ['detect'])], tasks: ['detect'], repeats: 1, ...o }); assert.equal(r.ok, false); assert.match(r.errors.join('|'), re); };
  await bad({ arms: [] }, /at least one arm/);
  await bad({ arms: [model('good', ['detect']), model('good', ['detect'])] }, /duplicated/);
  await bad({ arms: [{ id: 'x' }] }, /arm x/);
  await bad({ tasks: ['hunt'] }, /tasks must be/);
  await bad({ repeats: 0 }, /repeats/);
  await bad({ repeats: 99 }, /repeats/);
});

test('exploit and patch are decided by the lab, not the arm: the PoC is run in the proof fabric and the patch is replayed against the exploit', { skip: sandbox, timeout: 240000 }, async () => {
  const dir = path.join(FX, 'proof');
  const repro = path.join(dir, 'cases/vuln.reproducer.json');
  const arms = ['good', 'noisy', 'lazy'].map((p) => model(p, ['exploit', 'patch'], { argvExtra: [repro] }));
  const res = await runEval({ dataset: loadDatasetFile(path.join(dir, 'dataset.json')), arms, tasks: ['exploit', 'patch'], repeats: 3, concurrency: 3, timeoutMs: 60000 });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  const rep = summarizeRun(res.run); const by = Object.fromEntries(rep.arms.map((a) => [a.id, a]));
  assert.equal(by['m-good'].tasks.exploit.confirmationRate.mean, 1, 'a reproducer that really works is confirmed by execution');
  assert.equal(by['m-good'].tasks.exploit.falseConfirmationRate.mean, 0, 'the same reproducer on the fixed code is NOT confirmed');
  assert.equal(by['m-good'].tasks.patch.validPatchRate.mean, 1);
  assert.equal(by['m-good'].tasks.patch.exploitBlockedRate.mean, 1);
  assert.equal(by['m-noisy'].tasks.patch.exploitBlockedRate.mean, 0, 'a patch that still has the flaw is not blocked');
  assert.equal(by['m-noisy'].tasks.patch.validPatchRate.mean, 0);
  assert.equal(by['m-lazy'].tasks.exploit.confirmationRate.mean, 0); assert.equal(by['m-lazy'].tasks.patch.validPatchRate.mean, 0);
  const patchAttempt = res.run.attempts.find((a) => a.armId === 'm-good' && a.task === 'patch');
  assert.equal(patchAttempt.patch.testsPass, true, 'the dataset test command ran against the patched copy');
  assert.ok(patchAttempt.patch.digest && !('files' in patchAttempt.patch), 'the run keeps a digest of the patch, not its contents');
  // intelligence per dollar uses MEASURED outcomes and measured spend
  const g = by['m-good'].intelligencePerDollar;
  const spend = res.run.results.filter((r) => r.armId === 'm-good').reduce((s, r) => s + r.economics.usdMeasured, 0);
  const confirmed = res.run.results.filter((r) => r.armId === 'm-good').reduce((s, r) => s + r.scores.exploit.counts.confirmedVuln, 0);
  assert.ok(Math.abs(g.confirmedVulnerabilitiesPer100Usd.value - (confirmed / spend) * 100) < 1e-6);
  assert.ok(g.verifiedFixesPer100Usd.value > 0);
  assert.ok(by['m-good'].dollarsPer.verifiedFix > 0);
});

test('reports: every format carries the identity of the run, ids are escaped, and a single run is labelled', async () => {
  const hostile = model('good', ['detect'], { model: { id: '<img src=x onerror=alert(1)>', provider: 'fa&ke', local: true } });
  const { run } = await runEval({ dataset: detectDs(), arms: [baseline, hostile], tasks: ['detect'], repeats: 3, ...quiet, deps: { scanFn: stubScan } });
  const rep = summarizeRun(run);
  const md = renderReport(rep, 'md');
  for (const needle of [run.runId, 'Scanner:', 'Dataset: eval-lab-detect', String(run.dataset.hash).slice(-16), 'Machine:', run.startedAt, 'Leakage audit: clean', 'fa&ke/<img', 'not representative', 'Intelligence per dollar']) assert.ok(md.includes(needle), `markdown is missing ${needle}`);
  const html = renderReport(rep, 'html');
  assert.doesNotMatch(html, /<img src=x/); assert.match(html, /&lt;img src=x/); assert.doesNotMatch(html, /<script/i);
  assert.match(html, /^<!doctype html>/);
  const csv = renderReport(rep, 'csv').trim().split('\n');
  assert.equal(csv[0], 'arm,kind,task,metric,n,mean,stdev,min,max,ci95_low,ci95_high,representative');
  assert.ok(csv.length > 10 && csv.every((l) => l.split(',').length >= 12 || l.includes('"')));
  const json = JSON.parse(renderReport(rep, 'json')); assert.equal(json.runId, run.runId); assert.equal(json.header.datasetHash, run.dataset.hash);
  const chart = toChartData(rep); assert.ok(chart.series.length && chart.series.every((s) => 'arm' in s && 'metric' in s && 'value' in s)); assert.ok(chart.qualityVsCost.length >= 1);
  assert.deepEqual([...REPORT_FORMATS].sort(), ['chart', 'csv', 'html', 'json', 'md']);
  assert.throws(() => renderReport(rep, 'pdf'), /unknown report format/);
  assert.deepEqual(Object.keys(PRIMARY), ['detect', 'falsify', 'exploit', 'patch']);
});

test('scoreboard: only model arms, median per-call cost and latency, a newer run replaces an older one for the same model and dataset', async () => {
  const arms = [baseline, model('good', ['detect']), model('lazy', ['detect'])];
  const { run } = await runEval({ dataset: detectDs(), arms, tasks: ['detect'], repeats: 3, ...quiet, deps: { scanFn: stubScan } });
  const entries = scoreboardFromRun(run, arms);
  assert.deepEqual(entries.map((e) => e.model).sort(), ['fake/good', 'fake/lazy']);
  const g = entries.find((e) => e.model === 'fake/good');
  assert.equal(g.routerTask, 'hunt'); assert.equal(g.quality.mean, 1); assert.equal(g.quality.n, 3); assert.equal(g.quality.representative, true);
  assert.ok(Math.abs(g.medianCostUsd - 0.0081) < 1e-9); assert.equal(g.costKnown, true); assert.ok(g.medianLatencyMs > 0);
  assert.equal(g.evidence.runId, run.runId);
  const merged = mergeScoreboard(mergeScoreboard(null, entries), entries.map((e) => ({ ...e, quality: { ...e.quality, mean: 0.5 } })));
  assert.equal(merged.entries.length, 2); assert.equal(merged.entries.find((e) => e.model === 'fake/good').quality.mean, 0.5);
});
