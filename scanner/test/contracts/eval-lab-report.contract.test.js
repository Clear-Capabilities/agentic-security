// Contract test for the Eval Lab report (docs/reference/eval-lab-report.md).
//
// The page is the contract. The test builds a report from a stand-in model arm and the deterministic baseline, then holds every level of
// it to the page's tables in both directions, pins the schema constants, and proves the comparison can fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDatasetFile } from '../../src/posture/evaluation/lab/dataset.js';
import { runEval } from '../../src/posture/evaluation/lab/run.js';
import { summarizeRun, REPORT_FORMATS } from '../../src/posture/evaluation/lab/report.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/eval-lab');
const PAGE = readPage('docs/reference/eval-lab-report.md');
const price = { inputPerMTok: 3, outputPerMTok: 15 };
const model = { id: 'm-good', kind: 'model', tasks: ['detect', 'falsify'], model: { id: 'good', provider: 'fake', local: true }, adapter: { type: 'command', argv: [process.execPath, path.join(FX, 'fake-arm.mjs'), 'good'], timeoutMs: 8000 }, price };
const baseline = { id: 'baseline', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner', layer: 'deep-taint' } };

const res = await runEval({
  dataset: loadDatasetFile(path.join(FX, 'detect/dataset.json')), arms: [baseline, model], tasks: ['detect', 'falsify'], repeats: 3,
  concurrency: 4, timeoutMs: 20000, deps: { scanFn: async () => ({ findings: [] }) },
});
const report = summarizeRun(res.run);
const arm = report.arms.find(a => a.id === 'm-good');

test('contract: the report has exactly the documented fields at every level', () => {
  sameFields(report, fieldsUnder(PAGE, 'Report'), 'report');
  sameFields(report.header, fieldsUnder(PAGE, 'Header'), 'header');
  sameFields(arm, fieldsUnder(PAGE, 'Arm'), 'arm');
  sameFields(arm.tasks.detect, fieldsUnder(PAGE, 'Detect task'), 'detect task');
  sameFields(arm.tasks.falsify, fieldsUnder(PAGE, 'Falsify task'), 'falsify task');
  sameFields(arm.economics, fieldsUnder(PAGE, 'Economics'), 'economics');
  sameFields(arm.intelligencePerDollar, fieldsUnder(PAGE, 'Intelligence per dollar'), 'intelligence per dollar');
  sameFields(arm.dollarsPer, ['truePositive', 'confirmedExploit', 'verifiedFix'], 'dollarsPer');
  for (const k of Object.keys(arm.dollarsPer)) assert.ok(PAGE.includes(`\`${k}\``), `${k} is on the page`);
});

test('contract: every statistic has the documented shape, and an empty one says why', () => {
  const doc = fieldsUnder(PAGE, 'Statistic');
  sameFields(arm.tasks.detect.f1, doc, 'a measured statistic', ['note']);
  assert.ok(doc.includes('note'), 'the optional note is documented');
  const base = report.arms.find(a => a.id === 'baseline');
  assert.equal(base.tasks.detect.f1.representative, false, 'one deterministic run is not representative');
  assert.equal(arm.tasks.detect.f1.representative, true, 'three runs are');
});

test('contract: schema constants, formats and the primary statistic per task', () => {
  assert.equal(report.schema, 'agentic-security/eval-lab-report');
  assert.equal(report.version, 1);
  assert.ok(PAGE.includes('`agentic-security/eval-lab-report`'));
  assert.deepEqual([...REPORT_FORMATS].sort(), ['chart', 'csv', 'html', 'json', 'md']);
  assert.deepEqual(Object.keys(arm.primary).sort(), ['detect', 'falsify']);
});

test('contract: a cost that was not reported is null with the count of such attempts, never zero', () => {
  const free = { ...model, id: 'm-nocost', price: undefined };
  return runEval({ dataset: loadDatasetFile(path.join(FX, 'detect/dataset.json')), arms: [free], tasks: ['detect'], repeats: 3, concurrency: 4, timeoutMs: 20000 })
    .then(r => {
      const a = summarizeRun(r.run).arms[0];
      assert.ok(a.economics.unknownCostAttempts > 0);
      assert.notEqual(a.economics.usd.mean, 0, 'an unknown cost is not reported as free');
    });
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Report');
  assert.throws(() => sameFields({ ...report, extra: 1 }, doc, 'report'));
  const { notes, ...rest } = report;
  assert.throws(() => sameFields(rest, doc, 'report'));
  assert.ok(Array.isArray(notes));
});
