// Contract test for the strategic metrics (docs/reference/strategic-metrics.md): the real command over a real scan holds the report to the
// page in both directions, and the counting rules the page states are pinned with hand-computed inputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields, REPO } from '../helpers/contract-page.js';
import {
  assuranceCoverage, evidenceConversion, evidenceStateOf, verifiedRemediationRate, securityLearningRate, computeStrategicMetrics,
  EVIDENCE_STATES, STRATEGIC_METRICS_SCHEMA, STRATEGIC_METRICS_VERSION,
} from '../../src/posture/strategic-metrics.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/strategic-metrics.md');

const dir = mkTestTmp('agsec-metrics-contract-');
fs.cpSync(path.join(REPO, 'examples', 'assurance-demo'), dir, { recursive: true });
const run = (...a) => spawnSync(process.execPath, [CLI, ...a], { cwd: dir, encoding: 'utf8', timeout: 300000, env: { ...process.env, NO_COLOR: '1' } });
run('scan', '.', '--format', 'json');
const cmd = run('metrics', '.', '--format', 'json');
const report = JSON.parse(cmd.stdout);

test('contract: the command reports exactly the documented fields at every level', () => {
  assert.equal(cmd.status, 0, cmd.stderr);
  sameFields(report, fieldsUnder(PAGE, 'Report'), 'report');
  sameFields(report.assuranceCoverage, fieldsUnder(PAGE, 'Assurance Coverage'), 'assurance coverage', ['reason']);
  sameFields(report.evidenceConversion, fieldsUnder(PAGE, 'Evidence Conversion'), 'evidence conversion');
  sameFields(report.verifiedRemediationRate, fieldsUnder(PAGE, 'Verified Remediation Rate'), 'verified remediation rate');
  assert.equal(report.schema, STRATEGIC_METRICS_SCHEMA);
  assert.equal(report.version, STRATEGIC_METRICS_VERSION);
  assert.ok(fieldsUnder(PAGE, 'Assurance Coverage').includes('reason'), 'the optional reason is documented');
  assert.deepEqual(Object.keys(report.evidenceConversion.byState), [...EVIDENCE_STATES]);
  for (const s of EVIDENCE_STATES) assert.ok(PAGE.includes(`\`${s}\``), `${s} is on the page`);
});

test('contract: every figure carries its numerator and denominator, and the numbers agree with the scan', () => {
  const scan = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
  const ec = report.evidenceConversion;
  assert.equal(ec.denominator, scan.findings.length);
  assert.equal(Object.values(ec.byState).reduce((a, b) => a + b, 0), scan.findings.length, 'every finding lands in exactly one state');
  assert.equal(ec.numerator, scan.findings.length - ec.byState['single-signal']);
  const ac = report.assuranceCoverage;
  assert.equal(ac.files.denominator, scan.scanHealth.files.expected);
  assert.equal(ac.analyzers.denominator, scan.scanHealth.analyzers.expected);
  assert.equal(report.verifiedRemediationRate.denominator, 0, 'no fix attempts were recorded in this project');
  assert.equal(report.verifiedRemediationRate.percent, null, 'an empty denominator is null, never 0% or 100%');
});

test('contract: the learning rate is reported as unmeasured, with the reason', () => {
  assert.equal(report.securityLearningRate.status, 'unmeasured');
  assert.match(report.securityLearningRate.reason, /independent/);
  assert.equal(securityLearningRate().status, 'unmeasured');
});

test('contract: one status vocabulary on every metric, and the scope names the scan and the attempt window', () => {
  sameFields(report.scope, fieldsUnder(PAGE, 'Scope'), 'scope');
  assert.equal(report.scope.kind, 'per-scan');
  const scan = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
  assert.equal(report.scope.scanId, scan.scanId);
  assert.equal(report.scope.scanStartedAt, scan.startedAt);
  assert.deepEqual(report.scope.attempts, { from: null, to: null, recorded: 0 });
  assert.match(report.scope.trend, /not a trend/);
  const words = new Set(['measured', 'partial', 'unmeasured']);
  for (const k of ['assuranceCoverage', 'evidenceConversion', 'verifiedRemediationRate', 'securityLearningRate']) assert.ok(words.has(report[k].status), `${k}: ${report[k].status}`);
  assert.equal(report.verifiedRemediationRate.status, 'unmeasured', 'no attempts: unmeasured, not 0%');
  assert.equal(evidenceConversion([]).status, 'unmeasured');
  assert.equal(evidenceConversion([{ parser: 'REGEX' }]).status, 'measured');
});

test('contract: repeated attempts on one finding count once, by the latest; partial and failed attempts stay in the denominator; the window is the recorded span', () => {
  const r = verifiedRemediationRate([
    { at: '2026-11-01T10:00:00.000Z', stableId: 'F1', ok: false, verifiedFull: false },
    { at: '2026-11-01T11:00:00.000Z', stableId: 'F1', ok: true, verifiedFull: false },
    { at: '2026-11-01T12:00:00.000Z', stableId: 'F1', ok: true, verifiedFull: true },
    { at: '2026-11-02T09:00:00.000Z', stableId: 'F2', ok: true, verifiedFull: false },
    { at: '2026-11-02T08:00:00.000Z', stableId: 'F3', ok: false, verifiedFull: false },
    { ok: true, verifiedFull: true },
  ]);
  assert.equal(r.recorded, 6);
  assert.equal(r.repeated, 2, 'two earlier attempts on F1 were replaced by the latest');
  assert.equal(r.denominator, 4, 'F1, F2, F3 and the attempt with no finding id');
  assert.equal(r.numerator, 2, 'the latest F1 attempt and the anonymous one');
  assert.equal(r.percent, 50);
  assert.equal(r.failed, 2, 'F2 (partial) and F3 (failed) stay in the denominator');
  assert.deepEqual(r.window, { from: '2026-11-01T10:00:00.000Z', to: '2026-11-02T09:00:00.000Z' });
  // out-of-order timestamps: the latest by time wins, not the last line
  const reorder = verifiedRemediationRate([{ at: '2026-11-03T00:00:00.000Z', stableId: 'F1', verifiedFull: true }, { at: '2026-11-01T00:00:00.000Z', stableId: 'F1', verifiedFull: false }]);
  assert.deepEqual([reorder.numerator, reorder.denominator], [1, 1]);
  // no timestamps: the last line wins
  const positional = verifiedRemediationRate([{ stableId: 'F1', verifiedFull: true }, { stableId: 'F1', verifiedFull: false }]);
  assert.deepEqual([positional.numerator, positional.denominator, positional.window], [0, 1, { from: null, to: null }]);
  assert.equal(verifiedRemediationRate([]).status, 'unmeasured');
  assert.equal(verifiedRemediationRate([]).recorded, 0);
});

test('contract: assurance coverage headline is the lower of files and analyzers, and a count the scan did not report is never zero', () => {
  const low = assuranceCoverage({ status: 'partial', files: { expected: 10, scanned: 10, skipped: 0, unanalysed: 0, timedOut: 4 }, analyzers: { expected: 100, completed: 100, failed: 0, timedOut: 0, skippedByPolicy: 0 } });
  assert.equal(low.files.numerator, 6);
  assert.equal(low.files.percent, 60);
  assert.equal(low.analyzers.percent, 100);
  assert.equal(low.percent, 60, 'a complete analyzer set cannot hide files that never finished');
  assert.equal(low.status, 'measured');
  const noFiles = assuranceCoverage({ files: { expected: null, scanned: 5 }, analyzers: { expected: 10, completed: 9 } });
  assert.equal(noFiles.files, null);
  assert.equal(noFiles.status, 'partial');
  assert.equal(noFiles.percent, 90);
  assert.match(noFiles.reason, /files/);
  const none = assuranceCoverage(null);
  assert.equal(none.status, 'unmeasured');
  assert.equal(none.percent, null);
  assert.equal(assuranceCoverage({ files: { expected: 0, scanned: 0 }, analyzers: { expected: 0, completed: 0 } }).percent, null, 'nothing requested is not 100%');
});

test('contract: evidence states are counted at the strongest evidence present', () => {
  assert.equal(evidenceStateOf({ parser: 'REGEX' }), 'single-signal');
  assert.equal(evidenceStateOf({ parser: 'REGEX', corroboration: { by: ['REGEX', 'JS-FW'] } }), 'corroborated');
  assert.equal(evidenceStateOf({ parser: 'REGEX', corroboration: { by: ['REGEX', 'REGEX'] } }), 'single-signal', 'one analyzer twice is still one analyzer');
  assert.equal(evidenceStateOf({ parser: 'IR-TAINT' }), 'taint-confirmed');
  assert.equal(evidenceStateOf({ parser: 'IR-TAINT', proofTier: 'execution-proven' }), 'execution-proven');
  assert.equal(evidenceStateOf({ parser: 'REGEX', proof: { verdict: 'unproven' } }), 'single-signal', 'an unproven verdict is not evidence');
  const ec = evidenceConversion([{ parser: 'REGEX' }, { parser: 'REGEX', corroboration: { by: ['a', 'b'] } }, { parser: 'IR-TAINT' }, null, 'x']);
  assert.deepEqual([ec.numerator, ec.denominator, ec.percent], [2, 3, 66.7]);
  assert.equal(evidenceConversion([]).percent, null);
  assert.equal(evidenceConversion(undefined).denominator, 0);
});

test('contract: an attempt is fully verified only with the re-scan, the tests and the replay, and a re-scan alone is shown separately', () => {
  const r = verifiedRemediationRate([
    { ok: true, rescanOk: true, testsRan: true, testsOk: true, pocOk: true },
    { ok: true, rescanOk: true, testsRan: false, pocOk: false },
    { ok: true, rescanOk: true, testsRan: true, testsOk: true, pocOk: false },
    { ok: false, rescanOk: false },
  ]);
  assert.deepEqual([r.numerator, r.denominator, r.percent], [1, 4, 25]);
  assert.equal(r.disappearedOnly, 1, 'the attempt that passed only the re-scan is the shape a code-deleting fix produces');
  assert.equal(verifiedRemediationRate([{ verifiedFull: true }, { verifiedFull: false }]).percent, 50);
  assert.equal(verifiedRemediationRate([]).percent, null);
});

test('contract: no metric is reported from a scan that failed its integrity check, and no scan is a usage problem', () => {
  const bad = mkTestTmp('agsec-metrics-bad-');
  fs.cpSync(dir, bad, { recursive: true });
  fs.writeFileSync(path.join(bad, '.agentic-security', 'last-scan.json.sig'), '0'.repeat(64));
  const r = spawnSync(process.execPath, [CLI, 'metrics', '.'], { cwd: bad, encoding: 'utf8' });
  assert.equal(r.status, 1);
  const empty = mkTestTmp('agsec-metrics-empty-');
  fs.writeFileSync(path.join(empty, 'package.json'), '{"name":"e","version":"1.0.0"}');
  assert.equal(spawnSync(process.execPath, [CLI, 'metrics', '.'], { cwd: empty, encoding: 'utf8' }).status, 2);
  assert.equal(run('metrics', '.', '--format', 'xml').status, 2);
  for (const code of ['`0`', '`1`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`), `exit ${code} is on the page`);
});

test('contract: the text form names the figures and the learning rate, and the comparison fails when a field is added or dropped', () => {
  const text = run('metrics', '.').stdout;
  for (const w of ['Assurance Coverage', 'Evidence Conversion', 'Verified Remediation Rate', 'Security Learning Rate: not measured']) assert.ok(text.includes(w), w);
  const doc = fieldsUnder(PAGE, 'Report');
  assert.throws(() => sameFields({ ...report, extra: 1 }, doc, 'report'));
  const { version, ...rest } = report;
  assert.throws(() => sameFields(rest, doc, 'report'));
  assert.equal(version, 1);
  assert.deepEqual(Object.keys(computeStrategicMetrics()).sort(), [...doc].sort());
});
