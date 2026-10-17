// E6-01: every scan records structured, local, aggregate timings and error attribution, with its own cost measured.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createTelemetry, attributeErrors } from '../../src/pipeline/telemetry.js';
import { runDetector, setDetectorTimingSink } from '../../src/pipeline/detector-runner.js';
import { SummaryCache } from '../../src/dataflow/summaries.js';
import { runScan } from '../../src/runScan.js';
import { cleanup } from './helpers.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const APP = "const { exec } = require('child_process');\nconst express = require('express');\nconst app = express();\napp.get('/a', (req, res) => { exec('x ' + req.query.c); res.send('ok'); });\n";
async function project(n = 1) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6a-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
  for (let i = 0; i < n; i++) fs.writeFileSync(path.join(root, `a${i}.js`), APP.replace("'/a'", `'/a${i}'`));
  return root;
}
async function scanOf(root, env = {}) {
  const saved = {}; for (const k of Object.keys(env)) saved[k] = process.env[k];
  try { Object.assign(process.env, env); return (await runScan(root)).scan; } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}

test('stages, counters, memory and errors are recorded; durations are numbers; the record says nothing leaves the machine', () => {
  const t = createTelemetry();
  t.time('parse', () => { for (let i = 0; i < 1e5; i++); });
  t.record('detectors', 12.5); t.record('detectors', 7.5);
  t.count('files.scanned', 3); t.count('files.scanned'); t.set('cache.hits', 9);
  t.error('annotator:x', 'TypeError', 'boom   \n with   whitespace '.repeat(30));
  t.error('annotator:x', 'TypeError', 'again');
  const s = t.snapshot();
  assert.equal(s.schema, 'agentic-security/scan-telemetry'); assert.equal(s.deterministic, false);
  const det = s.stages.find((x) => x.name === 'detectors'); assert.equal(det.calls, 2); assert.equal(det.ms, 20);
  assert.ok(s.stages.find((x) => x.name === 'parse').ms >= 0);
  assert.deepEqual(s.counters, { 'cache.hits': 9, 'files.scanned': 4 });
  assert.ok(s.memory.rssHighWaterMb > 0 && s.memory.samples >= 3);
  assert.equal(s.errors.length, 1); assert.equal(s.errors[0].count, 2); assert.ok(s.errors[0].example.length <= 120 && !/\n/.test(s.errors[0].example));
  assert.match(s.outbound, /stays in the scan result/);
  assert.equal(s.stages[0].name, 'detectors', 'slowest first outside deterministic mode');
});

test('deterministic mode: every duration and memory figure is 0, the list is name-ordered, and two runs are byte-identical', () => {
  const run = () => { const t = createTelemetry({ deterministic: true }); t.record('b', 9); t.record('a', 3); t.detector('z', 4); t.detector('y', 1); t.count('n', 2); t.error('s', 'E', 'm'); return JSON.stringify(t.snapshot()); };
  const a = run(); const b = run();
  assert.equal(a, b);
  const s = JSON.parse(a);
  assert.deepEqual(s.stages.map((x) => x.name), ['a', 'b']); assert.ok(s.stages.every((x) => x.ms === 0));
  assert.equal(s.totalMs, 0); assert.equal(s.memory.rssHighWaterMb, 0); assert.equal(s.overhead.selfMs, 0);
  assert.deepEqual(s.detectors.map((x) => x.name), ['y', 'z']);
});

test('error attribution folds the existing error arrays into stage-attributed counts without changing them', () => {
  const t = createTelemetry({ deterministic: true });
  const annotatorErrors = [{ phase: 'annotateFoo', err: 'bad thing' }, { phase: 'annotateFoo', err: 'bad thing' }, { phase: 'annotateBar', err: 'other' }];
  const detectorErrors = [{ file: 'a.js', analyzer: 'scanXyz', err: 'oops' }];
  const before = JSON.stringify({ annotatorErrors, detectorErrors });
  attributeErrors(t, { annotatorErrors, detectorErrors, deepFailure: 'parser exploded', filesTimedOut: 2 });
  assert.equal(JSON.stringify({ annotatorErrors, detectorErrors }), before);
  const e = Object.fromEntries(t.snapshot().errors.map((x) => [x.stage, x.count]));
  assert.equal(e['annotator:annotateFoo'], 2); assert.equal(e['annotator:annotateBar'], 1); assert.equal(e['detector:scanXyz'], 1); assert.equal(e['deep-analysis'], 1); assert.equal(e['per-file-timeout'], 1);
  assert.ok(!JSON.stringify(t.snapshot().errors).includes('a.js'), 'no file path is recorded');
});

test('runDetector reports per-detector time only while a sink is set, and behaves exactly as before otherwise', () => {
  const errs = [];
  assert.equal(runDetector(errs, 'f.js', 'scanA', () => 5), 5);
  const seen = [];
  setDetectorTimingSink((name, ms) => seen.push([name, ms]));
  try {
    assert.equal(runDetector(errs, 'f.js', 'scanA', () => 7), 7);
    assert.equal(runDetector(errs, 'f.js', 'scanB', () => { throw new Error('x'); }), undefined);
  } finally { setDetectorTimingSink(null); }
  assert.deepEqual(seen.map((x) => x[0]), ['scanA', 'scanB']); assert.ok(seen.every((x) => x[1] >= 0));
  assert.equal(errs.length, 1);
  runDetector(errs, 'f.js', 'scanC', () => 1); assert.equal(seen.length, 2, 'unset sink: nothing recorded');
});

test('the summary cache counts hits and misses', () => {
  const c = new SummaryCache();
  assert.equal(c.get('q', new Set()), undefined); c.set('q', new Set(), { returnTainted: false });
  assert.ok(c.get('q', new Set())); assert.deepEqual(c.stats(), { hits: 1, misses: 1, size: 1 });
});

test('every real scan carries telemetry: stages for the file loop, linking and the annotators, per-detector time, and file counters', async () => {
  const root = await project(5);
  try {
    const s = await scanOf(root);
    const t = s.telemetry;
    assert.equal(t.schema, 'agentic-security/scan-telemetry'); assert.ok(t.totalMs > 0);
    const names = t.stages.map((x) => x.name);
    for (const n of ['detectors-per-file', 'cross-file-linking', 'index']) assert.ok(names.includes(n), `${n} in ${names.slice(0, 8).join()}`);
    assert.ok(names.filter((n) => n.startsWith('annotator:')).length >= 10);
    assert.ok(t.detectors.length >= 1 && t.detectors.every((d) => d.calls >= 1));
    assert.equal(t.counters['files.scanned'] >= 5, true);
    assert.ok(t.memory.rssHighWaterMb > 0);
    assert.deepEqual(t.errors, [], JSON.stringify(t.errors));
  } finally { cleanup(root); }
});

test('deep analysis time and summary-cache hit rate appear when deep analysis ran', async () => {
  const root = await project(3);
  try {
    const s = await scanOf(root, { AGENTIC_SECURITY_DEEP: '1' });
    const t = s.telemetry;
    assert.ok(t.stages.some((x) => x.name === 'deep-analysis'));
    assert.ok('cache.summary.hits' in t.counters && 'cache.summary.misses' in t.counters);
  } finally { cleanup(root); }
});

test('the cost of telemetry is measured and small: its own bookkeeping is under 3 percent of the scan', async () => {
  const root = await project(30);
  try {
    const s = await scanOf(root);
    const t = s.telemetry;
    assert.ok(t.overhead.selfMs >= 0);
    assert.ok(t.overhead.selfMs / t.totalMs < 0.03, `self ${t.overhead.selfMs} ms of ${t.totalMs} ms`);
  } finally { cleanup(root); }
});

test('deterministic scans give identical telemetry, and the module can send nothing: it imports no network or process module', async () => {
  const root = await project(4);
  try {
    const env = { AGENTIC_SECURITY_DETERMINISTIC: '1' };
    const a = JSON.stringify((await scanOf(root, env)).telemetry); const b = JSON.stringify((await scanOf(root, env)).telemetry);
    assert.equal(a, b);
    assert.equal(JSON.parse(a).deterministic, true);
  } finally { cleanup(root); }
  const src = fs.readFileSync(new URL('../../src/pipeline/telemetry.js', import.meta.url), 'utf8');
  assert.equal(/^\s*import\b/m.test(src), false, 'no imports at all');
  assert.equal(/\b(fetch|XMLHttpRequest|WebSocket|child_process|node:net|node:http)\b/.test(src.replace(/\/\/.*$/gm, '')), false);
});
