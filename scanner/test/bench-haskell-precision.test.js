// The Haskell real-code precision gate (bench/haskell-precision/runner.mjs), exercised in BOTH directions on SYNTHETIC data: a good input must exit 0 and
// every kind of bad input must exit non-zero with the reason named. The fixtures (labels, scan results, a stand-in sealed result) are built in a temp
// directory; the gate is pointed at them with its test hooks, so nothing here reads, runs or lists the real sealed set.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkTestTmp } from './helpers/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, '..', '..', 'bench', 'haskell-precision', 'runner.mjs');

// Labelled sites. development: tuning (a TP and an FP), verification (an FP), remainder (an FP); fresh: a TP and an FP.
const DEV = [
  { project: 'alpha', file: 'src/A.hs', line: 10, vuln: 'OS Command Injection (shell string)', half: 'tuning', label: 'TP' },
  { project: 'alpha', file: 'src/A.hs', line: 20, vuln: 'Path Traversal (readFile)', half: 'tuning', label: 'FP' },
  { project: 'beta', file: 'src/B.hs', line: 5, vuln: 'Weak hash function (MD5/SHA-1)', half: 'verification', label: 'FP' },
];
const REMAINDER = { 'beta:src/B.hs:9:path-traversal': { label: 'FP', reason: 'x' } };
const FRESH = { 'gamma:src/G.hs:3:OS Command Injection (shell string)': { label: 'TP', reason: 'x' }, 'gamma:src/G.hs:4:path-traversal': { label: 'FP', reason: 'x' } };
const row = (file, line, vuln, severity = 'high', status = 'entrypoint-reachable', extra = {}) => ({ id: `r${file}${line}`, file, line, vuln, severity, parser: 'IR-TAINT', reachability: status ? { status, premise: null, holeReason: null } : null, ...extra });
const results = () => ({
  dev: {
    alpha: [row('src/A.hs', 10, 'OS Command Injection (shell string)', 'critical'), row('src/A.hs', 20, 'Path Traversal (readFile)', 'high', 'unknown')],
    beta: [row('src/B.hs', 5, 'Weak hash function (MD5/SHA-1)', 'info', 'external-api', { originalSeverity: 'medium' }), row('src/B.hs', 9, 'Path Traversal (readFile)', 'high', 'external-api')],
  },
  fresh: { gamma: [row('src/G.hs', 3, 'OS Command Injection (shell string)', 'critical'), row('src/G.hs', 4, 'Path Traversal (readFile)', 'high', 'entrypoint-reachable')] },
});

function fixture() {
  const root = mkTestTmp('hs-precision-gate-');
  const labels = join(root, 'labels'); const data = join(root, 'data');
  mkdirSync(labels, { recursive: true }); mkdirSync(data, { recursive: true });
  const lab = {};
  DEV.forEach((l, i) => { lab[i] = { index: i, ...l }; });
  writeFileSync(join(labels, 'labels.json'), JSON.stringify({ note: 'synthetic', labels: lab }));
  writeFileSync(join(labels, 'labels-remainder.json'), JSON.stringify({ note: 'synthetic', labels: REMAINDER }));
  writeFileSync(join(labels, 'fresh-labels.json'), JSON.stringify({ note: 'synthetic', labels: FRESH }));
  return { root, labels, data };
}
function writeResults(root, name, r) {
  for (const set of ['dev', 'fresh']) {
    const dir = join(root, `${name}-${set}`); mkdirSync(dir, { recursive: true });
    for (const [id, rows] of Object.entries(r[set])) writeFileSync(join(dir, `${id}.json`), JSON.stringify({ id, haskell: rows }));
  }
  return { dev: join(root, `${name}-dev`), fresh: join(root, `${name}-fresh`) };
}
const run = (fx, args, res = null) => spawnSync(process.execPath, [RUNNER, ...args, '--labels-dir', fx.labels, '--data-dir', fx.data, ...(res ? ['--dev-results', res.dev, '--fresh-results', res.fresh] : [])], { encoding: 'utf8' });
function recorded() {
  const fx = fixture();
  const good = writeResults(fx.root, 'good', results());
  const u = run(fx, ['--update-baseline'], good);
  assert.equal(u.status, 0, u.stderr + u.stdout);
  return { fx, good };
}
const clone = (o) => JSON.parse(JSON.stringify(o));

test('good input: recording a baseline and then checking the same results exits 0, and reports what it measured', () => {
  const { fx, good } = recorded();
  const c = run(fx, ['--check'], good);
  assert.equal(c.status, 0, c.stderr + c.stdout);
  assert.match(c.stdout, /live: matches/);
  assert.match(c.stdout, /PASS/);
  const base = JSON.parse(readFileSync(join(fx.data, 'baseline.json'), 'utf8'));
  assert.equal(base.aggregates['development-tuning'].tp, 1);
  assert.equal(base.aggregates['development-tuning'].flagged, 2);
  assert.equal(base.aggregates['development-verification'].loweredToInfo, 1, 'a finding lowered to info is not a flagged site');
  assert.equal(base.sealed, null);
  // with no scan to compare (no clones, no injected results) the stored checks still run and the live part says it was skipped
  const stored = run(fx, ['--check']);
  assert.equal(stored.status, 0, stored.stderr);
  assert.match(stored.stdout, /live: skipped/);
});

test('bad input: nothing recorded is a failure, never a pass', () => {
  const fx = fixture();
  const c = run(fx, ['--check']);
  assert.equal(c.status, 1);
  assert.match(c.stderr, /no recorded baseline/);
});

test('bad input: a regression fails (a true positive no longer reported), and so does an improvement nobody recorded (a false positive now gone)', () => {
  const { fx } = recorded();
  const lost = clone(results());
  lost.dev.alpha = lost.dev.alpha.filter((r) => r.line !== 10);
  const a = run(fx, ['--check'], writeResults(fx.root, 'lost-tp', lost));
  assert.equal(a.status, 1);
  assert.match(a.stderr, /LIVE: the engine's report differs from the recorded measurement/);
  assert.match(a.stderr, /alpha:src\/A.hs:10/);

  const better = clone(results());
  better.dev.alpha = better.dev.alpha.filter((r) => r.line !== 20);
  const b = run(fx, ['--check'], writeResults(fx.root, 'fp-gone', better));
  assert.equal(b.status, 1, 'an unrecorded improvement must fail too');
  assert.match(b.stderr, /alpha:src\/A.hs:20/);

  const lowered = clone(results());
  lowered.dev.alpha[1].severity = 'info';
  assert.equal(run(fx, ['--check'], writeResults(fx.root, 'lowered', lowered)).status, 1);
});

test('bad input: a new flagged site anywhere in a project (an unlabelled false positive) fails through the whole-report census', () => {
  const { fx } = recorded();
  const more = clone(results());
  more.dev.beta.push(row('src/Other.hs', 77, 'Whole input read into memory without a size limit'));
  const r = run(fx, ['--check'], writeResults(fx.root, 'extra', more));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /dev\/beta \(whole report, labelled or not\)/);
});

test('bad input: a change of reachability status or of a lowering is a difference', () => {
  const { fx } = recorded();
  const moved = clone(results());
  moved.dev.alpha[1].reachability.status = 'entrypoint-reachable';
  assert.equal(run(fx, ['--check'], writeResults(fx.root, 'status', moved)).status, 1);
  const unlowered = clone(results());
  delete unlowered.dev.beta[0].originalSeverity;
  assert.equal(run(fx, ['--check'], writeResults(fx.root, 'orig', unlowered)).status, 1);
});

test('invariant: a site labelled a TRUE POSITIVE in unreachable-in-project fails, whatever the baseline says, and cannot be recorded', () => {
  const { fx } = recorded();
  const wrong = clone(results());
  wrong.dev.alpha[0].reachability.status = 'unreachable-in-project';
  wrong.dev.alpha[0].severity = 'info';
  const r = run(fx, ['--check'], writeResults(fx.root, 'tp-unreachable', wrong));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /labelled TRUE POSITIVE is in unreachable-in-project/);
  const fresh = fixture();
  const u = run(fresh, ['--update-baseline'], writeResults(fresh.root, 'tp-unreachable', wrong));
  assert.equal(u.status, 1);
  assert.match(u.stderr, /refusing to record/);
  assert.equal(existsSync(join(fresh.data, 'baseline.json')), false, 'nothing was recorded');
  // a false positive in that bucket is exactly what the mechanism is for, and passes
  const ok = clone(results());
  ok.dev.alpha[1].reachability.status = 'unreachable-in-project';
  const fx2 = fixture();
  assert.equal(run(fx2, ['--update-baseline'], writeResults(fx2.root, 'fp-unreachable', ok)).status, 0);
});

test('bad input: hand-editing the baseline, the stored measurement or a label fails', () => {
  const { fx, good } = recorded();
  const basePath = join(fx.data, 'baseline.json');
  const original = readFileSync(basePath, 'utf8');
  const edited = JSON.parse(original); edited.aggregates['development-tuning'].tp = 2;
  writeFileSync(basePath, JSON.stringify(edited));
  const a = run(fx, ['--check'], good);
  assert.equal(a.status, 1);
  assert.match(a.stderr, /baseline.json disagrees with the stored measurement for "development-tuning"/);
  writeFileSync(basePath, original);
  assert.equal(run(fx, ['--check'], good).status, 0, 'restored');

  const mPath = join(fx.data, 'measurements', 'development.json');
  const mOriginal = readFileSync(mPath, 'utf8');
  const m = JSON.parse(mOriginal); delete m.measurement.sites['development-tuning'][Object.keys(m.measurement.sites['development-tuning'])[0]];
  writeFileSync(mPath, JSON.stringify(m));
  assert.equal(run(fx, ['--check'], good).status, 1);
  writeFileSync(mPath, mOriginal);

  const lp = join(fx.labels, 'fresh-labels.json');
  const fl = JSON.parse(readFileSync(lp, 'utf8')); fl.labels['gamma:src/G.hs:4:path-traversal'].label = 'TP';
  writeFileSync(lp, JSON.stringify(fl));
  const l = run(fx, ['--check'], good);
  assert.equal(l.status, 1);
  assert.match(l.stderr, /labels changed for "fresh"/);
});

test('sealed set: not touched until recorded; required by --require-sealed; once recorded its committed result must match exactly', () => {
  const { fx, good } = recorded();
  const sealed = join(fx.root, 'sealed'); mkdirSync(sealed);
  const sealedArg = ['--sealed-dir', sealed];
  const none = run(fx, ['--check', ...sealedArg], good);
  assert.equal(none.status, 0, none.stderr);
  assert.match(none.stdout, /sealed: no baseline recorded/);
  assert.equal(run(fx, ['--check', '--require-sealed', ...sealedArg], good).status, 1);

  const labels = [{ id: 'a', project: 'p', language: 'haskell', file: 'f.hs', line: 1, vuln: 'v', verdict: 'tp', evidence: 'e' }];
  const digest = crypto.createHash('sha256').update(JSON.stringify(labels)).digest('hex');
  writeFileSync(join(sealed, 'labels.json'), JSON.stringify({ labelsDigest: digest, labels }));
  const resultsDoc = { scannerVersion: '9.9.9', labelsDigest: digest, all: { 'all haskell projects': { flagged: 10, tp: 1, fp: 8, ambiguous: 1, unlabeled: 0, precision: 0.1111 } } };
  writeFileSync(join(sealed, 'results.json'), JSON.stringify(resultsDoc));
  const rec = run(fx, ['--update-sealed-baseline', ...sealedArg]);
  assert.equal(rec.status, 0, rec.stderr);
  assert.equal(run(fx, ['--check', '--require-sealed', ...sealedArg], good).status, 0);

  writeFileSync(join(sealed, 'results.json'), JSON.stringify({ ...resultsDoc, all: { 'all haskell projects': { ...resultsDoc.all['all haskell projects'], tp: 2 } } }));
  const drift = run(fx, ['--check', ...sealedArg], good);
  assert.equal(drift.status, 1);
  assert.match(drift.stderr, /SEALED: the committed result of the sealed set differs/);

  // results produced against other labels than the ones on disk cannot be recorded
  const fx3 = recorded().fx;
  const s3 = join(fx3.root, 'sealed'); mkdirSync(s3);
  writeFileSync(join(s3, 'labels.json'), JSON.stringify({ labelsDigest: digest, labels }));
  writeFileSync(join(s3, 'results.json'), JSON.stringify({ ...resultsDoc, labelsDigest: 'f'.repeat(64) }));
  const bad = run(fx3, ['--update-sealed-baseline', '--sealed-dir', s3]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /produced against labels with digest/);
});

test('usage: no mode is a usage error (exit 2), never a silent pass', () => {
  const r = spawnSync(process.execPath, [RUNNER], { encoding: 'utf8' });
  assert.equal(r.status, 2);
});
