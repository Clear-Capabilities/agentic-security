// Independent evaluation population — unit tests for the scoring logic.
//
// This population is the only instrument in the repository that can support an
// accuracy claim, so its arithmetic has to be beyond argument. The I/O halves
// (mining advisories, fetching upstream trees, running the engine) are proven by
// hand and recorded in the commit; these tests pin the pure decisions.
//
// The bias throughout is that an entry we could not measure must never be
// counted against the engine, and a rate must never appear without its
// denominator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesCwe, scoreCounts, MIN_RELIABLE_N, purgeScanState, scanDirRaw } from '../../bench/independent/runner.mjs';
import { fixCommitOf, languageOf } from '../../bench/independent/mine.mjs';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// ------------------------------------------------------------ CWE matching
test('matching is exact on the CWE number, not a prefix', () => {
  assert.equal(matchesCwe([{ cwe: 'CWE-79' }], 'CWE-79'), true);
  // CWE-7 must not satisfy CWE-79, and CWE-790 must not either.
  assert.equal(matchesCwe([{ cwe: 'CWE-790' }], 'CWE-79'), false);
  assert.equal(matchesCwe([{ cwe: 'CWE-7' }], 'CWE-79'), false);
});

test('matching normalises case and whitespace but nothing else', () => {
  assert.equal(matchesCwe([{ cwe: ' cwe-89 ' }], 'CWE-89'), true);
});

test('a malformed label matches nothing', () => {
  // Guards against a mined entry with a junk CWE quietly scoring as a hit.
  for (const bad of ['', null, undefined, 'CWE-noinfo', 'sql-injection']) {
    assert.equal(matchesCwe([{ cwe: 'CWE-89' }], bad), false, `${bad} must not match`);
  }
});

test('matching ignores the engine\'s own vocabulary', () => {
  // Deliberate: scoring on vuln titles or families would grade the engine
  // against words it chose itself. Only the CWE counts.
  const findings = [{ vuln: 'SQL Injection', family: 'injection', cwe: 'CWE-89' }];
  assert.equal(matchesCwe(findings, 'CWE-89'), true);
  assert.equal(matchesCwe(findings, 'CWE-79'), false);
});

// ------------------------------------------------------------------ scoring
test('scoreCounts computes precision, recall and F1 with denominators', () => {
  const s = scoreCounts({ tp: 2, fp: 2, fn: 10, tn: 10 });
  assert.deepEqual(s.precision, { n: 2, d: 4, value: 0.5 });
  assert.deepEqual(s.recall, { n: 2, d: 12, value: 2 / 12 });
  assert.ok(Math.abs(s.f1 - 0.25) < 1e-9);
});

test('a rate with an empty denominator is null, never zero', () => {
  // 0/0 is "not measured". Rendering it as 0% would report a perfect failure
  // where nothing was tested at all.
  const s = scoreCounts({ tp: 0, fp: 0, fn: 0, tn: 0 });
  assert.equal(s.precision.value, null);
  assert.equal(s.recall.value, null);
  assert.equal(s.f1, null);
});

test('no true positives yields F1 null rather than a misleading zero', () => {
  const s = scoreCounts({ tp: 0, fp: 0, fn: 5, tn: 5 });
  assert.equal(s.precision.value, null, 'precision is unmeasured with no positives reported');
  assert.equal(s.recall.value, 0);
  assert.equal(s.f1, null);
});

test('every rate carries its {n, d} so a percentage cannot be quoted alone', () => {
  const s = scoreCounts({ tp: 3, fp: 1, fn: 1, tn: 4 });
  for (const r of [s.precision, s.recall]) {
    assert.equal(typeof r.n, 'number');
    assert.equal(typeof r.d, 'number');
  }
});

test('the reliability floor exists and is not trivially small', () => {
  assert.ok(MIN_RELIABLE_N >= 10, 'a handful of entries must not read as a measurement');
});

// ------------------------------------------------------------------- mining
test('an advisory with exactly one fix commit is admissible', () => {
  const fix = fixCommitOf({ references: ['https://github.com/o/r/commit/abc1234def5678'] });
  assert.deepEqual(fix, { owner: 'o', repo: 'r', sha: 'abc1234def5678' });
});

test('an advisory with no fix commit is rejected', () => {
  assert.equal(fixCommitOf({ references: ['https://example.com/advisory'] }), null);
});

test('an advisory with SEVERAL fix commits is rejected, not guessed at', () => {
  // Choosing which commit fixed it would be us making a judgement about our own
  // test set — the exact self-authorship this population exists to escape.
  const refs = [
    'https://github.com/o/r/commit/aaaaaaa',
    'https://github.com/o/r/commit/bbbbbbb',
  ];
  assert.equal(fixCommitOf({ references: refs }), null);
});

test('language is derived from the file, and an unknown extension is null', () => {
  assert.equal(languageOf('src/a.ts'), 'typescript');
  assert.equal(languageOf('src/a.py'), 'python');
  assert.equal(languageOf('README.md'), null);
});

// ------------------------------------------------------------ raw scan export
test('scanDirRaw returns both findings and the suppression log', async () => {
  // The independent-population harness scans code it doesn't own; state
  // writes must be off, same as runner.mjs's own main() (disableStateWrites())
  // — otherwise the scan mutates the very tree it's about to score.
  setStateWritesEnabled(false);
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'scandirraw-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
    // A file with an inline-ignore pragma: the engine finds it, then drops it,
    // logging the drop. This is the exact mechanism why-missed.mjs depends on.
    // Shape mirrors test/ignore-pragma.test.js's own positive control — a bare
    // tainted parameter is not enough to fire the shallow detector; it needs a
    // recognizable HTTP-source-to-exec-sink shape.
    fs.writeFileSync(
      path.join(d, 'app.js'),
      [
        "const { exec } = require('child_process');",
        'module.exports = function h(req, res) {',
        "  exec('ping ' + req.query.host, (e, o) => res.send(o)); // agentic-security-ignore",
        '};',
      ].join('\n')
    );
    const { findings, suppressions } = await scanDirRaw(d);
    assert.ok(Array.isArray(findings), 'findings must be an array');
    assert.ok(Array.isArray(suppressions), 'suppressions must be an array');
    assert.ok(
      suppressions.some(s => /inline pragma/.test(s.reason || '')),
      `expected an inline-pragma suppression entry, got: ${JSON.stringify(suppressions)}`
    );
  } finally { setStateWritesEnabled(true); fs.rmSync(d, { recursive: true, force: true }); }
});

test('purgeScanState removes .agentic-security before a scan', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'purge-'));
  try {
    const sd = path.join(d, '.agentic-security');
    fs.mkdirSync(sd, { recursive: true });
    fs.writeFileSync(path.join(sd, 'last-scan.json'), '{}');
    purgeScanState(d);
    assert.equal(fs.existsSync(sd), false);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
