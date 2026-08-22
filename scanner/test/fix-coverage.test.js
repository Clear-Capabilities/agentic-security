// Gate for published fix coverage (PRD F6.5).
//
// "A remediation feature that silently attempts everything is less trustworthy
// than one that declines 40% and says so." The number this replaces was computed
// only over fixes that were ATTEMPTED, so a finding synthesis never tried simply
// did not appear — the denominator quietly excluded every hard case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  fixCoverage, fixBucketOf, renderFixCoverage, DECLINED_TO_FIX,
} from '../src/posture/fix-coverage.js';

test('an authorisation finding is DECLINED, not silently attempted', () => {
  // The correct authz rule is a product decision. A scanner that invents one is
  // guessing at intent, and a wrong authz patch fails OPEN — the direction that
  // makes this worse than not trying.
  for (const fam of ['broken-access-control', 'idor', 'broken-authz']) {
    assert.equal(fixBucketOf({ family: fam }), 'declined', `${fam} must be declined`);
  }
});

test('every declined family states a REASON', () => {
  const unreasoned = Object.entries(DECLINED_TO_FIX)
    .filter(([, why]) => typeof why !== 'string' || why.trim().length < 40)
    .map(([f]) => f);
  assert.deepEqual(unreasoned, [], 'declined families needing a real reason');
});

test('"model-attemptable" is NOT counted as fixed', () => {
  // The distinction the bucket names exist for: attemptable is a promise to try,
  // not a claim of success. Whether the attempt works is fix-metrics.js's
  // question, measured from real runs.
  const cov = fixCoverage([{ family: 'sql-injection' }]);
  assert.equal(cov.model.n, 1);
  assert.match(cov.meaning, /NOT known to succeed/);
});

test('the three buckets partition the finding set exactly', () => {
  const findings = [
    { family: 'idor' }, { family: 'sql-injection' },
    { family: 'concurrency-bug' }, { family: 'xss' }, {},
  ];
  const cov = fixCoverage(findings);
  assert.equal(
    cov.deterministic.n + cov.model.n + cov.declined.n,
    findings.length,
    'a dropped finding always flatters whichever share is published',
  );
});

test('without source, the deterministic share is disclosed as a LOWER bound', () => {
  // Guessing "deterministic" without being able to run the synthesiser would
  // overstate the strongest bucket. Falling back to model-attemptable and SAYING
  // SO is the honest degradation.
  const cov = fixCoverage([{ family: 'weak-crypto', file: 'a.js' }]);
  assert.equal(cov.deterministicChecked, false);
  assert.match(renderFixCoverage(cov), /LOWER bound/);
});

test('a deterministic patch is recognised when source IS supplied', () => {
  // Positive control: without this the module could bucket everything as
  // model-attemptable and every other assertion would still pass.
  const file = 'a.js';
  const src = "const crypto = require('crypto');\nconst h = crypto.createHash('md5').update(x).digest('hex');\n";
  const cov = fixCoverage(
    [{ family: 'weak-crypto', file, line: 2, cwe: 'CWE-327', vuln: 'Weak Hash (MD5)' }],
    { [file]: src },
  );
  assert.equal(cov.deterministicChecked, true);
  assert.equal(
    cov.deterministic.n + cov.model.n, 1,
    'the finding must land in exactly one of the attemptable buckets',
  );
});

test('every share carries its denominator', () => {
  const cov = fixCoverage([{ family: 'idor' }, { family: 'xss' }]);
  for (const b of ['deterministic', 'model', 'declined']) assert.equal(cov[b].d, 2);
});

test('the rendered table prints the decline reasons, not just counts', () => {
  const md = renderFixCoverage(fixCoverage([{ family: 'idor' }]));
  assert.match(md, /1\/1/);
  assert.match(md, /Why each family is declined/);
  assert.match(md, /not recoverable from the code/);
});

test('an empty finding set does not fabricate a rate', () => {
  assert.match(renderFixCoverage(fixCoverage([])), /No findings/);
});
