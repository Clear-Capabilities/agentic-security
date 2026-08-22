// Gate for published proof coverage (PRD F7.2).
//
// The number this replaces was the proof RATE — computed over the findings that
// happened to be provable, which makes a small provable subset look like
// strength. Measured on the CVE corpus (215 roots, 280 findings) the real shape
// is 19% provable / 13% declined on purpose / 68% not yet classified.
//
// The three-bucket split is the whole point and these tests defend it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  proofCoverage, bucketOf, renderProofCoverage, INDETERMINATE_BY_CLASS,
} from '../src/posture/proof-coverage.js';

test('a supported class is provable', () => {
  assert.equal(bucketOf({ family: 'sql-injection' }), 'provable');
  assert.equal(bucketOf({ family: 'command-injection' }), 'provable');
});

test('a rule-slug-suffixed family still resolves to its proof class', () => {
  // Detectors emit `<family>-<rule-slug>`; matching the exact name only would
  // silently drop most real findings into "unclassified" and flatter the
  // backlog number.
  assert.equal(bucketOf({ family: 'sql-injection-via-string-concat' }), 'provable');
});

test('a deliberately-declined class is indeterminate, not unclassified', () => {
  for (const cls of ['ssrf', 'xss', 'idor']) {
    assert.equal(bucketOf({ family: cls }), 'indeterminate', `${cls} is declined on purpose`);
  }
});

test('every declined class states a REASON', () => {
  // A decline with no reason is indistinguishable from an oversight, which is
  // exactly the distinction this module exists to publish.
  const unreasoned = Object.entries(INDETERMINATE_BY_CLASS)
    .filter(([, why]) => typeof why !== 'string' || why.trim().length < 40)
    .map(([c]) => c);
  assert.deepEqual(unreasoned, [], 'declined classes needing a real reason');
});

test('an unknown class is unclassified — NOT folded into indeterminate', () => {
  // The load-bearing separation. Folding these together would let "we have not
  // looked at this" borrow the credibility of "we looked and it cannot be done".
  assert.equal(bucketOf({ family: 'header-hardening' }), 'unclassified');
  assert.equal(bucketOf({ family: 'some-brand-new-rule' }), 'unclassified');
});

test('a finding with no family is unclassified, never silently provable', () => {
  assert.equal(bucketOf({}), 'unclassified');
  assert.equal(bucketOf({ family: '' }), 'unclassified');
  assert.equal(bucketOf(null), 'unclassified');
});

test('the three buckets partition the finding set exactly', () => {
  // If they ever stop summing, some findings are being counted twice or dropped
  // — and a dropped finding always flatters whichever rate is being published.
  const findings = [
    { family: 'sql-injection' }, { family: 'command-injection' },
    { family: 'ssrf' }, { family: 'xss' },
    { family: 'header-hardening' }, {},
  ];
  const cov = proofCoverage(findings);
  assert.equal(cov.total, findings.length);
  assert.equal(
    cov.provable.n + cov.indeterminate.n + cov.unclassified.n + cov.ceiling.outOfScope.n,
    findings.length,
    'all FOUR buckets must partition the set — the ceiling bucket included',
  );
});

test('every share carries its denominator', () => {
  const cov = proofCoverage([{ family: 'sql-injection' }, { family: 'xss' }]);
  for (const b of ['provable', 'indeterminate', 'unclassified']) {
    assert.equal(cov[b].d, 2, `${b} must carry the denominator`);
  }
});

test('the rendered table reports counts with denominators and the decline reasons', () => {
  const cov = proofCoverage([{ family: 'ssrf' }, { family: 'sql-injection' }, { family: 'x-unknown' }]);
  const md = renderProofCoverage(cov);
  assert.match(md, /1\/3/, 'a share must never appear without its denominator');
  assert.match(md, /Why each class is declined/);
  assert.match(md, /confinement talking/, 'the SSRF reason must be printed, not just the count');
});

test('an empty finding set does not fabricate a rate', () => {
  const md = renderProofCoverage(proofCoverage([]));
  assert.match(md, /No findings/);
  assert.doesNotMatch(md, /100%|0%/, 'no percentage over an empty denominator');
});

// ── The stated ceiling (Feature 7 exit gate) ───────────────────────────────
//
// The in-process harness is JavaScript-only. Measured on the CVE corpus, 204 of
// 280 findings are Python / Java / C# / PHP / Kotlin / Go / Ruby — so proof
// coverage is 26% of ALL findings but 96% of the ones the harness can reach.
// Publishing only the first understates the harness; only the second overstates
// the product. Both, with denominators, or the number means whatever the reader
// assumes.

test('a non-JS finding is out-of-scope, NOT unclassified backlog', () => {
  // The distinction that matters: backlog implies "awaiting work". A Python
  // finding is not awaiting work on this harness — it is unreachable by it.
  assert.equal(bucketOf({ family: 'sql-injection', file: 'app.py' }), 'out-of-scope');
  assert.equal(bucketOf({ family: 'header-hardening', file: 'Main.java' }), 'out-of-scope');
});

test('language is decided BEFORE the proof class', () => {
  // A Python SQL-injection finding must not read as provable however good the
  // SQL class is. Checking the class first would report a ceiling case as a
  // capability.
  assert.equal(bucketOf({ family: 'sql-injection', file: 'a.py' }), 'out-of-scope');
  assert.equal(bucketOf({ family: 'sql-injection', file: 'a.js' }), 'provable');
});

test('every JS flavour the harness loads counts as reachable', () => {
  for (const f of ['a.js', 'a.cjs', 'a.mjs', 'a.jsx', 'a.ts', 'a.tsx']) {
    assert.notEqual(bucketOf({ family: 'sql-injection', file: f }), 'out-of-scope', `${f} must be reachable`);
  }
});

test('a finding with no file does NOT claim a ceiling', () => {
  // Unknown is not the same as unreachable. Guessing here would inflate the
  // ceiling and understate the backlog.
  assert.notEqual(bucketOf({ family: 'header-hardening' }), 'out-of-scope');
});

test('provable is reported both over all findings and over reachable ones', () => {
  const cov = proofCoverage([
    { family: 'sql-injection', file: 'a.js' },
    { family: 'sql-injection', file: 'b.py' },
    { family: 'header-hardening', file: 'c.js' },
  ]);
  assert.deepEqual({ n: cov.provable.n, d: cov.provable.d }, { n: 1, d: 3 }, 'share of ALL findings');
  assert.deepEqual(cov.provable.ofReachable, { n: 1, d: 2 }, 'share of REACHABLE findings');
});

test('the ceiling names the languages it excluded', () => {
  const cov = proofCoverage([
    { family: 'x', file: 'a.py' }, { family: 'x', file: 'b.py' }, { family: 'x', file: 'c.java' },
  ]);
  assert.deepEqual(cov.ceiling.outOfScope.byExtension, { '.py': 2, '.java': 1 });
  assert.match(cov.ceiling.reason, /JavaScript/);
});

test('the rendered table states the ceiling and BOTH readings of the rate', () => {
  const cov = proofCoverage([
    { family: 'sql-injection', file: 'a.js' }, { family: 'x', file: 'b.py' },
  ]);
  const md = renderProofCoverage(cov);
  assert.match(md, /Out of harness scope/);
  assert.match(md, /Ceiling/);
  assert.match(md, /1\/2 of ALL findings/);
  assert.match(md, /1\/1 of the reachable/);
});
