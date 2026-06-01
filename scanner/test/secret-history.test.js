// R15 — git-history secret sweep tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractAddedLines, scanHistoryDiff, sweepGitHistory } from '../src/posture/secret-history.js';
import { scanCredentials } from '../src/secrets/index.js';

// Build a detectable Stripe-shaped key at runtime so the two halves never sit
// adjacent in source (GitHub push protection scans source bytes, not the
// assembled value). Mirrors smoke.test.js.
function assembleStripeKey() {
  return 'sk_' + 'live_' + ('0123456789' + 'abcdefghij' + 'ABCD');
}

test('extractAddedLines: keeps + lines, drops the +++ header', () => {
  const diff = ['--- a/f', '+++ b/f', '@@ -1 +1,2 @@', '+const k = "v";', ' context', '-removed'].join('\n');
  assert.equal(extractAddedLines(diff), 'const k = "v";');
});

test('scanHistoryDiff: attributes commit + historical metadata (stub detector)', () => {
  const stub = (fp, txt) => (/SECRET/.test(txt) ? [{ id: 's1', vuln: 'Hardcoded Secret', severity: 'high', description: 'x' }] : []);
  const f = scanHistoryDiff('+const k = "SECRET";', 'abc1234def56', stub);
  assert.equal(f.length, 1);
  assert.equal(f[0].commit, 'abc1234def56');
  assert.equal(f[0]._historical, true);
  assert.match(f[0].vuln, /in git history/);
  assert.match(f[0].remediation, /[Rr]otate/);
});

test('scanHistoryDiff: real detector finds an assembled secret in an added line', () => {
  const diff = `+const stripe = "${assembleStripeKey()}";`;
  const f = scanHistoryDiff(diff, 'deadbeef0001', scanCredentials);
  assert.ok(f.length >= 1, `expected the assembled key to be detected, got ${f.length}`);
  assert.ok(f.every(x => x._historical && x.commit === 'deadbeef0001'));
});

test('scanHistoryDiff: nothing on a diff with no added secret', () => {
  assert.equal(scanHistoryDiff('+const x = 1;\n-old line', 'c0ffee', scanCredentials).length, 0);
});

test('sweepGitHistory: runs on this repo without throwing, returns an array', () => {
  const r = sweepGitHistory(process.cwd(), scanCredentials, { maxCommits: 5 });
  assert.ok(Array.isArray(r));
});

test('sweepGitHistory: degrades to [] for a non-git path / bad detector', () => {
  assert.deepEqual(sweepGitHistory('/nonexistent-xyz', scanCredentials, { maxCommits: 1 }), []);
  assert.deepEqual(sweepGitHistory(process.cwd(), null, {}), []);
});
