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

// Stage 4 correctness audit: scanHistoryDiff sets a git-history-specific
// `remediation` ("Rotate the credential now, then purge it from history...")
// via `{...f, remediation: '...'}` — but it never overrides `f.fix`, which
// the underlying detector (scanCredentials) already set to a generic
// "remove the hardcoded line" string. report/index.js's `_remediationOf`
// checks `.fix` BEFORE `.remediation`, so the generic advice always wins in
// the normalized/reported output — the historically-critical instruction
// ("removing it from HEAD alone is insufficient, purge history") never
// reaches any report format. This is actively misleading: a user acting on
// the generic advice alone would believe deleting the current line fixed
// the exposure, when the secret remains fully recoverable from git history.
// The commit hash and _historical marker are also dropped by the same
// merge's field allowlist.
test('secret-history: git-history-specific remediation and commit metadata survive normalizeFindings', async () => {
  const { normalizeFindings } = await import('../src/report/index.js');
  const diff = `+const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";`;
  const findings = scanHistoryDiff(diff, 'abc123def456', scanCredentials);
  assert.ok(findings.length >= 1, 'expected the git-history finding to be produced');
  const norm = normalizeFindings({ secrets: findings });
  const f = norm.find(n => n.kind === 'secret');
  assert.ok(f, 'expected the secret to survive normalizeFindings');
  assert.match(f.remediation, /purge it from history/i,
    `expected the git-history-specific remediation to win; got: ${f.remediation}`);
  assert.equal(f.commit, 'abc123def456');
});

test('sweepGitHistory: runs on this repo without throwing, returns an array', () => {
  const r = sweepGitHistory(process.cwd(), scanCredentials, { maxCommits: 5 });
  assert.ok(Array.isArray(r));
});

test('sweepGitHistory: degrades to [] for a non-git path / bad detector', () => {
  assert.deepEqual(sweepGitHistory('/nonexistent-xyz', scanCredentials, { maxCommits: 1 }), []);
  assert.deepEqual(sweepGitHistory(process.cwd(), null, {}), []);
});
