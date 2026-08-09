// Pre-publish release gate — unit tests for the pure decision functions.
//
// See scripts/release-check.mjs for the full design rationale. The shape
// mirrors test/scorecard-gate.test.js on purpose: the I/O + child-process
// path is proven by hand (broken and restored, both directions, exit codes
// captured) in the release report; these tests pin the decision logic on
// constructed inputs so a refactor cannot quietly loosen a check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKS,
  plannedCheckIds,
  evaluateWorkingTree,
  evaluateVersionConsistency,
  evaluateChangelogs,
  evaluateBundleIntegrity,
  evaluateHeadPushed,
  evaluateRemoteCi,
  evaluateCommandGate,
  extractVersionsFromSource,
} from '../../scripts/release-check.mjs';

// ---------------------------------------------------------------- check 1
test('release-gate — clean working tree passes', () => {
  const r = evaluateWorkingTree({ porcelain: '' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
});

test('release-gate — uncommitted change fails and names the file', () => {
  const r = evaluateWorkingTree({ porcelain: ' M scanner/src/engine.js\n' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /scanner\/src\/engine\.js/.test(e)));
  assert.ok(r.errors.some(e => /commit or stash/i.test(e)));
});

test('release-gate — untracked file fails too', () => {
  const r = evaluateWorkingTree({ porcelain: '?? scripts/scratch.mjs\n' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /scripts\/scratch\.mjs/.test(e)));
});

// ---------------------------------------------------------------- check 2
function versionSources(overrides = {}) {
  const base = {
    'scanner/package.json': ['1.2.3'],
    '.claude-plugin/plugin.json': ['1.2.3'],
    '.claude-plugin/marketplace.json': ['1.2.3', '1.2.3'],
    'CLAUDE.md': ['1.2.3'],
    'README.md': ['1.2.3'],
  };
  return Object.entries({ ...base, ...overrides })
    .map(([label, versions]) => ({ label, versions }));
}

test('release-gate — all version strings agree → pass, version reported', () => {
  const r = evaluateVersionConsistency({ sources: versionSources() });
  assert.equal(r.ok, true);
  assert.equal(r.version, '1.2.3');
  assert.deepEqual(r.errors, []);
});

test('release-gate — version mismatch in one file fails and names both values', () => {
  const r = evaluateVersionConsistency({
    sources: versionSources({ 'README.md': ['1.2.2'] }),
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /README\.md/.test(e) && /1\.2\.2/.test(e) && /1\.2\.3/.test(e)));
});

test('release-gate — marketplace.json half-bumped fails (both occurrences checked)', () => {
  const r = evaluateVersionConsistency({
    sources: versionSources({ '.claude-plugin/marketplace.json': ['1.2.3', '1.2.2'] }),
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /marketplace\.json/.test(e) && /1\.2\.2/.test(e)));
});

test('release-gate — a source with no version string at all fails', () => {
  const r = evaluateVersionConsistency({ sources: versionSources({ 'CLAUDE.md': [] }) });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /CLAUDE\.md/.test(e) && /no version/i.test(e)));
});

test('release-gate — version extraction pulls every occurrence from a source', () => {
  assert.deepEqual(
    extractVersionsFromSource('.claude-plugin/marketplace.json',
      '{"metadata":{"version":"9.9.9"},"plugins":[{"version":"9.9.8"}]}'),
    ['9.9.9', '9.9.8']
  );
  assert.deepEqual(extractVersionsFromSource('CLAUDE.md', '**Version:** 9.9.9  \n'), ['9.9.9']);
  assert.deepEqual(
    extractVersionsFromSource('README.md',
      '[![Version](https://img.shields.io/badge/version-9.9.9-blue)]()'),
    ['9.9.9']
  );
  assert.deepEqual(
    extractVersionsFromSource('scanner/package.json', '{"name":"x","version":"9.9.9"}'),
    ['9.9.9']
  );
});

// ---------------------------------------------------------------- check 3
test('release-gate — changelog entry present in both files → pass', () => {
  const r = evaluateChangelogs({
    version: '1.2.3',
    changelogs: [
      { label: 'CHANGELOG.md', content: '# Changelog\n\n## 1.2.3 — a title\n\nbody\n' },
      { label: 'scanner/CHANGELOG.md', content: '# Changelog\n\n## 1.2.3 — a title\n' },
    ],
  });
  assert.equal(r.ok, true);
});

test('release-gate — missing changelog entry fails and names the file', () => {
  const r = evaluateChangelogs({
    version: '1.2.3',
    changelogs: [
      { label: 'CHANGELOG.md', content: '## 1.2.3 — a title\n' },
      { label: 'scanner/CHANGELOG.md', content: '## 1.2.2 — older\n' },
    ],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /scanner\/CHANGELOG\.md/.test(e) && /1\.2\.3/.test(e)));
  assert.ok(!r.errors.some(e => /^CHANGELOG\.md/.test(e)));
});

test('release-gate — a generated changelog copy gets its own remedy', () => {
  const r = evaluateChangelogs({
    version: '1.2.3',
    changelogs: [{
      label: 'scanner/CHANGELOG.md',
      content: '## 1.2.2 — older\n',
      remedy: 'this file is generated — run the sync script.',
    }],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /generated/.test(e) && /sync/.test(e)));
});

test('release-gate — unreadable changelog fails, is not treated as satisfied', () => {
  const r = evaluateChangelogs({
    version: '1.2.3',
    changelogs: [{ label: 'CHANGELOG.md', content: null }],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /unreadable|missing/i.test(e)));
});

test('release-gate — a prefix version does not satisfy the entry (1.2.30 !== 1.2.3)', () => {
  const r = evaluateChangelogs({
    version: '1.2.3',
    changelogs: [{ label: 'CHANGELOG.md', content: '## 1.2.30 — later release\n' }],
  });
  assert.equal(r.ok, false);
});

// ---------------------------------------------------------------- check 4
test('release-gate — bundle sha matches sidecar → pass', () => {
  const r = evaluateBundleIntegrity({ bundleSha256: 'a'.repeat(64), sidecarSha256: 'a'.repeat(64) });
  assert.equal(r.ok, true);
});

test('release-gate — bundle sha mismatch fails and prints both hashes', () => {
  const r = evaluateBundleIntegrity({ bundleSha256: 'a'.repeat(64), sidecarSha256: 'b'.repeat(64) });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes('a'.repeat(64)) && e.includes('b'.repeat(64))));
  assert.ok(r.errors.some(e => /npm run build/.test(e)));
});

test('release-gate — missing bundle fails', () => {
  const r = evaluateBundleIntegrity({ bundleSha256: null, sidecarSha256: 'b'.repeat(64) });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /agentic-security\.mjs/.test(e)));
});

test('release-gate — missing sidecar fails (unverifiable is not satisfied)', () => {
  const r = evaluateBundleIntegrity({ bundleSha256: 'a'.repeat(64), sidecarSha256: null });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /\.sha256/.test(e)));
});

// ---------------------------------------------------------------- check 9
test('release-gate — HEAD contained in origin/main → pass', () => {
  const r = evaluateHeadPushed({
    headSha: 'deadbeef',
    remoteRefsContainingHead: ['origin/main', 'origin/feat/x'],
  });
  assert.equal(r.ok, true);
});

test('release-gate — HEAD not on origin/main fails and names the remedy', () => {
  const r = evaluateHeadPushed({ headSha: 'deadbeef', remoteRefsContainingHead: [] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /deadbeef/.test(e) && /origin\/main/.test(e)));
  assert.ok(r.errors.some(e => /push/i.test(e)));
});

test('release-gate — HEAD only on a feature branch still fails', () => {
  const r = evaluateHeadPushed({
    headSha: 'deadbeef',
    remoteRefsContainingHead: ['origin/feat/x'],
  });
  assert.equal(r.ok, false);
});

// --------------------------------------------------------------- check 10
test('release-gate — all remote check runs successful → pass', () => {
  const r = evaluateRemoteCi({
    cliAvailable: true,
    authenticated: true,
    checkRuns: [
      { name: 'ci', status: 'completed', conclusion: 'success' },
      { name: 'bench', status: 'completed', conclusion: 'skipped' },
    ],
  });
  assert.equal(r.ok, true);
});

test('release-gate — a failing remote check run fails the gate', () => {
  const r = evaluateRemoteCi({
    cliAvailable: true,
    authenticated: true,
    checkRuns: [
      { name: 'ci', status: 'completed', conclusion: 'success' },
      { name: 'bench', status: 'completed', conclusion: 'failure' },
    ],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /bench/.test(e) && /failure/.test(e)));
});

test('release-gate — an in-progress remote check run fails (not yet green)', () => {
  const r = evaluateRemoteCi({
    cliAvailable: true,
    authenticated: true,
    checkRuns: [{ name: 'ci', status: 'in_progress', conclusion: null }],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /in_progress/.test(e)));
});

test('release-gate — zero remote check runs fails (nothing proved green)', () => {
  const r = evaluateRemoteCi({ cliAvailable: true, authenticated: true, checkRuns: [] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /no .*check/i.test(e)));
});

test('release-gate — missing forge CLI fails rather than silently passing', () => {
  const r = evaluateRemoteCi({ cliAvailable: false, authenticated: false, checkRuns: null });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /unverifiable|not available|unavailable/i.test(e)));
});

test('release-gate — unauthenticated forge CLI fails rather than silently passing', () => {
  const r = evaluateRemoteCi({ cliAvailable: true, authenticated: false, checkRuns: null });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /authenticat/i.test(e)));
});

test('release-gate — escape hatch downgrades an unverifiable CI check to a loud warning', () => {
  const r = evaluateRemoteCi({
    cliAvailable: false, authenticated: false, checkRuns: null, allowUnverified: true,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
  assert.ok(r.warnings.some(w => /UNVERIFIED/.test(w)));
});

test('release-gate — escape hatch does NOT excuse a check run that actually failed', () => {
  const r = evaluateRemoteCi({
    cliAvailable: true,
    authenticated: true,
    checkRuns: [{ name: 'ci', status: 'completed', conclusion: 'failure' }],
    allowUnverified: true,
  });
  assert.equal(r.ok, false);
});

// ------------------------------------------------------------- checks 6-8
test('release-gate — a gated command exiting 0 passes, non-zero fails', () => {
  assert.equal(evaluateCommandGate({ label: 'npm test', exitCode: 0 }).ok, true);
  const bad = evaluateCommandGate({ label: 'npm test', exitCode: 1 });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some(e => /npm test/.test(e) && /exit(ed)? 1/.test(e)));
});

// -------------------------------------------------------- --fast selection
test('release-gate — full run plans all twelve checks in order', () => {
  const ids = plannedCheckIds({ fast: false });
  assert.equal(ids.length, 12);
  assert.deepEqual(ids, CHECKS.map(c => c.id));
});

test('release-gate — --fast skips only the slow gates, keeping 1-5, package-contents, and 9-10', () => {
  const ids = plannedCheckIds({ fast: true });
  const slowIds = CHECKS.filter(c => c.slow).map(c => c.id);
  assert.equal(slowIds.length, 4);
  assert.deepEqual(ids, CHECKS.filter(c => !c.slow).map(c => c.id));
  assert.equal(ids.length, 8);
  for (const s of slowIds) assert.ok(!ids.includes(s), `--fast must skip ${s}`);
  // The four cheap correctness gates, package-contents, and both provenance
  // gates must survive --fast: they are what make a fast run still meaningful.
  for (const keep of [
    'working-tree-clean', 'version-consistency', 'changelog-entry',
    'bundle-integrity', 'scorecard-freshness', 'package-contents',
    'head-pushed', 'remote-ci-green',
  ]) {
    assert.ok(ids.includes(keep), `--fast must still run ${keep}`);
  }
});

test('release-gate — the slow checks are the three command gates plus the registry gate', () => {
  assert.deepEqual(
    CHECKS.filter(c => c.slow).map(c => c.id),
    ['test-suite', 'corpus-gate', 'self-scan-gate', 'dependency-currency']
  );
});

// The dependency-currency gate is skipped by --fast because it is four
// registry round-trips, but prepublishOnly passes no flags — so a publish can
// never skip it. This pins that: it must be slow, and it must be in the set.
test('release-gate — dependency currency is registered, slow, and in the full run', () => {
  const check = CHECKS.find(c => c.id === 'dependency-currency');
  assert.ok(check, 'dependency-currency must be a registered check');
  assert.equal(check.slow, true);
  assert.ok(plannedCheckIds({ fast: false }).includes('dependency-currency'));
  assert.ok(!plannedCheckIds({ fast: true }).includes('dependency-currency'));
});

// package-contents is cheap and local (no network round-trip), so it is not
// slow and must survive --fast — the only check that examines the actual
// artifact should never be the one --fast quietly drops.
test('release-gate — package-contents is registered, not slow, and in the full run', () => {
  const check = CHECKS.find(c => c.id === 'package-contents');
  assert.ok(check, 'package-contents must be a registered check');
  assert.equal(check.slow, false);
  assert.ok(plannedCheckIds({ fast: false }).includes('package-contents'));
  assert.ok(plannedCheckIds({ fast: true }).includes('package-contents'));
});

test('release-gate — every check declares a remedy', () => {
  for (const c of CHECKS) {
    assert.equal(typeof c.remedy, 'string', `${c.id} needs a remedy`);
    assert.ok(c.remedy.length > 0, `${c.id} remedy must be non-empty`);
  }
});
