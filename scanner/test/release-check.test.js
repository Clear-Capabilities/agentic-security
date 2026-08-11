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
  readCheckTiers,
  CHECK_TIERS_FILE,
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
test('release-gate — full run plans all fourteen checks in order', () => {
  // M2 (Stage-0 audit, 2026) added mutation-gate + layer-recall-gate — both
  // slow, both were previously unreachable from every gate including this one.
  const ids = plannedCheckIds({ fast: false });
  assert.equal(ids.length, 14);
  assert.deepEqual(ids, CHECKS.map(c => c.id));
});

test('release-gate — mutation-gate and layer-recall-gate are registered and slow', () => {
  const mutation = CHECKS.find(c => c.id === 'mutation-gate');
  const layerRecall = CHECKS.find(c => c.id === 'layer-recall-gate');
  assert.ok(mutation, 'mutation-gate must be a registered release check');
  assert.equal(mutation.slow, true);
  assert.ok(layerRecall, 'layer-recall-gate must be a registered release check');
  assert.equal(layerRecall.slow, true);
});

test('release-gate — --fast skips only the slow gates, keeping 1-5, package-contents, and 9-10', () => {
  const ids = plannedCheckIds({ fast: true });
  const slowIds = CHECKS.filter(c => c.slow).map(c => c.id);
  assert.equal(slowIds.length, 6);
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

test('release-gate — the slow checks are the five command gates plus the registry gate', () => {
  assert.deepEqual(
    CHECKS.filter(c => c.slow).map(c => c.id),
    ['test-suite', 'corpus-gate', 'self-scan-gate', 'mutation-gate', 'layer-recall-gate', 'dependency-currency']
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

// ------------------------------------------- R2: blocking vs informational
//
// remote-ci-green required EVERY check on the commit. On 2026-08-09 a publish
// was blocked 15+ minutes by `realworld-bench` while 8 of 9 checks were green.
// That job measures detection rate against public vulnerable apps — a quality
// trend, not a statement about whether this build is publishable. The same
// over-broad requirement is why pushes to main were reporting "Bypassed rule
// violations": protection demanded checks that are not correctness gates, so
// the bypass became routine, and a routinely-bypassed rule is not a control.

const TIERS = { blocking: ['ci', 'corpus'], informational: ['realworld-bench'] };
const ciFacts = (checkRuns, tiers = TIERS) => ({
  cliAvailable: true, authenticated: true, checkRuns, headSha: 'abc1234', tiers,
});
const done = (name, conclusion) => ({ name, status: 'completed', conclusion });
const pending = (name) => ({ name, status: 'in_progress', conclusion: null });

test('release-check — a pending informational check does not block the release', () => {
  // The exact case observed on 2026-08-09.
  const r = evaluateRemoteCi(ciFacts([
    done('ci', 'success'), done('corpus', 'success'),
    { name: 'realworld-bench', status: 'in_progress', conclusion: null },
  ]));
  assert.equal(r.ok, true);
});

test('release-check — a pending BLOCKING check still blocks', () => {
  const r = evaluateRemoteCi(ciFacts([
    { name: 'ci', status: 'in_progress', conclusion: null }, done('corpus', 'success'),
  ]));
  assert.equal(r.ok, false);
  assert.match(r.errors.join('\n'), /"ci" is in_progress/);
});

test('release-check — a red blocking check blocks', () => {
  const r = evaluateRemoteCi(ciFacts([done('ci', 'success'), done('corpus', 'failure')]));
  assert.equal(r.ok, false);
  assert.match(r.errors.join('\n'), /"corpus" concluded failure/);
});

test('release-check — a FAILING informational check warns loudly but does not block', () => {
  // The tier must not make a trend regression invisible; it must only stop it
  // being a release blocker.
  const r = evaluateRemoteCi(ciFacts([
    done('ci', 'success'), done('corpus', 'success'), done('realworld-bench', 'failure'),
  ]));
  assert.equal(r.ok, true, 'an informational failure must not block');
  assert.match(r.warnings.join('\n'), /INFORMATIONAL/);
  assert.match(r.warnings.join('\n'), /realworld-bench/);
  assert.match(r.warnings.join('\n'), /trend regression/i);
});

test('release-check — an unclassified check is treated as BLOCKING and warned about', () => {
  // A job nobody tiered is a job nobody thought about. Defaulting it to
  // informational would let a new correctness gate silently stop gating.
  const r = evaluateRemoteCi(ciFacts([done('ci', 'success'), done('brand-new-job', 'failure')]));
  assert.equal(r.ok, false);
  assert.match(r.warnings.join('\n'), /brand-new-job/);
  assert.match(r.warnings.join('\n'), /required-checks\.json/);
});

test('release-check — a missing tier file fails closed: everything blocks', () => {
  const r = evaluateRemoteCi(ciFacts([done('realworld-bench', 'failure')], null));
  assert.equal(r.ok, false, 'failing to read the classification must never let a red check through');
});

test('release-check — the committed tier file is well-formed and the lists are disjoint', () => {
  const tiers = readCheckTiers();
  assert.ok(tiers, `${CHECK_TIERS_FILE} must exist and parse`);
  assert.ok(tiers.blocking.length > 0);
  assert.ok(tiers.informational.length > 0);
  const lists = { blocking: tiers.blocking, informational: tiers.informational, self: tiers.self || [] };
  for (const [a, b] of [['blocking', 'informational'], ['blocking', 'self'], ['informational', 'self']]) {
    const overlap = lists[a].filter(n => lists[b].includes(n));
    assert.deepEqual(overlap, [], `a check cannot be both ${a} and ${b}`);
  }
});

test('release-check — the gate does not wait on the job it is running inside', () => {
  // THE DEADLOCK THIS EXISTS TO PREVENT. The release workflow's job is named
  // `publish`, and the gate runs inside it. Looking for hosted CI on HEAD, the
  // gate saw a check named `publish` that was in_progress — itself — and
  // required it to finish. It never could. Both v0.135.0 and v0.136.0 failed
  // this way with all nine real checks green, and the resulting `publish:
  // failure` then blocked local publishes too.
  const tiers = readCheckTiers();
  assert.ok((tiers.self || []).includes('publish'),
    'the release workflow job must be classified self, or the gate deadlocks on itself');

  const green = [done('test', 'success'), done('corpus', 'success')];
  // Pending self — the exact deadlock.
  assert.equal(evaluateRemoteCi(ciFacts([...green, pending('publish')], tiers)).ok, true);
  // Failed self — the stale conclusion left behind by the deadlock.
  assert.equal(evaluateRemoteCi(ciFacts([...green, done('publish', 'failure')], tiers)).ok, true,
    'a self check says nothing about the commit, in either direction');
  // And the other direction: a genuinely red BLOCKING check still stops it.
  assert.equal(evaluateRemoteCi(ciFacts([done('test', 'failure'), pending('publish')], tiers)).ok, false,
    'excluding self must not weaken any real gate');
});

test('release-check — the long benchmarks are informational, the correctness gates are not', () => {
  // Pins the actual decision, so flipping a tier is a deliberate, reviewed diff
  // rather than an edit nobody notices.
  const tiers = readCheckTiers();
  for (const n of ['realworld-bench', 'synthetic-bench']) {
    assert.ok(tiers.informational.includes(n), `${n} must be informational`);
  }
  for (const n of ['test', 'corpus', 'sandbox-linux', 'determinism-compare']) {
    assert.ok(tiers.blocking.includes(n), `${n} must be blocking`);
  }
});

test('release-check — the tier file lists check-RUN names, never workflow names', () => {
  // The first draft listed 'ci' and 'codeql', which are workflow names. They
  // never appear as check runs, so they matched nothing — and branch protection
  // configured from that list would have hung every PR on contexts that never
  // report. Names must come from the check-runs API, not from the workflow file.
  const tiers = readCheckTiers();
  for (const bad of ['ci', 'codeql', 'Scanner F1 benchmark']) {
    assert.ok(!tiers.blocking.includes(bad) && !tiers.informational.includes(bad),
      `"${bad}" is a workflow name, not a check-run name`);
  }
});
