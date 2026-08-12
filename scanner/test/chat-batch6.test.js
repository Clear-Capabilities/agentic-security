// Tests for batch-6 enhancements:
//   #2 cross-repo-memory.js + pattern-propagation.js
//   #4 workflow-installer.js
//   #6 risk-dollars.js + time-to-fix.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { repoFingerprint, recordFix, recordTriage, findSiblingSignals, renderSiblingNote, _internals as _icr } from '../src/posture/cross-repo-memory.js';
import { annotateCrossRepoSignals } from '../src/posture/pattern-propagation.js';
import { detectProject, buildHookConfig, buildCiConfig } from '../src/posture/workflow-installer.js';
import { annotateRiskDollars, fmtUsd, _internals as _ird } from '../src/posture/risk-dollars.js';
import { annotateTimeToFix, renderTimeSummary, _internals as _itt } from '../src/posture/time-to-fix.js';

async function mkProject(extras = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'cb6-'));
  // Skip default package.json when extras explicitly include another lang manifest.
  const otherLangs = ['pyproject.toml', 'Cargo.toml', 'go.mod', 'Gemfile', 'pom.xml'];
  const skipDefault = otherLangs.some(k => k in extras);
  if (!skipDefault) await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"cb6"}');
  for (const [rel, content] of Object.entries(extras)) {
    const fp = path.join(dir, rel);
    await fsp.mkdir(path.dirname(fp), { recursive: true });
    await fsp.writeFile(fp, content);
  }
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── cross-repo memory ────────────────────────────────────────────────────

test('cross-repo: fingerprint is stable + privacy-preserving', async () => {
  const p = await mkProject();
  try {
    const a = repoFingerprint(p.dir);
    const b = repoFingerprint(p.dir);
    assert.equal(a, b);
    assert.equal(a.length, 12);
    assert.doesNotMatch(a, /[/.]/, 'no path chars leak');
  } finally { await p.cleanup(); }
});

test('cross-repo: recordFix + findSiblingSignals retrieves cross-repo', async () => {
  // Isolate the store to a tmp HOME so we don't pollute the real one.
  const tmpHome = await fsp.mkdtemp(path.join(os.tmpdir(), 'cr-home-'));
  const oldHome = process.env.HOME;
  process.env.HOME = tmpHome;
  try {
    const repoA = await mkProject();
    const repoB = await mkProject();
    try {
      recordFix({ scanRoot: repoA.dir, finding: { family: 'sqli', vuln: 'SQL injection', severity: 'critical' }, fixPattern: 'switched to db.prepare()' });
      // Query from repoB — should find sibling fix from repoA.
      const signals = findSiblingSignals(repoB.dir, { family: 'sqli' });
      assert.equal(signals.siblingFixes.length, 1);
      assert.equal(signals.siblingFixes[0].family, 'sqli');
      assert.match(signals.siblingFixes[0].fixPattern, /db\.prepare/);
      // Querying from repoA itself should NOT return the self entry.
      const sameRepo = findSiblingSignals(repoA.dir, { family: 'sqli' });
      assert.equal(sameRepo.siblingFixes.length, 0);
    } finally { await repoA.cleanup(); await repoB.cleanup(); }
  } finally {
    process.env.HOME = oldHome;
    await fsp.rm(tmpHome, { recursive: true, force: true });
  }
});

test('cross-repo: NO_CROSS_REPO env disables', async () => {
  process.env.AGENTIC_SECURITY_NO_CROSS_REPO = '1';
  try {
    const p = await mkProject();
    try {
      const r = recordFix({ scanRoot: p.dir, finding: { family: 'sqli' }, fixPattern: 'x' });
      // Either returned entry or null — must NOT have written the file.
      const signals = findSiblingSignals(p.dir, { family: 'sqli' });
      assert.equal(signals.siblingFixes.length, 0);
    } finally { await p.cleanup(); }
  } finally { delete process.env.AGENTIC_SECURITY_NO_CROSS_REPO; }
});

test('cross-repo: annotateCrossRepoSignals stamps findings', async () => {
  const tmpHome = await fsp.mkdtemp(path.join(os.tmpdir(), 'cr-home-'));
  const oldHome = process.env.HOME;
  process.env.HOME = tmpHome;
  try {
    const repoA = await mkProject();
    const repoB = await mkProject();
    try {
      recordFix({ scanRoot: repoA.dir, finding: { family: 'sqli' }, fixPattern: 'parameterized' });
      const findings = [{ family: 'sqli', severity: 'critical' }, { family: 'xss', severity: 'high' }];
      const r = annotateCrossRepoSignals(repoB.dir, findings);
      assert.equal(r.annotated, 1);
      assert.ok(findings[0].crossRepoSignal);
      assert.equal(findings[0].crossRepoSignal.fixes, 1);
      assert.equal(findings[1].crossRepoSignal, undefined);
    } finally { await repoA.cleanup(); await repoB.cleanup(); }
  } finally {
    process.env.HOME = oldHome;
    await fsp.rm(tmpHome, { recursive: true, force: true });
  }
});

// ── workflow-installer ──────────────────────────────────────────────────

test('workflow-installer: detectProject identifies node + husky', async () => {
  const p = await mkProject({ '.husky/.gitignore': '' });
  try {
    const r = detectProject(p.dir);
    assert.equal(r.lang, 'node');
    assert.equal(r.hookManager, 'husky');
  } finally { await p.cleanup(); }
});

test('workflow-installer: detectProject identifies python + pre-commit', async () => {
  const p = await mkProject({
    'pyproject.toml': '[project]\nname="x"\n',
    '.pre-commit-config.yaml': 'repos: []\n',
  });
  try {
    const r = detectProject(p.dir);
    assert.equal(r.lang, 'python');
    assert.equal(r.hookManager, 'pre-commit');
  } finally { await p.cleanup(); }
});

test('workflow-installer: detectProject finds CI provider', async () => {
  const p = await mkProject({ '.github/workflows/ci.yml': 'name: ci\n' });
  try {
    const r = detectProject(p.dir);
    assert.equal(r.ciProvider, 'github-actions');
  } finally { await p.cleanup(); }
});

test('workflow-installer: buildHookConfig generates husky pre-commit', async () => {
  const p = await mkProject({ '.husky/.gitignore': '' });
  try {
    const { manager, files } = buildHookConfig(p.dir);
    assert.equal(manager, 'husky');
    assert.ok(files['.husky/pre-commit']);
    assert.match(files['.husky/pre-commit'], /agentic-security/);
    assert.match(files['.husky/pre-commit'], /fail-on critical/);
  } finally { await p.cleanup(); }
});

test('workflow-installer: buildHookConfig falls back to pre-commit for python', async () => {
  const p = await mkProject({ 'pyproject.toml': '' });
  try {
    const { manager } = buildHookConfig(p.dir);
    assert.equal(manager, 'pre-commit');
  } finally { await p.cleanup(); }
});

test('workflow-installer: buildCiConfig github-actions includes SARIF upload', async () => {
  const p = await mkProject();
  try {
    const { provider, files } = buildCiConfig(p.dir, { provider: 'github-actions' });
    assert.equal(provider, 'github-actions');
    const yml = files['.github/workflows/agentic-security.yml'];
    assert.ok(yml);
    assert.match(yml, /codeql-action\/upload-sarif/);
    assert.match(yml, /lts\/\*/);
    assert.match(yml, /fetch-depth: 0/);
  } finally { await p.cleanup(); }
});

test('workflow-installer: buildCiConfig gitlab-ci + circleci both render', async () => {
  const p = await mkProject();
  try {
    const gl = buildCiConfig(p.dir, { provider: 'gitlab-ci' });
    const cc = buildCiConfig(p.dir, { provider: 'circleci' });
    assert.match(gl.files['.gitlab-ci-agentic-security.yml'], /agentic-security/);
    assert.match(cc.files['.circleci/agentic-security.yml'], /cimg\/node/);
  } finally { await p.cleanup(); }
});

// ── risk-dollars ────────────────────────────────────────────────────────

test('risk-dollars: annotateRiskDollars adds ev to each finding', async () => {
  const p = await mkProject();
  try {
    const findings = [
      { family: 'sqli', severity: 'critical', confidence: 0.9, reachabilityTier: 'route-reachable' },
      { family: 'unknown-family', severity: 'low', confidence: 0.6, reachabilityTier: 'unreachable' },
    ];
    const r = annotateRiskDollars(p.dir, findings);
    assert.equal(r.total, 2);
    assert.ok(findings[0].riskDollars.ev > 0);
    assert.ok(findings[0].riskDollars.ev > findings[1].riskDollars.ev, 'reachable critical > unreachable low');
  } finally { await p.cleanup(); }
});

test('risk-dollars: PHI data class amplifies impact', async () => {
  const p = await mkProject();
  try {
    const a = [{ family: 'sqli', severity: 'high', confidence: 0.8, reachabilityTier: 'route-reachable' }];
    const b = [{ family: 'sqli', severity: 'high', confidence: 0.8, reachabilityTier: 'route-reachable', dataClasses: ['PHI'] }];
    annotateRiskDollars(p.dir, a);
    annotateRiskDollars(p.dir, b);
    assert.ok(b[0].riskDollars.ev > a[0].riskDollars.ev * 3);
  } finally { await p.cleanup(); }
});

test('risk-dollars: fmtUsd formats large numbers', () => {
  assert.equal(fmtUsd(420_000), '$420k');
  assert.equal(fmtUsd(1_200_000), '$1.2M');
  assert.equal(fmtUsd(85), '$85');
});

test('risk-dollars: EPSS score overrides family base rate', async () => {
  const p = await mkProject();
  try {
    const f = [{ family: 'sqli', severity: 'medium', confidence: 0.8, reachabilityTier: 'route-reachable', epssScore: 0.9 }];
    annotateRiskDollars(p.dir, f);
    assert.equal(f[0].riskDollars.prob, 0.9);
  } finally { await p.cleanup(); }
});

// Stage 1 correctness audit: SCA entries carry reachabilityTier/
// routeReachable (engine.js's SCA reachability pass); SAST findings never
// do — annotateRiskDollars is only ever called with SAST findings
// (finalFindings), so _reachDiscount always fell through to 'unknown'
// (0.3x) for every finding it actually annotates, regardless of real
// reachability. SAST findings carry relevanceTier instead
// (posture/relevance.js) — this must be consulted as a fallback.
test('risk-dollars: relevanceTier is consulted as a fallback discount signal for SAST findings', async () => {
  const p = await mkProject();
  try {
    const direct = [{ family: 'sqli', severity: 'high', confidence: 0.8, relevanceTier: 'direct' }];
    const unreachable = [{ family: 'sqli', severity: 'high', confidence: 0.8, relevanceTier: 'unreachable' }];
    const unknown = [{ family: 'sqli', severity: 'high', confidence: 0.8 }];
    annotateRiskDollars(p.dir, direct);
    annotateRiskDollars(p.dir, unreachable);
    annotateRiskDollars(p.dir, unknown);
    assert.ok(direct[0].riskDollars.ev > unknown[0].riskDollars.ev, 'a directly-reachable finding must score higher than an unknown-reachability one');
    assert.ok(unknown[0].riskDollars.ev > unreachable[0].riskDollars.ev, 'an unknown-reachability finding must score higher than a provably-unreachable one');
  } finally { await p.cleanup(); }
});

// ── time-to-fix ─────────────────────────────────────────────────────────

test('time-to-fix: annotateTimeToFix sums hours + family rollup', async () => {
  const p = await mkProject();
  try {
    const findings = [
      { family: 'sqli',  severity: 'critical', fix: { code: 'db.prepare(sql)' } },
      { family: 'sqli',  severity: 'critical' },
      { family: 'authz', severity: 'high' },
    ];
    const r = annotateTimeToFix(p.dir, findings);
    assert.equal(r.perFinding, 3);
    assert.ok(r.totalHours > 0);
    assert.ok(r.perFamily.sqli > 0);
    assert.ok(r.perFamily.authz >= 1.5);
    for (const f of findings) assert.ok(f.estimatedFixHours > 0);
  } finally { await p.cleanup(); }
});

test('time-to-fix: patch-shape adjustment scales hours by patch size', () => {
  assert.equal(_itt._patchShapeAdjust({}), 1.0);
  assert.equal(_itt._patchShapeAdjust({ fix: { code: 'a\nb\nc' } }), 1.0);
  assert.equal(_itt._patchShapeAdjust({ fix: { code: Array(20).fill('x').join('\n') } }), 2.0);
});

test('time-to-fix: history-based estimate preferred over base', async () => {
  const p = await mkProject();
  try {
    // Inject a fake fix-history log.
    const dir = path.join(p.dir, '.agentic-security', 'fix-history');
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(path.join(dir, 'log.json'), JSON.stringify([
      { family: 'sqli', elapsedHours: 3.0 },
      { family: 'sqli', elapsedHours: 5.0 },
    ]));
    const findings = [{ family: 'sqli', severity: 'critical' }];
    annotateTimeToFix(p.dir, findings);
    assert.equal(findings[0].estimatedFixHoursSource, 'history');
    // 4 hours average × 1.0 patch-adj × 1.0 reach-adj
    assert.equal(findings[0].estimatedFixHours, 4);
  } finally { await p.cleanup(); }
});

test('time-to-fix: renderTimeSummary produces useful output', () => {
  const summary = renderTimeSummary({ perFinding: 5, totalHours: 12.5, perFamily: { sqli: 8, xss: 4.5 } });
  assert.match(summary, /5 finding/);
  assert.match(summary, /12\.5/);
  assert.match(summary, /sqli/);
});

test('time-to-fix: empty findings → zero summary', () => {
  const summary = renderTimeSummary(annotateTimeToFix('/tmp', []));
  assert.match(summary, /0 hours/);
});
