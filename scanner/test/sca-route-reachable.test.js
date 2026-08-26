// Phase 2 / Item 4 of the SCA improvement plan — route-reachable-via-function
// reachability tier for SCA, plus SCA-aware demotion in
// posture/reachability-filter.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoteUnreachable } from '../src/posture/reachability-filter.js';

// ── engine.js wiring: demoteUnreachable must actually run over supplyChain ──
//
// Stage 4 correctness audit: every test above proves demoteUnreachable()
// itself demotes an SCA finding correctly — but engine.js only ever calls
// it as `demoteUnreachable(finalFindings, {routes: aR})`, and `finalFindings`
// is the SAST array. `type: 'vulnerable_dep'` findings live exclusively in
// the separate `supplyChain` array (per src/sca/CLAUDE.md's own "Gotchas"
// section), which is never passed to demoteUnreachable at all. So the
// entire SCA branch inside demoteUnreachable — ~10 lines handling
// manifest-only/unreachable/transitive-only/build-only tiers — is dead code
// in production: a critical-severity dependency that is provably never
// imported anywhere in the project stays at full severity forever.
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u.includes('querybatch')) {
    return { ok: true, json: async () => ({ results: [{ vulns: [{ id: 'GHSA-wiring-test-0001' }] }] }) };
  }
  if (u.includes('/v1/vulns/')) {
    return { ok: true, json: async () => ({
      id: 'GHSA-wiring-test-0001',
      summary: 'synthetic critical vuln for demoteUnreachable wiring test',
      affected: [{ ranges: [{ events: [{ fixed: '9.9.9' }] }] }],
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      database_specific: { severity: 'CRITICAL' },
    }) };
  }
  return { ok: true, json: async () => ({}) };
};

const { runFullScan } = await import('../src/engine.js');

test('engine wiring: a manifest-only critical SCA dependency is demoted by a real scan, not left at full severity', async () => {
  const depFileContents = {
    'package.json': JSON.stringify({
      name: 'demo', version: '1.0.0',
      dependencies: { 'agentic-security-wiring-test-pkg': '4.17.15' },
    }),
  };
  const fileContents = {
    // demoteUnreachable requires the project to have >=1 detected route
    // (otherwise it treats reachability as uninformative and demotes
    // nothing at all — see reachability-filter.js's own haveRoutes guard).
    // This route never imports or calls the vulnerable package, so the
    // dependency itself still cannot rise above manifest-only.
    'server.js': "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.send('ok'));\n",
  };
  // scanRoot is a fake path that never exists on disk, so state-dir.js's
  // resolveProjectRoot() falls through to the real repo (via process.cwd())
  // instead of staying isolated — without this guard, sbom-diff.js writes a
  // REAL sbom-history snapshot for this synthetic package into the actual
  // repo's .agentic-security/, which then contaminates dependency-drift
  // diffs on later, unrelated scans of the real tree (self-scan included).
  process.env.AGENTIC_SECURITY_NO_STATE = '1';
  try {
    const result = await runFullScan({ fileContents, depFileContents, scanRoot: '/tmp/agentic-security-sca-wiring-test' });
    const sc = (result.supplyChain || []).find(s => s.type === 'vulnerable_dep' && s.name === 'agentic-security-wiring-test-pkg');
    assert.ok(sc, 'expected the synthetic vulnerable dependency to be found');
    assert.equal(sc.reachabilityTier, 'manifest-only', 'precondition: this dependency must land in a DEMOTE_SCA_TIERS tier');
    assert.equal(sc.severity, 'medium', 'a manifest-only critical SCA finding must be demoted, same as demoteUnreachable does in isolation');
    assert.equal(sc.unreachable, true);
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_STATE;
  }
});

// ── posture/reachability-filter.js: SCA findings demote by tier ─────────────

function makeScaFinding(tier, severity = 'critical') {
  return {
    type: 'vulnerable_dep',
    name: 'lodash', version: '4.17.20',
    severity,
    reachabilityTier: tier,
    cveAliases: ['CVE-2020-8203'],
  };
}

test('reachability-filter: route-reachable-via-function tier KEEPS severity', () => {
  const f = makeScaFinding('route-reachable-via-function', 'critical');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'critical');
  assert.notEqual(f.unreachable, true);
});

test('reachability-filter: function-reachable tier KEEPS severity', () => {
  const f = makeScaFinding('function-reachable', 'critical');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'critical');
});

test('reachability-filter: import-reachable tier KEEPS severity', () => {
  const f = makeScaFinding('import-reachable', 'high');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'high');
});

test('reachability-filter: manifest-only tier DEMOTES severity', () => {
  const f = makeScaFinding('manifest-only', 'critical');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'medium');
  assert.equal(f.unreachable, true);
  assert.equal(f._reachabilityDemoteReason, 'tier:manifest-only');
});

test('reachability-filter: transitive-only tier DEMOTES severity', () => {
  const f = makeScaFinding('transitive-only', 'high');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'low');
  assert.equal(f.unreachable, true);
});

test('reachability-filter: unreachable tier DEMOTES severity', () => {
  const f = makeScaFinding('unreachable', 'critical');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'medium');
});

test('reachability-filter: build-only tier DEMOTES severity', () => {
  const f = makeScaFinding('build-only', 'high');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'low');
});

test('reachability-filter: no routes → no demotion (even with bad tier)', () => {
  const f = makeScaFinding('manifest-only', 'critical');
  demoteUnreachable([f], { routes: [] });
  assert.equal(f.severity, 'critical');
  assert.notEqual(f.unreachable, true);
});

test('reachability-filter: include-unreachable flag bypasses demotion', () => {
  const f = makeScaFinding('manifest-only', 'critical');
  demoteUnreachable([f], { routes: [{}], includeUnreachable: true });
  assert.equal(f.severity, 'critical');
});

test('reachability-filter: env flag bypasses demotion', () => {
  process.env.AGENTIC_SECURITY_INCLUDE_UNREACHABLE = '1';
  const f = makeScaFinding('manifest-only', 'critical');
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'critical');
  delete process.env.AGENTIC_SECURITY_INCLUDE_UNREACHABLE;
});

test('reachability-filter: missing reachabilityTier on SCA = no demotion', () => {
  const f = { type: 'vulnerable_dep', name: 'pkg', severity: 'critical' };
  demoteUnreachable([f], { routes: [{}] });
  assert.equal(f.severity, 'critical');
});

test('reachability-filter: SCA + SAST findings demote independently', () => {
  const findings = [
    makeScaFinding('manifest-only', 'critical'),
    { vuln: 'SQL Injection', severity: 'high', reachable: false }, // SAST, unreachable
    { vuln: 'XSS', severity: 'high', reachable: true },             // SAST, reachable
  ];
  demoteUnreachable(findings, { routes: [{}] });
  // SCA demoted by tier
  assert.equal(findings[0].severity, 'medium');
  // SAST unreachable demoted via existing path
  assert.equal(findings[1].severity, 'low');
  // SAST reachable preserved
  assert.equal(findings[2].severity, 'high');
});
