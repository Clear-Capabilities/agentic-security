// Phase 2 / Item 4 of the SCA improvement plan — route-reachable-via-function
// reachability tier for SCA, plus SCA-aware demotion in
// posture/reachability-filter.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoteUnreachable } from '../src/posture/reachability-filter.js';

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
