// .agentic-security/sca-policy.yml loader, application, and triage bridge.
// Phase 4 / Item 7 of the SCA improvement plan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  loadScaPolicy, matchAcceptRisk, applyScaPolicy, appendAcceptRiskFromTriage,
} from '../src/posture/sca-policy.js';
import { syncWithScan, transition, loadTriage } from '../src/posture/triage.js';

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-sp-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  // posture/state-dir.js#isSafeStateDir refuses to write into
  // .agentic-security/ unless the parent dir has a project marker. The temp
  // dir is bare — add a package.json so writes can proceed.
  await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 't' }));
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

function writePolicy(dir, body) {
  fs.writeFileSync(path.join(dir, '.agentic-security', 'sca-policy.yml'), body);
}

const finding = (overrides = {}) => ({
  type: 'vulnerable_dep',
  name: 'lodash', version: '4.17.20', ecosystem: 'npm',
  cveAliases: ['CVE-2020-8203'],
  osvId: 'GHSA-test-0001',
  severity: 'high',
  ...overrides,
});

// ── loadScaPolicy ───────────────────────────────────────────────────────────

test('loadScaPolicy: returns null when no policy file exists', async () => {
  const s = await mkSession();
  try { assert.equal(loadScaPolicy(s.dir), null); }
  finally { await s.cleanup(); }
});

test('loadScaPolicy: parses YAML and normalizes', async () => {
  const s = await mkSession();
  try {
    writePolicy(s.dir, `
accept-risk:
  - cve: CVE-2024-12345
    reason: patched downstream
sla:
  critical: 7d
  high: 30d
major-version-freeze:
  npm: [react]
`);
    const p = loadScaPolicy(s.dir);
    assert.equal(p.acceptRisk.length, 1);
    assert.equal(p.acceptRisk[0].cve, 'CVE-2024-12345');
    assert.equal(p.sla.critical, 7 * 86400_000);
    assert.equal(p.sla.high, 30 * 86400_000);
    assert.deepEqual(p.majorVersionFreeze.npm, ['react']);
  } finally { await s.cleanup(); }
});

test('loadScaPolicy: malformed YAML returns _error', async () => {
  const s = await mkSession();
  try {
    writePolicy(s.dir, '*::: bad ::');
    const p = loadScaPolicy(s.dir);
    assert.match(p._error || '', /Failed to parse/);
  } finally { await s.cleanup(); }
});

// ── matchAcceptRisk ─────────────────────────────────────────────────────────

test('matchAcceptRisk: CVE match', () => {
  const policy = { acceptRisk: [{ cve: 'CVE-2020-8203', reason: 'r' }] };
  const m = matchAcceptRisk(finding(), policy);
  assert.equal(m.cve, 'CVE-2020-8203');
});

test('matchAcceptRisk: package match without version filter', () => {
  const policy = { acceptRisk: [{ package: 'lodash', reason: 'r' }] };
  const m = matchAcceptRisk(finding(), policy);
  assert.equal(m.package, 'lodash');
});

test('matchAcceptRisk: package match WITH version filter only matches exact version', () => {
  const policy = { acceptRisk: [{ package: 'lodash', version: '4.17.21', reason: 'r' }] };
  assert.equal(matchAcceptRisk(finding({ version: '4.17.20' }), policy), null);
  assert.ok(matchAcceptRisk(finding({ version: '4.17.21' }), policy));
});

test('matchAcceptRisk: expired entries are ignored', () => {
  const policy = { acceptRisk: [{ cve: 'CVE-2020-8203', expires: '2020-01-01', reason: 'r' }] };
  assert.equal(matchAcceptRisk(finding(), policy, new Date('2026-01-01')), null);
});

test('matchAcceptRisk: not-yet-expired entries are honored', () => {
  const policy = { acceptRisk: [{ cve: 'CVE-2020-8203', expires: '2030-01-01', reason: 'r' }] };
  assert.ok(matchAcceptRisk(finding(), policy, new Date('2026-01-01')));
});

// ── applyScaPolicy ──────────────────────────────────────────────────────────

test('applyScaPolicy: suppresses findings matching accept-risk', () => {
  const policy = { acceptRisk: [{ cve: 'CVE-2020-8203', reason: 'patched' }], sla: {}, majorVersionFreeze: {} };
  const findings = [finding()];
  const stats = applyScaPolicy(findings, policy);
  assert.equal(stats.suppressed, 1);
  assert.equal(findings[0].suppressed, true);
  assert.equal(findings[0].suppressionReason, 'patched');
  assert.equal(findings[0].suppressionSource, 'sca-policy.yml');
});

test('applyScaPolicy: tags SLA deadline', () => {
  const policy = { acceptRisk: [], sla: { high: 30 * 86400_000 }, majorVersionFreeze: {} };
  const findings = [finding({ firstSeenAt: '2026-01-01T00:00:00Z' })];
  applyScaPolicy(findings, policy, new Date('2026-02-15T00:00:00Z'));
  assert.ok(findings[0].slaDeadline);
  assert.equal(findings[0].slaOverdue, true); // 30d window expired by Feb 15
});

test('applyScaPolicy: critical-kev SLA picks the narrower bucket', () => {
  const policy = { acceptRisk: [], sla: { 'critical-kev': 7 * 86400_000, critical: 30 * 86400_000 }, majorVersionFreeze: {} };
  const f = finding({ severity: 'critical', kev: true, firstSeenAt: '2026-01-01T00:00:00Z' });
  applyScaPolicy([f], policy, new Date('2026-01-10T00:00:00Z'));
  // 7-day SLA expires Jan 8; on Jan 10 we are overdue.
  assert.equal(f.slaOverdue, true);
});

test('applyScaPolicy: flags major-version-frozen packages', () => {
  const policy = { acceptRisk: [], sla: {}, majorVersionFreeze: { npm: ['lodash'] } };
  const findings = [finding()];
  applyScaPolicy(findings, policy);
  assert.equal(findings[0].majorVersionFrozen, true);
});

test('applyScaPolicy: non-SCA findings are ignored', () => {
  const policy = { acceptRisk: [{ cve: 'CVE-X', reason: 'r' }], sla: {}, majorVersionFreeze: {} };
  const f = { type: 'sast', cveAliases: ['CVE-X'] };
  applyScaPolicy([f], policy);
  assert.notEqual(f.suppressed, true);
});

// ── appendAcceptRiskFromTriage ──────────────────────────────────────────────

test('appendAcceptRiskFromTriage: creates policy file when none exists', async () => {
  const s = await mkSession();
  try {
    const r = appendAcceptRiskFromTriage(s.dir, finding(), 'manual review confirmed not exploitable');
    assert.equal(r.ok, true);
    const policy = loadScaPolicy(s.dir);
    assert.equal(policy.acceptRisk.length, 1);
    assert.equal(policy.acceptRisk[0].cve, 'CVE-2020-8203');
    assert.match(policy.acceptRisk[0].reason, /not exploitable/);
  } finally { await s.cleanup(); }
});

test('appendAcceptRiskFromTriage: refuses duplicate CVE', async () => {
  const s = await mkSession();
  try {
    appendAcceptRiskFromTriage(s.dir, finding(), 'first');
    const second = appendAcceptRiskFromTriage(s.dir, finding(), 'duplicate');
    assert.equal(second.ok, false);
    assert.match(second.reason, /already in accept-risk/);
  } finally { await s.cleanup(); }
});

// ── triage bridge (transition wont-fix → sca-policy.yml) ────────────────────

test('triage bridge: wont-fix on SCA finding materializes accept-risk entry', async () => {
  const s = await mkSession();
  try {
    syncWithScan(s.dir, [finding({ id: 'sca-1' })]);
    const r = transition(s.dir, 'sca-1', 'wont-fix', 'compensating control in place');
    assert.equal(r.ok, true);
    assert.equal(r.policyBridge.ok, true);
    const policy = loadScaPolicy(s.dir);
    assert.equal(policy.acceptRisk.length, 1);
    assert.equal(policy.acceptRisk[0].cve, 'CVE-2020-8203');
    assert.match(policy.acceptRisk[0].reason, /compensating control/);
  } finally { await s.cleanup(); }
});

test('triage bridge: wont-fix on SAST finding does NOT touch sca-policy', async () => {
  const s = await mkSession();
  try {
    const sast = { id: 'sast-1', vuln: 'XSS', severity: 'high', file: 'a.js', type: 'xss' };
    syncWithScan(s.dir, [sast]);
    const r = transition(s.dir, 'sast-1', 'wont-fix', 'false positive');
    assert.equal(r.ok, true);
    assert.equal(r.policyBridge, null);
    assert.equal(loadScaPolicy(s.dir), null);
  } finally { await s.cleanup(); }
});

test('triage bridge: round-trip — bridge then rescan applies suppression', async () => {
  const s = await mkSession();
  try {
    // 1) Sync + wont-fix → policy gets the entry.
    syncWithScan(s.dir, [finding({ id: 'sca-1' })]);
    transition(s.dir, 'sca-1', 'wont-fix', 'r');
    // 2) Reload policy; apply to a fresh batch of findings → suppression hits.
    const policy = loadScaPolicy(s.dir);
    const fresh = [finding({ id: 'sca-2' })];
    const stats = applyScaPolicy(fresh, policy);
    assert.equal(stats.suppressed, 1);
    assert.equal(fresh[0].suppressed, true);
  } finally { await s.cleanup(); }
});
