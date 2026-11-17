// Verified remediation M4-05: infrastructure repair (FR-15) judged on the EFFECTIVE configuration of every declared file, through the
// deployment boundary adapters. Nothing is executed or deployed; a repair run still needs the operator to enable it, like every family.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkInfrastructure } from '../../src/repair/infrastructure.js';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { validateProfile } from '../../src/repair/profile.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair', 'compose-exposure');
const M = 'deploy/docker-compose.yml'; const O = 'deploy/docker-compose.override.yml';
const setup = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'infra-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const files = { [M]: fs.readFileSync(path.join(root, M), 'utf8'), [O]: fs.readFileSync(path.join(root, O), 'utf8') };
  return { root, profile, files };
};
const variants = (files) => {
  const noPort = files[M].replace('    ports:\n      - "8081:8081"\n', '');
  return {
    overrideRepublishes: { [M]: noPort, [O]: 'services:\n  admin-api:\n    ports:\n      - "9090:8081"\n' },
    allClosed: { [M]: noPort.replace('"443:8443"', '"127.0.0.1:443:8443"') },
    unreadable: { [M]: noPort, [O]: 'resource "docker_container" "admin" {\n  ports { internal = 8081 }\n}\n' },
    loopback: { [M]: files[M].replace('"8081:8081"', '"127.0.0.1:8081:8081"') },
  };
};

describe('[M4-05] effective infrastructure configuration', () => {
  test('the files are judged together: an override that re-publishes the port keeps the service exposed; closing everything breaks the approved service; an unreadable file is a gap', () => {
    const s = setup();
    const v = variants(s.files);
    const at = (f) => checkInfrastructure(s.profile.infrastructure, { ...s.files, ...f });
    assert.match(at({}).problems.join(' '), /admin-api is still exposed by port\/admin-api:8081/);
    assert.match(at(v.overrideRepublishes).problems.join(' '), /admin-api is still exposed by port\/admin-api:9090/);
    assert.match(at(v.allClosed).problems.join(' '), /web is no longer exposed: an approved workflow is broken/);
    assert.match(at(v.unreadable).problems.join(' '), /unsupported-format, so its effect on exposure is unknown/);
    const ok = at(v.loopback);
    assert.equal(ok.ok, true, ok.problems.join('; '));
    assert.deepEqual(Object.keys(ok.exposed), ['web'], 'reachability through web\'s dependency is not direct exposure');
  });

  test('an infrastructure-only profile needs no application factory, database or actors, and its files must be application files', () => {
    const s = setup();
    assert.deepEqual(validateProfile(s.profile), []);
    assert.match(validateProfile({ ...s.profile, infrastructure: { ...s.profile.infrastructure, files: ['deploy/other.yml'] } }).join(' '), /must be application files/);
    assert.match(validateProfile({ ...s.profile, infrastructure: { ...s.profile.infrastructure, mustNotExpose: [] } }).join(' '), /at least one service/);
  });

  test('[AC-15.4/15.5] through the coordinator: the override, the over-closure and the unreadable file are rejected, loopback binding is verified, and nothing is deployed', async () => {
    const s = setup();
    const p = planRepair({ root: s.root, finding: { findingId: 'infra:admin', file: M }, family: 'infrastructure', profile: s.profile, profileOrigin: 'repository-file' });
    assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
    const v = variants(s.files);
    const items = [['overrideRepublishes', 1], ['allClosed', 1], ['unreadable', 2], ['loopback', 3]].map(([k, round]) => ({ round, strategy: k, files: v[k] }));
    const r = await runRepair({ root: s.root, plan: p.plan, config: resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } }), proposers: [queueProposer(items)], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } } });
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    for (const k of ['overrideRepublishes', 'allClosed', 'unreadable']) assert.equal(by[k].status, 'rejected', k);
    assert.equal(by.loopback.status, 'verified-for-contract', r.record.reasons.join('; '));
    assert.equal(r.record.environment, 'not-checked');
    assert.equal(r.record.obligationResults.find((o) => o.revision === 'original').observed, 'failed');
  });
});
