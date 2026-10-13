import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveVexStatus, VEX_STATUSES } from '../../src/artifact/vex.js';

function vuln(overrides = {}) {
  return { purl: 'pkg:npm/lodash@4.17.15', ecosystem: 'npm', name: 'lodash', version: '4.17.15', fixedVersions: [], ...overrides };
}

test('VEX/0: VEX_STATUSES is exactly the four PRD-named statuses, frozen', () => {
  assert.deepEqual([...VEX_STATUSES], ['affected', 'not_affected', 'fixed', 'under_investigation']);
  assert.ok(Object.isFrozen(VEX_STATUSES));
});

test('VEX/1: the affected component absent from the artifact is not_affected with component_not_present', () => {
  const r = deriveVexStatus({ vulnerability: vuln(), artifactComponents: [] });
  assert.equal(r.status, 'not_affected');
  assert.equal(r.justification, 'component_not_present');
});

test('VEX/2: present + confirmed unreachable is not_affected with vulnerable_code_not_in_execute_path', () => {
  const r = deriveVexStatus({
    vulnerability: vuln(),
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15' }],
    reachability: { reachable: false, reason: 'no call site reaches the vulnerable function' },
  });
  assert.equal(r.status, 'not_affected');
  assert.equal(r.justification, 'vulnerable_code_not_in_execute_path');
});

test('VEX/3: present + installed version >= a fixed version is "fixed"', () => {
  const r = deriveVexStatus({
    vulnerability: vuln({ purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21', fixedVersions: ['4.17.21'] }),
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.21' }],
  });
  assert.equal(r.status, 'fixed');
});

test('VEX/4: present + confirmed reachable is "affected"', () => {
  const r = deriveVexStatus({
    vulnerability: vuln(),
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15' }],
    reachability: { reachable: true, reason: 'a call site reaches the vulnerable function' },
  });
  assert.equal(r.status, 'affected');
});

test('VEX/5: present, no reachability evidence either way, not confirmed fixed, defaults to under_investigation — NEVER a confident affected or not_affected', () => {
  const r = deriveVexStatus({ vulnerability: vuln(), artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15' }] });
  assert.equal(r.status, 'under_investigation');
});

test('VEX/6: an unparseable version pair never produces a fabricated "fixed" verdict', () => {
  const r = deriveVexStatus({
    vulnerability: vuln({ version: 'not-a-version', fixedVersions: ['also-not-a-version'] }),
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15' }],
  });
  assert.notEqual(r.status, 'fixed');
});

test('VEX/7: requires a vulnerability object and an artifactComponents array', () => {
  assert.throws(() => deriveVexStatus({ vulnerability: null, artifactComponents: [] }), TypeError);
  assert.throws(() => deriveVexStatus({ vulnerability: vuln(), artifactComponents: null }), TypeError);
});

test('VEX/8: OS-package components (no purl) are matched by ecosystem+name+version', () => {
  const r = deriveVexStatus({
    vulnerability: { ecosystem: 'Debian', name: 'curl', version: '7.68.0-1' },
    artifactComponents: [{ ecosystem: 'Debian', name: 'curl', version: '7.68.0-1' }],
  });
  assert.notEqual(r.status, 'not_affected');
});
