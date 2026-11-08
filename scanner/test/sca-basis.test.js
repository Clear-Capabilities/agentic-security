import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateScaBasis, dedupeAdvisoryAliases, versionBasisOf } from '../src/sca/basis.js';

const dep = (o = {}) => ({ type: 'vulnerable_dep', ecosystem: 'npm', name: 'minimist', version: '0.0.8', osvId: 'GHSA-xvch-5gv4-984h', cveAliases: ['CVE-2021-44906'], file: 'package.json', line: 4, fixedVersions: ['0.2.4'], severity: 'high', ...o });

test('a manifest constraint and a lock entry are different bases, and neither is deployment evidence', () => {
  assert.equal(versionBasisOf('package.json'), 'declared-constraint');
  assert.equal(versionBasisOf('app/package-lock.json'), 'locked');
  assert.equal(versionBasisOf('stack.yaml.lock'), 'locked');
  const [a, b] = annotateScaBasis([dep(), dep({ file: 'package-lock.json' })]);
  assert.equal(a.basis.versionBasis, 'declared-constraint');
  assert.equal(b.basis.versionBasis, 'locked');
  assert.equal(a.basis.deploymentEvidence, 'none');
  assert.ok(a.basis.gaps.some((g) => /not proof that it is deployed/.test(g)));
  assert.ok(a.basis.gaps.some((g) => /declared constraint/.test(g)));
});

test('the basis records identity, advisory, range, fix and timestamp, and names what is missing', () => {
  const [s] = annotateScaBasis([dep({ advisoryModified: '2024-01-01T00:00:00Z', affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }] }] })]);
  assert.equal(s.basis.advisory.id, 'GHSA-xvch-5gv4-984h');
  assert.equal(s.basis.advisory.modified, '2024-01-01T00:00:00Z');
  assert.equal(s.basis.advisory.fixedVersions[0], '0.2.4');
  assert.equal(s.basis.source.file, 'package.json');
  assert.ok(!s.basis.gaps.some((g) => /affected range not recorded/.test(g)));
  const [m] = annotateScaBasis([dep()]);
  assert.ok(m.basis.gaps.some((g) => /affected range not recorded/.test(g)));
});

test('unknown reachability is recorded as unknown and changes neither severity nor presence', () => {
  const s = dep();
  const out = annotateScaBasis([s]);
  assert.equal(out[0].basis.reachability, 'unknown');
  assert.equal(out[0].severity, 'high');
  assert.equal(out.length, 1);
});

test('alias duplicates merge but every occurrence and identifier is kept', () => {
  const a = dep();
  const b = dep({ osvId: 'CVE-2021-44906', cveAliases: [], file: 'web/package.json', line: 9 });
  const other = dep({ version: '1.2.3', osvId: 'GHSA-other', cveAliases: [] });
  const out = dedupeAdvisoryAliases([a, b, other]);
  assert.equal(out.length, 2);
  const m = out.find((x) => x.version === '0.0.8');
  assert.deepEqual(m.advisoryIds, ['CVE-2021-44906', 'GHSA-xvch-5gv4-984h']);
  assert.equal(m.occurrences.length, 2);
  assert.deepEqual(m.mergedAdvisories, ['CVE-2021-44906']);
  assert.equal(a.occurrences, undefined, 'inputs are not mutated');
});

test('different packages or versions with the same alias do not merge', () => {
  const out = dedupeAdvisoryAliases([dep(), dep({ name: 'other' }), dep({ version: '0.0.9' })]);
  assert.equal(out.length, 3);
});
