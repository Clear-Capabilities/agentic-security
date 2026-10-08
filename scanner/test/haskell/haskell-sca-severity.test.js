// Advisory-own severity for Hackage findings: CVSS v3.x base score, named severity fallback, and the honest default.
// Real pinned HSEC records are used where they carry a vector (they all carry it on affected[]); records marked
// SYNTHETIC cover the shapes the real ones lack (record-level vector, named severity, v4, malformed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { cvssV3BaseScore, levelFromScore, advisorySeverity, NO_RATING_BASIS } from '../../src/language/cvss.js';
import { AdvisoryDb, evaluateComponents } from '../../src/language/haskell-sca.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'hackage-advisories', 'records');
const REAL = readdirSync(DIR).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')));
const real = (id) => REAL.find((r) => r.id === id);
const NOW = Date.parse('2026-10-03T00:00:00Z');
const run = (records, name, version) => evaluateComponents([{ name, version }], new AdvisoryDb({ records, source: 'fixture', generatedAt: '2026-10-01T00:00:00Z', now: NOW })).findings;

// SYNTHETIC: shaped like an HSEC export, ids and package names are invented.
const syn = (id, pkg, sev = {}) => ({
  id, summary: `synthetic ${id}`, aliases: [], modified: '2026-01-01T00:00:00Z', published: '2026-01-01T00:00:00Z',
  affected: [{ package: { name: pkg, ecosystem: 'Hackage', purl: `pkg:hackage/${pkg}` }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0' }] }], ...(sev.affected || {}) }],
  ...(sev.rec || {}),
});

test('CVSS v3 calculator matches published reference scores', () => {
  const want = {
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H': 7.5,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': 9.8,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': 10,
    'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H': 8.8,
    'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H': 8.8,
    'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N': 5.9,
    'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N': 3.7,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N': 0,
  };
  for (const [v, s] of Object.entries(want)) assert.equal(cvssV3BaseScore(v).score, s, v);
});

test('score to level boundaries', () => {
  assert.deepEqual([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(levelFromScore), [null, 'low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
});

test('unparseable or unsupported vectors yield no score and a reason, never a guess', () => {
  for (const v of ['CVSS:3.1/AV:N/AC:L', 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'nonsense', 'CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', null]) {
    const r = cvssV3BaseScore(v);
    assert.equal(r.ok, false, String(v)); assert.ok(r.reason);
  }
});

test('real records: the advisory CVSS vector drives severity, with score and basis recorded', () => {
  const a = run(REAL, 'xml-conduit', '1.9.0.0');            // HSEC-2023-0004, 7.5
  assert.equal(a.length, 1);
  assert.equal(a[0].severity, 'high'); assert.equal(a[0].severityScore, 7.5);
  assert.equal(a[0].severityBasis, 'CVSS v3.1 base score 7.5 from the advisory');
  const b = run(REAL, 'aeson', '1.5.6.0').find((f) => f.osvId === 'HSEC-2023-0001'); // PR:L, 6.5
  assert.equal(b.severity, 'medium'); assert.equal(b.severityScore, 6.5);
  assert.equal(advisorySeverity(real('HSEC-2023-0012')).level, 'low');      // 3.7
  assert.equal(advisorySeverity(real('HSEC-2023-0013')).level, 'high');     // 8.8 (scope changed)
});

test('SYNTHETIC: record-level vector, critical, and the highest score across entries wins', () => {
  const crit = syn('SYN-0001', 'synpkg', { rec: { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }] } });
  const f = run([crit], 'synpkg', '1.0')[0];
  assert.equal(f.severity, 'critical'); assert.equal(f.severityScore, 10);
  const mixed = syn('SYN-0002', 'synpkg2', { rec: { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' }] }, affected: { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] } });
  assert.equal(run([mixed], 'synpkg2', '1.0')[0].severity, 'high');
});

test('SYNTHETIC: a named database_specific severity is used only when no vector scores', () => {
  const named = (s, vec) => syn('SYN-N', 'namedpkg', { rec: { database_specific: { severity: s }, ...(vec ? { severity: [{ type: 'CVSS_V3', score: vec }] } : {}) } });
  const mod = run([named('MODERATE')], 'namedpkg', '1.0')[0];
  assert.equal(mod.severity, 'medium'); assert.equal(mod.severityScore, null); assert.match(mod.severityBasis, /"MODERATE" stated by the advisory/);
  assert.equal(run([named('critical')], 'namedpkg', '1.0')[0].severity, 'critical');
  // a vector that scores beats the name
  assert.equal(run([named('LOW', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')], 'namedpkg', '1.0')[0].severity, 'critical');
  // a vector that cannot be scored falls back to the name
  assert.equal(run([named('HIGH', 'CVSS:3.1/garbage')], 'namedpkg', '1.0')[0].severity, 'high');
});

test('SYNTHETIC: nothing usable keeps the medium default and states why', () => {
  const none = run([syn('SYN-X', 'nopkg')], 'nopkg', '1.0')[0];
  assert.equal(none.severity, 'medium'); assert.equal(none.severityBasis, NO_RATING_BASIS); assert.equal(none.severityScore, null);
  const v4 = run([syn('SYN-V4', 'v4pkg', { rec: { severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }] } })], 'v4pkg', '1.0')[0];
  assert.equal(v4.severity, 'medium'); assert.match(v4.severityBasis, /no severity rating that could be used.*v4/);
  const bad = run([syn('SYN-B', 'badpkg', { rec: { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }], database_specific: { severity: 'WEIRD' } } })], 'badpkg', '1.0')[0];
  assert.equal(bad.severity, 'medium'); assert.match(bad.severityBasis, /missing base metric.*unrecognised severity "WEIRD"/);
  const zero = run([syn('SYN-Z', 'zeropkg', { rec: { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' }] } })], 'zeropkg', '1.0')[0];
  assert.equal(zero.severity, 'medium'); assert.match(zero.severityBasis, /0\.0/);
});
