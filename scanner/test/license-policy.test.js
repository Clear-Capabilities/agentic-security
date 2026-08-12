// 0.8.0 Feat-10: License policy enforcement tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyLicense, evaluateLicensePolicy } from '../src/posture/license-policy.js';

const policy = {
  allow:   ['MIT', 'APACHE-2.0', 'BSD-3-CLAUSE', 'BSD-2-CLAUSE', 'ISC'],
  deny:    ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
  review:  ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0'],
  unknown: 'review',
};

test('License policy — single SPDX licenses classify against allow/deny/review', () => {
  assert.equal(classifyLicense('MIT', policy),         'allow');
  assert.equal(classifyLicense('mit', policy),         'allow'); // case insensitive
  assert.equal(classifyLicense('GPL-3.0', policy),     'deny');
  assert.equal(classifyLicense('LGPL-2.1', policy),    'review');
  assert.equal(classifyLicense('Unknown-1.0', policy), 'review'); // unknown bucket
  assert.equal(classifyLicense('', policy),            'review');
});

test('License policy — compound SPDX expressions deny if ANY atom is denied', () => {
  assert.equal(classifyLicense('(MIT OR GPL-3.0)', policy), 'deny');
  assert.equal(classifyLicense('(MIT OR Apache-2.0)', policy), 'allow');
  assert.equal(classifyLicense('(MPL-2.0 OR Apache-2.0)', policy), 'review');
});

test('License policy — evaluateLicensePolicy emits findings only for deny/review/unknown', () => {
  const components = [
    { name: 'a', version: '1.0.0', ecosystem: 'npm', license: 'MIT',      filePath: 'package.json' },
    { name: 'b', version: '2.0.0', ecosystem: 'npm', license: 'GPL-3.0',  filePath: 'package.json' },
    { name: 'c', version: '3.0.0', ecosystem: 'npm', license: 'LGPL-2.1', filePath: 'package.json' },
    { name: 'd', version: '4.0.0', ecosystem: 'npm', license: '',         filePath: 'package.json' },
  ];
  const findings = evaluateLicensePolicy(components, policy);
  assert.equal(findings.length, 3, `expected 3 (b/c/d); got ${findings.length}`);
  // Deny is 'high' severity
  const deny = findings.find(f => /Denied/.test(f.vuln));
  assert.ok(deny);
  assert.equal(deny.severity, 'high');
  assert.equal(deny.kind, 'license');
});

test('License policy — null policy emits no findings', () => {
  const findings = evaluateLicensePolicy([{ name: 'a', license: 'GPL-3.0' }], null);
  assert.equal(findings.length, 0);
});

// Stage 4 correctness audit: evaluateLicensePolicy sets `package`, `version`,
// `ecosystem`, `license` on every finding so a consumer can tell WHICH
// component and WHICH license triggered it — but normalizeFindings'
// logicVulns merge (report/index.js) builds its output object from an
// explicit field allowlist that never included these four. A license-policy
// finding surviving normalizeFindings (the shape every report format and
// last-scan.json actually ships) carries only the human-readable `vuln`
// string; there is no structured way for a consumer (CSV column, SARIF
// property, MCP tool) to recover which package/license/ecosystem it's about
// without regex-parsing prose.
test('License policy — package/version/ecosystem/license survive normalizeFindings', async () => {
  const { normalizeFindings } = await import('../src/report/index.js');
  const findings = evaluateLicensePolicy(
    [{ name: 'bad-lib', version: '2.0.0', ecosystem: 'npm', license: 'GPL-3.0', filePath: 'package.json' }],
    policy,
  );
  const norm = normalizeFindings({ logicVulns: findings });
  const f = norm.find(n => n.kind === 'license');
  assert.ok(f, 'expected the license-policy finding to survive normalizeFindings');
  assert.equal(f.package, 'bad-lib');
  assert.equal(f.version, '2.0.0');
  assert.equal(f.ecosystem, 'npm');
  assert.equal(f.license, 'GPL-3.0');
});
