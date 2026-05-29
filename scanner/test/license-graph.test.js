// Tests for license-graph.js (transitive license analysis) and
// license-attributions.js (ATTRIBUTIONS.md / NOTICE emit).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import { analyzeLicenseGraph, _internals as _lg } from '../src/posture/license-graph.js';
import { generateAttributions, persistAttributions } from '../src/posture/license-attributions.js';

const mkComp = (ecosystem, name, version, license, opts = {}) => ({
  ecosystem, name, version, license, ...opts,
});

test('license-graph: MIT direct dep + AGPL transitive flagged under saas', () => {
  const comps = [
    mkComp('npm', 'my-cool-lib', '1.0.0', 'MIT'),
    mkComp('npm', 'gpl-dep', '2.0.0', 'AGPL-3.0', { transitive: true, importedBy: ['npm:my-cool-lib@1.0.0'] }),
  ];
  const r = analyzeLicenseGraph(comps, { distributionMode: 'saas' });
  const agpl = r.findings.find(f => f.package === 'gpl-dep');
  assert.ok(agpl, `expected AGPL finding; got ${r.findings.map(f => f.package).join(',')}`);
  assert.equal(agpl.severity, 'high');
  assert.ok(agpl.depPath.length === 2, 'depPath includes parent');
  assert.equal(agpl.distributionMode, 'saas');
});

test('license-graph: GPL is denied under library mode but reviewed under saas', () => {
  const comp = [mkComp('npm', 'gpl-thing', '1.0.0', 'GPL-3.0')];
  const r1 = analyzeLicenseGraph(comp, { distributionMode: 'library' });
  const r2 = analyzeLicenseGraph(comp, { distributionMode: 'saas' });
  assert.equal(r1.findings[0].severity, 'high', 'library mode → deny');
  assert.equal(r2.findings[0].severity, 'low', 'saas mode → review');
});

test('license-graph: AGPL is denied under saas mode (network-use)', () => {
  const r = analyzeLicenseGraph([mkComp('npm', 'm', '1', 'AGPL-3.0')], { distributionMode: 'saas' });
  assert.equal(r.findings[0].severity, 'high');
  assert.equal(r.findings[0].licenseFamily, 'network_copyleft');
});

test('license-graph: BSL / SSPL / Elastic-2.0 source-available licenses denied across modes', () => {
  const licenses = ['BSL-1.1', 'SSPL-1.0', 'Elastic-2.0'];
  for (const lic of licenses) {
    for (const mode of ['saas', 'binary', 'library']) {
      const r = analyzeLicenseGraph([mkComp('npm', 'm', '1', lic)], { distributionMode: mode });
      assert.equal(r.findings[0].severity, 'high', `${lic} under ${mode}`);
      assert.equal(r.findings[0].licenseFamily, 'source_available');
    }
  }
});

test('license-graph: permissive licenses pass under all modes', () => {
  for (const lic of ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', '0BSD']) {
    for (const mode of ['saas', 'binary', 'library']) {
      const r = analyzeLicenseGraph([mkComp('npm', 'm', '1', lic)], { distributionMode: mode });
      assert.equal(r.findings.length, 0, `${lic} under ${mode}: should be allow`);
    }
  }
});

test('license-graph: dual-license trap (GPL OR Commercial) flagged', () => {
  const comp = [mkComp('npm', 'qt-bindings', '1.0.0', '(GPL-3.0 OR Commercial)')];
  const r = analyzeLicenseGraph(comp, { distributionMode: 'binary' });
  assert.ok(r.findings.some(f => f.family === 'license-dual-trap'),
    `expected dual-trap; got ${r.findings.map(f => f.family).join(',')}`);
});

test('license-graph: known relicensing event (elasticsearch) is flagged', () => {
  const r = analyzeLicenseGraph([mkComp('npm', 'elasticsearch', '7.15.0', 'Elastic-2.0')], { distributionMode: 'saas' });
  assert.ok(r.findings.some(f => f.family === 'license-relicense'));
});

test('license-graph: LGPL is review under binary mode, allow under saas', () => {
  const c = [mkComp('npm', 'm', '1', 'LGPL-3.0')];
  const r1 = analyzeLicenseGraph(c, { distributionMode: 'binary' });
  const r2 = analyzeLicenseGraph(c, { distributionMode: 'saas' });
  assert.equal(r1.findings[0]?.severity, 'low', 'binary review');
  assert.equal(r2.findings.length, 0, 'saas allow');
});

test('license-graph: classifier handles compound expressions correctly', () => {
  assert.equal(_lg._classify('MIT'), 'permissive');
  assert.equal(_lg._classify('Apache-2.0'), 'permissive');
  assert.equal(_lg._classify('GPL-3.0'), 'strong_copyleft');
  assert.equal(_lg._classify('AGPL-3.0'), 'network_copyleft');
  assert.equal(_lg._classify('SSPL-1.0'), 'source_available');
  // Compound: pick worst.
  assert.equal(_lg._classify('(MIT OR GPL-3.0)'), 'strong_copyleft');
  assert.equal(_lg._classify('(GPL-3.0 OR AGPL-3.0)'), 'network_copyleft');
  assert.equal(_lg._classify(''), 'unknown');
});

// ── Attributions emit ──────────────────────────────────────────────────────

test('attributions: ATTRIBUTIONS.md generated and deterministic', async () => {
  const comps = [
    mkComp('npm', 'react', '18.3.1', 'MIT'),
    mkComp('npm', 'lodash', '4.17.21', 'MIT'),
    mkComp('pypi', 'numpy', '1.26.0', 'BSD-3-Clause'),
  ];
  const r1 = generateAttributions(comps);
  const r2 = generateAttributions(comps);
  assert.equal(r1.markdown, r2.markdown, 'output must be deterministic');
  assert.ok(r1.markdown.includes('react'));
  assert.ok(r1.markdown.includes('numpy'));
  assert.equal(r1.componentCount, 3);
});

test('attributions: NOTICE emitted when Apache-2.0 present, omitted when not', () => {
  const r1 = generateAttributions([mkComp('npm', 'x', '1', 'Apache-2.0')]);
  assert.ok(r1.notice, 'Apache present → NOTICE generated');
  const r2 = generateAttributions([mkComp('npm', 'x', '1', 'MIT')]);
  assert.equal(r2.notice, '', 'no Apache → no NOTICE');
});

test('attributions: persistAttributions writes ATTRIBUTIONS.md and NOTICE', async () => {
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'attribs-'));
  try {
    const r = generateAttributions([mkComp('npm', 'fastify', '4', 'MIT'),
                                    mkComp('npm', 'express', '4', 'Apache-2.0')]);
    persistAttributions(tmp, r);
    const mdPath = path.join(tmp, '.agentic-security', 'ATTRIBUTIONS.md');
    const notPath = path.join(tmp, '.agentic-security', 'NOTICE');
    assert.ok(fs.existsSync(mdPath));
    assert.ok(fs.existsSync(notPath));
    const notice = fs.readFileSync(notPath, 'utf8');
    assert.ok(notice.includes('Apache 2.0'));
    assert.ok(notice.includes('express'));
  } finally { await fsp.rm(tmp, { recursive: true, force: true }); }
});

test('license-graph: empty components → empty findings', () => {
  const r = analyzeLicenseGraph([]);
  assert.equal(r.findings.length, 0);
  assert.equal(r.summary.total, 0);
});
