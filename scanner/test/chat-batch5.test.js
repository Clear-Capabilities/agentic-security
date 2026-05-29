// Tests for batch-5 Claude Code enhancements:
//   #1A watch-mode.js + dep-add-guard.js
//   #3  claude-authorship.js
//   #5  auditor-walkthrough.js + 8 bundled frameworks

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { computeDelta, renderStatusLine, persistStatus, readStatus, _internals as _iw } from '../src/posture/watch-mode.js';
import { parseInstallCommand, inspectPackage, _internals as _idg } from '../src/posture/dep-add-guard.js';
import { analyzeAuthorshipPatterns, extractOriginatingPromptCluster, suggestClaudeMdEvolution } from '../src/posture/claude-authorship.js';
import {
  listFrameworks, loadFramework, evaluateFramework,
  renderWalkthrough, persistWalkthrough,
} from '../src/posture/auditor-walkthrough.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'cb5-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"cb5"}');
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── watch-mode ────────────────────────────────────────────────────────────

test('watch: computeDelta detects added + removed + severity counts', () => {
  const prev = [{ file: 'a.js', line: 1, family: 'sqli', severity: 'critical' }];
  const cur  = [
    { file: 'a.js', line: 1, family: 'sqli', severity: 'critical' },
    { file: 'b.js', line: 5, family: 'xss',  severity: 'high'     },
    { file: 'c.js', line: 9, family: 'csrf', severity: 'critical' },
  ];
  const d = computeDelta(prev, cur);
  assert.equal(d.addedCount, 2);
  assert.equal(d.removedCount, 0);
  assert.equal(d.newCritical, 1);
  assert.equal(d.newHigh, 1);
});

test('watch: renderStatusLine surfaces critical added', () => {
  const line = renderStatusLine({ newCritical: 2, newHigh: 1, fixedCritical: 0, fixedHigh: 0, addedCount: 3, removedCount: 0 });
  assert.match(line, /\+2 crit/);
  assert.match(line, /\+1 high/);
});

test('watch: persistStatus + readStatus round-trip', async () => {
  const p = await mkProject();
  try {
    persistStatus(p.dir, { addedCount: 1, removedCount: 0, newCritical: 1, newHigh: 0, fixedCritical: 0, fixedHigh: 0, added: [{ file: 'x.js', line: 1, family: 'sqli', severity: 'critical', vuln: 'SQL injection' }], removed: [] });
    const r = readStatus(p.dir);
    assert.ok(r);
    assert.equal(r.delta.newCritical, 1);
    assert.equal(r.addedTop5.length, 1);
    assert.ok(fs.existsSync(path.join(p.dir, '.agentic-security', 'watch-status.md')));
  } finally { await p.cleanup(); }
});

test('watch: _isScanable accepts/rejects correctly', () => {
  assert.equal(_iw._isScanable('src/a.ts'), true);
  assert.equal(_iw._isScanable('src/a.py'), true);
  assert.equal(_iw._isScanable('node_modules/x/y.js'), false);
  assert.equal(_iw._isScanable('.git/index'), false);
  assert.equal(_iw._isScanable('docs/readme.md'), false);
});

// ── dep-add-guard ─────────────────────────────────────────────────────────

test('dep-guard: parses npm install', () => {
  const r = parseInstallCommand('npm install lodash express @types/node');
  assert.equal(r.length, 2);  // @types/node skipped
  assert.deepEqual(r[0], { ecosystem: 'npm', name: 'lodash' });
  assert.deepEqual(r[1], { ecosystem: 'npm', name: 'express' });
});

test('dep-guard: parses pip install', () => {
  const r = parseInstallCommand('pip install requests flask==2.3.0');
  assert.deepEqual(r[0], { ecosystem: 'pypi', name: 'requests' });
  assert.deepEqual(r[1], { ecosystem: 'pypi', name: 'flask' });
});

test('dep-guard: parses gem install + cargo add + go get', () => {
  assert.deepEqual(parseInstallCommand('gem install rails')[0], { ecosystem: 'rubygems', name: 'rails' });
  assert.deepEqual(parseInstallCommand('cargo add tokio')[0], { ecosystem: 'cargo', name: 'tokio' });
  assert.deepEqual(parseInstallCommand('go get github.com/spf13/cobra')[0], { ecosystem: 'golang', name: 'github.com/spf13/cobra' });
});

test('dep-guard: sca-policy.yml deny list flags packages', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, '.agentic-security', 'sca-policy.yml'),
      'deny:\n  - name: evil-package\n',
    );
    const r = inspectPackage({ ecosystem: 'npm', name: 'evil-package', scanRoot: p.dir });
    assert.equal(r.decision, 'deny');
  } finally { await p.cleanup(); }
});

test('dep-guard: levenshtein distance correct', () => {
  assert.equal(_idg._levenshtein('lodash', 'lodahs'), 2);
  assert.equal(_idg._levenshtein('react', 'reactt'), 1);
  assert.equal(_idg._levenshtein('foo', 'foo'), 0);
});

// ── claude-authorship ─────────────────────────────────────────────────────

test('claude-authorship: analyzes aiAuthored share + lift', () => {
  const findings = [
    { family: 'sqli', aiAuthored: true,  severity: 'critical', file: 'a.js', introducedBy: 'Claude' },
    { family: 'sqli', aiAuthored: true,  severity: 'critical', file: 'b.js', introducedBy: 'Claude' },
    { family: 'sqli', aiAuthored: false, severity: 'critical', file: 'c.js', introducedBy: 'Alice' },
    { family: 'xss',  aiAuthored: false, severity: 'high',     file: 'd.js', introducedBy: 'Bob' },
  ];
  const a = analyzeAuthorshipPatterns(findings);
  assert.equal(a.total, 4);
  assert.equal(a.ai, 2);
  const sqli = a.patterns.find(p => p.family === 'sqli');
  assert.ok(sqli);
  assert.equal(sqli.aiCount, 2);
  assert.ok(sqli.lift > 1, 'AI overrepresented in sqli');
});

test('claude-authorship: clusters similar prompts', () => {
  const findings = [
    { id: '1', family: 'sqli', file: 'a.js', severity: 'critical', originatingPrompt: 'add an endpoint for users to update profile' },
    { id: '2', family: 'csrf', file: 'b.js', severity: 'high',     originatingPrompt: 'add an endpoint for users to update settings' },
    { id: '3', family: 'xss',  file: 'c.js', severity: 'high',     originatingPrompt: 'render markdown comments inline' },
  ];
  const clusters = extractOriginatingPromptCluster(findings);
  assert.ok(clusters.length >= 1);
  const big = clusters[0];
  assert.equal(big.size, 2);
  assert.ok(big.families.includes('sqli'));
  assert.ok(big.families.includes('csrf'));
});

test('claude-authorship: suggestClaudeMdEvolution drafts stanzas', () => {
  const analysis = {
    total: 100,
    ai: 50,
    patterns: [
      { family: 'sqli', aiCount: 10, humanCount: 2, aiShare: 0.83, expectedShare: 0.5, lift: 1.67, maxSeverity: 'critical', fileCount: 5 },
      { family: 'authz', aiCount: 1, humanCount: 0, lift: 5, aiShare: 1, expectedShare: 0.5, maxSeverity: 'high', fileCount: 1 },
    ],
  };
  const sugs = suggestClaudeMdEvolution(analysis);
  assert.ok(sugs.length >= 1);
  assert.equal(sugs[0].family, 'sqli');
  assert.match(sugs[0].suggestion, /parameterized/);
});

// ── auditor-walkthrough ──────────────────────────────────────────────────

test('auditor: listFrameworks finds all 8 bundled frameworks', async () => {
  const p = await mkProject();
  try {
    const fws = listFrameworks(p.dir);
    const ids = fws.map(f => f.id).sort();
    assert.ok(ids.includes('nist-csf-2'));
    assert.ok(ids.includes('owasp-asvs-5'));
    assert.ok(ids.includes('owasp-llm-top-10'));
    assert.ok(ids.includes('eu-ai-act'));
    assert.ok(ids.includes('gdpr'));
    assert.ok(ids.includes('hipaa-security-rule'));
    assert.ok(ids.includes('ccpa'));
    assert.ok(ids.includes('nist-ai-600-1'));
    // No SOC2 / ISO / PCI bundled
    for (const banned of ['soc2', 'iso27001', 'pci-dss']) assert.ok(!ids.includes(banned));
  } finally { await p.cleanup(); }
});

test('auditor: project BYO controls.json is honored', async () => {
  const p = await mkProject();
  try {
    const dir = path.join(p.dir, '.agentic-security', 'compliance', 'my-internal-policy');
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(path.join(dir, 'controls.json'), JSON.stringify({
      id: 'my-internal-policy',
      name: 'My Org Internal Policy',
      publisher: 'My Org',
      license: 'internal',
      controls: [{ id: 'IP-1', summary: 'No hardcoded secrets.', mapsTo: ['family:hardcoded-secret'] }],
    }));
    const fws = listFrameworks(p.dir);
    assert.ok(fws.find(f => f.id === 'my-internal-policy'));
    const loaded = loadFramework(p.dir, 'my-internal-policy');
    assert.ok(loaded);
    assert.equal(loaded.controls.length, 1);
  } finally { await p.cleanup(); }
});

test('auditor: evaluateFramework marks present when zero findings', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-asvs-5');
    assert.ok(fw);
    const r = evaluateFramework(p.dir, fw, { findings: [], components: [] });
    // Most controls map to families with zero findings → 'present' status
    const present = r.filter(x => x.status === 'present').length;
    assert.ok(present >= 3, `expected ≥3 controls present, got ${present}`);
  } finally { await p.cleanup(); }
});

test('auditor: evaluateFramework marks partial when open findings on a mapsTo family', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-asvs-5');
    const scan = { findings: [{ family: 'sqli', severity: 'critical' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const v51 = r.find(x => x.control.id === 'V5.1');
    assert.ok(v51);
    assert.equal(v51.status, 'partial');
    assert.ok(v51.observations.some(o => /sqli.*finding/.test(o)));
  } finally { await p.cleanup(); }
});

test('auditor: renderWalkthrough produces Markdown with summary + per-control sections', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'gdpr');
    const r = evaluateFramework(p.dir, fw, { findings: [] });
    const body = renderWalkthrough(fw, r);
    assert.match(body, /^# Auditor walkthrough/);
    assert.match(body, /Summary/);
    assert.match(body, /GDPR|General Data Protection/i);
    assert.match(body, /DOES NOT certify compliance|does not certify/i);
  } finally { await p.cleanup(); }
});

test('auditor: persistWalkthrough writes file', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'nist-csf-2');
    const r = evaluateFramework(p.dir, fw, { findings: [] });
    const body = renderWalkthrough(fw, r);
    const fp = persistWalkthrough(p.dir, fw, body);
    assert.ok(fs.existsSync(fp));
    assert.match(fp, /nist-csf-2\.md$/);
  } finally { await p.cleanup(); }
});

test('auditor: no copyrighted standards bundled', async () => {
  const p = await mkProject();
  try {
    const fws = listFrameworks(p.dir).map(f => f.id);
    for (const banned of ['soc2', 'soc-2', 'iso-27001', 'iso27001', 'pci-dss', 'pcidss', 'hitrust']) {
      assert.ok(!fws.includes(banned), `should not bundle ${banned} (copyrighted)`);
    }
  } finally { await p.cleanup(); }
});

test('auditor: license field reflects public-domain or CC source', async () => {
  const p = await mkProject();
  try {
    const fws = listFrameworks(p.dir);
    for (const f of fws.filter(x => x.source === 'bundled')) {
      assert.ok(f.license, `${f.id} must declare license`);
      // Every bundled framework must be public-domain / CC / public-law.
      assert.match(f.license, /public|Creative Commons|EU law|federal|California statute|public-domain/i,
        `${f.id} license "${f.license}" doesn't look public-domain / CC`);
    }
  } finally { await p.cleanup(); }
});
