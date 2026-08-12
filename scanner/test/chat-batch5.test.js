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

// ── CMP-2 ────────────────────────────────────────────────────────────────
//
// (a) evaluateFramework read only scan.findings (SAST-only) — secrets, SCA
//     and logic findings were invisible to every framework's family:
//     mappings, even though the scan object it's handed carries all four
//     channels (the same shape last-scan.json has).
// (b) a `rule:` mapping set anySignal=true unconditionally and never set
//     allCleared=false — so a control whose only evidence is "verify this
//     manually" (the rule: observation's own text) could resolve to
//     'present', the same status as a control with real, checked evidence.

test('CMP-2: evaluateFramework sees secrets, logicVulns and supplyChain findings, not just SAST', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'ccpa'); // maps family:hardcoded-secret
    const scanWithSecret = { findings: [], secrets: [{ family: 'hardcoded-secret', severity: 'critical' }] };
    const r = evaluateFramework(p.dir, fw, scanWithSecret);
    const withSecretFamily = r.filter(x =>
      Array.isArray(x.control.mapsTo) && x.control.mapsTo.includes('family:hardcoded-secret'));
    assert.ok(withSecretFamily.length > 0, 'ccpa must map at least one control to family:hardcoded-secret');
    assert.ok(withSecretFamily.every(x => x.status !== 'present'),
      'a critical secret finding must not be invisible to a control mapped to its family');
  } finally { await p.cleanup(); }
});

test('CMP-2: evaluateFramework sees an open vulnerable-dep (SCA) finding', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-asvs-5'); // V10.1 maps family:vulnerable-dep
    const scan = { findings: [], supplyChain: [{ severity: 'critical', name: 'left-pad', vuln: 'CVE-x' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const v101 = r.find(x => x.control.id === 'V10.1');
    assert.ok(v101);
    assert.notEqual(v101.status, 'present',
      'a critical SCA finding must not be invisible to the control mapped to family:vulnerable-dep');
  } finally { await p.cleanup(); }
});

test('CMP-2: a control whose only mapping is rule: can never resolve to "present" (rule-only pass)', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-llm-top-10'); // has a control mapped to rule:no-max-tokens
    const r = evaluateFramework(p.dir, fw, { findings: [] });
    const ruleOnly = r.filter(x =>
      Array.isArray(x.control.mapsTo) &&
      x.control.mapsTo.every(m => m.startsWith('rule:')));
    assert.ok(ruleOnly.length > 0, 'expected at least one rule:-only control in owasp-llm-top-10');
    for (const c of ruleOnly) {
      assert.notEqual(c.status, 'present',
        `${c.control.id}: a control whose evidence says "verify manually" must not report as fully present`);
    }
  } finally { await p.cleanup(); }
});

// ── Stage 6 correctness audit ──────────────────────────────────────────
//
// (a) `family:auth-missing`/`family:authz` are compliance-JSON-only strings
//     no detector ever emits — real missing-auth findings use family names
//     like `broken-access-control`. Every control mapped to auth-missing/
//     authz read 'present' regardless of open findings.
// (b) `family:X:Y` subfamily qualifiers were parsed then discarded — any
//     finding of family X counted against every control mapped to family X,
//     regardless of which subfamily the control actually named.
// (c) the documented 'absent' status (a control where nothing at all
//     passed) was unreachable — every non-present, non-manual control
//     rendered as 'partial', collapsing "mostly clean, one gap" and
//     "completely unevidenced" into the same bucket.

test('Stage6: a critical broken-access-control finding is visible to a control mapped to family:auth-missing', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-asvs-5'); // V2.1 maps solely to family:auth-missing
    const scan = { findings: [{ family: 'broken-access-control', subfamily: 'missing-auth', severity: 'critical' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const v21 = r.find(x => x.control.id === 'V2.1');
    assert.ok(v21);
    assert.notEqual(v21.status, 'present',
      'a critical unauthenticated-route finding must not be invisible to the control mapped to family:auth-missing');
  } finally { await p.cleanup(); }
});

test('Stage6: a framework-specific missing-auth family (fastapi-missing-auth) also reaches family:auth-missing', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-asvs-5');
    const scan = { findings: [{ family: 'fastapi-missing-auth', severity: 'high' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const v21 = r.find(x => x.control.id === 'V2.1');
    assert.notEqual(v21.status, 'present');
  } finally { await p.cleanup(); }
});

test('Stage6: family:X:Y subfamily qualifier scopes the match — an unrelated subfamily does not falsely flag a control', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-llm-top-10');
    // llm-tool-exec is LLM07's subfamily, not LLM06's (llm-credential-in-prompt).
    const scan = { findings: [{ family: 'llm-app-security', subfamily: 'llm-tool-exec', severity: 'critical' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const llm06 = r.find(x => x.control.id === 'LLM06');
    assert.ok(llm06);
    assert.equal(llm06.status, 'present',
      'an llm-tool-exec finding must not count against LLM06, which is scoped to the llm-credential-in-prompt subfamily');
  } finally { await p.cleanup(); }
});

test('Stage6: family:X:Y subfamily qualifier still matches when the subfamily is the right one', async () => {
  const p = await mkProject();
  try {
    const fw = loadFramework(p.dir, 'owasp-llm-top-10');
    const scan = { findings: [{ family: 'llm-app-security', subfamily: 'llm-credential-in-prompt', severity: 'critical' }] };
    const r = evaluateFramework(p.dir, fw, scan);
    const llm06 = r.find(x => x.control.id === 'LLM06');
    assert.notEqual(llm06.status, 'present');
  } finally { await p.cleanup(); }
});

test('Stage6: evaluateFramework can report "absent" for a control where nothing at all passed', () => {
  const fw = {
    id: 'synthetic', name: 'Synthetic', publisher: 'test', license: 'internal',
    controls: [{ id: 'S-1', summary: 'Totally unevidenced control.', mapsTo: ['family:sqli'] }],
  };
  const scan = { findings: [{ family: 'sqli', severity: 'critical' }] };
  const r = evaluateFramework('/tmp/does-not-need-to-exist', fw, scan);
  assert.equal(r[0].status, 'absent',
    'a control whose only mapping totally fails (no passing evidence at all) should read absent, not partial');
});

test('Stage6: a mixed control (some mappings pass, one fails) still reads "partial", not "absent"', () => {
  const fw = {
    id: 'synthetic', name: 'Synthetic', publisher: 'test', license: 'internal',
    controls: [{ id: 'S-2', summary: 'Mixed control.', mapsTo: ['family:sqli', 'family:xss'] }],
  };
  const scan = { findings: [{ family: 'sqli', severity: 'critical' }] }; // xss family has zero findings -> clears
  const r = evaluateFramework('/tmp/does-not-need-to-exist', fw, scan);
  assert.equal(r[0].status, 'partial');
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
