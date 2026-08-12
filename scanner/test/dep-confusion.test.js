// 0.9.0 Feat-15: Dependency confusion + typosquat tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { levenshtein, detectDepConfusion } from '../src/sca/dep-confusion.js';

// ── engine.js wiring: detectDepConfusion's results must reach scan output ──
//
// Stage 4 correctness audit: engine.js calls
// `const dc=detectDepConfusion(annotatedComponents,scanRoot);aF.push(...dc);`
// at line ~8727 — but `finalFindings` (what actually gets returned as
// scan.findings) is computed once, earlier, as
// `finalFindings=dedupeFindingsWithEvidence(aF)` (line ~8012), a snapshot
// that is never re-derived from `aF` again. Every `aF.push()` after that
// line — including this one — pushes into a disconnected, dead array.
// The dep-confusion/typosquat findings are computed correctly but never
// appear in scan.findings OR scan.supplyChain: they are silently discarded,
// not merely mischannelled.
globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [] }) });
const { runFullScan } = await import('../src/engine.js');

test('engine wiring: a typosquat dependency found by detectDepConfusion actually reaches scan output', async () => {
  const depFileContents = {
    'package.json': JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: { reactt: '1.0.0' } }),
  };
  const fileContents = { 'index.js': 'console.log("no use of the typosquatted package");\n' };
  const result = await runFullScan({ fileContents, depFileContents, scanRoot: '/tmp/agentic-security-dep-confusion-wiring-test' });
  const inFindings = (result.findings || []).some(f => /typosquat/i.test(f.vuln || ''));
  const inSupplyChain = (result.supplyChain || []).some(f => /typosquat/i.test(f.vuln || ''));
  assert.ok(inFindings || inSupplyChain, 'expected the typosquat finding to appear somewhere in scan output (found in neither scan.findings nor scan.supplyChain)');
});

test('Levenshtein — basic distances + maxDistance early exit', () => {
  assert.equal(levenshtein('lodash', 'lodash'), 0);
  assert.equal(levenshtein('lodahs', 'lodash'), 2);  // transposition = 2 substitutions in plain Levenshtein
  assert.equal(levenshtein('loadash', 'lodash'), 1); // single insertion
  assert.equal(levenshtein('lodas', 'lodash'), 1);   // single deletion
  assert.equal(levenshtein('react', 'reactt'), 1);
  assert.equal(levenshtein('aaaa', 'bbbbbbbbb'), 3); // > maxDistance → 3 (early exit returns max+1)
});

test('Typosquat detection — flags 1–2 edit distance from popular packages', () => {
  const components = [
    { ecosystem: 'npm', name: 'lodahs',  version: '1.0.0', filePath: 'package.json' }, // 2-edit from lodash
    { ecosystem: 'npm', name: 'lodash',  version: '4.17.21', filePath: 'package.json' }, // legitimate
    { ecosystem: 'npm', name: 'reactt',  version: '1.0.0', filePath: 'package.json' }, // 1-edit from react
    { ecosystem: 'npm', name: 'totally-novel-name', version: '1.0.0', filePath: 'package.json' }, // novel — no match
  ];
  const findings = detectDepConfusion(components, null);
  assert.equal(findings.length, 2, `expected 2 typosquat findings; got ${findings.length}: ${findings.map(f=>f.vuln).join(', ')}`);
  // 1-edit (reactt) is critical, 2-edit (lodahs) is high
  const reactFinding = findings.find(f => /reactt/.test(f.vuln));
  assert.equal(reactFinding.severity, 'critical');
  const lodashFinding = findings.find(f => /lodahs/.test(f.vuln));
  assert.equal(lodashFinding.severity, 'high');
});

// CMP-1 (Stage 6 follow-up): neither finding constructor here set `family`,
// so both fell through to the generic `vulnerable-dep` default every unset
// supplyChain finding gets in auditor-walkthrough.js — invisible to any
// compliance control mapped to the more specific family:dependency-confusion
// (ccpa.json).
test('Typosquat detection — findings carry family: dependency-confusion, not the generic vulnerable-dep default', () => {
  const components = [
    { ecosystem: 'npm', name: 'reactt', version: '1.0.0', filePath: 'package.json' }, // 1-edit from react
  ];
  const findings = detectDepConfusion(components, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].family, 'dependency-confusion');
});

test('Typosquat — popular package itself does NOT trigger', () => {
  const components = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }];
  const findings = detectDepConfusion(components, null);
  assert.equal(findings.length, 0);
});

test('Typosquat — unrelated package names do not match', () => {
  const components = [
    { ecosystem: 'npm', name: 'my-internal-utility', version: '1.0.0' },
    { ecosystem: 'npm', name: '@mycompany/sdk', version: '2.0.0' },
  ];
  const findings = detectDepConfusion(components, null);
  // Without internal-scopes.yml, the @mycompany/sdk shouldn't fire.
  assert.equal(findings.length, 0);
});
