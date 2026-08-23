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
  const reactFinding = findings.find(f => /reactt/.test(f.vuln));
  assert.equal(reactFinding.severity, 'critical');
  // `lodahs` USED to score `high` here, because plain Levenshtein charges 2
  // for a transposition. Under Damerau-Levenshtein it is one adjacent swap and
  // scores `critical`, which is the right answer: transposing two characters
  // is the most common real typo and therefore the STRONGEST typosquat signal,
  // not the weakest. The expectation was changed deliberately when the
  // distance measure changed — see dep-confusion.js's MAX_DIVERGENCE note.
  const lodashFinding = findings.find(f => /lodahs/.test(f.vuln));
  assert.equal(lodashFinding.severity, 'critical');
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

// ── PRD F3.1 — the typosquat FP budget, measured on real dependency trees ────
//
// `bench/sca-replay` ran this detector over 13 pinned real repositories and it
// produced 166 findings at critical/high severity, of which ZERO were
// typosquats. A representative sample:
//
//   ms ~ ws        acorn ~ cors     ajv ~ ava      six ~ tox
//   abab ~ ava     arg ~ yargs      bail ~ babel   aws4 ~ ws
//
// npm/cli alone produced 37, next.js 128. Every one names a real, popular,
// entirely legitimate package — `ms` is a top-50 npm package — at a severity
// that puts it above genuine advisory matches in the report.
//
// The cause is that plain edit distance is meaningless on short names: at
// distance 2, `ava` and `abab` differ by two thirds of their length, and any
// two-character name is within one edit of any other. Two changes fix it:
//
//   1. Damerau-Levenshtein, so a TRANSPOSITION costs 1 rather than 2. That is
//      the single most common real typo and the one plain Levenshtein scores
//      worst — `lodahs` for `lodash` is one slip of the fingers, not two edits.
//   2. The distance must be small RELATIVE to the name. A quarter of the
//      shorter name is the threshold; beyond that it is a different word.
//
// These tests are the FP budget. They exist so that widening the reference
// package list later cannot quietly reintroduce the noise.
import { detectDepConfusion as _detect } from '../src/sca/dep-confusion.js';

const REAL_FALSE_POSITIVES = [
  ['ms', '2.1.2'], ['acorn', '8.7.0'], ['ajv', '8.10.0'], ['six', '1.15.0'],
  ['abab', '2.0.5'], ['arg', '5.0.1'], ['bail', '1.0.5'], ['aws4', '1.11.0'],
  ['docs', '1.0.0'], ['asap', '2.0.6'], ['alex', '9.1.0'],
];

test('typosquat: the real-world false positives measured by bench/sca-replay stay silent', () => {
  const components = REAL_FALSE_POSITIVES.map(([name, version]) => ({
    ecosystem: 'npm', name, version, filePath: 'package-lock.json',
  }));
  const findings = _detect(components, null).filter((f) => /typosquat/.test(f.id));
  assert.deepEqual(
    findings.map((f) => f.vuln), [],
    'every one of these is a legitimate, popular package; none is a typosquat',
  );
});

test('typosquat: real typosquat shapes still fire', () => {
  // The transposition case is the one plain Levenshtein got wrong, and it is
  // the most common real typo — so it must survive the tightening, not merely
  // be tolerated by it.
  const components = [
    { ecosystem: 'npm', name: 'lodahs', version: '1.0.0', filePath: 'package.json' },   // transposition of lodash
    { ecosystem: 'npm', name: 'reactt', version: '1.0.0', filePath: 'package.json' },   // doubled last char of react
    { ecosystem: 'npm', name: 'expres', version: '1.0.0', filePath: 'package.json' },   // dropped char of express
  ];
  const flagged = _detect(components, null)
    .filter((f) => /typosquat/.test(f.id)).map((f) => f.package).sort();
  assert.deepEqual(flagged, ['expres', 'lodahs', 'reactt']);
});

test('typosquat: two-character names are never evidence', () => {
  // `ms` vs `ws` is one edit on a two-character name — which is to say, every
  // two-character package in existence is one edit from every other.
  const findings = _detect([{ ecosystem: 'npm', name: 'ms', version: '2.1.2' }], null);
  assert.equal(findings.length, 0);
});

test('typosquat: a flagged finding names the package in a field, not only in prose', () => {
  // A supply-chain finding whose subject exists only inside an English
  // sentence cannot be triaged, suppressed, or grouped by anything downstream.
  const [f] = _detect([{ ecosystem: 'npm', name: 'lodahs', version: '1.0.0' }], null);
  assert.equal(f.package, 'lodahs');
  assert.equal(f.version, '1.0.0');
  assert.equal(f.ecosystem, 'npm');
});
