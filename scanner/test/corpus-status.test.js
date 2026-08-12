import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { analyzeCorpus, summarizeCorpusStatus, TARGET_CWES, TARGET_LANGUAGES } from '../src/posture/corpus-status.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const entries = [
  { cve: 'A', cwe: 'CWE-89', language: 'javascript' },
  { cve: 'B', cwe: 'CWE-89', language: 'python' },
  { cve: 'C', cwe: 'CWE-79', language: 'javascript' },
];

test('analyzeCorpus tallies language/CWE and the coverage matrix', () => {
  const r = analyzeCorpus(entries, { target: 500 });
  assert.equal(r.total, 3);
  assert.equal(r.byLanguage.javascript, 2);
  assert.equal(r.byCwe['CWE-89'], 2);
  assert.equal(r.matrix['CWE-89'].python, 1);
  assert.equal(r.progressPct, 1);
  assert.equal(r.remainingToTarget, 497);
});

test('gaps are empty target cells and counts are consistent', () => {
  const r = analyzeCorpus(entries);
  assert.equal(r.cellsTotal, TARGET_CWES.length * TARGET_LANGUAGES.length);
  assert.equal(r.cellsCovered + r.gapCount, r.cellsTotal);
  // CWE-89/javascript is covered → not a gap; CWE-89/go is a gap.
  assert.ok(!r.gaps.some(g => g.cwe === 'CWE-89' && g.language === 'javascript'));
  assert.ok(r.gaps.some(g => g.cwe === 'CWE-89' && g.language === 'go'));
});

test('summarizeCorpusStatus renders progress + gaps', () => {
  const s = summarizeCorpusStatus(analyzeCorpus(entries));
  assert.match(s, /3\/500 entries/);
  assert.match(s, /cells covered/);
  assert.match(s, /example gaps:/);
});

test('handles empty / junk input without throwing', () => {
  const r = analyzeCorpus(null);
  assert.equal(r.total, 0);
  assert.equal(r.gapCount, r.cellsTotal);
});

// S7 (Stage 2 measurement-completeness audit): bench/cve-replay/corpus-status.mjs
// only walked regression/ and capability/, silently omitting the deep/ tier —
// runner.mjs's own canonical TIERS constant is ['regression', 'capability',
// 'deep'], and corpus-baseline.json (the file the CI gate actually trusts)
// counts all three. Two numbers that both claim to be "size of the CVE-replay
// corpus" disagreed by exactly the size of the omitted tier, with nobody told.
test('corpus-status.mjs counts all three tiers (regression + capability + deep), matching corpus-baseline.json', () => {
  const bench = path.join(REPO_ROOT, 'bench', 'cve-replay');
  const baseline = JSON.parse(fs.readFileSync(path.join(bench, 'corpus-baseline.json'), 'utf8'));
  const baselineTotal = Object.keys(baseline.entries || baseline).length
    || baseline.total; // tolerate either shape without over-assuming the schema
  assert.ok(Number.isInteger(baselineTotal) && baselineTotal > 0, 'expected a real baseline entry count to compare against');

  const r = spawnSync('node', [path.join(bench, 'corpus-status.mjs'), '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `corpus-status.mjs must exit 0; stderr: ${r.stderr}`);
  const report = JSON.parse(r.stdout);
  assert.equal(report.total, baselineTotal,
    `corpus-status.mjs reported ${report.total} entries but corpus-baseline.json has ${baselineTotal} — the deep/ tier must not be silently dropped`);
});
