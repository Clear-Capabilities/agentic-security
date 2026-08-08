// R14 — vulnerability archaeology.
//
// A commit-message classifier cannot be precise, so the tests pin the thing
// that makes an imprecise signal usable: that weak evidence is tiered
// separately, never inflates the strong tier, and never ranks a file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  classifyCommit, mineVulnHistory, annotateHistoricalRisk, renderArchaeology, TIERS,
} from '../src/posture/vuln-archaeology.js';

// ------------------------------------------------------------- classifier

test('a CVE or GHSA reference is the strong tier', () => {
  for (const s of [
    'fix CVE-2024-1234 in the parser',
    'bump dep for GHSA-abcd-1234-wxyz',
    'CVE-2019-11043',
  ]) {
    const c = classifyCommit(s);
    assert.equal(c?.tier, 'identified', `missed identifier in: ${s}`);
    assert.match(c.evidence, /references/);
  }
});

test('a fix verb paired with a vulnerability noun is the medium tier', () => {
  for (const s of [
    'fix XSS in the comment renderer',
    'patch a path traversal in the uploader',
    'sanitize user input to prevent SQL injection',
  ]) {
    assert.equal(classifyCommit(s)?.tier, 'likely', `misclassified: ${s}`);
  }
});

test('test/doc/chore commits that name a vulnerability are the weak tier', () => {
  // The trap: these contain both a fix verb and a vulnerability noun while
  // fixing nothing. Counting them as real fixes would inflate every hotspot.
  for (const s of [
    'add tests for the XSS fix',
    'document how we prevent CSRF',
    'rename the sanitizer module',
    'revert "fix command injection"',
    'update changelog for the SSRF patch',
  ]) {
    assert.equal(classifyCommit(s)?.tier, 'mentioned', `should be weak: ${s}`);
  }
});

test('ordinary commits classify as nothing at all', () => {
  for (const s of ['bump lodash to 4.17.21', 'add dark mode', 'refactor the router', '', null, undefined]) {
    assert.equal(classifyCommit(s), null, `false match on: ${s}`);
  }
});

test('a CVE reference beats the non-fix heuristic', () => {
  // An explicit identifier is strong evidence even in a chore-shaped message.
  assert.equal(classifyCommit('update tests for CVE-2024-1234')?.tier, 'identified');
});

test('every tier the classifier emits is a declared tier', () => {
  for (const s of ['fix CVE-2024-1234', 'fix XSS', 'add XSS tests']) {
    assert.ok(TIERS.includes(classifyCommit(s).tier));
  }
});

// ------------------------------------------------------------- mining

function repo(commits) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arch-'));
  const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
  execFileSync('git', ['init', '-q', dir], { stdio: 'ignore' });
  git('config', 'user.email', 't@example.com');
  git('config', 'user.name', 'T');
  git('config', 'commit.gpgsign', 'false');
  for (const [subject, file] of commits) {
    fs.writeFileSync(path.join(dir, file), `${subject}\n${Math.random()}\n`);
    git('add', file);
    git('commit', '-q', '-m', subject);
  }
  return dir;
}

test('a non-repository degrades to unavailable, never an error', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'notrepo-'));
  try {
    const h = mineVulnHistory(dir);
    assert.equal(h.available, false);
    assert.match(h.reason, /git history unavailable/);
    assert.deepEqual(h.hotspots, []);
    assert.match(renderArchaeology(h), /skipped/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('mines real history and ranks hotspots by strong evidence only', () => {
  const dir = repo([
    ['fix CVE-2024-1111 in the auth handler', 'auth.js'],
    ['fix XSS in the auth handler', 'auth.js'],
    ['add tests for the XSS fix', 'render.js'],
    ['document CSRF protections', 'render.js'],
    ['add dark mode', 'ui.js'],
  ]);
  try {
    const h = mineVulnHistory(dir);
    assert.equal(h.available, true);
    assert.equal(h.byTier.identified, 1);
    assert.equal(h.byTier.likely, 1);
    assert.equal(h.byTier.mentioned, 2);

    const files = h.hotspots.map(x => x.file);
    assert.equal(files[0], 'auth.js', 'the file with real fixes must rank first');
    assert.ok(!files.includes('render.js'),
      'a file whose only signal is the weak tier must NOT be ranked — that sorts by classifier error');
    assert.ok(!files.includes('ui.js'));

    const auth = h.hotspots[0];
    assert.equal(auth.identified, 1);
    assert.equal(auth.likely, 1);
    assert.ok(auth.subjects.length > 0, 'a hotspot must carry the evidence behind it');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a commit subject cannot forge a record boundary', () => {
  // Subjects are arbitrary user text. A newline-delimited format would let a
  // crafted message inject a fake commit record; the NUL-delimited one cannot.
  const dir = repo([
    ['fix XSS in parser', 'a.js'],
    ['chore: normal', 'b.js'],
  ]);
  try {
    const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
    fs.writeFileSync(path.join(dir, 'c.js'), 'x');
    git('add', 'c.js');
    git('commit', '-q', '-m', 'chore: harmless\n\nfix CVE-2099-9999 totally real\nevil.js');
    const h = mineVulnHistory(dir);
    assert.ok(!h.hotspots.some(x => x.file === 'evil.js'),
      'a fabricated file path in a commit body became a hotspot');
    assert.equal(h.byTier.identified, 0, 'a CVE in the body must not count as a subject match');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('annotation is advisory and never touches severity', () => {
  const h = {
    available: true,
    hotspots: [{ file: 'auth.js', identified: 2, likely: 1, mentioned: 5, subjects: [] }],
  };
  const findings = [
    { file: 'auth.js', severity: 'medium' },
    { file: 'other.js', severity: 'low' },
  ];
  const n = annotateHistoricalRisk(findings, h);
  assert.equal(n, 1);
  assert.equal(findings[0].historicalRisk.priorSecurityFixes, 3,
    'the weak tier must not inflate the count');
  assert.equal(findings[0].severity, 'medium', 'severity must be untouched');
  assert.equal(findings[1].historicalRisk, undefined);
  assert.match(findings[0].historicalRisk.note, /not evidence about this finding/);
});

test('annotation is a no-op when history is unavailable', () => {
  const findings = [{ file: 'a.js', severity: 'high' }];
  assert.equal(annotateHistoricalRisk(findings, { available: false }), 0);
  assert.equal(findings[0].historicalRisk, undefined);
});

test('truncation is disclosed rather than implied', () => {
  const dir = repo([
    ['fix XSS one', 'a.js'],
    ['fix XSS two', 'a.js'],
    ['fix XSS three', 'a.js'],
  ]);
  try {
    const h = mineVulnHistory(dir, { maxCommits: 2 });
    assert.equal(h.commitsScanned, 2);
    assert.equal(h.truncated, true);
    assert.match(renderArchaeology(h), /history truncated/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the summary names the ranking caveat', () => {
  const dir = repo([['fix XSS in parser', 'a.js']]);
  try {
    assert.match(renderArchaeology(mineVulnHistory(dir)), /Ranking ignores the "mentioned" tier/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('ranking is churn-corrected — a high-traffic file is not a hotspot', () => {
  // The failure this prevents, observed on this repository: release commits
  // whose subject mentions security also touch the changelog, manifest and
  // version files, so a raw count ranked CLAUDE.md and package.json top while
  // the actual vulnerable source was buried.
  const commits = [];
  // A file touched by everything, security or not.
  for (let i = 0; i < 20; i++) commits.push([`chore: release ${i}`, 'CHANGELOG.md']);
  commits.push(['fix XSS in the renderer', 'CHANGELOG.md']);
  const dir = repo(commits);
  try {
    const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
    // A file whose short history is mostly security work.
    fs.writeFileSync(path.join(dir, 'auth.js'), 'x');
    git('add', 'auth.js');
    git('commit', '-q', '-m', 'fix command injection in auth');

    const h = mineVulnHistory(dir);
    const top = h.hotspots[0];
    assert.equal(top.file, 'auth.js', 'the concentrated file must outrank the high-churn one');
    assert.equal(top.concentration, 1);
    assert.ok(!h.hotspots.some(x => x.file === 'CHANGELOG.md'),
      'a file with 1 security commit in 21 must not be reported as a hotspot');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('every hotspot carries the denominator behind its concentration', () => {
  const dir = repo([
    ['fix XSS in parser', 'a.js'],
    ['chore: tidy', 'a.js'],
  ]);
  try {
    const h = mineVulnHistory(dir, { minConcentration: 0 });
    const a = h.hotspots.find(x => x.file === 'a.js');
    assert.equal(a.totalCommits, 2, 'the total must be counted across ALL commits, not just matched ones');
    assert.equal(a.concentration, 0.5);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
