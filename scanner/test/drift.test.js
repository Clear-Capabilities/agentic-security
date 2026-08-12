// 0.6.0 Feat-4: Drift report — verify diffing two synthetic scans.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { driftBetween, driftToMarkdown } from '../src/posture/drift.js';

const baseScan = {
  routes: [
    { method: 'GET',  path: '/users',   file: 'app.js', line: 10, hasAuth: true,  classifications: ['PII'] },
    { method: 'POST', path: '/login',   file: 'app.js', line: 20, hasAuth: false, classifications: [] },
  ],
  components: [
    { ecosystem: 'npm', name: 'express', version: '4.18.0' },
    { ecosystem: 'npm', name: 'lodash',  version: '4.17.20' },
  ],
  supplyChain: [
    { type: 'vulnerable_dep', ecosystem: 'npm', name: 'lodash', version: '4.17.20', severity: 'high', osvId: 'GHSA-old' },
  ],
  findings: [],
  logicVulns: [],
};

const newScan = JSON.parse(JSON.stringify(baseScan));
// Drop auth from /users
newScan.routes[0].hasAuth = false;
// Add a new unauthenticated endpoint
newScan.routes.push({ method: 'GET', path: '/admin', file: 'admin.js', line: 5, hasAuth: false, classifications: ['Confidential'] });
// Add a new dep
newScan.components.push({ ecosystem: 'npm', name: 'jsonwebtoken', version: '8.5.1' });
// Add a new critical finding
newScan.findings.push({ kind: 'sast', severity: 'critical', vuln: 'SQL Injection', file: 'admin.js', line: 12 });

test('Drift — auth boundary lost flagged as critical tier', () => {
  const d = driftBetween(baseScan, newScan);
  assert.equal(d.tier, 'critical', `expected critical tier; got ${d.tier}`);
  assert.equal(d.authBoundaries.lost.length, 1);
  assert.equal(d.authBoundaries.lost[0].path, '/users');
});

test('Drift — added endpoints, deps, and findings are surfaced', () => {
  const d = driftBetween(baseScan, newScan);
  assert.equal(d.routes.added.length, 1);
  assert.equal(d.routes.added[0].path, '/admin');
  assert.equal(d.deps.added.length, 1);
  assert.equal(d.deps.added[0].name, 'jsonwebtoken');
  assert.equal(d.findings.added.length, 1);
  assert.equal(d.findings.added[0].vuln, 'SQL Injection');
});

test('Drift — newly exposed data class detected (Confidential added)', () => {
  const d = driftBetween(baseScan, newScan);
  assert.ok(d.dataClasses.newlyExposed.includes('Confidential'),
    `expected Confidential newly exposed; got: ${d.dataClasses.newlyExposed.join(', ')}`);
});

// S7 (Stage 2 measurement-completeness audit): _findingKey used to be purely
// `${kind}:${file}:${line}:${vuln}` — a PR that shifts an existing, still-
// unfixed finding's line (e.g. adding an unrelated import above it) made it
// look like one finding was "removed" and a different one "added," inflating
// drift tier and falsely flagging the PR as introducing+fixing something it
// never touched. stableId (posture/stable-id.js) omits the exact line by
// design and must be preferred when present.
test('Drift — a finding that only shifted line (same stableId) is not double-counted as added+removed', () => {
  const base = {
    routes: [], components: [], supplyChain: [],
    findings: [{ kind: 'sast', severity: 'critical', vuln: 'SQL Injection', file: 'app.js', line: 20, stableId: 'stable-abc' }],
    logicVulns: [],
  };
  const shifted = JSON.parse(JSON.stringify(base));
  shifted.findings[0].line = 21; // unrelated edit shifted this finding down one line
  const d = driftBetween(base, shifted);
  assert.equal(d.findings.added.length, 0, `expected no added findings from a pure line shift, got: ${JSON.stringify(d.findings.added)}`);
  assert.equal(d.findings.removed.length, 0, `expected no removed findings from a pure line shift, got: ${JSON.stringify(d.findings.removed)}`);
});

test('Drift — driftToMarkdown produces a usable report', () => {
  const md = driftToMarkdown(driftBetween(baseScan, newScan));
  assert.ok(/Posture drift/.test(md), 'header missing');
  assert.ok(/Auth boundaries LOST/i.test(md), 'auth-lost section missing');
  assert.ok(/admin/.test(md), 'new endpoint not surfaced');
  assert.ok(/SQL Injection/.test(md) || /New findings/.test(md), 'new findings not surfaced');
});

test('Drift — identical scans produce info tier with no changes', () => {
  const d = driftBetween(baseScan, baseScan);
  assert.equal(d.tier, 'info');
  assert.equal(d.totalChanged, 0);
});
