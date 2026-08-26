// Per-framework severity-threshold override (assurance-hardening PRD FR-502,
// "the fuller scope"). auditor-walkthrough.js's own header/comment already
// documented that raising OPEN_FINDING_MIN_SEVERITY to a single global
// 'medium' floor (test/compliance-severity-threshold.test.js) was only half
// of FR-502's acceptance criterion — "policy-specific rather than globally
// high/critical" needs a real per-framework config surface, which this file
// covers. SEVERITY_RANK was deliberately structured to make this a
// contained change; this test file proves it actually landed that way.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateFramework, _internals } from '../src/posture/auditor-walkthrough.js';

function mkProject(configBody) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cmp-sev-policy-'));
  if (configBody !== undefined) {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.agentic-security', _internals.SEVERITY_POLICY_FILE), configBody);
  }
  return dir;
}

function frameworkFor(id, family) {
  return { id, name: 'test-framework', controls: [{ id: 'T1', summary: 'x', mapsTo: [`family:${family}`] }] };
}

function lowFindingScan(family) {
  return { findings: [{ family, severity: 'low', file: 'a.js', line: 1 }], secrets: [], logicVulns: [], supplyChain: [] };
}

test('no config file at all — behavior is unchanged from the global medium floor', () => {
  const dir = mkProject();
  try {
    const [r] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(r.status, 'present', 'a low-severity finding must not open the control under the default floor');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a byFramework override lowers the floor for that framework only — a low finding now opens the control', () => {
  const dir = mkProject(JSON.stringify({ byFramework: { gdpr: 'low' } }));
  try {
    const [gdprResult] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(gdprResult.status, 'absent');
    assert.ok(gdprResult.observations.some(o => /low\+/.test(o)));

    const [otherResult] = evaluateFramework(dir, frameworkFor('hipaa-security-rule', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(otherResult.status, 'present', 'an unrelated framework with no byFramework entry must still use the medium default');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a `default` override applies to every framework with no more specific byFramework entry', () => {
  const dir = mkProject(JSON.stringify({ default: 'low' }));
  try {
    const [r] = evaluateFramework(dir, frameworkFor('any-framework-id', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(r.status, 'absent');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a byFramework entry wins over `default` for that specific framework', () => {
  const dir = mkProject(JSON.stringify({ default: 'low', byFramework: { gdpr: 'critical' } }));
  try {
    const [r] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(r.status, 'present', 'gdpr is raised to critical by its own entry, overriding the low default — a low finding must not open it');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an unknown/invalid severity value falls back to the medium default rather than breaking the comparison', () => {
  const dir = mkProject(JSON.stringify({ byFramework: { gdpr: 'super-critical-typo' } }));
  try {
    const [r] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(r.status, 'present', 'an invalid override value must degrade to the safe default, never silently disable the comparison');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('malformed JSON degrades to the medium default, never throws', () => {
  const dir = mkProject('not json{{{');
  try {
    assert.doesNotThrow(() => evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection')));
    const [r] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), lowFindingScan('sql-injection'));
    assert.equal(r.status, 'present');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('_resolveOpenFindingMinSeverity: no scanRoot returns the built-in default directly', () => {
  assert.equal(_internals._resolveOpenFindingMinSeverity(null, 'gdpr'), 'medium');
});

test('a critical-severity override still correctly opens the control on a critical finding (raising the bar in the OTHER direction also works)', () => {
  const dir = mkProject(JSON.stringify({ byFramework: { gdpr: 'critical' } }));
  try {
    const scan = { findings: [{ family: 'sql-injection', severity: 'critical', file: 'a.js', line: 1 }], secrets: [], logicVulns: [], supplyChain: [] };
    const [r] = evaluateFramework(dir, frameworkFor('gdpr', 'sql-injection'), scan);
    assert.equal(r.status, 'absent');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
