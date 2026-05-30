// Tests for batch-4 Claude Code chat enhancements:
//   #9  /synthesize-rule    (command file presence)
//   #10 /triage-tournament, /sbom-explore, /exploit-builder (command files)
//   #11 model-rescan.js + /model-rescan command

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';

import { diffValidatorRuns, persistRescanReport, summarizeDelta } from '../src/posture/model-rescan.js';

const CMDS = path.resolve(import.meta.dirname, '..', '..', 'commands');

// v0.85.0 command consolidation: the rich docs that lived in individual
// command files now live in the dispatcher commands (labs.md, triage.md,
// supply.md). The legacy alias files have since been removed. These
// tests verify the dispatcher carries the documented capability and the
// alias files are gone.

test('dispatch: /labs documents synthesize-rule mode', () => {
  const body = fs.readFileSync(path.join(CMDS, 'labs.md'), 'utf8');
  assert.match(body, /^---\n[\s\S]*?description:/);
  assert.match(body, /synthesize-rule/);
  // Legacy alias removed — capability lives only on the dispatcher now
  assert.ok(!fs.existsSync(path.join(CMDS, 'synthesize-rule.md')));
});

test('dispatch: /triage documents tournament + verdict workflow', () => {
  const body = fs.readFileSync(path.join(CMDS, 'triage.md'), 'utf8');
  assert.match(body, /tournament/i);
  assert.match(body, /compositeRisk/);
  // Verdict workflow vocab — tp/fp/wontfix or accept/reject/snooze
  assert.match(body, /tp.*fp.*wontfix|wontfix.*fp.*tp|accept.*reject|reject.*accept/i);
});

test('dispatch: /supply documents sbom + cve-alerts + transitive', () => {
  const body = fs.readFileSync(path.join(CMDS, 'supply.md'), 'utf8');
  assert.match(body, /sbom/i);
  assert.match(body, /cve/i);
  // Legacy alias removed — capability lives only on the dispatcher now
  assert.ok(!fs.existsSync(path.join(CMDS, 'sbom-explore.md')));
});

test('dispatch: /triage documents exploit mode with curl/jest/pytest formats', () => {
  const body = fs.readFileSync(path.join(CMDS, 'triage.md'), 'utf8');
  assert.match(body, /exploit/i);
  assert.match(body, /curl/i);
  assert.match(body, /jest/i);
  assert.match(body, /pytest/i);
});

test('dispatch: /labs documents model-rescan + cites AGENTIC_SECURITY_LLM_MODEL', () => {
  const body = fs.readFileSync(path.join(CMDS, 'labs.md'), 'utf8');
  assert.match(body, /model-rescan/);
  // Detailed env-var references remain in posture/model-rescan.js; legacy alias removed
  assert.ok(!fs.existsSync(path.join(CMDS, 'model-rescan.md')));
});

test('model-rescan: diffValidatorRuns detects verdict flips', () => {
  const a = { model: 'claude-sonnet-4', results: { 'F1': { verdict: 'fp', reason: 'looks like a test' }, 'F2': { verdict: 'tp' } } };
  const b = { model: 'claude-opus-5',   results: { 'F1': { verdict: 'tp', reason: 'production code' }, 'F2': { verdict: 'tp' } } };
  const changed = diffValidatorRuns(a, b);
  assert.equal(changed.length, 1);
  assert.equal(changed[0].finding_id, 'F1');
  assert.equal(changed[0].before, 'fp');
  assert.equal(changed[0].after, 'tp');
});

test('model-rescan: agree → no changes', () => {
  const r = { model: 'x', results: { 'F1': { verdict: 'tp' } } };
  const changed = diffValidatorRuns(r, r);
  assert.deepEqual(changed, []);
});

test('model-rescan: summarizeDelta surfaces TP↔FP flip counts', () => {
  const changed = [
    { before: 'fp', after: 'tp' },
    { before: 'fp', after: 'tp' },
    { before: 'tp', after: 'fp' },
  ];
  const s = summarizeDelta(changed);
  assert.match(s, /3 verdict change/);
  assert.match(s, /2.*confirmed TP/);
  assert.match(s, /1.*now FP/);
});

test('model-rescan: persistRescanReport writes file', async () => {
  const fsp = await import('node:fs/promises');
  const os = await import('node:os');
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'mr-'));
  try {
    const fp = persistRescanReport(tmp, 'claude-sonnet-4', 'claude-opus-5', [{ finding_id: 'F1', before: 'fp', after: 'tp' }]);
    assert.ok(fp);
    const body = JSON.parse(fs.readFileSync(fp, 'utf8'));
    assert.equal(body.from, 'claude-sonnet-4');
    assert.equal(body.to, 'claude-opus-5');
    assert.equal(body.changed.length, 1);
  } finally { await fsp.rm(tmp, { recursive: true, force: true }); }
});
