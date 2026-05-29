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

test('commands: synthesize-rule.md present + has frontmatter', () => {
  const fp = path.join(CMDS, 'synthesize-rule.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /^---\n[\s\S]*?description:/);
  assert.match(body, /argument-hint:/);
  assert.match(body, /--from-cve/);
});

test('commands: triage-tournament.md present + describes flow', () => {
  const fp = path.join(CMDS, 'triage-tournament.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /accept.*reject.*snooze/i);
  assert.match(body, /compositeRisk/);
});

test('commands: sbom-explore.md present + lists example queries', () => {
  const fp = path.join(CMDS, 'sbom-explore.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /transitive/);
  assert.match(body, /CVE/);
});

test('commands: exploit-builder.md present + lists output formats', () => {
  const fp = path.join(CMDS, 'exploit-builder.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /curl/);
  assert.match(body, /jest/i);
  assert.match(body, /pytest/);
});

test('commands: model-rescan.md present + cites AGENTIC_SECURITY_LLM_MODEL', () => {
  const fp = path.join(CMDS, 'model-rescan.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /AGENTIC_SECURITY_LLM_MODEL/);
  assert.match(body, /AGENTIC_SECURITY_LLM_VALIDATE/);
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
