// Tests for batch-4 Claude Code chat enhancements:
//   #9  /synthesize-rule    (command file presence)
//   #10 /triage-tournament, /sbom-explore, /exploit-builder (command files)
//   #11 model-rescan.js + /model-rescan command

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as os from 'node:os';
import * as fsp from 'node:fs/promises';
import { diffValidatorRuns, persistRescanReport, summarizeDelta, runModelRescan } from '../src/posture/model-rescan.js';

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

// Stage 6 correctness audit: diffValidatorRuns/persistRescanReport/
// summarizeDelta above were fully built with no producer to feed them a
// real {model, results} run file — /labs --model-rescan was disclosed as
// genuinely unwired. runModelRescan is the missing producer: it re-runs
// llm-validator's validateMany twice (baseline env, then toModel via the
// existing AGENTIC_SECURITY_LLM_MODEL_VALIDATE override) and turns the two
// runs into a real delta report.
async function mkScanRoot(findings) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'model-rescan-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.writeFile(path.join(dir, 'a.js'), 'const x = 1;\n');
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), JSON.stringify({ findings }));
  return dir;
}

test('runModelRescan: requires a --model argument', async () => {
  const dir = await mkScanRoot([{ id: 'F1', severity: 'high', file: 'a.js', line: 1, vuln: 'X' }]);
  const r = await runModelRescan(dir, {});
  assert.equal(r.ok, false);
  assert.match(r.reason, /no --model/);
  await fsp.rm(dir, { recursive: true, force: true });
});

test('runModelRescan: refuses cleanly when there is no prior scan', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'model-rescan-empty-'));
  const r = await runModelRescan(dir, { toModel: 'claude-opus-5' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /run a scan first/);
  await fsp.rm(dir, { recursive: true, force: true });
});

test('runModelRescan: produces a real {from, to, changed, reportPath} delta (degrades honestly to unvalidated with no endpoint configured, matching the rest of this codebase — setting a MODEL alone can\'t establish a provider)', async () => {
  const dir = await mkScanRoot([
    { id: 'F1', stableId: 'stable-f1-aaaaaaaa', severity: 'critical', file: 'a.js', line: 1, vuln: 'SQLi' },
  ]);
  const r = await runModelRescan(dir, { toModel: 'claude-opus-5' });
  assert.equal(r.ok, true, JSON.stringify(r));
  // No AGENTIC_SECURITY_LLM_ENDPOINT/PRESET is configured in this test env,
  // so neither run can actually resolve a provider — both correctly report
  // 'unvalidated' rather than falsely claiming the requested model ran.
  assert.equal(r.from, 'unvalidated');
  assert.equal(r.to, 'unvalidated');
  assert.deepEqual(r.changed, [], 'both unvalidated runs must agree — nothing to report as changed');
  assert.ok(r.reportPath && fs.existsSync(r.reportPath), 'expected a persisted rescan report');
  const persisted = JSON.parse(fs.readFileSync(r.reportPath, 'utf8'));
  assert.equal(persisted.to, 'unvalidated');
  await fsp.rm(dir, { recursive: true, force: true });
});

test('runModelRescan: the model override genuinely reaches provider resolution, not just the report label', async () => {
  // A deliberately unreachable-but-syntactically-valid endpoint (port 0):
  // resolveProvider succeeds (so `model` reflects the real resolved config,
  // not the 'unvalidated' fallback), while the actual HTTP call fails fast
  // with no live network dependency — same technique test/llm-validator-
  // default-on.test.js already uses.
  const dir = await mkScanRoot([
    { id: 'F1', stableId: 'stable-f1-bbbbbbbb', severity: 'critical', file: 'a.js', line: 1, vuln: 'SQLi' },
  ]);
  const prevEndpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const prevModel = process.env.AGENTIC_SECURITY_LLM_MODEL;
  process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'http://localhost:0/never';
  process.env.AGENTIC_SECURITY_LLM_MODEL = 'baseline-model';
  try {
    const r = await runModelRescan(dir, { toModel: 'challenger-model' });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.from, 'baseline-model', 'the "from" run must resolve the baseline env model, not a placeholder');
    assert.equal(r.to, 'challenger-model', 'the "to" run must resolve the requested override model, proving AGENTIC_SECURITY_LLM_MODEL_VALIDATE genuinely took effect');
  } finally {
    if (prevEndpoint === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT; else process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prevEndpoint;
    if (prevModel === undefined) delete process.env.AGENTIC_SECURITY_LLM_MODEL; else process.env.AGENTIC_SECURITY_LLM_MODEL = prevModel;
    await fsp.rm(dir, { recursive: true, force: true });
  }
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
