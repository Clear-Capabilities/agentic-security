// PRD Epic 4 — the autonomous loop.
//
// The dangerous version of this feature applies patches because the scanner
// stopped complaining. These tests exist to make that impossible: the gate is
// that the PoC no longer fires AND the tests still pass, and every path that
// cannot establish both must end in NEEDS_REVIEW without writing anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  runAutopilot, summarizeAutopilot, renderAutopilotSummary, loadAutopilotState, OUTCOMES,
} from '../src/posture/autopilot.js';

const critical = (over = {}) => ({
  stableId: 'f1', file: 'a.js', line: 2, vuln: 'Command Injection', severity: 'critical', ...over,
});

// A fully-working set of stages; individual tests override one at a time.
const goodStages = (over = {}) => ({
  scan: async () => ({ findings: [critical()] }),
  prove: async () => ({ proofTier: 'execution-proven', proofEvidence: { ran: true } }),
  validate: async () => ({ verdict: 'upheld' }),
  synthesizeFix: async () => ({ patch: { 'a.js': 'fixed' } }),
  verifyFix: async () => ({ ok: true, pocStillFires: false, testsPass: true }),
  ...over,
});

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'autopilot-'));

test('the happy path reaches VERIFIED_FIXED', async () => {
  const r = await runAutopilot({ stages: goodStages() });
  assert.equal(r.ok, true);
  assert.equal(r.results[0].outcome, 'VERIFIED_FIXED');
});

test('gates are ON by default — a verified patch is NOT written', async () => {
  // Autonomy plus write access is the combination that turns a bad patch into a
  // bad commit. The default must be the one that cannot.
  let applied = 0;
  const r = await runAutopilot({ stages: goodStages({ applyFix: async () => { applied++; } }) });
  assert.equal(r.results[0].outcome, 'VERIFIED_FIXED');
  assert.equal(applied, 0, 'a patch was written without an explicit opt-in');
  assert.equal(r.results[0].applied, false);
});

test('apply:true writes only the verified patch', async () => {
  let applied = 0;
  const r = await runAutopilot({ apply: true, stages: goodStages({ applyFix: async () => { applied++; } }) });
  assert.equal(applied, 1);
  assert.equal(r.results[0].applied, true);
});

test('a patch the PoC still defeats is NEEDS_REVIEW and is never applied', async () => {
  // The core rule: a re-scan proves the DETECTOR went quiet; only re-running
  // the exploit proves the hole is shut.
  let applied = 0;
  const r = await runAutopilot({
    apply: true,
    stages: goodStages({
      verifyFix: async () => ({ ok: false, pocStillFires: true, testsPass: true }),
      applyFix: async () => { applied++; },
    }),
  });
  assert.equal(r.results[0].outcome, 'NEEDS_REVIEW');
  assert.match(r.results[0].reason, /still fires/);
  assert.equal(applied, 0, 'a patch that did not fix the bug was applied');
});

test('a patch that breaks the tests is NEEDS_REVIEW and is never applied', async () => {
  let applied = 0;
  const r = await runAutopilot({
    apply: true,
    stages: goodStages({
      verifyFix: async () => ({ ok: false, pocStillFires: false, testsPass: false }),
      applyFix: async () => { applied++; },
    }),
  });
  assert.equal(r.results[0].outcome, 'NEEDS_REVIEW');
  assert.match(r.results[0].reason, /test suite fails/);
  assert.equal(applied, 0);
});

test('with no verifier, nothing can be VERIFIED_FIXED', async () => {
  // An unverifiable patch is NEEDS_REVIEW even if it looks right — the claim
  // requires the evidence, not the absence of contrary evidence.
  let applied = 0;
  const stages = goodStages({ applyFix: async () => { applied++; } });
  delete stages.verifyFix;
  const r = await runAutopilot({ apply: true, stages });
  assert.equal(r.results[0].outcome, 'NEEDS_REVIEW');
  assert.match(r.results[0].reason, /cannot be re-verified/);
  assert.equal(applied, 0);
});

test('a verifier that throws fails closed', async () => {
  const r = await runAutopilot({
    apply: true,
    stages: goodStages({ verifyFix: async () => { throw new Error('verifier crashed'); } }),
  });
  assert.equal(r.results[0].outcome, 'NEEDS_REVIEW');
});

test('an unproven finding is reported UNPROVEN, not dismissed and not fixed', async () => {
  let fixes = 0;
  const r = await runAutopilot({
    stages: goodStages({
      prove: async () => ({ proofTier: 'taint-proven', proofEvidence: { ran: false, reason: 'no PoC' } }),
      synthesizeFix: async () => { fixes++; return { patch: {} }; },
    }),
  });
  assert.equal(r.results[0].outcome, 'UNPROVEN');
  assert.equal(fixes, 0, 'an unproven finding must not be auto-fixed at this tier');
  assert.match(renderAutopilotSummary(r.summary), /not dismissed/);
});

test('a refuted finding is recorded, not deleted', async () => {
  // Recall-preserving, same rule as the rest of the engine.
  const r = await runAutopilot({
    stages: goodStages({ validate: async () => ({ verdict: 'refuted' }) }),
  });
  assert.equal(r.results.length, 1, 'a refuted finding must still appear in the results');
  assert.equal(r.results[0].outcome, 'NEEDS_REVIEW');
  assert.match(r.results[0].reason, /refuted/);
});

test('no synthesised patch is NO_FIX, distinct from a failed fix', async () => {
  const r = await runAutopilot({ stages: goodStages({ synthesizeFix: async () => null }) });
  assert.equal(r.results[0].outcome, 'NO_FIX');
});

test('only in-scope severities are considered, and the rest are REPORTED', async () => {
  // Silence about what was skipped is how a partial run reads as a full one.
  const r = await runAutopilot({
    severities: ['critical'],
    stages: goodStages({
      scan: async () => ({ findings: [critical(), critical({ stableId: 'f2', severity: 'low' })] }),
    }),
  });
  assert.equal(r.results.length, 1);
  assert.equal(r.outOfScope, 1);
  assert.match(renderAutopilotSummary(r.summary), /below the severity floor/);
});

test('the run is resumable and does not redo completed findings', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'autopilot.json');
    let proves = 0;
    const stages = goodStages({ prove: async () => { proves++; return { proofTier: 'execution-proven', proofEvidence: { ran: true } }; } });
    await runAutopilot({ stages, stateFile });
    assert.equal(proves, 1);
    const second = await runAutopilot({ stages, stateFile });
    assert.equal(proves, 1, 'a completed finding was re-processed');
    assert.ok(second.skipped.includes('scan'));
    assert.equal(second.results[0].outcome, 'VERIFIED_FIXED');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// Stage 5 correctness audit: the resume short-circuit
// (`if (prior?.outcome) { results.push(prior); continue; }`) unconditionally
// replays ANY cached terminal outcome, including a VERIFIED_FIXED record
// from a prior GATED (apply:false) run — whose cached `applied` is `false`
// and whose `reason` literally says "gates on: patch is ready but was not
// written". It never checks whether the CURRENT run's `apply` flag differs
// from what produced that cached record, so the second, --apply run of the
// exact two-step workflow this tool is designed around (preview once, then
// re-run with --apply once satisfied) silently never calls applyFix. Exit
// code 0, outcome VERIFIED_FIXED, applied:false — the vulnerable file is
// never touched, and nothing in the return value screams "this is wrong."
test('resuming with apply:true after a gated (apply:false) run actually applies the fix', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'autopilot.json');
    let applied = 0;
    const stages = goodStages({ applyFix: async () => { applied++; } });
    // Run 1: default gate (apply:false) — preview only, per the documented
    // safe-by-default workflow.
    const first = await runAutopilot({ stages, stateFile });
    assert.equal(first.results[0].outcome, 'VERIFIED_FIXED');
    assert.equal(first.results[0].applied, false);
    assert.equal(applied, 0);
    // Run 2: SAME stateFile, resume:true (default), now apply:true — the
    // user reviewed the preview and wants the already-proven-safe patch
    // written.
    const second = await runAutopilot({ apply: true, stages, stateFile });
    assert.equal(applied, 1, 'applyFix was never called on the apply:true resume run');
    assert.equal(second.results[0].outcome, 'VERIFIED_FIXED');
    assert.equal(second.results[0].applied, true,
      `expected the resumed run to actually apply the fix; got ${JSON.stringify(second.results[0])}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('state survives to disk mid-run', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'autopilot.json');
    await runAutopilot({ stages: goodStages(), stateFile });
    const st = loadAutopilotState(stateFile);
    assert.ok(st.stages.scan, 'the scan stage was not checkpointed');
    assert.ok(Object.keys(st.findings).length, 'no per-finding state was written');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('refuses without a scan stage rather than reporting an empty clean run', async () => {
  const r = await runAutopilot({ stages: {} });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no scan stage/);
});

test('every outcome the loop can emit is declared', async () => {
  // An undeclared outcome would vanish from every count in the summary.
  const seen = new Set();
  for (const stages of [
    goodStages(),
    goodStages({ verifyFix: async () => ({ ok: false, pocStillFires: true, testsPass: true }) }),
    goodStages({ synthesizeFix: async () => null }),
    goodStages({ prove: async () => ({ proofTier: 'unproven', proofEvidence: {} }) }),
  ]) {
    const r = await runAutopilot({ stages });
    for (const x of r.results) seen.add(x.outcome);
  }
  for (const o of seen) assert.ok(OUTCOMES.includes(o), `undeclared outcome: ${o}`);
  assert.equal(seen.size, 4, 'expected all four outcomes to be reachable');
});

test('the summary leads with what was NOT fixed', () => {
  const s = summarizeAutopilot([
    { outcome: 'VERIFIED_FIXED', applied: true }, { outcome: 'NEEDS_REVIEW' },
  ], 0);
  const line = renderAutopilotSummary(s);
  assert.match(line, /NEEDS_REVIEW — not applied/);
});
