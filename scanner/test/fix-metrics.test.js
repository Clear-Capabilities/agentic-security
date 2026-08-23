// R5 — the reported time-to-validated-fix distribution.
//
// The tests that matter here are the honesty ones: the bucketing rules exist
// so the headline cannot be inflated, so each rule gets an assertion that
// fails if it is relaxed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  summarizeFixAxes, renderFixAxes,
  recordFixAttempt, loadFixAttempts, summarizeFixDurations,
  fixDurationReport, renderFixDurationSummary, bucketOf, FIX_STAGES, _internals,
} from '../src/posture/fix-metrics.js';

// A real project root: `state-dir.js` refuses to create `.agentic-security/`
// anywhere without a project marker, and metrics are no exception to that.
function tmpRoot() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'fixmetrics-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"fixture"}');
  return d;
}

const attempt = (over = {}) => ({
  at: '2026-08-07T00:00:00.000Z', stableId: 'sid', ok: true, testsRan: true,
  stages: { rescan: 10, lint: 5, tests: 100, honesty: 1 }, totalMs: 116, ...over,
});

test('round-trips attempts through the append-only log', () => {
  const root = tmpRoot();
  try {
    assert.equal(recordFixAttempt(root, attempt()), true);
    assert.equal(recordFixAttempt(root, attempt({ totalMs: 200 })), true);
    const back = loadFixAttempts(root);
    assert.equal(back.length, 2);
    assert.deepEqual(back.map(a => a.totalMs), [116, 200]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a torn trailing line is dropped, the records before it survive', () => {
  const root = tmpRoot();
  try {
    recordFixAttempt(root, attempt());
    // Simulate a write interrupted mid-record.
    fs.appendFileSync(path.join(root, '.agentic-security', 'fix-metrics.jsonl'), '{"ok":true,"tot');
    const back = loadFixAttempts(root);
    assert.equal(back.length, 1, 'the intact record must survive a torn tail');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('no log at all reads as no metrics, never as a throw', () => {
  const root = tmpRoot();
  try {
    assert.deepEqual(loadFixAttempts(root), []);
    assert.equal(fixDurationReport(root).attempts, 0);
    assert.equal(renderFixDurationSummary(fixDurationReport(root)), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('every attempt lands in exactly one bucket, and the counts sum', () => {
  const attempts = [
    attempt(),
    attempt({ ok: true, testsRan: false }),
    attempt({ ok: false, testsRan: true }),
    attempt({ ok: false, testsRan: false }),
  ];
  const s = summarizeFixDurations(attempts);
  assert.equal(s.attempts, 4);
  assert.equal(
    s.counts.validated + s.counts.validatedWithoutTests + s.counts.failed,
    s.attempts,
    'bucket counts must partition the attempts — a lost attempt is a silently shrunk denominator',
  );
  assert.deepEqual(s.counts, { validated: 1, validatedWithoutTests: 1, failed: 2 });
});

test('a failed attempt is never counted as time-to-validated-fix', () => {
  // The failure is deliberately fast; blending it in would drag the median down.
  const s = summarizeFixDurations([
    attempt({ totalMs: 5000 }),
    attempt({ ok: false, totalMs: 3 }),
  ]);
  assert.equal(s.timeToValidatedFix.n, 1);
  assert.equal(s.timeToValidatedFix.p50Ms, 5000, 'the fast failure must not enter the validated distribution');
  assert.equal(s.timeToFailure.n, 1);
  assert.equal(s.timeToFailure.p50Ms, 3);
});

test('"tests skipped" is bucketed apart from "tests passed"', () => {
  const s = summarizeFixDurations([
    attempt({ totalMs: 5000 }),
    attempt({ testsRan: false, totalMs: 20 }),
  ]);
  assert.equal(bucketOf(attempt({ testsRan: false })), 'validatedWithoutTests');
  assert.equal(s.timeToValidatedFix.n, 1, 'a fix with no suite to run is not a test-validated fix');
  assert.equal(s.timeToValidatedFix.p50Ms, 5000);
  assert.equal(s.timeToValidatedFixWithoutTests.n, 1);
  assert.equal(s.timeToValidatedFixWithoutTests.p50Ms, 20);
});

test('per-stage timings come from validated runs only', () => {
  const s = summarizeFixDurations([
    attempt({ stages: { rescan: 10, lint: 5, tests: 100, honesty: 1 } }),
    // A failed run stops early: its `tests` stage is truncated to ~0 and would
    // understate the stage if it were counted.
    attempt({ ok: false, stages: { rescan: 10, lint: 0, tests: 0, honesty: 0 } }),
  ]);
  assert.equal(s.byStage.tests.n, 1);
  assert.equal(s.byStage.tests.p50Ms, 100);
  for (const stage of FIX_STAGES) assert.ok(stage in s.byStage, `missing stage ${stage}`);
});

test('percentiles below the reliability floor are flagged, not hidden', () => {
  const few = summarizeFixDurations([attempt(), attempt({ totalMs: 200 })]);
  assert.equal(few.timeToValidatedFix.reliable, false);
  assert.equal(typeof few.timeToValidatedFix.p50Ms, 'number', 'the figure is still reported');
  assert.match(renderFixDurationSummary(few), /percentiles not yet reliable/);

  const many = summarizeFixDurations(
    Array.from({ length: _internals.RELIABLE_N }, (_, i) => attempt({ totalMs: 100 + i })),
  );
  assert.equal(many.timeToValidatedFix.reliable, true);
  assert.doesNotMatch(renderFixDurationSummary(many), /not yet reliable/);
});

test('n, min, max and mean are exact regardless of sample size', () => {
  const s = summarizeFixDurations([
    attempt({ totalMs: 10 }), attempt({ totalMs: 20 }), attempt({ totalMs: 60 }),
  ]);
  const d = s.timeToValidatedFix;
  assert.deepEqual([d.n, d.minMs, d.maxMs, d.meanMs], [3, 10, 60, 30]);
});

test('percentiles are nearest-rank — every reported figure is a duration some run took', () => {
  const observed = [10, 20, 30, 40];
  const s = summarizeFixDurations(observed.map(totalMs => attempt({ totalMs })));
  assert.ok(observed.includes(s.timeToValidatedFix.p50Ms));
  assert.ok(observed.includes(s.timeToValidatedFix.p90Ms));
});

test('an empty distribution reports nulls, not zeros', () => {
  // Zero would read as "validated instantly"; null reads as "not measured".
  const s = summarizeFixDurations([attempt({ ok: false })]);
  assert.equal(s.timeToValidatedFix.n, 0);
  assert.equal(s.timeToValidatedFix.p50Ms, null);
  assert.equal(s.timeToValidatedFix.meanMs, null);
});

test('metrics never create a stray state dir outside a project', () => {
  // The bug this guards is the one state-dir.js exists for: a state folder
  // appearing in some unrelated directory. Recording must decline, not force.
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'fixmetrics-bare-'));
  try {
    assert.equal(recordFixAttempt(bare, attempt()), false);
    assert.equal(fs.existsSync(path.join(bare, '.agentic-security')), false);
  } finally { fs.rmSync(bare, { recursive: true, force: true }); }
});

// Stage 5 correctness audit: the docstring declares `@returns {boolean}
// whether the record was written`, and every other early-exit in this
// function returns `false` — except the stateWritesEnabled() check, which
// is a bare `return;` (undefined). Sibling functions in the same state-dir
// family (state-dir.js's safeWriteState/ensureStateDir) correctly return
// false/null on this same condition.
test('returns false, not undefined, when state writes are disabled', () => {
  const root = tmpRoot();
  process.env.AGENTIC_SECURITY_NO_STATE = '1';
  try {
    assert.equal(recordFixAttempt(root, attempt()), false,
      'expected a boolean false, not undefined, when state writes are disabled');
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_STATE;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a malformed record cannot enter a distribution', () => {
  const root = tmpRoot();
  try {
    recordFixAttempt(root, attempt());
    fs.appendFileSync(
      path.join(root, '.agentic-security', 'fix-metrics.jsonl'),
      JSON.stringify({ ok: true, testsRan: true, totalMs: 'not-a-number' }) + '\n',
    );
    assert.equal(loadFixAttempts(root).length, 1, 'a record with no numeric totalMs is not a measurement');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── PRD F6.1 — three axes, reported separately ─────────────────────────────
//
// All three legs existed and were collapsed into one boolean. That matters
// because axis (a) — "the finding disappeared" — is satisfiable by DELETING
// CODE: the rescan goes quiet, there is nothing left to fail, and on a project
// with no detectable suite the attempt reaches ok:true having proven only that
// the detector stopped firing.

test('F6.1: the three axes are scored INDEPENDENTLY, not read off the verdict', () => {
  // Reading each axis off `ok` would make them three copies of one number. A
  // leg that passed inside a FAILED attempt still counts for its own axis.
  const s = summarizeFixAxes([
    { ok: false, rescanOk: false, testsRan: true, testsOk: true, pocOk: false },
  ]);
  assert.equal(s.findingDisappeared.n, 0, 'a failed rescan must not count as disappearance');
  assert.equal(s.testsStillPass.n, 1, 'a passing suite inside a failed attempt still counts for axis (b)');
});

test('F6.1: aOnly isolates the code-deleting shape', () => {
  // The number nobody was publishing: disappearance with NEITHER corroborating
  // axis. A high aOnly beside a high headline is a remediation feature deleting
  // code and calling it a fix.
  const s = summarizeFixAxes([
    { ok: true, rescanOk: true, testsRan: false, pocOk: false },   // suspicious
    { ok: true, rescanOk: true, testsRan: true, testsOk: true, pocOk: true }, // real
  ]);
  assert.deepEqual(s.aOnly, { n: 1, d: 2 });
  assert.deepEqual(s.satisfiesAll, { n: 1, d: 2 });
});

test('F6.1: "tests skipped" is never counted as "tests passed"', () => {
  // A project with no detectable suite is a WEAKER check, not a passing one.
  const s = summarizeFixAxes([{ ok: true, rescanOk: true, testsRan: false, pocOk: true }]);
  assert.equal(s.testsStillPass.n, 0, 'a suite that never ran cannot have passed');
});

test('F6.1: every axis carries its denominator', () => {
  const s = summarizeFixAxes([{ ok: true, rescanOk: true }, { ok: false }]);
  for (const k of ['findingDisappeared', 'testsStillPass', 'verifierAgrees', 'satisfiesAll', 'aOnly']) {
    assert.equal(s[k].d, 2, `${k} must carry the denominator`);
  }
});

test('F6.1: zero attempts does not fabricate a rate', () => {
  const s = summarizeFixAxes([]);
  assert.equal(s.total, 0);
  assert.match(s.caveat, /means nothing/);
  assert.match(renderFixAxes(s), /No fix attempts/);
});

test('F6.1: the rendered table names the code-deleting risk explicitly', () => {
  const md = renderFixAxes(summarizeFixAxes([{ ok: true, rescanOk: true }]));
  assert.match(md, /deleting code/, 'the reader must be told what aOnly means');
  assert.match(md, /the only row that means "fixed"/);
});
