// realworld-recall — bench scoring/judge/miss-analyzer unit tests (addition #6).
//
// These verify the recall-scoring MATH, the deterministic matcher, the
// offline-degrading judge, and the miss-analyzer heuristics deterministically —
// no scanner run, no network. The runner's end-to-end behaviour (corpus → scan
// → match → judge → score → miss-analysis) is smoke-checked separately; the
// correctness of the primitives lives here so it can never silently drift.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchExpected, scoreRecall, checkGate } from '../../bench/realworld-recall/score.mjs';
import { judgeDetection } from '../../bench/realworld-recall/judge.mjs';
import { analyzeMiss } from '../../bench/realworld-recall/analyze-misses.mjs';

// ---------------------------------------------------------------------------
// matchExpected — deterministic fallback matcher
// ---------------------------------------------------------------------------

test('matchExpected: deterministic hit on same location + same class', () => {
  const expected = { finding_id: 'V1', type: 'sql-injection', cwe: 'CWE-89', location: 'src/db/users.js:42' };
  const emitted = [
    { id: 'F1', file: 'project/src/db/users.js', line: 42, family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 },
    { id: 'F2', file: 'src/other.js', line: 3, family: 'xss', cwe: 'CWE-79', confidence: 0.8 },
  ];
  const r = matchExpected(expected, emitted);
  assert.equal(r.detected, true);
  assert.equal(r.matched, 'F1');
  assert.equal(r.confidence, 0.9);
});

test('matchExpected: misses when class differs at the same location', () => {
  const expected = { finding_id: 'V4', type: 'ssrf', cwe: 'CWE-918', location: 'src/net/fetch.js:20' };
  const emitted = [{ id: 'F3', file: 'src/net/fetch.js', line: 20, family: 'open-redirect', cwe: 'CWE-601', confidence: 0.6 }];
  const r = matchExpected(expected, emitted);
  assert.equal(r.detected, false);
  assert.equal(r.matched, null);
});

test('matchExpected: misses when location differs for the same class', () => {
  const expected = { finding_id: 'V1', type: 'sql-injection', cwe: 'CWE-89', location: 'src/db/users.js:42' };
  const emitted = [{ id: 'F9', file: 'src/db/orders.js', line: 7, family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 }];
  assert.equal(matchExpected(expected, emitted).detected, false);
});

test('matchExpected: class match tolerates separator/case differences', () => {
  const expected = { finding_id: 'V1', type: 'SQL Injection', location: 'a.js:1' };
  const emitted = [{ id: 'F1', file: 'a.js', line: 1, family: 'sql_injection', confidence: 0.7 }];
  assert.equal(matchExpected(expected, emitted).detected, true);
});

test('matchExpected: a genuine judge-error verdict propagates detected:null (reserved)', () => {
  const expected = { finding_id: 'V1', type: 'sql-injection', cwe: 'CWE-89', location: 'src/db/users.js:42' };
  const emitted = [{ id: 'F1', file: 'src/db/users.js', line: 42, family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 }];
  const r = matchExpected(expected, emitted, { detected: null, reasoning: 'judge-error: timeout' });
  assert.equal(r.detected, null);
});

test('matchExpected: the no-endpoint sentinel falls back to the deterministic matcher', () => {
  const expected = { finding_id: 'V1', type: 'sql-injection', cwe: 'CWE-89', location: 'src/db/users.js:42' };
  const emitted = [{ id: 'F1', file: 'src/db/users.js', line: 42, family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 }];
  const r = matchExpected(expected, emitted, { detected: null, reasoning: 'no-llm-endpoint: falls back to deterministic matcher' });
  assert.equal(r.detected, true);
  assert.equal(r.matched, 'F1');
});

// ---------------------------------------------------------------------------
// scoreRecall — recall / detection-rate math (null-not-zero discipline)
// ---------------------------------------------------------------------------

test('scoreRecall: counts detected/missed/judgeErrors; detectionRate excludes judge-errors; byType breakdown', () => {
  const results = [
    { id: 'a', type: 'sql-injection', detected: true },
    { id: 'b', type: 'sql-injection', detected: false },
    { id: 'c', type: 'command-injection', detected: true },
    { id: 'd', type: 'path-traversal', detected: null }, // judge error — excluded from denom
  ];
  const s = scoreRecall(results);
  assert.equal(s.total, 4);
  assert.equal(s.detected, 2);
  assert.equal(s.missed, 1);
  assert.equal(s.judgeErrors, 1);
  // detectionRate = detected / (total - judgeErrors) = 2 / 3
  assert.equal(s.detectionRate, 0.6667);
  assert.equal(s.byType['sql-injection'].detected, 1);
  assert.equal(s.byType['sql-injection'].missed, 1);
  assert.equal(s.byType['sql-injection'].detectionRate, 0.5);
  assert.equal(s.byType['command-injection'].detectionRate, 1);
  // a type seen only via a judge-error → denom 0 → null, NOT a misleading 0
  assert.equal(s.byType['path-traversal'].detectionRate, null);
});

test('scoreRecall: all judge-errors → detectionRate null (no divide-by-zero)', () => {
  const s = scoreRecall([{ type: 'x', detected: null }, { type: 'y', detected: null }]);
  assert.equal(s.detected, 0);
  assert.equal(s.judgeErrors, 2);
  assert.equal(s.detectionRate, null);
});

test('scoreRecall: empty input → zero counts, null rate', () => {
  const s = scoreRecall([]);
  assert.equal(s.total, 0);
  assert.equal(s.detectionRate, null);
});

// ---------------------------------------------------------------------------
// checkGate — returns a violations array; a null metric under a live threshold
// is itself a violation.
// ---------------------------------------------------------------------------

test('checkGate: passes when met, flags below-threshold, flags a null metric under an active threshold', () => {
  const good = scoreRecall([{ type: 'sqli', detected: true }, { type: 'sqli', detected: true }]); // rate 1.0
  assert.deepEqual(checkGate(good, { minDetectionRate: 0.9 }), []);

  const belowScore = scoreRecall([{ type: 'sqli', detected: true }, { type: 'sqli', detected: false }]); // 0.5
  const below = checkGate(belowScore, { minDetectionRate: 0.9 });
  assert.ok(below.length >= 1);
  assert.match(below.join(' '), /detectionRate/);

  // null aggregate metric (all judge-errors) under an active threshold → violation
  const nullScore = scoreRecall([{ type: 'sqli', detected: null }]);
  const g = checkGate(nullScore, { minDetectionRate: 0.5 });
  assert.ok(g.length >= 1);
  assert.match(g.join(' '), /unmeasured/);
});

// ---------------------------------------------------------------------------
// judgeDetection — bench-only semantic judge; degrades to null offline WITHOUT
// throwing and WITHOUT any network call.
// ---------------------------------------------------------------------------

test('judgeDetection: offline (no endpoint) returns detected:null and never throws or hits the network', () => {
  const saved = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const v = judgeDetection({
      expectedFinding: { finding_id: 'V1', type: 'sql-injection', location: 'a.js:1' },
      emittedFindings: [{ id: 'F1', file: 'a.js', family: 'sql-injection' }],
    });
    assert.equal(v.detected, null);
    assert.match(v.reasoning, /no-llm-endpoint/);
  } finally {
    if (saved !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = saved;
  }
});

test('judgeDetection: with an endpoint set it still degrades to null (stub not wired) without throwing', () => {
  const v = judgeDetection({
    expectedFinding: { finding_id: 'V1', type: 'sql-injection', location: 'a.js:1' },
    emittedFindings: [],
    endpoint: 'http://127.0.0.1:9/unreachable',
  });
  assert.equal(v.detected, null);
  assert.match(v.reasoning, /judge-error|not wired/);
});

// ---------------------------------------------------------------------------
// analyzeMiss — picks the earliest pipeline stage that dropped the finding and
// proposes a concrete rule/prompt change. Deterministic.
// ---------------------------------------------------------------------------

const STAGES = ['recon-entrypoint', 'detector', 'taint', 'posture-filter', 'proof-gate'];

test('analyzeMiss: no detector candidate → lost at the detector stage, non-empty fix', () => {
  const r = analyzeMiss({ finding_id: 'V3', type: 'path-traversal', location: 'src/files/read.js:15', detectorFired: false }, { stages: STAGES });
  assert.equal(r.missId, 'V3');
  assert.equal(r.lostAtStage, 'detector');
  assert.equal(typeof r.proposedFix, 'string');
  assert.ok(r.proposedFix.length > 0);
});

test('analyzeMiss: entrypoint/posture/proof signals each map to their stage', () => {
  assert.equal(analyzeMiss({ finding_id: 'V5', type: 'xss', entrypointFound: false }, { stages: STAGES }).lostAtStage, 'recon-entrypoint');
  assert.equal(analyzeMiss({ finding_id: 'V6', type: 'xss', postureFiltered: true }, { stages: STAGES }).lostAtStage, 'posture-filter');
  assert.equal(analyzeMiss({ finding_id: 'V7', type: 'idor', proofFailed: true }, { stages: STAGES }).lostAtStage, 'proof-gate');
});

test('analyzeMiss: the earliest failing stage wins when several signals are set', () => {
  const r = analyzeMiss({ finding_id: 'V8', type: 'sqli', detectorFired: false, taintConnected: false }, { stages: STAGES });
  assert.equal(r.lostAtStage, 'detector'); // detector precedes taint in the ordered list
});

test('analyzeMiss: with no explicit signal still returns a plausible stage + fix', () => {
  const r = analyzeMiss({ finding_id: 'V9', type: 'sqli', location: 'x.js:1' }, {});
  assert.equal(r.missId, 'V9');
  assert.ok(r.lostAtStage);
  assert.ok(r.proposedFix.length > 0);
});
