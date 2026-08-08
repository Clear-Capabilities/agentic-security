import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toFindingShape, judgeCandidates } from '../src/discovery/judge.js';

const cand = (over = {}) => ({
  id: 'c1', focusAreaId: 'fa1', lens: 'injection', title: 'SQLi in login',
  file: 'auth.js', line: 12, family: 'injection', cwe: 'CWE-74',
  rationale: 'string concat into a query', entryPoint: 'req.body.n', sink: 'db.query',
  confirmation: { tier: 'taint-confirmed', evidence: {} },
  refutation: { refuted: false, voterCount: 3, refuteCount: 0, undecided: false, votes: [] },
  ...over,
});

test('toFindingShape emits every required schema field', () => {
  const f = toFindingShape(cand());
  for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) {
    assert.ok(f[k] !== undefined && f[k] !== null && f[k] !== '', `missing ${k}`);
  }
  assert.equal(f.parser, 'DISCOVERY');
  assert.equal(f.family, 'injection');
  assert.ok(f.stableId);
  assert.equal(f.discovery.lens, 'injection');
});

test('a taint-confirmed candidate outranks an unconfirmed one in severity', () => {
  const hi = toFindingShape(cand());
  const lo = toFindingShape(cand({ confirmation: { tier: 'unconfirmed', evidence: null } }));
  assert.equal(hi.severity, 'high');
  assert.equal(lo.severity, 'low');
});

test('judgeCandidates marks same-file/line/family as a duplicate of the prior scan', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'injection', stableId: 'x' }] };
  const r = judgeCandidates([cand()], prior, null);
  assert.equal(r.fresh.length, 0);
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.duplicates[0].duplicateOf, 'x');
});

test('a different family at the same line is fresh, not a duplicate', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'crypto', stableId: 'x' }] };
  const r = judgeCandidates([cand()], prior, null);
  assert.equal(r.fresh.length, 1);
});

test('a stableId a human marked fp is suppressed', () => {
  const f = toFindingShape(cand());
  const r = judgeCandidates([cand()], null, { [f.stableId]: 'fp' });
  assert.equal(r.suppressed.length, 1);
  assert.equal(r.fresh.length, 0);
});

test('a stableId marked tp is still fresh — a prior true positive is not a duplicate', () => {
  const f = toFindingShape(cand());
  const r = judgeCandidates([cand()], null, { [f.stableId]: 'tp' });
  assert.equal(r.fresh.length, 1);
});

test('stableId collides across lines of the same lens and file — pinned deliberately', () => {
  // computeStableId hashes ruleId + snippet + path shape + basename, NOT the
  // line, so it survives code moving. Two candidates of one lens in one file
  // therefore share an id. This is pinned so a future change to stable-id.js
  // that alters the behaviour shows up here as a decision, not a surprise.
  const a = toFindingShape(cand({ line: 12 }));
  const b = toFindingShape(cand({ id: 'c2', line: 99 }));
  assert.equal(a.stableId, b.stableId);
  assert.equal(a.ruleId, 'discovery:injection');
});

test('file+line+family is the primary duplicate key, so a different sink at a new line is fresh', () => {
  // Prior finding at auth.js:12 with sink 'db.query'.
  const priorFinding = toFindingShape(cand({ line: 12 }));
  // New candidate at auth.js:99 with different sink — should be fresh even though
  // same lens and file, because line is different and sink discriminates the id.
  const r = judgeCandidates([cand({ id: 'c2', line: 99, sink: 'child_process.exec' })], { findings: [priorFinding] }, null);
  assert.equal(r.fresh.length, 1);
  assert.equal(r.duplicates.length, 0);
});

test('regression: different sink at different line is not silently swallowed as duplicate', () => {
  // Scenario: prior scan found SQLi at auth.js:12 via 'db.query'.
  // Now judge a command-injection candidate at auth.js:400 via 'child_process.exec'.
  // These are distinct vulnerabilities and must not collapse onto one id.
  const sqliPrior = toFindingShape(cand({ line: 12, sink: 'db.query', title: 'SQLi in login' }));
  const cmdInjCandidate = cand({
    id: 'c2', line: 400, sink: 'child_process.exec', title: 'Command injection in shell',
  });
  const r = judgeCandidates([cmdInjCandidate], { findings: [sqliPrior] }, null);
  assert.equal(r.fresh.length, 1, 'command injection should be fresh, not swallowed');
  assert.equal(r.duplicates.length, 0);
});

test('every candidate lands in exactly one bucket', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'injection', stableId: 'x' }] };
  const cands = [cand(), cand({ id: 'c2', line: 99 }), cand({ id: 'c3', line: 50 })];
  const r = judgeCandidates(cands, prior, null);
  assert.equal(r.fresh.length + r.duplicates.length + r.suppressed.length, 3);
});

test('missing prior scan and feedback are tolerated', () => {
  const r = judgeCandidates([cand()], undefined, undefined);
  assert.equal(r.fresh.length, 1);
});
