// scanner/test/discovery-disprove.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REFUTE_ANGLES, buildRefutePrompt, disproveCandidate, disprovePanel } from '../src/discovery/disprove.js';

const C = { id: 'c1', file: 'a.js', line: 3, title: 'SQLi in login', rationale: 'concat', confirmation: { tier: 'unconfirmed' } };

test('there are three refutation angles and each prompt names its own', () => {
  assert.equal(REFUTE_ANGLES.length, 3);
  for (const a of REFUTE_ANGLES) {
    const p = buildRefutePrompt(C, a);
    assert.ok(p.includes(a));
    assert.ok(p.includes('SQLi in login'));
    assert.ok(/refute/i.test(p), 'the voter must be told to refute, not to assess');
  }
});

test('a majority of refute votes drops the candidate', async () => {
  const llmInvoke = async () => '{"refuted":true,"reason":"unreachable"}';
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 3);
  assert.equal(out.refutation.refuteCount, 3);
  assert.equal(out.refutation.refuted, true);
});

test('a tie is not a majority and the candidate survives', async () => {
  let n = 0;
  const llmInvoke = async () => (++n <= 2 ? '{"refuted":true,"reason":"x"}' : '{"refuted":false,"reason":"y"}');
  const out = await disproveCandidate(C, { llmInvoke, angles: ['reachability', 'preconditions', 'sanitization', 'reachability'] });
  assert.equal(out.refutation.refuteCount, 2);
  assert.equal(out.refutation.voterCount, 4);
  assert.equal(out.refutation.refuted, false, '2 of 4 is not a majority');
});

test('voters that error are excluded from the denominator, not counted as agreement', async () => {
  let n = 0;
  const llmInvoke = async () => {
    if (++n === 1) return '{"refuted":true,"reason":"x"}';
    throw new Error('timeout');
  };
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 1);
  assert.equal(out.refutation.refuteCount, 1);
  assert.equal(out.refutation.refuted, true);
});

test('when no voter votes the panel is undecided and the candidate survives', async () => {
  const llmInvoke = async () => { throw new Error('down'); };
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 0);
  assert.equal(out.refutation.undecided, true);
  assert.equal(out.refutation.refuted, false, 'silence must never refute');
});

test('with no llmInvoke the panel is undecided and does not throw', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const out = await disproveCandidate(C, {});
    assert.equal(out.refutation.undecided, true);
    assert.equal(out.refutation.refuted, false);
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('disprovePanel splits survivors from refuted', async () => {
  const llmInvoke = async (p) => (p.includes('doomed') ? '{"refuted":true}' : '{"refuted":false}');
  const r = await disprovePanel([C, { ...C, id: 'c2', title: 'doomed' }], { llmInvoke });
  assert.deepEqual(r.survivors.map(s => s.id), ['c1']);
  assert.deepEqual(r.refuted.map(s => s.id), ['c2']);
});
