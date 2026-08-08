// The active-learning suppression quorum.
//
// `learning.js` lets triage feedback suppress findings. The root CLAUDE.md
// warns: "Do not lower the quorum default without thinking about what a
// malicious-PR-author could suppress." Adversarial review found the code did
// not enforce that warning — `Math.max(1, …)` accepted
// AGENTIC_SECURITY_LEARN_QUORUM=1, so a SINGLE triage verdict could suppress a
// finding, and because suppression also matches on family+filePattern, one
// verdict could silence a family across a path.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { applyFeedback, loadFeedback } from '../src/posture/learning.js';

const STABLE_ID = 'deadbeefdeadbeef';

function root(entries) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'learn-'));
  fs.mkdirSync(path.join(d, '.agentic-security'), { recursive: true });
  // The real filename is `triage-feedback.json`. An earlier draft wrote
  // `feedback.json`, so nothing loaded and the suppression assertions passed
  // for the wrong reason; the positive-control test below caught it.
  fs.writeFileSync(
    path.join(d, '.agentic-security', 'triage-feedback.json'),
    JSON.stringify({ entries }),
  );
  // PRECONDITION, not decoration. Read the fixture back through the module's
  // own loader and assert it arrived. Without this, a wrong filename makes
  // `applyFeedback` return early and every "nothing was suppressed" assertion
  // below passes with no data loaded at all — which is exactly what happened on
  // the first draft of this file.
  const loaded = loadFeedback(d);
  assert.equal(loaded.entries?.length, entries.length,
    'fixture did not load through loadFeedback — the suppression assertions would be vacuous');
  return d;
}

const fpEntry = () => ({ stableId: STABLE_ID, verdict: 'fp', family: 'xss', file: 'a.js' });
const finding = () => ({ stableId: STABLE_ID, family: 'xss', file: 'a.js', severity: 'high' });

function withEnv(env, fn) {
  const saved = { ...process.env };
  try {
    Object.assign(process.env, env);
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    return fn();
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

test('a single verdict never suppresses, even when quorum=1 is requested', () => {
  // The attack: one triage verdict (from anyone who can land a PR) silencing a
  // real finding. Requesting quorum=1 must be raised to 2, not honoured.
  const d = root([fpEntry()]);
  try {
    const r = withEnv(
      { AGENTIC_SECURITY_LEARN: '1', AGENTIC_SECURITY_LEARN_QUORUM: '1' },
      () => applyFeedback(d, [finding()]),
    );
    assert.equal(r.suppressed.length, 0, 'one verdict suppressed a finding at quorum=1');
    assert.equal(r.kept.length, 1);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('zero, negative and malformed quorum values are all floored to 2', () => {
  const d = root([fpEntry()]);
  try {
    for (const q of ['0', '-5', 'abc', '']) {
      const r = withEnv(
        { AGENTIC_SECURITY_LEARN: '1', AGENTIC_SECURITY_LEARN_QUORUM: q },
        () => applyFeedback(d, [finding()]),
      );
      assert.equal(r.suppressed.length, 0, `quorum='${q}' allowed a single-verdict suppression`);
    }
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('two independent verdicts do suppress — the floor is not a disable switch', () => {
  // The feature must still work at its documented default, or the fix would be
  // a silent removal rather than a hardening.
  const d = root([
    { ...fpEntry(), at: '2026-01-01' },
    { ...fpEntry(), at: '2026-01-02' },
  ]);
  try {
    const r = withEnv(
      { AGENTIC_SECURITY_LEARN: '1' },
      () => applyFeedback(d, [finding()]),
    );
    assert.equal(r.suppressed.length, 1, 'quorum of 2 should suppress with two verdicts');
    assert.equal(r.kept.length, 0);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a higher quorum than the default is still honoured', () => {
  const d = root([
    { ...fpEntry(), at: '2026-01-01' },
    { ...fpEntry(), at: '2026-01-02' },
  ]);
  try {
    const r = withEnv(
      { AGENTIC_SECURITY_LEARN: '1', AGENTIC_SECURITY_LEARN_QUORUM: '5' },
      () => applyFeedback(d, [finding()]),
    );
    assert.equal(r.suppressed.length, 0, 'raising the bar must still raise it');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the whole subsystem stays off unless explicitly enabled', () => {
  const d = root([
    { ...fpEntry(), at: '2026-01-01' },
    { ...fpEntry(), at: '2026-01-02' },
  ]);
  try {
    const r = withEnv({ AGENTIC_SECURITY_LEARN: undefined }, () => applyFeedback(d, [finding()]));
    assert.equal(r.suppressed.length, 0);
    assert.equal(r.kept.length, 1);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
