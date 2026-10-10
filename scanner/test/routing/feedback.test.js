// X-607: routing feedback protection. SYNTHETIC outcomes and fake transports; no network, no real adjudicator.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFeedbackStore, signFeedback, authorizePayload, sendToProvider } from '../../src/posture/routing/feedback.js';
import { createProviderAdapter } from '../../src/posture/routing/adapter.js';
import { createReceiptLog, verifyReceiptChain } from '../../src/posture/routing/receipts.js';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { taskOf, outcomeOf, syntheticPopulation, BASE_CONFIG } from '../helpers/routing-fixtures.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FEEDBACK_SRC = fs.readFileSync(path.join(HERE, '..', '..', 'src', 'posture', 'routing', 'feedback.js'), 'utf8');
const KEYS = { 'adj-1': 'k-adjudicator-one-0123456789', 'ver-1': 'k-verifier-service-0123456789', 'model-cand': 'k-the-model-itself-0123456789' };
const ACTORS = { 'adj-1': { kind: 'human', key: KEYS['adj-1'] }, 'ver-1': { kind: 'verifier-service', key: KEYS['ver-1'] }, 'model-cand': { kind: 'human', key: KEYS['model-cand'] } };
const SECRET_SRC = 'const proprietaryScoringAlgorithm = 42; // SECRET_BODY_MARKER';
const CANARY_KEY = 'sk_' + 'live_' + '0123456789' + 'abcdefghij' + 'ABCD';
const NOW = '2026-05-01T00:00:00Z';

const delayed = (i, o = {}) => outcomeOf({ task: taskOf(i), model: 'model-cand', correct: null, delayed: true, synthetic: true, ...o });
function fb(outcome, over = {}, actor = 'adj-1') {
  const f = { outcomeId: outcome.id, taskId: outcome.taskId, verdict: 'correct', evidenceKind: 'independent-adjudication', adjudicationVersion: 'adjudication-1', reasonCode: 'initial-label', actorId: actor, submittedAt: NOW, ...over };
  f.sig = over.sig ?? signFeedback(KEYS[actor] ?? KEYS['adj-1'], f);
  return f;
}
const storeOf = (outcomes, o = {}) => createFeedbackStore({ actors: ACTORS, outcomes, ...o });
const noLeak = (value) => { const t = JSON.stringify(value); for (const s of [SECRET_SRC, 'SECRET_BODY_MARKER', 'proprietaryScoringAlgorithm', CANARY_KEY]) assert.ok(!t.includes(s), `leaked: ${s}`); };

describe('[X-607.AC01] only authorized adjudicators or trusted verifier services update labels; originals are immutable; corrections are auditable', () => {
  test('an authorized adjudicator labels an unlabelled outcome, and the label reaches the calibration input with its provenance', () => {
    const o = delayed(1);
    const s = storeOf([o]);
    const r = s.submit(fb(o));
    assert.equal(r.ok, true);
    const applied = s.applyToOutcomes([o]);
    assert.equal(applied.outcomes[0].outcome, 'correct');
    assert.equal(applied.outcomes[0].labelSource, 'adjudication');
    assert.equal(applied.outcomes[0].adjudicationVersion, 'adjudication-1');
    assert.equal(applied.outcomes[0].id, o.id, 'same outcome, now labelled');
    assert.equal(o.outcome, 'delayed', 'the base record is not mutated');
  });

  test('a trusted verifier service may supply a trusted-execution label; a human may not', () => {
    const o = delayed(2);
    const s = storeOf([o]);
    assert.equal(s.submit(fb(o, { evidenceKind: 'trusted-execution', verificationRecordId: 'vrec:abc123', actorId: 'ver-1' }, 'ver-1')).ok, true);
    assert.equal(s.effective(o.id).evidenceKind, 'trusted-execution');
    const o2 = delayed(3);
    const s2 = storeOf([o2]);
    const r = s2.submit(fb(o2, { evidenceKind: 'trusted-execution', verificationRecordId: 'vrec:abc123' }));
    assert.equal(r.reason, 'unauthorized');
  });

  test('an unregistered actor, or an actor with an invalid id, cannot label anything', () => {
    const o = delayed(4);
    const s = storeOf([o]);
    const f = { outcomeId: o.id, taskId: o.taskId, verdict: 'incorrect', evidenceKind: 'independent-adjudication', adjudicationVersion: 'a', reasonCode: 'initial-label', actorId: 'mallory', submittedAt: NOW };
    f.sig = signFeedback('whatever-key-0123456789', f);
    assert.equal(s.submit(f).reason, 'unauthorized');
    assert.equal(s.entries().length, 0);
    assert.equal(s.applyToOutcomes([o]).outcomes[0].outcome, 'delayed', 'the outcome stays unlabelled');
  });

  test('the model under test cannot adjudicate itself, even with a valid key', () => {
    const o = delayed(5);
    const s = storeOf([o]);
    const r = s.submit(fb(o, {}, 'model-cand'));
    assert.equal(r.reason, 'poisoned');
    assert.match(r.detail, /model under test/);
  });

  test('the original label is immutable: a conflicting label is refused and only a citing correction changes the effective label', () => {
    const o = delayed(6);
    const s = storeOf([o]);
    const first = s.submit(fb(o)).entry;
    const conflict = s.submit(fb(o, { verdict: 'incorrect', submittedAt: '2026-05-02T00:00:00Z' }));
    assert.equal(conflict.reason, 'poisoned');
    assert.match(conflict.detail, /correction/);
    assert.equal(s.effective(o.id).verdict, 'correct');
    const fix = s.submit(fb(o, { verdict: 'incorrect', reasonCode: 'mislabelled', correctsFeedbackId: first.id, submittedAt: '2026-05-03T00:00:00Z' }));
    assert.equal(fix.ok, true);
    assert.equal(s.effective(o.id).verdict, 'incorrect');
    assert.equal(s.original(o.id).verdict, 'correct', 'the original is still there, unchanged');
    assert.equal(s.original(o.id).id, first.id);
    assert.deepEqual(s.history(o.id).map((e) => `${e.kind}:${e.verdict}`), ['original:correct', 'correction:incorrect']);
    assert.equal(s.applyToOutcomes([o]).outcomes[0].outcome, 'incorrect');
  });

  test('stored entries cannot be edited in place', () => {
    const o = delayed(7);
    const s = storeOf([o]);
    const e = s.submit(fb(o)).entry;
    assert.equal(Object.isFrozen(e), true);
    assert.throws(() => { 'use strict'; e.verdict = 'incorrect'; }, TypeError);
    assert.equal(s.original(o.id).verdict, 'correct');
  });

  test('a correction must name an entry in the outcome history, give a reason, and come from an authorized actor', () => {
    const o = delayed(8); const other = delayed(9);
    const s = storeOf([o, other]);
    const first = s.submit(fb(o)).entry;
    const otherFirst = s.submit(fb(other)).entry;
    assert.equal(s.submit(fb(o, { verdict: 'incorrect', reasonCode: 'mislabelled', correctsFeedbackId: 'fb:doesnotexist' })).reason, 'unverifiable');
    assert.equal(s.submit(fb(o, { verdict: 'incorrect', reasonCode: 'mislabelled', correctsFeedbackId: otherFirst.id })).reason, 'unverifiable', 'cannot correct another outcome\'s entry');
    assert.equal(s.submit(fb(o, { verdict: 'incorrect', reasonCode: 'initial-label', correctsFeedbackId: first.id })).reason, 'poisoned', 'a correction cannot pose as an initial label');
    const mallory = { outcomeId: o.id, taskId: o.taskId, verdict: 'incorrect', evidenceKind: 'independent-adjudication', adjudicationVersion: 'a', reasonCode: 'mislabelled', correctsFeedbackId: first.id, actorId: 'mallory', submittedAt: NOW };
    mallory.sig = signFeedback('x'.repeat(24), mallory);
    assert.equal(s.submit(mallory).reason, 'unauthorized');
    assert.equal(s.effective(o.id).verdict, 'correct');
  });

  test('accepted and quarantined submissions are receipted without any content', () => {
    const log = createReceiptLog({ now: () => NOW });
    const o = delayed(10);
    const s = storeOf([o], { log });
    s.submit(fb(o));
    s.submit(fb(o, { sig: 'f'.repeat(64) }));
    assert.deepEqual(log.entries().map((r) => r.body.event), ['label-accepted', 'quarantined']);
    assert.equal(verifyReceiptChain(log.entries()).ok, true);
  });
});

describe('[X-607.AC02] feedback keeps minimal sanitized metadata; source and evidence leave only when task policy and egress policy allow', () => {
  test('fields outside the allowlist are dropped, and only their names are kept', () => {
    const o = delayed(11);
    const s = storeOf([o]);
    const f = fb(o, {}); // signed over allowlisted fields only
    const noisy = { ...f, source: SECRET_SRC, evidence: `request with ${CANARY_KEY}`, note: 'free text', excerpt: SECRET_SRC };
    const r = s.submit(noisy);
    assert.equal(r.ok, true);
    assert.deepEqual([...r.entry.strippedFields], ['evidence', 'excerpt', 'note', 'source']);
    noLeak(s.entries()); noLeak(s.quarantineReport());
    assert.equal(Object.keys(r.entry).sort().includes('source'), false);
  });

  test('a quarantined record keeps its reason, never the dropped content', () => {
    const o = delayed(12);
    const s = storeOf([o]);
    const f = fb(o, { sig: '0'.repeat(64) });
    s.submit({ ...f, source: SECRET_SRC, evidence: CANARY_KEY, actorId: `bad actor ${CANARY_KEY}` });
    noLeak(s.quarantineReport());
    assert.equal(s.quarantineReport().items[0].actorId, null, 'an unsafe actor id is not echoed');
  });

  test('task policy is a separate gate: source and evidence are denied unless the task policy allows them', () => {
    const allow = () => ({ allowed: true });
    const t = taskOf(1);
    assert.equal(authorizePayload({ taskPolicy: {}, kind: 'source', task: t, endpoint: 'http://127.0.0.1:1', egress: allow }).code, 'TASK_POLICY_DENIES_SOURCE');
    assert.equal(authorizePayload({ taskPolicy: {}, kind: 'evidence', task: t, endpoint: 'http://127.0.0.1:1', egress: allow }).code, 'TASK_POLICY_DENIES_EVIDENCE');
    assert.equal(authorizePayload({ taskPolicy: { allowSourceEgress: 'yes' }, kind: 'source', task: t, endpoint: 'http://127.0.0.1:1', egress: allow }).allowed, false, 'only the boolean true allows');
    assert.equal(authorizePayload({ taskPolicy: { allowSourceEgress: true }, kind: 'source', task: t, endpoint: 'http://127.0.0.1:1', egress: allow }).allowed, true);
    assert.equal(authorizePayload({ taskPolicy: { allowEvidenceEgress: true }, kind: 'evidence', task: t, endpoint: 'http://127.0.0.1:1', egress: allow }).allowed, true);
    assert.equal(authorizePayload({ taskPolicy: {}, kind: 'surprise', task: t, endpoint: 'x' }).code, 'UNKNOWN_PAYLOAD_KIND');
  });

  test('the egress policy is the second gate: a task policy that allows cannot override an egress denial', () => {
    const seen = [];
    const deny = (ctx) => { seen.push(ctx); return { allowed: false, reason: 'provider not approved' }; };
    const r = authorizePayload({ taskPolicy: { allowSourceEgress: true }, kind: 'source', task: taskOf(1), endpoint: 'https://api.example.invalid', model: 'm', egress: deny });
    assert.equal(r.allowed, false);
    assert.equal(r.code, 'EGRESS_DENIED');
    assert.equal(seen[0].dataClass, 'source-code');
    assert.equal(seen[0].purpose, 'routing-feedback');
    const sens = authorizePayload({ taskPolicy: { allowSourceEgress: true }, kind: 'source', task: taskOf(2, { dataClass: 'sensitive' }), endpoint: 'http://127.0.0.1:1', egress: (c) => { seen.push(c); return { allowed: true }; } });
    assert.equal(sens.allowed, true);
    assert.equal(seen.at(-1).dataClass, 'sensitive', 'a sensitive task keeps its stricter class');
    const manifest = authorizePayload({ taskPolicy: { allowSourceEgress: true }, kind: 'source', task: taskOf(1), endpoint: 'http://127.0.0.1:1', egress: () => ({ allowed: true }), manifestEgress: () => ({ allowed: false, code: 'host-not-granted' }) });
    assert.equal(manifest.allowed, false, 'a capability manifest that denies the host wins');
    const boom = authorizePayload({ taskPolicy: { allowSourceEgress: true }, kind: 'source', task: taskOf(1), endpoint: 'http://127.0.0.1:1', egress: () => { throw new Error('x'); } });
    assert.equal(boom.allowed, false, 'an egress evaluator that throws denies');
  });

  describe('sending goes only through the guarded adapter', () => {
    let realFetch; let fetchCalls = 0;
    before(() => { realFetch = globalThis.fetch; globalThis.fetch = () => { fetchCalls += 1; throw new Error('no network client'); }; });
    after(() => { globalThis.fetch = realFetch; });
    const LOCAL = 'http://127.0.0.1:11434';
    function adapterOf(transport) {
      const root = mkTestTmp('routing-feedback-');
      fs.writeFileSync(path.join(root, 'package.json'), '{"name":"t"}');
      const config = resolveAssuranceConfig({ scanRoot: root, env: {}, platform: 'linux', overrides: { features: { 'model-routing': true } } });
      return createProviderAdapter({ config, scanRoot: root, provider: 'provider-a', model: 'model-cand', modelVersion: '1', endpoint: LOCAL, transport, priceBook: priceBookFromCatalog() });
    }

    test('a denied payload never reaches the adapter or its transport; an allowed one is sent once, redacted', async () => {
      let calls = 0; let received = null;
      const adapter = adapterOf(async (req) => { calls += 1; received = req.text; return { text: 'ok', finishReason: 'stop', usage: { inputTokens: 10, outputTokens: 2 } }; });
      const invoke = { task: taskOf(1), runId: 'r1', prompt: `review ${SECRET_SRC}\nconst k = "${CANARY_KEY}";` };
      const base = { adapter, kind: 'source', task: taskOf(1), endpoint: LOCAL, model: 'model-cand', invoke };
      const denied = await sendToProvider({ ...base, taskPolicy: {}, egress: () => ({ allowed: true }) });
      assert.equal(denied.sent, false);
      assert.equal(calls, 0);
      const deniedByEgress = await sendToProvider({ ...base, taskPolicy: { allowSourceEgress: true }, egress: () => ({ allowed: false, reason: 'no' }) });
      assert.equal(deniedByEgress.sent, false);
      assert.equal(calls, 0);
      const sent = await sendToProvider({ ...base, taskPolicy: { allowSourceEgress: true }, egress: () => ({ allowed: true }) });
      assert.equal(sent.sent, true);
      assert.equal(calls, 1);
      assert.ok(!received.includes(CANARY_KEY), 'the guarded adapter redacted the credential before sending');
      noLeak(sent.result.telemetry);
      assert.equal(fetchCalls, 0);
    });

    test('there is no bypass client: the module imports no network primitive, transport or HTTP client', () => {
      assert.ok(!/\bfetch\s*\(|node:https?|node:net|node:dgram|XMLHttpRequest|WebSocket|\btransport\b/.test(FEEDBACK_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')), 'feedback.js must have no way to send except through the adapter it is handed');
    });
  });
});

describe('[X-607.AC03] poisoned, duplicated, unverifiable or tampered feedback is quarantined and excluded from calibration with a visible count and reason', () => {
  test('a record changed after signing is tampered; an unsigned or unknown-outcome record is unverifiable', () => {
    const o = delayed(20);
    const s = storeOf([o]);
    const f = fb(o, { verdict: 'incorrect' });
    assert.equal(s.submit({ ...f, verdict: 'correct' }).reason, 'tampered');
    const unsigned = { ...fb(o) }; delete unsigned.sig;
    assert.equal(s.submit(unsigned).reason, 'unverifiable');
    assert.equal(s.submit(fb({ id: 'rout:nonexistent', taskId: 'x' })).reason, 'unverifiable');
    assert.equal(s.submit(fb(o, { sig: 'not-hex' })).reason, 'unverifiable');
    assert.equal(s.submit(fb(o, { sig: 'a'.repeat(64) })).reason, 'tampered');
    assert.equal(s.entries().length, 0);
  });

  test('an identical record, and a second agreeing label, are duplicates; a different task id is poisoned', () => {
    const o = delayed(21); const other = delayed(22);
    const s = storeOf([o, other]);
    assert.equal(s.submit(fb(o)).ok, true);
    assert.equal(s.submit(fb(o)).reason, 'duplicate');
    assert.equal(s.submit(fb(o, { submittedAt: '2026-05-09T00:00:00Z' })).reason, 'duplicate', 'same verdict again');
    assert.equal(s.submit(fb(o, { taskId: other.taskId, submittedAt: '2026-05-10T00:00:00Z' })).reason, 'poisoned');
    assert.equal(s.entries().length, 1);
  });

  test('a flood from one actor is quarantined past its limit', () => {
    const outs = Array.from({ length: 6 }, (_, i) => delayed(30 + i));
    const s = storeOf(outs, { maxPerActor: 3 });
    const results = outs.map((o) => s.submit(fb(o)));
    assert.deepEqual(results.map((r) => r.ok), [true, true, true, false, false, false]);
    assert.equal(s.quarantineReport().byReason.poisoned, 3);
    assert.match(s.quarantineReport().items[0].detail, /more than 3 submissions/);
  });

  test('the quarantine report states a count and a reason for each, and totals are exact', () => {
    const o = delayed(40);
    const s = storeOf([o]);
    s.submit({ ...fb(o), verdict: 'incorrect' }); // tampered
    s.submit(fb(o)); // accepted
    s.submit(fb(o)); // duplicate
    s.submit({ ...fb(o, { sig: undefined }), sig: undefined }); // unverifiable
    const q = s.quarantineReport();
    assert.equal(q.count, 3);
    assert.deepEqual({ ...q.byReason }, { unauthorized: 0, unverifiable: 1, tampered: 1, duplicate: 1, poisoned: 0 });
    assert.ok(q.items.every((i) => i.reason && i.detail));
  });

  test('quarantined feedback never reaches the calibration input; a tampered stored label is excluded and counted', () => {
    const pop = syntheticPopulation({ dev: 20, held: 40, models: [{ id: 'model-a', version: '1', acc: 0.9 }, { id: 'model-b', version: '1', acc: 0.9 }] });
    const flipped = { ...pop.outcomes[5], outcome: pop.outcomes[5].outcome === 'correct' ? 'incorrect' : 'correct' }; // label edited after the fact
    const duplicate = pop.outcomes[7];
    const clean = pop.outcomes.filter((_, i) => i !== 5);
    const s = storeOf(pop.outcomes);
    const applied = s.applyToOutcomes([flipped, ...clean, duplicate]);
    assert.equal(applied.outcomes.length, clean.length, 'the flipped label and the duplicate are out');
    assert.deepEqual(applied.excluded.map((e) => e.reason).sort(), ['duplicate', 'tampered']);
    assert.equal(applied.quarantine.outcomes.byReason.tampered, 1);
    assert.equal(applied.quarantine.count, 2);
    const cal = buildCalibration({ outcomes: applied.outcomes, config: { ...BASE_CONFIG, baselineModel: 'model-a' } });
    assert.equal(cal.ok, true);
    assert.equal(cal.artifact.counts.input, clean.length);
    assert.equal(cal.artifact.exclusions.counts.duplicate, 0, 'the calibration saw no duplicate: it was quarantined first');
  });

  test('an invalid or malformed outcome is quarantined as unverifiable rather than passed on', () => {
    const o = delayed(50);
    const s = storeOf([o]);
    const applied = s.applyToOutcomes([o, { id: 'rout:x' }, null, { ...o, id: 'rout:forged' }]);
    assert.equal(applied.outcomes.length, 1);
    assert.equal(applied.excluded.length, 3);
    assert.ok(applied.excluded.every((e) => ['tampered', 'unverifiable'].includes(e.reason)));
  });
});
