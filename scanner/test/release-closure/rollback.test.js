// REL-002.AC03: rollback restores known-good behaviour and flags incompatible or stale assurance claims;
// feature failure does not erase previously recorded evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { gatesFor, newLedger, promote, effectiveMode } from '../../src/posture/assurance/rollout.js';
import { planRollback, applyRollback, EvidenceStore, guardedFeatureRun } from '../../src/posture/assurance/rollback.js';
import { mkTestTmp } from '../helpers/tmp.js';

const D = 'a'.repeat(64);
const F = 'model-routing';
const cfg = (overrides = {}, env = {}) => resolveAssuranceConfig({ scanRoot: mkTestTmp('rb-'), env, overrides, platform: 'darwin' });
const ev = (feature, stage) => Object.fromEntries(gatesFor(feature, stage).map((g) => [g.id, { met: true, ref: g.kind === 'suite' ? g.closureStep : `artifact-${g.id}`, digest: D }]));
const to = (ledger, feature, stage) => promote(ledger, feature, ev(feature, stage)).ledger;
const active = () => to(to(newLedger(), F, 'shadow-canary'), F, 'opt-in-supported');

const item = (id, kind, policyVersion, feature = F) => ({ id, kind, digest: `sha256:${id.padEnd(64, '0').slice(0, 64)}`, producedUnder: { feature, policyVersion } });
const STORE = [
  item('a1', 'verification', 1), // produced under the first policy, readable by a legacy consumer
  item('a2', 'routingLabel', 2), // produced at shadow-canary; no previous reader for this kind
  item('a3', 'verification', 3), // produced under the opt-in policy
  item('b1', 'verification', 3, 'portfolio-assurance'), // another feature: untouched
];
const CLAIMS = [
  { id: 'claim-ok', evidenceRefs: ['a1'] },
  { id: 'claim-stale', evidenceRefs: ['a1', 'a3'] },
  { id: 'claim-incompat', evidenceRefs: ['a2'] },
  { id: 'claim-dangling', evidenceRefs: ['zz'] },
  { id: 'claim-other', evidenceRefs: ['b1'] },
];

test('[REL-002.AC03] rollback restores the last known-good stage and its behaviour', () => {
  const on = cfg({ features: { [F]: true } });
  const ledger = active();
  assert.equal(effectiveMode(on, ledger, F).mode, 'active');
  const plan = planRollback({ ledger, feature: F, store: STORE, claims: CLAIMS });
  assert.equal(plan.ok, true);
  assert.deepEqual({ stage: plan.restore.stage, policyVersion: plan.restore.policyVersion }, { stage: 'shadow-canary', policyVersion: 2 });
  const done = applyRollback(ledger, plan, { reason: 'canary regression' });
  assert.equal(done.ok, true);
  assert.equal(done.ledger.features[F].stage, 'shadow-canary');
  assert.equal(effectiveMode(on, done.ledger, F).mode, 'shadow', 'the behaviour is the shadow-canary behaviour again: results recorded, never used');
  // once more: back to the fixtures stage
  const again = applyRollback(done.ledger, planRollback({ ledger: done.ledger, feature: F }));
  assert.equal(again.ledger.features[F].stage, 'offline-fixtures');
  assert.equal(effectiveMode(on, again.ledger, F).mode, 'fixtures');
  // at the first stage the only known-good behaviour is off, and the plan says which configuration change does it
  const last = planRollback({ ledger: again.ledger, feature: F });
  assert.deepEqual(last.configChange, { feature: F, enabled: false, why: last.configChange.why });
  const off = cfg({ features: { [F]: last.configChange.enabled } });
  assert.equal(effectiveMode(off, again.ledger, F).mode, 'off');
  // a rollback is recorded, history is only ever appended
  assert.deepEqual(done.ledger.features[F].history.map((h) => h.event), ['init', 'promote', 'promote', 'rollback']);
  assert.deepEqual(done.ledger.features[F].history.slice(0, 3), ledger.features[F].history, 'earlier history is byte-identical');
  assert.equal(ledger.features[F].stage, 'opt-in-supported', 'the input ledger is not mutated');
});

test('[REL-002.AC03] re-promotion after a rollback never reuses a policy version, so older records stay identifiable', () => {
  const done = applyRollback(active(), planRollback({ ledger: active(), feature: F })).ledger;
  assert.equal(done.features[F].policyVersion, 2);
  const re = to(done, F, 'opt-in-supported');
  assert.equal(re.features[F].policyVersion, 4, 'policy 3 was used before the rollback and is not reused');
});

test('[REL-002.AC03] rollback flags stale and incompatible evidence and claims, and removes nothing', () => {
  const plan = planRollback({ ledger: active(), feature: F, store: STORE, claims: CLAIMS });
  assert.equal(plan.annotations.a1, undefined, 'a record under the restored policy with a previous reader is fine');
  assert.deepEqual(plan.annotations.a3.flags, ['stale'], 'a record from the rolled-back policy is stale');
  assert.deepEqual(plan.annotations.a2.flags, ['incompatible'], 'a kind with no previous reader is flagged incompatible');
  assert.match(plan.annotations.a2.reasons.join(' '), /no previous reader/);
  assert.equal(plan.annotations.b1, undefined, 'another feature\'s evidence is untouched');
  assert.equal(plan.claims['claim-ok'].status, 'valid');
  assert.equal(plan.claims['claim-other'].status, 'valid');
  assert.equal(plan.claims['claim-stale'].status, 'flagged');
  assert.match(plan.claims['claim-stale'].reasons.join(' '), /a3: stale/);
  assert.equal(plan.claims['claim-incompat'].status, 'flagged');
  assert.match(plan.claims['claim-dangling'].reasons.join(' '), /dangling/);
  assert.deepEqual(plan.retained, STORE.map((i) => i.id), 'every id is retained');
  // the store and claims were inputs only: byte-identical afterwards
  const before = JSON.stringify([STORE, CLAIMS]);
  applyRollback(active(), plan);
  assert.equal(JSON.stringify([STORE, CLAIMS]), before);
  assert.equal(planRollback({ ledger: active(), feature: 'nope' }).ok, false);
  assert.equal(applyRollback(active(), { ok: false, reason: 'x' }).ok, false);
});

test('[REL-002.AC03] with nothing newer than the restored policy and a previous reader, nothing is flagged', () => {
  const calm = [item('c1', 'verification', 1), item('c2', 'verification', 2)];
  const plan = planRollback({ ledger: active(), feature: F, store: calm, claims: [{ id: 'k', evidenceRefs: ['c1', 'c2'] }] });
  assert.deepEqual(plan.annotations, {});
  assert.equal(plan.claims.k.status, 'valid');
});

test('[REL-002.AC03] a feature that throws leaves earlier evidence untouched and records the failure', async () => {
  const store = new EvidenceStore();
  assert.equal(store.append(item('e1', 'verification', 1)).ok, true);
  assert.equal(store.append(item('e2', 'verification', 1)).ok, true);
  const before = store.digest();
  const r = await guardedFeatureRun(store, F, async (s) => { s.append(item('e3', 'verification', 2)); throw new Error('provider exploded'); });
  assert.equal(r.status, 'blocked');
  assert.equal(r.code, 'feature-failed');
  assert.match(r.reason, /provider exploded/);
  assert.equal(store.failures.length, 1);
  const ids = store.all().map((i) => i.id);
  assert.deepEqual(ids, ['e1', 'e2', 'e3'], 'what was recorded before the failure, including this run\'s own earlier append, stays');
  assert.notEqual(store.digest(), before, 'control: the digest does move when evidence is added');
  // a successful run returns its value
  const ok = await guardedFeatureRun(store, F, async () => 42);
  assert.deepEqual({ status: ok.status, value: ok.value }, { status: 'ok', value: 42 });
});

test('[REL-002.AC03] evidence is never overwritten: redelivery is idempotent and a conflicting digest is refused', () => {
  const store = new EvidenceStore();
  const a = item('x1', 'verification', 1);
  assert.deepEqual(store.append(a), { ok: true, duplicate: false });
  assert.deepEqual(store.append(a), { ok: true, duplicate: true });
  const r = store.append({ ...a, digest: `sha256:${'f'.repeat(64)}` });
  assert.equal(r.ok, false);
  assert.match(r.reason, /never overwritten/);
  assert.deepEqual(store.all()[0], a);
  assert.equal(store.append({ id: 5 }).ok, false);
  assert.equal(store.append(null).ok, false);
});

test('[REL-002.AC03] a file-backed store survives a crash mid-write: earlier evidence is intact and the torn tail is reported, not trusted', async () => {
  const file = path.join(mkTestTmp('rb-store-'), 'evidence.jsonl');
  const a = new EvidenceStore({ file });
  a.append(item('f1', 'verification', 1));
  a.append(item('f2', 'verification', 1));
  await guardedFeatureRun(a, F, async () => { throw new Error('boom'); });
  const bytesBefore = fs.readFileSync(file);
  fs.appendFileSync(file, '{"type":"item","item":{"id":"f3","dig'); // the process died halfway through a line
  const b = new EvidenceStore({ file });
  assert.deepEqual(b.all().map((i) => i.id), ['f1', 'f2']);
  assert.equal(b.unreadable, 1, 'the torn line is counted, not silently ignored');
  assert.equal(b.failures.length, 1, 'the earlier failure record survives too');
  assert.ok(fs.readFileSync(file).subarray(0, bytesBefore.length).equals(bytesBefore), 'nothing already written was rewritten');
  // reopening without damage reads everything
  const c = new EvidenceStore({ file: path.join(mkTestTmp('rb-store-'), 'none.jsonl') });
  assert.equal(c.all().length, 0);
});

test('[REL-002.AC03] a rollback with a feature failure in between keeps every record and still flags the right ones', async () => {
  const store = new EvidenceStore();
  for (const i of STORE) store.append(i);
  await guardedFeatureRun(store, F, async () => { throw new Error('canary tripped'); });
  const digestBefore = store.digest();
  const plan = planRollback({ ledger: active(), feature: F, store: store.all(), claims: CLAIMS });
  const done = applyRollback(active(), plan, { reason: 'canary tripped' });
  assert.equal(store.digest(), digestBefore, 'rollback did not touch the evidence');
  assert.equal(store.all().length, STORE.length);
  assert.equal(Object.keys(done.annotations).length, 2);
});
