// Protected routing feedback (X-607): who may label an outcome, what is kept, what may leave the machine, and what is refused.
//
// AC01  Only authorized actors can change a quality label. An actor is either a human adjudicator or a trusted verifier service, is
//       registered by the operator with a secret, and signs each feedback record (HMAC-SHA256 over the record). The first accepted
//       label for an outcome is its ORIGINAL and is never modified or removed; a change is a CORRECTION that cites the entry it
//       corrects and a reason code, and the full history is kept (`history`). The effective label is the latest accepted entry.
// AC02  A feedback record is an allowlist of fields. Anything else (source text, evidence, free text) is dropped and only the
//       NAMES of the dropped fields are kept. Source code or evidence reaches a provider only through `sendToProvider`, which needs
//       the task policy to allow that kind of payload AND the egress policy (or a capability-manifest egress check) to allow it, and
//       then sends through the guarded adapter. This module holds no network client and no transport of its own.
// AC03  Feedback that is unauthorized, unverifiable (missing or unknown fields, unknown outcome), tampered (signature mismatch, or a
//       stored label that no longer matches its own id), duplicated or poisoned (conflicts with the original, flood from one actor,
//       wrong task, a reviewer that is not independent) is QUARANTINED: kept out of calibration, counted, with the reason visible.
//
// Limit, stated plainly: a trusted-execution label carries its verification record id only at labelling time, so a flipped label on
// an outcome that ALREADY carries a trusted-execution label cannot be recomputed here; adjudicated labels can be (labelId is a
// function of the label). The operator's actor keys are the trust root; this is tamper evidence, not independent certification.

import * as crypto from 'node:crypto';
import { digestOf, canonicalize } from '../assurance/identity.js';
import { routingLabelId } from '../assurance/contracts.js';
import { deriveRoutingLabel, buildRoutingOutcome, validateRoutingOutcome } from './outcomes.js';
import { evaluateEgress } from '../../egress/policy.js';

export const FEEDBACK_FIELDS = Object.freeze(['outcomeId', 'taskId', 'verdict', 'evidenceKind', 'adjudicationVersion', 'verificationRecordId', 'reasonCode', 'correctsFeedbackId', 'actorId', 'submittedAt', 'sig']);
export const FEEDBACK_REASON_CODES = Object.freeze(['initial-label', 'mislabelled', 'reviewer-error', 'new-evidence']);
export const QUARANTINE_REASONS = Object.freeze(['unauthorized', 'unverifiable', 'tampered', 'duplicate', 'poisoned']);
export const ACTOR_KINDS = Object.freeze(['human', 'verifier-service']);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

/** The signature an actor attaches: HMAC-SHA256 over the canonical record without `sig`. */
export function signFeedback(key, fields) {
  const { sig: _omit, ...rest } = fields;
  return crypto.createHmac('sha256', String(key)).update(canonicalize(rest)).digest('hex');
}

/**
 * @param {object} o
 * @param {Object<string,{kind:'human'|'verifier-service', key:string}>} o.actors  registered by the operator; keys stay in this closure
 * @param {object[]} o.outcomes   the base routing outcomes feedback may refer to
 * @param {number} [o.maxPerActor] submissions from one actor beyond this are quarantined as a flood
 * @param {object} [o.log]        receipt log; each accepted and quarantined submission appends a sanitized receipt
 */
export function createFeedbackStore({ actors, outcomes, maxPerActor = 1000, log = null }) {
  const registry = new Map();
  for (const [id, a] of Object.entries(actors || {})) {
    if (SAFE_ID.test(id) && a && ACTOR_KINDS.includes(a.kind) && typeof a.key === 'string' && a.key.length >= 16) registry.set(id, { kind: a.kind, key: a.key });
  }
  const byOutcome = new Map((outcomes || []).filter((o) => validateRoutingOutcome(o).ok).map((o) => [o.id, o]));
  const accepted = [];
  const quarantined = [];
  const seenDigests = new Set();
  const perActor = new Map();

  const quarantine = (fb, stripped, reason, detail) => {
    const item = Object.freeze({
      id: `q:${digestOf({ fb, reason }).slice(7, 23)}`, reason, detail,
      actorId: typeof fb.actorId === 'string' && SAFE_ID.test(fb.actorId) ? fb.actorId : null,
      outcomeId: typeof fb.outcomeId === 'string' && fb.outcomeId.length <= 80 ? fb.outcomeId : null, strippedFields: stripped,
    });
    quarantined.push(item);
    if (log) log.append('feedback', { event: 'quarantined', reason, id: item.id, actorId: item.actorId });
    return { ok: false, quarantined: true, reason, detail, id: item.id };
  };

  function submit(raw) {
    const input = raw && typeof raw === 'object' ? raw : {};
    const stripped = Object.keys(input).filter((k) => !FEEDBACK_FIELDS.includes(k)).sort();
    const fb = {};
    for (const k of FEEDBACK_FIELDS) if (input[k] !== undefined) fb[k] = typeof input[k] === 'string' ? input[k].slice(0, 200) : input[k];

    // flood control counts every submission from an actor, accepted or not
    if (typeof fb.actorId === 'string') {
      const n = (perActor.get(fb.actorId) || 0) + 1;
      perActor.set(fb.actorId, n);
      if (n > maxPerActor) return quarantine(fb, stripped, 'poisoned', `more than ${maxPerActor} submissions from one actor`);
    }
    const missing = ['outcomeId', 'taskId', 'verdict', 'evidenceKind', 'reasonCode', 'actorId', 'submittedAt'].filter((k) => typeof fb[k] !== 'string' || !fb[k]);
    if (missing.length) return quarantine(fb, stripped, 'unverifiable', `missing fields: ${missing.join(', ')}`);
    if (!['correct', 'incorrect'].includes(fb.verdict)) return quarantine(fb, stripped, 'unverifiable', 'verdict must be correct or incorrect');
    if (!FEEDBACK_REASON_CODES.includes(fb.reasonCode)) return quarantine(fb, stripped, 'unverifiable', 'unknown reason code');

    const actor = registry.get(fb.actorId);
    if (!actor) return quarantine(fb, stripped, 'unauthorized', 'the actor is not a registered adjudicator or verifier service');
    if (fb.evidenceKind === 'trusted-execution' && actor.kind !== 'verifier-service') return quarantine(fb, stripped, 'unauthorized', 'only a trusted verifier service may supply trusted-execution labels');
    if (fb.evidenceKind === 'independent-adjudication' && !ACTOR_KINDS.includes(actor.kind)) return quarantine(fb, stripped, 'unauthorized', 'not an adjudicator');

    if (typeof fb.sig !== 'string' || !/^[0-9a-f]{64}$/.test(fb.sig)) return quarantine(fb, stripped, 'unverifiable', 'the record is not signed');
    const expected = signFeedback(actor.key, fb);
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(fb.sig, 'hex'))) return quarantine(fb, stripped, 'tampered', 'the signature does not match the record');

    const outcome = byOutcome.get(fb.outcomeId);
    if (!outcome) return quarantine(fb, stripped, 'unverifiable', 'the outcome is not one this store knows');
    if (outcome.taskId !== fb.taskId) return quarantine(fb, stripped, 'poisoned', 'the feedback names a different task than the outcome');

    const contentDigest = digestOf({ ...fb, sig: undefined });
    if (seenDigests.has(contentDigest)) return quarantine(fb, stripped, 'duplicate', 'an identical feedback record was already accepted');

    const history = accepted.filter((e) => e.outcomeId === fb.outcomeId);
    const isCorrection = typeof fb.correctsFeedbackId === 'string' && fb.correctsFeedbackId.length > 0;
    if (!isCorrection) {
      if (fb.reasonCode !== 'initial-label') return quarantine(fb, stripped, 'poisoned', 'a label that corrects nothing must be an initial label');
      if (history.length) {
        return history[history.length - 1].verdict === fb.verdict
          ? quarantine(fb, stripped, 'duplicate', 'the outcome already has this label')
          : quarantine(fb, stripped, 'poisoned', 'conflicts with the original label; a change must be a correction that cites the entry it corrects');
      }
    } else {
      if (fb.reasonCode === 'initial-label') return quarantine(fb, stripped, 'poisoned', 'a correction cannot be marked as an initial label');
      if (!history.some((e) => e.id === fb.correctsFeedbackId)) return quarantine(fb, stripped, 'unverifiable', 'the entry being corrected is not in this outcome\'s history');
    }

    const derived = deriveRoutingLabel({
      task: { taskId: outcome.taskId, taskKind: outcome.taskKind, stratum: outcome.stratum }, model: outcome.model, outcome: fb.verdict,
      evidence: { kind: fb.evidenceKind, reviewerKind: actor.kind, reviewerId: fb.actorId, adjudicationVersion: fb.adjudicationVersion, verificationRecordId: fb.verificationRecordId },
    });
    if (!derived.accepted) return quarantine(fb, stripped, derived.code === 'NOT_INDEPENDENT' ? 'poisoned' : 'unverifiable', derived.reason);

    seenDigests.add(contentDigest);
    const entry = Object.freeze({
      id: `fb:${contentDigest.slice(7, 23)}`, kind: isCorrection ? 'correction' : 'original', outcomeId: fb.outcomeId, taskId: fb.taskId, verdict: fb.verdict,
      evidenceKind: fb.evidenceKind, adjudicationVersion: fb.adjudicationVersion ?? null, verificationRecordId: fb.verificationRecordId ?? null,
      reasonCode: fb.reasonCode, correctsFeedbackId: isCorrection ? fb.correctsFeedbackId : null, actorId: fb.actorId, actorKind: actor.kind, submittedAt: fb.submittedAt,
      strippedFields: Object.freeze(stripped), contentDigest,
    });
    accepted.push(entry);
    if (log) log.append('feedback', { event: entry.kind === 'correction' ? 'correction-accepted' : 'label-accepted', id: entry.id, outcomeId: entry.outcomeId, verdict: entry.verdict, actorId: entry.actorId });
    return { ok: true, quarantined: false, entry };
  }

  const history = (outcomeId) => accepted.filter((e) => e.outcomeId === outcomeId);
  const effective = (outcomeId) => { const h = history(outcomeId); return h.length ? h[h.length - 1] : null; };

  const report = () => {
    const byReason = Object.fromEntries(QUARANTINE_REASONS.map((r) => [r, 0]));
    for (const q of quarantined) byReason[q.reason] += 1;
    return { count: quarantined.length, byReason, items: quarantined.slice() };
  };

  /**
   * Build the outcome list a calibration may use: outcomes that carry a label are re-checked, outcomes with an effective accepted
   * feedback label get that label, and everything unusable is quarantined and EXCLUDED, with the count and reasons returned.
   */
  function applyToOutcomes(base) {
    const out = []; const dropped = []; const seen = new Set();
    for (const o of Array.isArray(base) ? base : []) {
      const v = validateRoutingOutcome(o);
      if (!v.ok) { dropped.push({ id: o?.id ?? null, reason: v.errors.some((e) => e.code === 'ID_MISMATCH') ? 'tampered' : 'unverifiable', detail: v.errors.map((e) => e.code).join(',') }); continue; }
      if (seen.has(o.id)) { dropped.push({ id: o.id, reason: 'duplicate', detail: 'an outcome with this id was already taken' }); continue; }
      seen.add(o.id);
      if (o.labelSource === 'adjudication') {
        const recomputed = routingLabelId({ taskId: o.taskId, taskKind: o.taskKind, stratum: o.stratum, model: o.model, outcome: o.outcome, labelSource: 'adjudication', verificationRecordId: null });
        if (recomputed !== o.labelId) { dropped.push({ id: o.id, reason: 'tampered', detail: 'the stored label no longer matches its own id' }); continue; }
      }
      const eff = effective(o.id);
      if (!eff || (o.outcome === eff.verdict && o.labelSource !== 'none')) { out.push(o); continue; }
      const label = deriveRoutingLabel({
        task: { taskId: o.taskId, taskKind: o.taskKind, stratum: o.stratum }, model: o.model, outcome: eff.verdict,
        evidence: { kind: eff.evidenceKind, reviewerKind: eff.actorKind, reviewerId: eff.actorId, adjudicationVersion: eff.adjudicationVersion, verificationRecordId: eff.verificationRecordId },
      });
      if (!label.accepted) { dropped.push({ id: o.id, reason: 'unverifiable', detail: label.reason }); continue; }
      const rebuilt = buildRoutingOutcome({
        runId: o.runId, task: { taskId: o.taskId, taskKind: o.taskKind, stratum: o.stratum, synthetic: o.synthetic }, model: o.model, modelVersion: o.modelVersion, status: o.status,
        outcome: label.label.outcome, label: label.label, adjudicationVersion: label.adjudicationVersion ?? null, group: o.group ?? null, usage: o.usage, costUsd: o.costUsd,
        costStatus: o.costStatus, latencyMs: o.latencyMs, cacheState: o.cacheState, observedAt: o.observedAt ?? null, synthetic: o.synthetic,
      });
      if (rebuilt.ok) out.push(rebuilt.outcome); else dropped.push({ id: o.id, reason: 'unverifiable', detail: 'the relabelled outcome failed validation' });
    }
    const byReason = Object.fromEntries(QUARANTINE_REASONS.map((r) => [r, 0]));
    for (const d of dropped) byReason[d.reason] += 1;
    return { outcomes: out, excluded: dropped, quarantine: { count: dropped.length + quarantined.length, outcomes: { count: dropped.length, byReason }, feedback: report() } };
  }

  return { submit, history, effective, original: (id) => history(id).find((e) => e.kind === 'original') ?? null, quarantineReport: report, applyToOutcomes, entries: () => accepted.slice() };
}

// ---------------------------------------------------------------- what may leave the machine (AC02)

const PAYLOAD_KINDS = Object.freeze(['metadata', 'source', 'evidence']);
const DATA_CLASS_OF = Object.freeze({ metadata: 'public', source: 'source-code', evidence: 'sensitive' });

/**
 * May this kind of payload go to this endpoint for this task? Both must allow: the task policy (explicit `allowSourceEgress` /
 * `allowEvidenceEgress`, default false) and the egress policy (or the capability manifest's egress check). Never sends anything.
 */
export function authorizePayload({ taskPolicy = {}, kind, task = null, endpoint, model = null, scanRoot = null, egress = evaluateEgress, manifestEgress = null }) {
  if (!PAYLOAD_KINDS.includes(kind)) return { allowed: false, by: 'input', code: 'UNKNOWN_PAYLOAD_KIND', reason: `kind must be one of ${PAYLOAD_KINDS.join(', ')}` };
  if (kind === 'source' && taskPolicy.allowSourceEgress !== true) return { allowed: false, by: 'task-policy', code: 'TASK_POLICY_DENIES_SOURCE', reason: 'the task policy does not allow source code to leave the machine' };
  if (kind === 'evidence' && taskPolicy.allowEvidenceEgress !== true) return { allowed: false, by: 'task-policy', code: 'TASK_POLICY_DENIES_EVIDENCE', reason: 'the task policy does not allow evidence to leave the machine' };
  const dataClass = kind === 'source' && task?.dataClass === 'sensitive' ? 'sensitive' : DATA_CLASS_OF[kind];
  const ctx = { scanRoot, purpose: 'routing-feedback', endpoint, model, dataClass };
  let e;
  try { e = manifestEgress ? manifestEgress(ctx) : egress(ctx); } catch { e = { allowed: false, code: 'egress-error' }; }
  if (!e || e.allowed !== true) return { allowed: false, by: 'egress-policy', code: 'EGRESS_DENIED', reason: (e && (e.reason || e.code)) || 'egress policy denied' };
  return { allowed: true, by: null, code: 'allowed', reason: 'task policy and egress policy both allow this payload' };
}

/**
 * Send a payload through a guarded adapter (createProviderAdapter) only when `authorizePayload` allows it. There is no other path:
 * this module has no transport. A denial never touches the adapter.
 */
export async function sendToProvider({ adapter, taskPolicy, kind, task, endpoint, model, scanRoot = null, egress = evaluateEgress, manifestEgress = null, invoke }) {
  const auth = authorizePayload({ taskPolicy, kind, task, endpoint, model, scanRoot, egress, manifestEgress });
  if (!auth.allowed) return { sent: false, authorization: auth };
  const result = await adapter.invoke(invoke);
  return { sent: true, authorization: auth, result };
}
