// Capability decisions as CORE-002 records, and the advisory (hook) view.
//
// A policy decision (decide.js) becomes an `agentic-security/capability-decision`
// record. The record schema already carries the honesty rule this module relies
// on: only runner or proxy mediation, naming a backend and the digest of an
// active probe, may claim `enforced`. `enforced` here is true only when the
// runner says the backend is an advertised one and every required control was
// proved; a development-host run is recorded as a runner-mediated decision with
// `enforced: false`.
import { SCHEMA_VERSION } from '../posture/assurance/schema-kit.js';
import { capabilityDecisionId, validateCapabilityDecision } from '../posture/assurance/contracts.js';
import { sanitizeSubject } from './reasons.js';
import { decide } from './decide.js';

/**
 * @param {object} d            a decision from `decide`
 * @param {object} o
 * @param {'runner'|'proxy'|'in-process-policy'|'hook-advisory'|'none'} o.mediation
 * @param {boolean} o.enforced
 * @param {string|null} o.backend
 * @param {string|null} o.probeDigest
 * @returns {{ok: boolean, record: object|null, errors: object[]}}
 */
export function toCapabilityDecisionRecord(d, { mediation, enforced, backend = null, probeDigest = null }) {
  const rec = {
    schema: 'agentic-security/capability-decision', schemaVersion: SCHEMA_VERSION,
    taskId: d.taskId ?? 'unbound', capability: d.kind, subject: sanitizeSubject(d.subject, 200),
    decision: d.decision, mediation, enforced: enforced === true, backend,
    ...(probeDigest ? { probeDigest } : {}),
    reason: `${d.code}: ${d.reason}`,
  };
  rec.id = capabilityDecisionId(rec);
  const v = validateCapabilityDecision(rec);
  return v.ok ? { ok: true, record: Object.freeze(rec), errors: [] } : { ok: false, record: null, errors: v.errors };
}

/**
 * What a hook may say about an action. The same policy answer, labelled as
 * advice: mediation `hook-advisory` and never enforced, however the manifest
 * reads. A shell command string is not an action the policy can parse, so it is
 * reported as unsupported for enforcement and left to the runner's structured
 * execution.
 */
export function advise(bound, action, ctx) {
  if (action && action.kind === 'command' && typeof action.command === 'string') {
    return Object.freeze({
      advisory: true, enforced: false, decision: 'unsupported', code: 'interpreter-blocked',
      note: 'a shell command string cannot be mediated; run it as an executable and an argument array through the capability runner',
      record: null,
    });
  }
  const d = decide(bound, action, ctx);
  const r = toCapabilityDecisionRecord(d, { mediation: 'hook-advisory', enforced: false, backend: null });
  return Object.freeze({
    advisory: true, enforced: false, decision: d.decision, code: d.code,
    note: 'advice only: a hook response explains a decision, it does not enforce one', record: r.ok ? r.record : null,
  });
}
