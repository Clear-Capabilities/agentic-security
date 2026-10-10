// The MCP tool gate (X-505.AC01, X-505.AC03).
//
// Every tool call is checked against the SAME decision function the runner and
// the hooks use (`decide`), for the CURRENT task identity, before its handler
// runs. The identity is the one the operator bound to the server; nothing the
// calling agent sends can change it: tool arguments are closed schemas, and an
// identity named in the request metadata is compared with the bound one and
// refused when it differs (`identity-spoofed`).
//
//   no policy, feature off   the gate is inactive: behaviour is exactly what it
//                            was before this module existed
//   feature on, no policy    read tools pass; a mutating or externally
//                            communicating tool is refused (`identity-missing`),
//                            because there is no task to check it for
//   policy bound             every tool is checked: it must be a declared tool
//                            action (deny by default), a mutating one must also
//                            have the session root inside a declared write root,
//                            and a tool missing from the classification table is
//                            refused (`tool-unclassified`)
//
// A denial is synchronous and final for that call: no prompt, no waiting, no
// retry inside the gate. It carries the missing capability and a reviewable
// proposed change (recovery.js); repeated denials hit the finite limit there.
//
// This is POLICY at the tool boundary. The tool then runs in the MCP server
// process, so the decision is recorded as `in-process-policy` and never
// `enforced`; the runner is the only enforcement layer.
import { resolveAssuranceConfig } from '../posture/assurance/config.js';
import { reasonText, sanitizeSubject } from './reasons.js';
import { toolCapabilityFor, isMutatingOrExternal } from './tool-registry.js';
import { mediate, createDenialGuard } from './recovery.js';
import { toCapabilityDecisionRecord } from './records.js';

const FEATURE = 'capability-enforcement';
const MAX_KEPT = 500;

function synthetic(bound, kind, code, subject) {
  return Object.freeze({
    decision: 'deny', code, reason: reasonText(code), kind, subject: sanitizeSubject(subject),
    taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
  });
}

/** Whether the OPERATOR enabled the feature (environment only; a project file can never enable it). */
export function featureEnabledByOperator(env = process.env) {
  try { return resolveAssuranceConfig({ env }).features?.[FEATURE]?.enabled === true; } catch { return false; }
}

/**
 * @param {object} o
 * @param {string} o.sessionRoot
 * @param {{bound: object, binding: object}|null} [o.policy]  the task's bound manifest and the identity it acts for
 * @param {object} [o.guard]    denial guard (default: a fresh one with the default limits)
 * @param {object} [o.env]
 */
export function createToolGate({ sessionRoot, policy = null, guard, env = process.env } = {}) {
  let current = policy && policy.bound && policy.binding ? { bound: policy.bound, binding: policy.binding } : null;
  const denialGuard = guard || createDenialGuard();
  const kept = [];

  function record(decision) {
    const r = toCapabilityDecisionRecord(decision, { mediation: 'in-process-policy', enforced: false, backend: null });
    if (r.ok) { kept.push(r.record); if (kept.length > MAX_KEPT) kept.shift(); }
    return r.ok ? r.record : null;
  }

  function refused(d) {
    return Object.freeze({
      allowed: false, blocked: true, code: d.code, reason: d.reason, decision: d,
      missing: Object.freeze({ capability: 'tool', code: d.code, detail: d.subject }),
      proposal: null, attemptsRemaining: null, exhausted: false, record: record(d),
    });
  }

  function blockedResult(m, extra = {}) {
    return Object.freeze({
      allowed: false, blocked: true, code: m.decision.code, reason: m.decision.reason, decision: m.decision, missing: m.missing,
      proposal: m.proposal, attemptsRemaining: m.attemptsRemaining, exhausted: m.exhausted, record: record(m.decision), ...extra,
    });
  }

  const self = {
    /** The gate is active when a policy is bound or the operator turned the feature on. */
    active: () => current !== null || featureEnabledByOperator(env),
    hasPolicy: () => current !== null,
    /** Operator-side: replace the bound policy (a new policy version, a different task). Stale bindings are then refused. */
    update(next) { current = next && next.bound && next.binding ? { bound: next.bound, binding: next.binding } : null; },
    decisions: () => kept.slice(),
    guard: denialGuard,

    /**
     * @param {string} name   the tool the agent asked for
     * @param {{claimedTaskId?: string}} [req]   identity claimed in the request, if any
     */
    check(name, { claimedTaskId } = {}) {
      if (!self.active()) return Object.freeze({ allowed: true, skipped: true, decision: null });
      if (!current) {
        if (!isMutatingOrExternal(name)) return Object.freeze({ allowed: true, skipped: true, decision: null });
        return refused(synthetic(null, 'tool', 'identity-missing', String(name)));
      }
      const { bound, binding } = current;
      if (claimedTaskId !== undefined && claimedTaskId !== binding.taskId) {
        return refused(synthetic(bound, 'tool', 'identity-spoofed', `${String(name)} (claimed task ${sanitizeSubject(claimedTaskId, 60)})`));
      }
      const cap = toolCapabilityFor(name);
      if (!cap) return refused(synthetic(bound, 'tool', 'tool-unclassified', String(name)));
      const ctx = { binding };
      const decisions = [];
      for (const req of cap.requires) {
        const action = req === 'tool' ? { kind: 'tool', tool: name } : { kind: 'filesystem-write', path: sessionRoot };
        const m = mediate(bound, action, ctx, { guard: denialGuard });
        if (m.status !== 'ok') return blockedResult(m, { checked: decisions.length });
        decisions.push(m.decision); record(m.decision);
      }
      return Object.freeze({ allowed: true, skipped: false, decision: decisions[0], decisions });
    },
  };
  return Object.freeze(self);
}
