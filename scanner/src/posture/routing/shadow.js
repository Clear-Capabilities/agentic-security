// Shadow mode (X-605.AC01): record the route the constrained policy WOULD pick, and change nothing.
//
// The recorder has no transport, no adapter and no client: it cannot issue a provider call, paid or otherwise, so "no extra paid
// calls by default" holds by construction rather than by a flag. `shadow()` returns the production route it was given, the same object
// and untouched; the proposal is only written to the record list (and the receipt log, when one is supplied). Whether a proposal is
// ever acted on is the promotion gate's decision (promotion.js), not this module's.
//
// If the operator disabled adaptive routing (control.js) nothing is decided or recorded.

import { routeConstrained } from './decide.js';

export const SHADOW_SCHEMA = 'agentic-security/routing-shadow-record';

export function createShadowRecorder({ log = null, control = null } = {}) {
  const records = [];
  return {
    /**
     * @param {object} o
     * @param {object} o.task             from buildRoutingTask
     * @param {{model:string, effort?:string}} o.productionRoute  the route production will use; returned unchanged
     * @param {...object} o.rest          the remaining routeConstrained inputs (candidates, calibration, policy, now, egress, ...)
     */
    shadow({ task, productionRoute, ...decideArgs }) {
      if (!productionRoute || typeof productionRoute.model !== 'string' || !productionRoute.model) {
        throw new Error('shadow mode needs the production route it is shadowing');
      }
      if (control && control.mode === 'disabled') {
        return { route: productionRoute, shadow: null, recorded: false, paidCalls: 0, reason: 'adaptive routing is disabled by the operator' };
      }
      const decision = routeConstrained({ ...decideArgs, task, baselineRoute: productionRoute });
      const record = Object.freeze({
        schema: SHADOW_SCHEMA, taskId: task?.taskId ?? null, stratum: task?.stratum ?? null,
        production: Object.freeze({ model: productionRoute.model }),
        proposed: Object.freeze({
          status: decision.status, code: decision.code, model: decision.selected ? decision.selected.model : null,
          modelVersion: decision.selected ? decision.selected.modelVersion : null, via: decision.selected ? decision.selected.via : null,
          policyVersion: decision.policyVersion, decisionHash: decision.decisionHash,
        }),
        synthetic: decision.synthetic === true || task?.synthetic === true, paidCalls: 0,
      });
      records.push(record);
      if (log) log.append('shadow-decision', record);
      return { route: productionRoute, shadow: record, recorded: true, paidCalls: 0 };
    },
    records() { return records.slice(); },
    /** The latest record for each task. A re-decision replaces the earlier one in this view; the earlier record stays in `records()`. */
    latestByTask() {
      const m = new Map();
      for (const r of records) m.set(r.taskId, r);
      return [...m.values()];
    },
  };
}
