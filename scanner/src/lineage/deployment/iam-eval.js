// Action-specific IAM decisions for the boundary graph (threat-model PRD FR-03.1, FR-03.4; TM-03).
//
// A deny blocks a requested action only when its action and resource patterns match that action and resource AND its condition holds.
// Before this, any deny edge on a hop blocked it: an unrelated `s3:DeleteObject` deny closed an `s3:GetObject` path, and a conditional
// deny whose predicate was never evaluated closed it too.
//
// The finite policy subset this module decides, and nothing more:
//   actions and resources  exact strings and IAM globs (`*`, `?`), case-insensitive for actions, case-sensitive for resources
//   conditions             StringEquals, StringNotEquals, Bool, ArnEquals; every operator and every key must hold (AND), any listed
//                          value of a key satisfies it (OR); a key the request context does not supply is UNKNOWN
//   anything else          (an `...IfExists` or set operator, a policy variable, a value outside the attribute grammar, a clipped
//                          action list) is recorded as unsupported and leaves the decision UNRESOLVED, never allowed or blocked
//
// Network denies are not IAM decisions and are not judged here: they still block the hop they sit on.
const SUPPORTED_OPERATORS = new Set(['StringEquals', 'StringNotEquals', 'Bool', 'ArnEquals']);
const MAX_CONDITIONS = 8;
const VALUE_GRAMMAR = /^[A-Za-z0-9_.:\/*,@ +=-]{0,200}$/;

/** IAM glob to RegExp. */
function glob(pattern, flags = '') {
  return new RegExp(`^${String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, flags);
}
export const actionMatches = (pattern, action) => glob(pattern, 'i').test(String(action));
export const resourceMatches = (pattern, resource) => glob(pattern).test(String(resource));

/**
 * The structured attributes a grants edge carries for one statement. Fits the graph's attribute grammar (at most 16 keys; values
 * limited to a safe character set), so the graph contract and its digests are unchanged for every existing field.
 */
export function statementAttrs(actions, condition) {
  const joined = actions.join(',');
  const attrs = { actions: joined.slice(0, 250), actionsComplete: joined.length <= 250 };
  if (!condition || typeof condition !== 'object' || !Object.keys(condition).length) return attrs;
  attrs.conditioned = true;
  let n = 0; let supported = true;
  for (const [op, block] of Object.entries(condition)) {
    if (!SUPPORTED_OPERATORS.has(op) || !block || typeof block !== 'object') { supported = false; continue; }
    for (const [key, raw] of Object.entries(block)) {
      const values = [].concat(raw).map(String);
      const text = `${op} ${key}=${values.join(',')}`;
      if (n >= MAX_CONDITIONS || !VALUE_GRAMMAR.test(text) || values.some((v) => v.includes(',') || v.includes('${'))) { supported = false; continue; }
      attrs[`cond${n++}`] = text;
    }
  }
  attrs.conditionSupported = supported;
  return attrs;
}

/** Evaluate an edge's encoded condition against a request context. 'true' | 'false' | 'unknown' (with the reason). */
export function evaluateCondition(attrs, context = {}) {
  if (!attrs || !attrs.conditioned) return { result: 'true', reason: 'unconditional' };
  if (attrs.conditionSupported !== true) return { result: 'unknown', reason: 'the condition uses an operator or value outside the supported subset' };
  const ctx = context && typeof context === 'object' ? context : {};
  let unknown = null;
  for (const [k, text] of Object.entries(attrs)) {
    if (!/^cond\d+$/.test(k)) continue;
    const m = /^(\S+) ([^=]+)=(.*)$/.exec(String(text));
    if (!m) return { result: 'unknown', reason: 'an encoded condition could not be read' };
    const [, op, key, list] = m;
    const values = list.split(',');
    if (!Object.prototype.hasOwnProperty.call(ctx, key)) { unknown = unknown ?? `the request context does not supply ${key}`; continue; }
    const actual = String(ctx[key]);
    const holds = op === 'StringNotEquals' ? !values.includes(actual) : op === 'Bool' ? values.map((v) => v.toLowerCase()).includes(actual.toLowerCase()) : values.includes(actual);
    if (!holds) return { result: 'false', reason: `${op} ${key} does not hold for ${actual}` };
  }
  return unknown ? { result: 'unknown', reason: unknown } : { result: 'true', reason: 'every condition holds for the request context' };
}

const actionsOf = (e) => String(e.attrs?.actions ?? '').split(',').filter(Boolean);
const clipped = (e) => e.attrs?.actionsComplete === false;
/** An edge that records no action list (another adapter, a hand-built graph): what it covers is not known. */
export const opaque = (e) => actionsOf(e).length === 0;
/** The pseudo-action used when the allow statements record no actions: "whatever was granted". */
export const UNKNOWN_ACTION = '(unrecorded)';

/**
 * Decide one action across a hop's allow and deny grants edges.
 * @returns {{action:string, outcome:'possible'|'blocked'|'unresolved'|'not-granted', blockers:object[], unresolvedBy:string[]}}
 */
export function decideAction(allows, denies, action, context) {
  const unresolvedBy = [];
  let granted = false;
  for (const e of allows) {
    const pats = actionsOf(e);
    if (opaque(e)) { granted = true; continue; } // an allow with no action list grants something; it is not narrowed here
    if (!pats.some((p) => actionMatches(p, action))) { if (clipped(e)) unresolvedBy.push(`allow ${e.id}: its action list was clipped, so ${action} may be granted`); continue; }
    const c = evaluateCondition(e.attrs, context);
    if (c.result === 'true') granted = true;
    else if (c.result === 'unknown') { granted = true; unresolvedBy.push(`allow ${e.id}: ${c.reason}`); }
  }
  if (!granted && !unresolvedBy.length) return { action, outcome: 'not-granted', blockers: [], unresolvedBy };
  const blockers = [];
  for (const d of denies) {
    const pats = actionsOf(d);
    // a deny with no action list, or any deny when the granted actions are themselves unrecorded, cannot be matched: unresolved
    if (opaque(d)) { unresolvedBy.push(`deny ${d.id}: it records no action list, so whether it covers ${action} is unknown`); continue; }
    if (action === UNKNOWN_ACTION) { unresolvedBy.push(`deny ${d.id}: the granted actions are not recorded, so whether it covers them is unknown`); continue; }
    if (!pats.some((p) => actionMatches(p, action))) { if (clipped(d)) unresolvedBy.push(`deny ${d.id}: its action list was clipped`); continue; }
    const c = evaluateCondition(d.attrs, context);
    if (c.result === 'true') blockers.push({ edgeId: d.id, action, matchedActions: pats.filter((p) => actionMatches(p, action)), condition: c.reason });
    else if (c.result === 'unknown') unresolvedBy.push(`deny ${d.id}: ${c.reason}`);
  }
  if (blockers.length) return { action, outcome: 'blocked', blockers, unresolvedBy };
  return { action, outcome: unresolvedBy.length ? 'unresolved' : 'possible', blockers, unresolvedBy };
}
