// Validation of a profile's finalVerification.closure block (REL-003). Kept free of imports so the profile validator can use it without
// a dependency cycle through the evidence modules.
export const GATE_GROUPS = Object.freeze(['quality', 'routing', 'release']);
export const DELIVERABLE_KINDS = Object.freeze(['implementation-diff', 'prd-ledger', 'scorecards', 'policy-cards', 'replayable-fixtures', 'release-assurance-bundle']);

/** Problems with a profile's finalVerification.closure block (empty when valid). `finalGateIds` are the ids the profile actually runs. */
export function validateClosureConfig(c, finalGateIds = []) {
  const p = [];
  if (!c || typeof c !== 'object' || Array.isArray(c)) return ['finalVerification.closure must be an object'];
  if (typeof c.releaseRequirement !== 'string' || !c.releaseRequirement) p.push('closure.releaseRequirement must name the requirement that closes the document');
  const e = c.expect || {};
  for (const k of ['requirements', 'criteria', 'weight']) if (!Number.isInteger(e[k]) || e[k] < 1) p.push(`closure.expect.${k} must be a positive integer`);
  const gates = c.requiredGates || {};
  for (const g of GATE_GROUPS) {
    if (!Array.isArray(gates[g])) { p.push(`closure.requiredGates.${g} must be an array of final gate ids`); continue; }
    for (const id of gates[g]) if (!finalGateIds.includes(id)) p.push(`closure.requiredGates.${g} names "${id}", which is not one of the profile's finalGates (a required gate must actually run)`);
  }
  for (const m of c.measuredGates || []) {
    if (!m || typeof m.id !== 'string' || !GATE_GROUPS.slice(0, 2).includes(m.group)) p.push('closure.measuredGates entries need an id and group "quality" or "routing"');
    else if (!Array.isArray(m.args) || typeof m.executable !== 'string' || !(m.timeoutSeconds > 0)) p.push(`closure.measuredGates ${m.id} needs executable, args and a finite timeoutSeconds`);
    else if (!['status-json', 'evaluation-gates'].includes(m.parse)) p.push(`closure.measuredGates ${m.id} parse must be "status-json" or "evaluation-gates"`);
  }
  const d = c.deliverables || {};
  for (const k of ['scorecards', 'policyCards', 'replayableFixtures', 'artifacts', 'scopeFiles']) if (d[k] !== undefined && (!Array.isArray(d[k]) || d[k].some((x) => typeof x !== 'string'))) p.push(`closure.deliverables.${k} must be an array of repository-relative paths`);
  for (const k of ['scorecards', 'policyCards', 'replayableFixtures', 'artifacts']) if (!Array.isArray(d[k]) || !d[k].length) p.push(`closure.deliverables.${k} must name at least one file`);
  const lim = c.limits || {};
  if (!lim.max || typeof lim.max !== 'object') p.push('closure.limits.max must give the ceilings the profile limits may not exceed');
  return p;
}

