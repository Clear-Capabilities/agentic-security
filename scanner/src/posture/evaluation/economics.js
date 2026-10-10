// Security economics (QA-004.AC03): what finding and fixing defects cost, with the cost kinds kept apart.
//
// A ledger is a list of entries, each one thing that was spent:
//   { id, kind, amountUsd | minutes, targetId, attemptId?, rootCauseId?, outcome? }
// `kind` is one of
//   model           model inference charged to the evaluation
//   tool            tool and infrastructure compute (scanner time, sandbox, runner)
//   cache           cache charges (writes and reads priced separately from fresh inference)
//   human-review    reviewer MINUTES, never converted to dollars here (a rate is a policy choice, not a measurement)
// `outcome` classifies the work the spend bought: confirmed | validated-fix | refuted | inconclusive | failed | duplicate.
//
// The rules that keep these figures honest:
//   - the kinds are reported side by side and never silently summed; human minutes are not dollars;
//   - an entry with no amount is UNMEASURED and counted as such, never read as zero;
//   - cost per confirmed defect divides ALL machine spend (successful, failed, refuted and duplicate attempts alike) by the number
//     of DISTINCT root causes independently confirmed, so failed attempts raise the price and a defect found twice is one defect;
//   - cost per validated fix divides the same spend by distinct root causes with an independently validated repair;
//   - with no confirmed defect the ratio is `null` (undefined), not 0 and not the total.
//
// Pure: no fs, no clock.

import { SCHEMA_VERSION } from '../assurance/schema-kit.js';
import { digestOf } from '../assurance/identity.js';

const COST_KINDS = Object.freeze(['model', 'tool', 'cache', 'human-review']);
export const OUTCOMES = Object.freeze(['confirmed', 'validated-fix', 'refuted', 'inconclusive', 'failed', 'duplicate']);
const ECON_SCHEMA = 'agentic-security/evaluation-economics';

function validateEntry(e, i) {
  const errs = [];
  if (!e || typeof e !== 'object') return [{ code: 'BAD_TYPE', path: `entries[${i}]`, message: 'must be an object' }];
  if (!COST_KINDS.includes(e.kind)) errs.push({ code: 'BAD_ENUM', path: `entries[${i}].kind`, message: `kind must be one of ${COST_KINDS.join(', ')}` });
  if (e.outcome !== undefined && !OUTCOMES.includes(e.outcome)) errs.push({ code: 'BAD_ENUM', path: `entries[${i}].outcome`, message: `outcome must be one of ${OUTCOMES.join(', ')}` });
  const field = e.kind === 'human-review' ? 'minutes' : 'amountUsd';
  const other = e.kind === 'human-review' ? 'amountUsd' : 'minutes';
  if (e[other] !== undefined && e[other] !== null) errs.push({ code: 'RULE_VIOLATION', path: `entries[${i}].${other}`, message: `a ${e.kind} entry is measured in ${field}; ${other} would mix units` });
  if (e[field] !== undefined && e[field] !== null && !(typeof e[field] === 'number' && Number.isFinite(e[field]) && e[field] >= 0)) errs.push({ code: 'BAD_VALUE', path: `entries[${i}].${field}`, message: `${field} must be a non-negative number or absent (unmeasured)` });
  if ((e.outcome === 'confirmed' || e.outcome === 'validated-fix') && !e.rootCauseId) errs.push({ code: 'RULE_VIOLATION', path: `entries[${i}].rootCauseId`, message: 'a confirmed or validated outcome must name its root cause so duplicates cannot be counted twice' });
  return errs;
}

/** @param {object[]} entries */
export function accountCosts(entries) {
  const errors = (entries || []).flatMap(validateEntry);
  if (errors.length) return { ok: false, errors };

  const totals = { model: { usd: 0, entries: 0, unmeasured: 0 }, tool: { usd: 0, entries: 0, unmeasured: 0 }, cache: { usd: 0, entries: 0, unmeasured: 0 }, humanReview: { minutes: 0, entries: 0, unmeasured: 0 } };
  const slot = { model: 'model', tool: 'tool', cache: 'cache', 'human-review': 'humanReview' };
  const confirmed = new Set(); const validated = new Set();
  const byOutcome = {};
  for (const e of entries || []) {
    const t = totals[slot[e.kind]];
    t.entries++;
    const v = e.kind === 'human-review' ? e.minutes : e.amountUsd;
    if (v === undefined || v === null) t.unmeasured++;
    else if (e.kind === 'human-review') t.minutes += v; else t.usd += v;
    const o = e.outcome || 'unclassified';
    byOutcome[o] = byOutcome[o] || { usd: 0, minutes: 0, entries: 0 };
    byOutcome[o].entries++;
    if (v !== undefined && v !== null) { if (e.kind === 'human-review') byOutcome[o].minutes += v; else byOutcome[o].usd += v; }
    if (e.outcome === 'confirmed') confirmed.add(e.rootCauseId);
    if (e.outcome === 'validated-fix') { validated.add(e.rootCauseId); confirmed.add(e.rootCauseId); }
  }
  // Machine spend: every kind except reviewer minutes, INCLUDING failed, refuted, inconclusive and duplicate work.
  const machineUsd = totals.model.usd + totals.tool.usd + totals.cache.usd;
  const unmeasuredMachine = totals.model.unmeasured + totals.tool.unmeasured + totals.cache.unmeasured;
  const div = (n, d) => (d > 0 ? n / d : null);
  const out = {
    schema: ECON_SCHEMA, schemaVersion: SCHEMA_VERSION, ok: true, errors: [],
    totals,
    separation: 'model, tool, cache and human-review figures are never combined; human review is in minutes, the rest in USD',
    machineSpendUsd: machineUsd,
    unmeasuredMachineEntries: unmeasuredMachine,
    confirmedDefects: confirmed.size, validatedFixes: validated.size,
    costPerConfirmedDefectUsd: div(machineUsd, confirmed.size),
    costPerValidatedFixUsd: div(machineUsd, validated.size),
    humanMinutesPerConfirmedDefect: div(totals.humanReview.minutes, confirmed.size),
    humanMinutesPerValidatedFix: div(totals.humanReview.minutes, validated.size),
    byOutcome,
    note: 'ratios divide ALL machine spend (failed, refuted and duplicate attempts included) by DISTINCT independently confirmed root causes; a ratio over an incomplete ledger is a lower bound',
    lowerBound: unmeasuredMachine > 0,
  };
  out.economicsHash = digestOf({ ...out, economicsHash: undefined });
  return out;
}
