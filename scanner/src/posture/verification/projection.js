// One projection of the verification record for every interface (X-206).
//
// The CLI JSON report, the MCP tools, the human-readable report and the autopilot response all show the SAME verification of
// the SAME finding. They do that by calling this one module: nothing else renders, summarises or re-derives a state, a scope,
// an evidence id or a replay prerequisite. A surface that formats its own text would eventually disagree with the others,
// which is the defect this file exists to prevent.
//
// Rules the projection keeps:
//   - It is a VIEW. It reads a validated version-1 record (`assurance/verification-record.js`) and invents nothing: an
//     invalid record yields `{ ok: false, errors }`, never a guessed state.
//   - Nothing the record holds is dropped. Every record field has a counterpart in the view (the test enumerates them), so a
//     richer consumer loses nothing and a legacy consumer keeps its own boolean view under `legacy`.
//   - The text never labels a partial result "safe" or "fixed". It states what the check established and what it did not,
//     in words chosen per state, and a repair is described by its own separate status.
//   - Output is deterministic: no clock, no randomness, a fixed key order and sorted prerequisites.
import { validateVerificationRecord } from '../assurance/verification-record.js';
import { toLegacyVerificationView } from '../assurance/migrations.js';
import { isPlainObject } from '../assurance/schema-kit.js';
import { trustedNegativeDenominator } from '../oracles/scenario-classes.js';

export const VIEW_SCHEMA = 'agentic-security/verification-view';
const VIEW_VERSION = '1.0.0';

const RUNTIME_ORACLE_KINDS = ['runtime-replay', 'differential'];

// What a reader is told for each state. Chosen so no partial state reads as a pass: only `confirmed` and `refuted` say anything
// was decided, and both are limited to the declared scenario.
const STATE_LABEL = Object.freeze({
  confirmed: 'CONFIRMED (the declared scenario reproduced the effect)',
  refuted: 'NOT REPRODUCED (the declared scenario did not reproduce the effect)',
  inconclusive: 'INCONCLUSIVE (nothing was decided)',
  'not-run': 'NOT RUN (no check was executed)',
  unsupported: 'UNSUPPORTED (no applicable check exists here)',
  error: 'ERROR (the check failed to run)',
});

const REPAIR_LINE = Object.freeze({
  none: 'no patch is recorded for this finding',
  proposed: 'a patch was proposed; it has not been replay-verified',
  applied: 'a patch was applied; its effect has not been replay-verified',
  'replay-verified': 'a patch was replay-verified against the declared scenario and functional cases only',
  'rolled-back': 'a patch was rolled back',
});

function verifiedStatement(rec) {
  const how = rec.oracle ? `oracle '${rec.oracle.id}'${rec.oracle.version ? ` v${rec.oracle.version}` : ''}` : 'no oracle';
  const at = rec.commit ? ` at commit ${rec.commit.slice(0, 12)}` : ' without an exact commit';
  switch (rec.outcome) {
    case 'confirmed': return `${how} reproduced the effect${at}, within: ${rec.scope.description}`;
    case 'refuted': return `${how} ran with valid preconditions and did not reproduce the effect${at}, within: ${rec.scope.description}`;
    case 'inconclusive': return `nothing was established${rec.attempt > 0 ? ` (${how} ran but did not decide)` : ''}`;
    case 'not-run': return 'nothing was established; no check was executed';
    case 'unsupported': return 'nothing was established; no applicable check exists in this environment';
    default: return 'nothing was established; the check did not complete';
  }
}

function untestedStatements(rec) {
  const out = [];
  if (rec.outcome === 'confirmed' || rec.outcome === 'refuted') {
    out.push('behaviour outside the declared scenario and inputs');
    if (rec.outcome === 'refuted') out.push('other inputs and code paths that could still reach the same effect');
  } else if (rec.outcome === 'inconclusive') {
    out.push('whether the effect is reachable: the check did not decide');
  } else {
    out.push('the hypothesis itself: it has not been exercised');
  }
  if (rec.repair.status !== 'replay-verified') out.push('the effect of any proposed patch under a trusted exploit-negative replay');
  if (rec.confirmationLevel === 'none' && rec.outcome !== 'confirmed') out.push('independent adjudication: none is recorded');
  return out;
}

/**
 * The replay prerequisites for this record. Derived ones come from the record itself, so every surface computes the same
 * list. Typed prerequisites a replay attempt reported (`replay/replay.js`) are merged in by id.
 */
function replayPrerequisites(rec, supplied) {
  const items = new Map();
  items.set('exact-commit', {
    id: 'exact-commit', state: rec.commit ? 'met' : 'unmet',
    detail: rec.commit ? 'the record is bound to one exact commit' : 'no exact commit is recorded; a replay cannot be pinned',
  });
  const runtime = !!rec.oracle && RUNTIME_ORACLE_KINDS.includes(rec.oracle.kind);
  items.set('runtime-oracle', {
    id: 'runtime-oracle', state: runtime ? 'met' : 'unmet',
    detail: runtime ? `oracle '${rec.oracle.id}' is a runtime oracle` : 'no runtime oracle produced this record, so there is nothing to replay',
  });
  items.set('execution-boundary', {
    id: 'execution-boundary', state: 'declared',
    detail: `recorded on ${rec.scope.platform}${rec.scope.backend ? ` (${rec.scope.backend} backend)` : ''}; a replay needs an equivalent host`,
  });
  for (const p of Array.isArray(supplied) ? supplied : []) {
    if (!isPlainObject(p) || typeof p.id !== 'string' || !p.id) continue;
    const state = ['met', 'unmet', 'declared'].includes(p.state) ? p.state : 'unmet';
    const item = { id: p.kind ? `${p.kind}:${p.id}` : p.id, state, detail: typeof p.reason === 'string' && p.reason ? p.reason.slice(0, 200) : 'reported by the replay attempt' };
    if (typeof p.resumable === 'boolean') item.resumable = p.resumable;
    items.set(item.id, item);
  }
  const list = [...items.values()].sort((a, b) => a.id.localeCompare(b.id));
  const replayable = runtime && !!rec.commit && !['not-run', 'unsupported'].includes(rec.outcome) && !list.some((p) => p.state === 'unmet');
  return { replayable, prerequisites: list };
}

function textLines(view) {
  const lines = [];
  lines.push(`Verification: ${STATE_LABEL[view.state]}`);
  lines.push(`  Record: ${view.recordId}${view.oracle ? `  oracle: ${view.oracle.id}${view.oracle.version ? `@${view.oracle.version}` : ''}` : '  oracle: none'}`);
  lines.push(`  Scope: ${view.scope.description} [${view.scope.platform}${view.scope.backend ? `/${view.scope.backend}` : ''}]`);
  lines.push(`  Verified: ${view.summary.verified}`);
  lines.push(`  Not verified: ${view.summary.untested.join('; ')}`);
  lines.push(`  Repair: ${REPAIR_LINE[view.repair.status]}`);
  lines.push(`  Reason: ${view.reason}`);
  lines.push(`  Evidence: ${view.evidenceIds.length ? view.evidenceIds.join(', ') : 'none'}`);
  lines.push(`  Replay prerequisites: ${view.replay.prerequisites.map((p) => `${p.id} (${p.state})`).join(', ')}${view.replay.replayable ? '' : ' [not replayable as recorded]'}`);
  return lines;
}

/**
 * Project a version-1 verification record.
 *
 * @param {object} record  a record from `emitVerification` / `runOracle`
 * @param {object} [o]
 * @param {object[]} [o.replay]  typed prerequisites a replay attempt reported (`attempt.prerequisites`)
 * @returns {{ ok: boolean, view: object|null, errors: object[] }} never throws
 */
export function projectVerification(record, o = {}) {
  try {
    const v = validateVerificationRecord(record);
    if (!v.ok) return { ok: false, view: null, errors: v.errors };
    const replay = replayPrerequisites(record, o.replay);
    const view = {
      schema: VIEW_SCHEMA, schemaVersion: VIEW_VERSION,
      recordId: record.id, recordSchemaVersion: record.schemaVersion,
      hypothesisId: record.hypothesisId, commit: record.commit, detectorOrigin: record.detectorOrigin,
      oracle: record.oracle, attempt: record.attempt,
      state: record.outcome, reason: record.reason,
      confirmationLevel: record.confirmationLevel, preconditions: record.preconditions,
      scope: record.scope, repair: record.repair,
      evidence: record.evidence.map((e) => ({ id: e.id, kind: e.kind, producer: e.producer, digest: e.digest, source: e.source ?? null })),
      evidenceIds: record.evidence.map((e) => e.id),
      referencedEvidenceIds: [...record.evidenceRefs],
      replay,
      summary: { verified: verifiedStatement(record), untested: untestedStatements(record) },
      legacy: toLegacyVerificationView(record),
      migration: record.migration ?? null, createdAt: record.createdAt ?? null,
    };
    view.text = textLines(view);
    return { ok: true, view, errors: [] };
  } catch (e) {
    return { ok: false, view: null, errors: [{ code: 'RULE_VIOLATION', path: '', message: `verification projection failed: ${String(e?.message || e).slice(0, 160)}` }] };
  }
}

/**
 * The fields every surface adds to an output that carries a verification record. The key is `verificationView`, NOT
 * `verification`: a finding's `verification` field is the producer/verifier separation record
 * (`posture/verification-separation.js`) and keeps its meaning. ADDITIVE: an output without a record gets
 * `{}` and is byte-identical to what it was. A record that does not validate is reported, not dropped and not guessed.
 */
export function verificationFields(record, o = {}) {
  if (!isPlainObject(record)) return {};
  const p = projectVerification(record, o);
  return p.ok ? { verificationView: p.view } : { verificationView: null, verificationViewErrors: p.errors };
}

/**
 * The trusted-negative accounting for a set of verification records, for every interface that summarises a run
 * (`oracles/scenario-classes.js` owns the rule): only a decided result of an executed oracle of an advertised non-taint class,
 * with proven preconditions and trusted runtime proof, is counted. Every other record is listed with why it was left out, so an
 * unsupported or unrun case can never read as "checked and clean". Records that are not valid are reported as excluded.
 */
export function verificationCoverage(records) {
  const list = (Array.isArray(records) ? records : []).filter(isPlainObject);
  const valid = list.filter((r) => validateVerificationRecord(r).ok);
  const d = trustedNegativeDenominator(valid);
  const invalid = list.length - valid.length;
  const excluded = [...d.excluded, ...Array.from({ length: invalid }, () => ({ id: null, outcome: null, reason: 'malformed' }))];
  const reasons = {};
  for (const e of excluded) reasons[e.reason] = (reasons[e.reason] || 0) + 1;
  const why = Object.entries(reasons).sort(([a], [b]) => a.localeCompare(b)).map(([k, n]) => `${k}: ${n}`).join(', ');
  const lines = [`Trusted non-taint verification: ${d.denominator} decided (${d.trustedNegatives} not reproduced, ${d.trustedPositives} confirmed) of ${list.length} record(s); ${excluded.length} not counted${excluded.length ? ` (${why})` : ''}`];
  return { schema: 'agentic-security/verification-coverage', schemaVersion: '1.0.0', total: list.length, denominator: d.denominator, trustedNegatives: d.trustedNegatives, trustedPositives: d.trustedPositives, excluded, lines };
}
