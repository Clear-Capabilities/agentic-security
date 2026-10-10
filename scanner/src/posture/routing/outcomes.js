// Routing tasks, truth labels and outcome records (X-601).
//
// Extends the routing label contract (posture/assurance/contracts.js) with the two records routing needs and that contract does
// not describe: the TASK being routed (what kind of work, in which language, for which vulnerability class, how much context, which
// model capabilities it needs) and the OUTCOME of running it on one model (what happened, what it cost, how long it took, what the
// cache did, and whether anyone has decided if the answer was right).
//
// Three rules carry the module:
//
//   1. Four task kinds, never pooled. Discovery, triage, verification planning and repair fail differently and are priced
//      differently, so a stratum always begins with the kind and a quality estimate for one never stands in for another.
//   2. A truth label has exactly two sources: independent adjudication (a human or a verifier service that is not the model under
//      test) and trusted execution (a verification record produced by the protected verifier). Provider agreement, a model's own
//      confidence, an accepted suggestion and any model-only judgement are SIGNALS, not truth: `deriveRoutingLabel` refuses them and
//      records the outcome as `unknown`, so a popular answer can never become a correct one.
//   3. Nothing is dropped. An outcome whose status is failed, timed out, cancelled, a provider error or partial is a first-class
//      record, and so is one whose correctness is unknown or delayed. The ledger has no remove operation, and its summary reports
//      every status and every outcome so the denominator a later estimate uses is visible.
//
// Pure: no fs, no clock, no network.

import { SCHEMA_VERSION, makeCtx, result, guardObject, checkHeader, checkFields, checkEnum, checkString, checkId, isPlainObject } from '../assurance/schema-kit.js';
import { semanticId, digestOf } from '../assurance/identity.js';
import { ROUTING_TASK_KINDS, ROUTING_OUTCOMES, ROUTING_LABEL_SCHEMA, routingLabelId, validateRoutingLabel } from '../assurance/contracts.js';

export { ROUTING_TASK_KINDS, ROUTING_OUTCOMES };

export const ROUTING_TASK_SCHEMA = 'agentic-security/routing-task';
export const ROUTING_OUTCOME_SCHEMA = 'agentic-security/routing-outcome';

/** Capabilities a task can require of a model. A closed vocabulary: an unknown capability is rejected, never matched loosely. */
export const REQUIRED_CAPABILITIES = Object.freeze(['code-reasoning', 'code-edit', 'long-context', 'structured-output', 'tool-use', 'execution-planning']);
/** Sensitivity of what the prompt carries; the privacy constraint of a routing decision reads it. */
export const DATA_CLASSES = Object.freeze(['public', 'source-code', 'sensitive']);
/** Upper bounds of the context buckets, in tokens. The bucket, not the exact count, is part of the stratum. */
export const CONTEXT_BUCKETS = Object.freeze([
  Object.freeze({ id: 'xs', max: 4_000 }), Object.freeze({ id: 's', max: 16_000 }), Object.freeze({ id: 'm', max: 64_000 }),
  Object.freeze({ id: 'l', max: 200_000 }), Object.freeze({ id: 'xl', max: Infinity }),
]);

export const OUTCOME_STATUSES = Object.freeze(['completed', 'partial', 'failed', 'timeout', 'cancelled', 'provider-error', 'blocked']);
/** Statuses that are operational failures. They are kept, counted and reported; they are never filtered out of a denominator. */
export const FAILURE_STATUSES = Object.freeze(['failed', 'timeout', 'cancelled', 'provider-error', 'blocked']);
export const CACHE_STATES = Object.freeze(['hit', 'partial', 'miss', 'ineligible', 'unknown']);
export const USAGE_SOURCES = Object.freeze(['measured', 'estimated', 'unknown']);

export function contextBucketOf(tokens) {
  if (!Number.isFinite(tokens) || tokens < 0) return null;
  return CONTEXT_BUCKETS.find((b) => tokens <= b.max).id;
}

const KEY_PART = /^[A-Za-z0-9_.+:-]+$/;
export function stratumKey({ taskKind, language, vulnClass, contextBucket }) {
  return `${taskKind}|${language}|${vulnClass}|${contextBucket}`;
}

/** Coarser strata a thinly-sampled stratum may fall back to, finest first: kind|language|class, kind|language, kind. */
export function stratumParents(stratum) {
  const parts = String(stratum).split('|');
  const out = [];
  for (let n = parts.length - 1; n >= 1; n--) out.push(parts.slice(0, n).join('|'));
  return out;
}

// ---------------------------------------------------------------- task

const TASK_ALLOWED = [
  'schema', 'schemaVersion', 'id', 'taskId', 'taskKind', 'language', 'vulnClass', 'contextTokens', 'contextBucket', 'requiredCapabilities',
  'dataClass', 'stratum', 'synthetic', 'createdAt',
];
const TASK_REQUIRED = ['schema', 'schemaVersion', 'id', 'taskId', 'taskKind', 'language', 'vulnClass', 'contextTokens', 'contextBucket', 'requiredCapabilities', 'dataClass', 'stratum', 'synthetic'];
const ROUTING_TASK_ID_FIELDS = Object.freeze(['taskId', 'taskKind', 'language', 'vulnClass', 'contextBucket', 'requiredCapabilities', 'dataClass']);

function routingTaskId(t) { return semanticId('rtask', t, ROUTING_TASK_ID_FIELDS); }

/**
 * Build a task record. Returns `{ ok, task, errors }`; an invalid input yields no task, never a half-filled one.
 * `requiredCapabilities` is sorted and de-duplicated so two callers that list the same needs in a different order get the same id.
 */
export function buildRoutingTask({ taskId, taskKind, language, vulnClass, contextTokens, requiredCapabilities = [], dataClass = 'source-code', synthetic = false } = {}) {
  const caps = Array.isArray(requiredCapabilities) ? [...new Set(requiredCapabilities)].sort() : requiredCapabilities;
  const bucket = contextBucketOf(contextTokens);
  const lang = typeof language === 'string' ? language.trim().toLowerCase() : language;
  const t = {
    schema: ROUTING_TASK_SCHEMA, schemaVersion: SCHEMA_VERSION, taskId, taskKind, language: lang, vulnClass, contextTokens,
    contextBucket: bucket, requiredCapabilities: caps, dataClass, synthetic,
  };
  t.stratum = bucket && ROUTING_TASK_KINDS.includes(taskKind) && KEY_PART.test(String(lang)) && KEY_PART.test(String(vulnClass))
    ? stratumKey(t) : null;
  t.id = routingTaskId(t);
  const v = validateRoutingTask(t);
  return v.ok ? { ok: true, task: Object.freeze(t), errors: [] } : { ok: false, task: null, errors: v.errors };
}

export function validateRoutingTask(t) {
  const g = guardObject(t);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, t, ROUTING_TASK_SCHEMA)) return result(ctx);
  checkFields(ctx, t, TASK_ALLOWED, TASK_REQUIRED);
  checkString(ctx, 'taskId', t.taskId);
  checkEnum(ctx, 'taskKind', t.taskKind, ROUTING_TASK_KINDS);
  if (!checkString(ctx, 'language', t.language) || !KEY_PART.test(t.language)) ctx.err('BAD_TYPE', 'language', 'must be a simple language name (letters, digits, . _ + : -)');
  if (!checkString(ctx, 'vulnClass', t.vulnClass) || !KEY_PART.test(t.vulnClass)) ctx.err('BAD_TYPE', 'vulnClass', 'must be a simple class id such as CWE-89 (letters, digits, . _ + : -)');
  if (!Number.isInteger(t.contextTokens) || t.contextTokens < 0) ctx.err('BAD_TYPE', 'contextTokens', 'must be a non-negative integer');
  else if (t.contextBucket !== contextBucketOf(t.contextTokens)) ctx.err('RULE_VIOLATION', 'contextBucket', 'does not match contextTokens');
  if (!Array.isArray(t.requiredCapabilities)) ctx.err('BAD_TYPE', 'requiredCapabilities', 'must be an array');
  else {
    t.requiredCapabilities.forEach((c, i) => checkEnum(ctx, `requiredCapabilities[${i}]`, c, REQUIRED_CAPABILITIES));
    if (new Set(t.requiredCapabilities).size !== t.requiredCapabilities.length) ctx.err('DUPLICATE_ID', 'requiredCapabilities', 'lists a capability twice');
  }
  checkEnum(ctx, 'dataClass', t.dataClass, DATA_CLASSES);
  if (typeof t.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (ctx.errors.length === 0 && t.stratum !== stratumKey(t)) ctx.err('RULE_VIOLATION', 'stratum', 'does not match kind, language, class and context bucket');
  checkId(ctx, t, routingTaskId(t));
  return result(ctx);
}

// ---------------------------------------------------------------- truth labels

/** Evidence kinds that may decide correctness, and the routing-label source each one maps to. */
export const TRUTH_SOURCES = Object.freeze({ 'independent-adjudication': 'adjudication', 'trusted-execution': 'trusted-execution' });
/** Signals that look like labels and are not. Named so a refusal can say exactly what was offered. */
export const NON_TRUTH_SIGNALS = Object.freeze(['provider-agreement', 'self-reported-confidence', 'accepted-suggestion', 'model-judgement', 'majority-vote']);
export const INDEPENDENT_REVIEWER_KINDS = Object.freeze(['human', 'verifier-service']);

/**
 * Turn an asserted outcome plus its evidence into a routing label, or refuse.
 *
 * `evidence` is `{ kind, reviewerKind, reviewerId, adjudicationVersion, verificationRecordId }`. A decided outcome (`correct` or
 * `incorrect`) is accepted only with:
 *   - `independent-adjudication`: a reviewer of kind human or verifier-service whose id is neither the model under test nor its
 *     provider, plus the adjudication protocol version; or
 *   - `trusted-execution`: a verification record id (`vrec:...`) produced by the protected verifier.
 * Anything else, including every NON_TRUTH_SIGNALS kind, is refused and the outcome is recorded as `unknown` with no source. The
 * refusal is returned (`accepted: false`, `code`, `reason`) so the caller cannot mistake a downgrade for a decision.
 *
 * `unknown` and `delayed` need no evidence and are accepted as they are: not knowing is a legitimate, retained outcome.
 */
export function deriveRoutingLabel({ task, model, provider = null, outcome, evidence = null } = {}) {
  const base = { schema: ROUTING_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION, taskId: task?.taskId, taskKind: task?.taskKind, stratum: task?.stratum, model };
  const finish = (o, source, extra = {}) => {
    const label = { ...base, outcome: o, labelSource: source, ...(extra.verificationRecordId ? { verificationRecordId: extra.verificationRecordId } : {}) };
    label.id = routingLabelId(label);
    const v = validateRoutingLabel(label);
    return { label: v.ok ? Object.freeze(label) : null, errors: v.errors, ...extra.meta };
  };
  if (!isPlainObject(task) || typeof model !== 'string' || !model) return { accepted: false, code: 'BAD_INPUT', reason: 'a task record and a model id are required', label: null, errors: [] };
  if (!ROUTING_OUTCOMES.includes(outcome)) return { accepted: false, code: 'BAD_INPUT', reason: `outcome must be one of ${ROUTING_OUTCOMES.join(', ')}`, label: null, errors: [] };
  if (outcome === 'unknown' || outcome === 'delayed') {
    return { accepted: true, ...finish(outcome, 'none') };
  }
  const refuse = (code, reason) => ({ accepted: false, code, reason, downgradedTo: 'unknown', offeredKind: evidence?.kind ?? null, ...finish('unknown', 'none') });
  if (!isPlainObject(evidence) || typeof evidence.kind !== 'string') return refuse('NOT_A_TRUTH_LABEL', `a '${outcome}' outcome needs adjudication or trusted-execution evidence; none was given`);
  if (NON_TRUTH_SIGNALS.includes(evidence.kind)) return refuse('NOT_A_TRUTH_LABEL', `'${evidence.kind}' is a signal, not a truth label: it cannot decide correctness`);
  const source = TRUTH_SOURCES[evidence.kind];
  if (!source) return refuse('NOT_A_TRUTH_LABEL', `unknown evidence kind '${evidence.kind}'`);
  if (evidence.kind === 'independent-adjudication') {
    if (!INDEPENDENT_REVIEWER_KINDS.includes(evidence.reviewerKind)) return refuse('NOT_INDEPENDENT', `reviewer kind '${evidence.reviewerKind}' is not independent of the model (allowed: ${INDEPENDENT_REVIEWER_KINDS.join(', ')})`);
    if (typeof evidence.reviewerId !== 'string' || !evidence.reviewerId) return refuse('NOT_INDEPENDENT', 'an adjudication names its reviewer');
    if (evidence.reviewerId === model || (provider && evidence.reviewerId === provider)) return refuse('NOT_INDEPENDENT', 'the reviewer is the model under test or its provider');
    if (typeof evidence.adjudicationVersion !== 'string' || !evidence.adjudicationVersion) return refuse('MISSING_PROVENANCE', 'an adjudication records the adjudication protocol version');
    return { accepted: true, adjudicationVersion: evidence.adjudicationVersion, ...finish(outcome, source) };
  }
  // trusted execution
  if (typeof evidence.verificationRecordId !== 'string' || !evidence.verificationRecordId.startsWith('vrec:')) return refuse('MISSING_PROVENANCE', 'trusted execution cites the verification record it came from (vrec:...)');
  return { accepted: true, adjudicationVersion: typeof evidence.adjudicationVersion === 'string' ? evidence.adjudicationVersion : null, ...finish(outcome, source, { verificationRecordId: evidence.verificationRecordId }) };
}

// ---------------------------------------------------------------- outcome records

const OUT_ALLOWED = [
  'schema', 'schemaVersion', 'id', 'runId', 'taskId', 'taskKind', 'stratum', 'model', 'modelVersion', 'status', 'outcome', 'labelId', 'labelSource',
  'adjudicationVersion', 'group', 'usage', 'costUsd', 'costStatus', 'latencyMs', 'cacheState', 'observedAt', 'synthetic', 'createdAt',
];
const OUT_REQUIRED = ['schema', 'schemaVersion', 'id', 'runId', 'taskId', 'taskKind', 'stratum', 'model', 'modelVersion', 'status', 'outcome', 'labelSource', 'usage', 'costUsd', 'costStatus', 'latencyMs', 'cacheState', 'synthetic'];
const ROUTING_OUTCOME_ID_FIELDS = Object.freeze(['runId', 'taskId', 'model', 'modelVersion']);
export const COST_STATUSES = Object.freeze(['measured', 'bounded-estimate', 'unknown']);

function routingOutcomeId(o) { return semanticId('rout', o, ROUTING_OUTCOME_ID_FIELDS); }

const countOrNull = (v) => v === null || (Number.isInteger(v) && v >= 0);

/**
 * Build an outcome record. `usage` fields that were not observed MUST be `null`: a missing count is unknown, not zero. `label` is the
 * (accepted) result of `deriveRoutingLabel`, or omitted when the outcome is unknown or delayed.
 */
export function buildRoutingOutcome({ runId, task, model, modelVersion = null, status, outcome = 'unknown', label = null, adjudicationVersion = null, group = null, usage = {}, costUsd = null, costStatus = 'unknown', latencyMs = null, cacheState = 'unknown', observedAt = null, synthetic = false } = {}) {
  const u = {
    inputTokens: usage.inputTokens ?? null, outputTokens: usage.outputTokens ?? null, cachedInputTokens: usage.cachedInputTokens ?? null,
    retries: usage.retries ?? 0, source: usage.source ?? 'unknown',
  };
  const o = {
    schema: ROUTING_OUTCOME_SCHEMA, schemaVersion: SCHEMA_VERSION, runId, taskId: task?.taskId, taskKind: task?.taskKind, stratum: task?.stratum, model,
    modelVersion, status, outcome: label ? label.outcome : outcome, labelSource: label ? label.labelSource : 'none', usage: u, costUsd, costStatus, latencyMs, cacheState, synthetic: !!(synthetic || task?.synthetic),
  };
  if (label?.id) o.labelId = label.id;
  if (adjudicationVersion) o.adjudicationVersion = adjudicationVersion;
  if (group) o.group = group;
  if (observedAt) o.observedAt = observedAt;
  o.id = routingOutcomeId(o);
  const v = validateRoutingOutcome(o);
  return v.ok ? { ok: true, outcome: Object.freeze(o), errors: [] } : { ok: false, outcome: null, errors: v.errors };
}

export function validateRoutingOutcome(o) {
  const g = guardObject(o);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, o, ROUTING_OUTCOME_SCHEMA)) return result(ctx);
  checkFields(ctx, o, OUT_ALLOWED, OUT_REQUIRED);
  for (const f of ['runId', 'taskId', 'stratum', 'model']) checkString(ctx, f, o[f]);
  checkEnum(ctx, 'taskKind', o.taskKind, ROUTING_TASK_KINDS);
  if (o.modelVersion !== null && typeof o.modelVersion !== 'string') ctx.err('BAD_TYPE', 'modelVersion', 'must be a string, or null when unknown');
  checkEnum(ctx, 'status', o.status, OUTCOME_STATUSES);
  const outOk = checkEnum(ctx, 'outcome', o.outcome, ROUTING_OUTCOMES);
  checkEnum(ctx, 'labelSource', o.labelSource, ['adjudication', 'trusted-execution', 'none']);
  checkEnum(ctx, 'costStatus', o.costStatus, COST_STATUSES);
  checkEnum(ctx, 'cacheState', o.cacheState, CACHE_STATES);
  if (!isPlainObject(o.usage)) ctx.err('BAD_TYPE', 'usage', 'must be an object');
  else {
    for (const f of ['inputTokens', 'outputTokens', 'cachedInputTokens']) if (!countOrNull(o.usage[f])) ctx.err('BAD_TYPE', `usage.${f}`, 'must be a non-negative integer, or null when unknown (never 0 for unknown)');
    if (!Number.isInteger(o.usage.retries) || o.usage.retries < 0) ctx.err('BAD_TYPE', 'usage.retries', 'must be a non-negative integer');
    checkEnum(ctx, 'usage.source', o.usage.source, USAGE_SOURCES);
    if (o.usage.cachedInputTokens !== null && o.usage.inputTokens !== null && o.usage.cachedInputTokens > o.usage.inputTokens) ctx.err('RULE_VIOLATION', 'usage.cachedInputTokens', 'cannot exceed inputTokens');
  }
  if (o.costUsd !== null && !(typeof o.costUsd === 'number' && Number.isFinite(o.costUsd) && o.costUsd >= 0)) ctx.err('BAD_TYPE', 'costUsd', 'must be a non-negative number, or null when unknown');
  if (o.costUsd === null && o.costStatus === 'measured') ctx.err('RULE_VIOLATION', 'costStatus', 'a measured cost has a value');
  if (o.costUsd !== null && o.costStatus === 'unknown') ctx.err('RULE_VIOLATION', 'costStatus', 'a cost with a value is measured or a bounded estimate');
  if (o.latencyMs !== null && !(typeof o.latencyMs === 'number' && Number.isFinite(o.latencyMs) && o.latencyMs >= 0)) ctx.err('BAD_TYPE', 'latencyMs', 'must be a non-negative number, or null when unknown');
  if (typeof o.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (o.observedAt !== undefined && (typeof o.observedAt !== 'string' || Number.isNaN(Date.parse(o.observedAt)))) ctx.err('BAD_TYPE', 'observedAt', 'must be an ISO timestamp');
  if (o.group !== undefined) checkString(ctx, 'group', o.group);
  // A decided outcome names the source that decided it; unknown and delayed name none. The same rule the label contract enforces.
  if (outOk) {
    if (['correct', 'incorrect'].includes(o.outcome) && o.labelSource === 'none') ctx.err('RULE_VIOLATION', 'labelSource', `a '${o.outcome}' outcome needs an adjudication or trusted-execution source`);
    if (['unknown', 'delayed'].includes(o.outcome) && o.labelSource !== 'none') ctx.err('RULE_VIOLATION', 'labelSource', `an '${o.outcome}' outcome has no decided source`);
    if (['correct', 'incorrect'].includes(o.outcome) && o.labelSource === 'adjudication' && !o.adjudicationVersion) ctx.err('MISSING_FIELD', 'adjudicationVersion', 'an adjudicated outcome records the adjudication version');
    if (['correct', 'incorrect'].includes(o.outcome) && !o.labelId) ctx.err('MISSING_FIELD', 'labelId', 'a decided outcome cites its label');
  }
  checkId(ctx, o, routingOutcomeId(o));
  return result(ctx);
}

// ---------------------------------------------------------------- the ledger

/**
 * An append-only collection of outcome records. There is no remove, no filter-in-place and no overwrite: `add` rejects an invalid or
 * duplicate record with a reason instead of discarding it quietly, and `summary` reports every status and outcome so the population
 * a calibration draws from can be seen whole.
 */
export function createOutcomeLedger() {
  const byId = new Map();
  const rejected = [];
  return {
    add(o) {
      const v = validateRoutingOutcome(o);
      if (!v.ok) { rejected.push({ id: o?.id ?? null, reason: 'invalid', errors: v.errors }); return { ok: false, code: 'INVALID', errors: v.errors }; }
      if (byId.has(o.id)) { rejected.push({ id: o.id, reason: 'duplicate' }); return { ok: false, code: 'DUPLICATE_ID', errors: [{ code: 'DUPLICATE_ID', path: 'id', message: `outcome ${o.id} is already in the ledger` }] }; }
      byId.set(o.id, o);
      return { ok: true, errors: [] };
    },
    all() { return [...byId.values()]; },
    rejected() { return rejected.map((r) => ({ ...r })); },
    summary() {
      const rows = [...byId.values()];
      const tally = (key, vocab) => Object.fromEntries(vocab.map((k) => [k, rows.filter((r) => r[key] === k).length]));
      return {
        total: rows.length,
        byStatus: tally('status', OUTCOME_STATUSES),
        byOutcome: tally('outcome', ROUTING_OUTCOMES),
        byTaskKind: tally('taskKind', ROUTING_TASK_KINDS),
        labelled: rows.filter((r) => r.labelSource !== 'none').length,
        unlabelled: rows.filter((r) => r.labelSource === 'none').length,
        failures: rows.filter((r) => FAILURE_STATUSES.includes(r.status)).length,
        rejectedAtIntake: rejected.length,
        digest: digestOf(rows.map((r) => r.id).sort()),
      };
    },
  };
}
