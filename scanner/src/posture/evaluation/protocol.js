// Frozen current-engine evaluation protocol (QA-001).
//
// A protocol is the thing registered BEFORE any result is looked at: dataset
// scope, thresholds, matching rules, budgets and split membership. Its hash is
// computed over every semantic field, so a changed threshold or a moved target
// is a different protocol, never an edit of the old one.
//
// What this module does NOT do: it creates no population, no labels and no
// results. A protocol marked `synthetic` can exercise the machinery and can
// never satisfy a real-code gate (gates.js enforces that).
//
// Pure: no fs, no clock, no network. Validators return `{ ok, errors }` with the
// same error shape the assurance schema kit uses.

import {
  SCHEMA_VERSION, makeCtx, result, guardObject, checkHeader, checkFields, checkDigest, checkCommit, checkString,
  isPlainObject, isDigest,
} from '../assurance/schema-kit.js';
import { digestOf } from '../assurance/identity.js';
import { groupTargets, splitStraddles } from './grouping.js';

const PROTOCOL_SCHEMA = 'agentic-security/evaluation-protocol';

// The nine advertised core languages (docs/POSITIONING.md, PRD section 3).
export const CORE_LANGUAGES = Object.freeze([
  'javascript', 'python', 'java', 'kotlin', 'go', 'ruby', 'php', 'csharp', 'rust',
]);

// PRD section 5. These are release TARGETS registered in advance, not claims
// about current performance. They live in code so a protocol that omits or
// loosens one is detectable (`validateProtocol` compares against this floor).
export const PREREGISTERED_THRESHOLDS = Object.freeze({
  perLanguageF1: 0.80,
  overallMicroF1: 0.80,
  overallMacroF1: 0.80,
  pooledPrecision: 0.90,
  pooledRecall: 0.75,
  perLanguageF1LowerBound: 0.70,
  completion: 0.95,
  minPositivesPerCoreLanguage: 100,
  minNegativesPerCoreLanguage: 100,
  minPositivesPerFamily: 30,
  intervalMethod: 'grouped-bootstrap-95',
});

export const DEFAULT_MATCHING = Object.freeze({
  policy: 'root-cause-location',
  lineWindow: 3,
  requireFamilyOrCwe: true,
  cweAloneSufficient: false,
  lineLessFindingsMatch: false,
});

const FIELDS = [
  'schema', 'schemaVersion', 'protocolVersion', 'supersedes', 'synthetic', 'engine', 'measurement', 'tools', 'models',
  'datasetLicenses', 'scope', 'matching', 'limits', 'thresholds', 'targets', 'originalTargetIds', 'retired', 'splits',
  'grouping', 'comparability', 'protocolHash', 'createdAt',
];
const REQUIRED = [
  'schema', 'schemaVersion', 'protocolVersion', 'synthetic', 'engine', 'measurement', 'tools', 'models', 'datasetLicenses',
  'scope', 'matching', 'limits', 'thresholds', 'targets', 'originalTargetIds', 'splits', 'protocolHash',
];
// Everything except the hash itself and the informational clock.
const HASHED = FIELDS.filter((f) => f !== 'protocolHash' && f !== 'createdAt');

export function protocolHashOf(p) {
  const material = {};
  for (const f of HASHED) material[f] = p?.[f] === undefined ? null : p[f];
  return digestOf({ kind: 'evaluation-protocol', material });
}

function deepFreeze(v) {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const k of Object.keys(v)) deepFreeze(v[k]);
  }
  return v;
}

const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * Validate a protocol, frozen or not. A protocol whose hash does not match its
 * content fails with HASH_MISMATCH: that is what "immutable" means here.
 */
export function validateProtocol(p) {
  const g = guardObject(p);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, p, PROTOCOL_SCHEMA)) return result(ctx);
  checkFields(ctx, p, FIELDS, REQUIRED);

  if (!Number.isInteger(p.protocolVersion) || p.protocolVersion < 1) ctx.err('BAD_TYPE', 'protocolVersion', 'must be a positive integer');
  if (typeof p.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');

  // AC01: pinned versions, digests and a clean measurement tree.
  if (!isPlainObject(p.engine)) ctx.err('BAD_TYPE', 'engine', 'must be an object');
  else { checkString(ctx, 'engine.version', p.engine.version); checkDigest(ctx, 'engine.bundleDigest', p.engine.bundleDigest); }
  if (!isPlainObject(p.measurement)) ctx.err('BAD_TYPE', 'measurement', 'must be an object');
  else {
    checkCommit(ctx, 'measurement.commit', p.measurement.commit, { nullable: false });
    if (p.measurement.cleanTree !== true) ctx.err('RULE_VIOLATION', 'measurement.cleanTree', 'the measurement tree must be clean; a dirty tree cannot be pinned');
  }
  if (!isPlainObject(p.tools) || Object.keys(p.tools).length === 0) ctx.err('MISSING_FIELD', 'tools', 'tool versions must be pinned');
  if (!Array.isArray(p.models)) ctx.err('BAD_TYPE', 'models', 'must be an array (empty when no model is used)');
  else p.models.forEach((m, i) => { if (!isPlainObject(m) || !m.provider || !m.model || !m.version) ctx.err('BAD_TYPE', `models[${i}]`, 'must name provider, model and version'); });
  if (!isPlainObject(p.datasetLicenses) || Object.keys(p.datasetLicenses).length === 0) ctx.err('MISSING_FIELD', 'datasetLicenses', 'dataset licenses must be declared');

  if (!isPlainObject(p.scope) || !Array.isArray(p.scope.languages) || !p.scope.languages.length || !Array.isArray(p.scope.families) || !p.scope.families.length) {
    ctx.err('MISSING_FIELD', 'scope', 'scope must declare languages[] and families[]');
  }
  if (!isPlainObject(p.matching)) ctx.err('BAD_TYPE', 'matching', 'must be an object');
  else if (p.matching.cweAloneSufficient !== false) ctx.err('RULE_VIOLATION', 'matching.cweAloneSufficient', 'CWE agreement alone can never make a true positive');
  if (!isPlainObject(p.limits)) ctx.err('BAD_TYPE', 'limits', 'must be an object');
  else {
    for (const k of ['perTargetTimeoutMs', 'spendCeilingUsd', 'replicates']) {
      if (typeof p.limits[k] !== 'number' || !(p.limits[k] >= 0)) ctx.err('BAD_TYPE', `limits.${k}`, 'must be a non-negative number');
    }
  }

  // Thresholds may be stricter than the floor, never looser or missing.
  if (!isPlainObject(p.thresholds)) ctx.err('BAD_TYPE', 'thresholds', 'must be an object');
  else {
    for (const [k, floor] of Object.entries(PREREGISTERED_THRESHOLDS)) {
      const v = p.thresholds[k];
      if (typeof floor === 'string') { if (v !== floor) ctx.err('RULE_VIOLATION', `thresholds.${k}`, `must be '${floor}'`); continue; }
      if (typeof v !== 'number') { ctx.err('MISSING_FIELD', `thresholds.${k}`, 'preregistered threshold is missing'); continue; }
      if (v < floor) ctx.err('RULE_VIOLATION', `thresholds.${k}`, `${v} is looser than the preregistered ${floor}`);
    }
  }

  // Targets: pairs, licenses, commits, digests.
  const ids = new Set();
  if (!Array.isArray(p.targets) || p.targets.length === 0) ctx.err('MISSING_FIELD', 'targets', 'a protocol needs at least one target');
  else {
    p.targets.forEach((t, i) => {
      const at = `targets[${i}]`;
      if (!isPlainObject(t)) { ctx.err('BAD_TYPE', at, 'must be an object'); return; }
      if (!checkString(ctx, `${at}.id`, t.id)) return;
      if (ids.has(t.id)) ctx.err('DUPLICATE_ID', `${at}.id`, `duplicate target id ${t.id}`);
      ids.add(t.id);
      checkString(ctx, `${at}.language`, t.language);
      checkString(ctx, `${at}.license`, t.license);
      checkCommit(ctx, `${at}.preCommit`, t.preCommit, { nullable: false });
      checkCommit(ctx, `${at}.postCommit`, t.postCommit, { nullable: true });
      checkDigest(ctx, `${at}.digest`, t.digest);
      if (isPlainObject(p.datasetLicenses) && t.license && !(t.license in p.datasetLicenses)) ctx.err('RULE_VIOLATION', `${at}.license`, `license ${t.license} is not declared in datasetLicenses`);
      if (isPlainObject(p.scope) && Array.isArray(p.scope.languages) && t.language && !p.scope.languages.includes(t.language)) ctx.err('RULE_VIOLATION', `${at}.language`, `${t.language} is outside the declared scope`);
    });
  }

  // AC03: nothing silently disappears from the original denominator.
  const retired = Array.isArray(p.retired) ? p.retired : [];
  const retiredIds = new Set();
  retired.forEach((r, i) => {
    if (!isPlainObject(r) || !r.id || !r.reason) ctx.err('BAD_TYPE', `retired[${i}]`, 'a retired target must name id and reason');
    else retiredIds.add(r.id);
  });
  if (!Array.isArray(p.originalTargetIds)) ctx.err('BAD_TYPE', 'originalTargetIds', 'must be an array');
  else {
    for (const id of p.originalTargetIds) {
      if (!ids.has(id) && !retiredIds.has(id)) ctx.err('RULE_VIOLATION', 'originalTargetIds', `target ${id} left the population without a disclosed retirement`);
    }
  }

  // Splits: immutable membership, a partition of the targets, no group straddling it.
  if (!isPlainObject(p.splits) || !Array.isArray(p.splits.dev) || !Array.isArray(p.splits.sealed)) ctx.err('BAD_TYPE', 'splits', 'must be {dev[], sealed[]}');
  else {
    const dev = new Set(p.splits.dev); const sealed = new Set(p.splits.sealed);
    for (const id of dev) if (sealed.has(id)) ctx.err('RULE_VIOLATION', 'splits', `target ${id} is in both development and sealed`);
    for (const id of ids) if (!dev.has(id) && !sealed.has(id)) ctx.err('RULE_VIOLATION', 'splits', `target ${id} is in no split`);
    for (const id of [...dev, ...sealed]) if (!ids.has(id)) ctx.err('DANGLING_REF', 'splits', `split names unknown target ${id}`);
    if (Array.isArray(p.targets) && ctx.errors.length === 0) {
      for (const grp of splitStraddles(groupTargets(p.targets).groups, p.splits)) {
        ctx.err('RULE_VIOLATION', 'splits', `related samples ${grp.members.join(', ')} (${grp.reasons.join('; ')}) straddle development and sealed`);
      }
    }
  }

  if (typeof p.protocolHash !== 'string' || !isDigest(p.protocolHash)) ctx.err('BAD_DIGEST', 'protocolHash', 'must be a sha256 digest');
  else if (ctx.errors.length === 0 && p.protocolHash !== protocolHashOf(p)) {
    ctx.err('HASH_MISMATCH', 'protocolHash', 'content does not match protocolHash: the protocol was changed after it was frozen');
  }
  return result(ctx);
}

/**
 * Freeze a draft. The draft must already carry its splits; use `assignSplits`
 * (grouping.js) to produce them. Returns `{ ok, errors, protocol }`; on success
 * the protocol is deeply frozen and carries its hash.
 */
export function freezeProtocol(draft) {
  const p = clone(draft || {});
  p.schema = PROTOCOL_SCHEMA;
  p.schemaVersion = SCHEMA_VERSION;
  p.protocolVersion = Number.isInteger(p.protocolVersion) ? p.protocolVersion : 1;
  if (p.supersedes === undefined) p.supersedes = null;
  if (p.thresholds === undefined) p.thresholds = { ...PREREGISTERED_THRESHOLDS };
  if (p.matching === undefined) p.matching = { ...DEFAULT_MATCHING };
  if (!Array.isArray(p.originalTargetIds)) p.originalTargetIds = (p.targets || []).map((t) => t.id).sort();
  if (!Array.isArray(p.retired)) p.retired = [];
  if (p.comparability === undefined) p.comparability = { comparableWith: [] };
  p.protocolHash = protocolHashOf(p);
  const v = validateProtocol(p);
  if (!v.ok) return { ok: false, errors: v.errors, protocol: null };
  return { ok: true, errors: [], protocol: deepFreeze(p) };
}

// ---------------------------------------------------------------- versioned diff

function flatten(v, prefix, out) {
  if (Array.isArray(v) || !isPlainObject(v)) { out[prefix] = digestOf(v === undefined ? null : v) + ':' + JSON.stringify(v ?? null).slice(0, 200); return; }
  for (const k of Object.keys(v).sort()) flatten(v[k], prefix ? `${prefix}.${k}` : k, out);
}

/** Field-level diff of two protocols' hashed content. Empty `changes` means identical content. */
export function diffProtocols(a, b) {
  const fa = {}; const fb = {};
  for (const f of HASHED) { flatten(a?.[f], f, fa); flatten(b?.[f], f, fb); }
  const paths = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].sort();
  const changes = [];
  for (const path of paths) if (fa[path] !== fb[path]) changes.push({ path, change: !(path in fa) ? 'added' : !(path in fb) ? 'removed' : 'modified' });
  return { from: a?.protocolHash || null, to: b?.protocolHash || null, changes, identical: changes.length === 0 };
}

// Fields that define the measurement. Once a result exists they can never be
// edited in place, only superseded by a new protocol and a new measurement.
const MEASUREMENT_DEFINING = ['thresholds', 'matching', 'scope', 'limits', 'targets', 'originalTargetIds', 'retired', 'splits', 'engine', 'measurement', 'tools', 'models', 'datasetLicenses', 'grouping'];

/**
 * Amend a frozen protocol BEFORE any result was observed for it. The result is a
 * new versioned protocol that names what it supersedes, carries the field diff,
 * and is comparable with nothing earlier. A removed target must be disclosed as
 * retired with a reason; it stays in `originalTargetIds`.
 *
 * `observedResults` is the list of result records known to the caller. If any is
 * bound to this protocol's hash the amendment is refused with POST_RESULT_CHANGE:
 * a threshold, matching rule or denominator cannot move once results exist. The
 * only route forward is `deriveSuccessorProtocol`, which needs a fresh sealed set.
 */
export function amendProtocol(frozen, patch, { observedResults = [], reason } = {}) {
  const base = validateProtocol(frozen);
  if (!base.ok) return { ok: false, errors: base.errors, protocol: null, diff: null };
  const bound = (observedResults || []).filter((r) => r && r.protocolHash === frozen.protocolHash);
  if (bound.length > 0) {
    return {
      ok: false, protocol: null, diff: null,
      errors: [{ code: 'POST_RESULT_CHANGE', path: '', message: `${bound.length} result(s) already exist for protocol ${frozen.protocolHash}; its thresholds, matching rules, scope and denominator cannot change in place` }],
    };
  }
  if (!reason || typeof reason !== 'string') return { ok: false, protocol: null, diff: null, errors: [{ code: 'MISSING_FIELD', path: 'reason', message: 'an amendment must state its reason' }] };
  const next = clone(frozen);
  for (const [k, v] of Object.entries(patch || {})) {
    if (!MEASUREMENT_DEFINING.includes(k)) return { ok: false, protocol: null, diff: null, errors: [{ code: 'UNKNOWN_FIELD', path: k, message: `'${k}' is not an amendable protocol field` }] };
    next[k] = clone(v);
  }
  // Removed targets are retired, never dropped.
  const keep = new Set((next.targets || []).map((t) => t.id));
  const retired = Array.isArray(next.retired) ? next.retired : [];
  const known = new Set(retired.map((r) => r.id));
  for (const t of frozen.targets) if (!keep.has(t.id) && !known.has(t.id)) retired.push({ id: t.id, reason: `removed by amendment: ${reason}`, retiredInVersion: frozen.protocolVersion + 1 });
  next.retired = retired;
  next.protocolVersion = frozen.protocolVersion + 1;
  next.supersedes = frozen.protocolHash;
  next.comparability = { comparableWith: [], invalidates: [frozen.protocolHash], reason };
  next.protocolHash = protocolHashOf(next);
  const v = validateProtocol(next);
  if (!v.ok) return { ok: false, errors: v.errors, protocol: null, diff: null };
  return { ok: true, errors: [], protocol: deepFreeze(next), diff: diffProtocols(frozen, next) };
}

/**
 * After results exist, the only legal change is a SUCCESSOR protocol with a new
 * measurement. Its sealed set must not overlap any sealed target already
 * consumed by an observed result, so a consumed holdout is never reused.
 */
export function deriveSuccessorProtocol(frozen, draft, { observedResults = [], consumedSealedIds = [] } = {}) {
  const consumed = new Set(consumedSealedIds);
  for (const r of observedResults || []) for (const id of r?.sealedTargetIds || []) consumed.add(id);
  if (consumed.size === 0 && (observedResults || []).some((r) => r?.protocolHash === frozen?.protocolHash)) {
    for (const id of frozen.splits.sealed) consumed.add(id);
  }
  const reused = (draft?.splits?.sealed || []).filter((id) => consumed.has(id));
  if (reused.length) {
    return { ok: false, protocol: null, errors: [{ code: 'SEALED_REUSE', path: 'splits.sealed', message: `sealed target(s) ${reused.join(', ')} were already consumed by an observed result; a successor needs a fresh sealed population` }] };
  }
  const r = freezeProtocol({
    ...draft,
    protocolVersion: (frozen?.protocolVersion || 0) + 1,
    supersedes: frozen?.protocolHash || null,
    comparability: { comparableWith: [], invalidates: [frozen?.protocolHash].filter(Boolean), reason: 'successor protocol with a new measurement' },
  });
  return { ...r, diff: r.ok ? diffProtocols(frozen, r.protocol) : null };
}

/**
 * Does a result or run record belong to this exact protocol? A record produced
 * under any other hash (or under a hash that no longer matches the protocol's
 * content) is rejected: it cannot be re-scored under changed rules.
 */
export function assertBoundToProtocol(record, protocol) {
  const v = validateProtocol(protocol);
  if (!v.ok) return { ok: false, errors: v.errors };
  if (!record || record.protocolHash !== protocol.protocolHash) {
    return { ok: false, errors: [{ code: 'PROTOCOL_MISMATCH', path: 'protocolHash', message: `record is bound to ${record?.protocolHash || 'no protocol'}, not ${protocol.protocolHash}` }] };
  }
  return { ok: true, errors: [] };
}
