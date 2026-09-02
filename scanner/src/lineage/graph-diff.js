// graph-diff.js — M4 deliverable #9 (FR-503 §14, DFG-022), sub-project
// 8b, Task 1: the GraphDiff extension contract + computeGraphDiff + honest
// change-cause classification.
//
// Mirrors graph-snapshot.js's/obligation-mapping.js's/decision-story.js's
// own shape exactly: a record is explicitly NOT a DataFlowGraph v1 entity
// (§10.10 — "associated with, but not required inside, the immutable base
// graph"), never added to dataflow-graph.schema.json, never routed
// through validate.js's validateGraph(). See ids.js's diffId() for the id
// scheme.
//
// This module ONLY computes a diff between two already-persisted
// GraphSnapshot records and classifies why each removed flow disappeared,
// as far as real, checkable signals allow. It does NOT decide what a
// caller should DO with a GraphDiff (no CLI, no drift-policy matching —
// see this sub-project's own task brief: those are Tasks 2/3).
//
// ── Design judgment calls made in this file (disclosed, not hidden) ──
//
// 1. WATCHED_FLOW_FIELDS includes `governanceRefs`, not just the four
//    scalar fields the task brief names literally
//    (protectionSummary/policyVerdict/handling/coverageStatus). Read
//    directly against dataflow-graph.schema.json's own flow $def (§145 of
//    that file) and graph-builder.js's real flow-construction loop:
//    `flow.governanceRefs` is a real, populated field (coverage.js's
//    `resolveGovernanceRefs` default, keyed by
//    dataflow/privacy-governance.js's own GOVERNANCE_FIELDS —
//    purpose/lawfulBasis/subject/retention/residency/recipient/transfer/
//    minimization/consent/access/deletion), never a fabricated shape. A
//    "retention/deletion or lawful-basis change" — AC-27's own bullet
//    list — can ONLY show up as a governanceRefs difference, since none
//    of the other four watched fields carry that information at all. The
//    diff compares it value-by-value over GOVERNANCE_FIELDS (never a
//    bare object-identity/JSON-string check), emitting one changed-field
//    entry per differing governance field (`governanceRefs.<field>`), so
//    a caller learns WHICH governance fact changed, not just "something
//    in governance changed."
//
// 2. Non-flow removed entities (nodes/edges/dataElements) always get
//    causeClassification: 'application_change'. The task brief's Global
//    Constraint says the coverage-regression check applies "per removed
//    flow entry ONLY" — read literally, that leaves open what a removed
//    node/edge/dataElement gets. The same reasoning the brief gives for
//    added/changed entries applies here too ("no other real signal
//    exists... do not invent one") — a removed node/edge/dataElement has
//    no flow-level protection/policy verdict to have regressed, and this
//    module has no coverage-completeness signal scoped to a bare node or
//    edge (coverage.js's own ledger is source/sink/language-level, not
//    node/edge-level) — so 'application_change' is the only honest
//    default for those three entity kinds.
//
// 3. Change-cause classification for flows.changed entries is always
//    'application_change', per the brief's own literal instruction — a
//    CHANGED flow (same id, different watched field) can never be a
//    coverage regression by definition: coverage regression means the
//    engine stopped seeing something, and a flow whose id is still
//    present in both snapshots was, by construction, seen in both.

import { snapshotsComparable } from './graph-snapshot.js';
import { diffId } from './ids.js';
import { GOVERNANCE_FIELDS } from '../dataflow/privacy-governance.js';

const DIFF_VERSION = '1.0.0';

const ENTITY_ARRAYS = Object.freeze(['nodes', 'edges', 'dataElements', 'flows']);

// See judgment call #1 above for why `governanceRefs` is included
// alongside the brief's own literal four.
export const WATCHED_FLOW_FIELDS = Object.freeze([
  'protectionSummary', 'policyVerdict', 'handling', 'coverageStatus', 'governanceRefs',
]);

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

function _idMap(arr) {
  const m = new Map();
  for (const e of arr ?? []) {
    if (e && typeof e.id === 'string') m.set(e.id, e);
  }
  return m;
}

/** Sorted id-set diff between two id->entity Maps. Deterministic order. */
function _idSetDiff(beforeMap, afterMap) {
  const added = [];
  const removed = [];
  for (const id of afterMap.keys()) if (!beforeMap.has(id)) added.push(id);
  for (const id of beforeMap.keys()) if (!afterMap.has(id)) removed.push(id);
  added.sort();
  removed.sort();
  return { added, removed };
}

function _addedEntry(id, afterSnapshot) {
  return {
    id,
    causeClassification: 'application_change',
    firstSeen: { commit: afterSnapshot.commit, capturedAt: afterSnapshot.capturedAt },
  };
}

function _removedEntry(id, beforeSnapshot, causeClassification, extra = {}) {
  return {
    id,
    causeClassification,
    lastSeen: { commit: beforeSnapshot.commit, capturedAt: beforeSnapshot.capturedAt },
    ...extra,
  };
}

/**
 * Diffs one flow's WATCHED_FLOW_FIELDS between two snapshots of the SAME
 * flow id. Returns an array of {field, before, after} — empty when
 * nothing watched differs. Never a bare "something changed" — every
 * entry names the exact field and its real before/after value.
 */
function _diffFlowFields(before, after) {
  const changes = [];
  for (const field of WATCHED_FLOW_FIELDS) {
    if (field === 'governanceRefs') {
      const b = before.governanceRefs ?? {};
      const a = after.governanceRefs ?? {};
      for (const gField of GOVERNANCE_FIELDS) {
        const bv = b[gField] ?? null;
        const av = a[gField] ?? null;
        if (JSON.stringify(bv) !== JSON.stringify(av)) {
          changes.push({ field: `governanceRefs.${gField}`, before: bv, after: av });
        }
      }
      continue;
    }
    const bv = before[field] ?? null;
    const av = after[field] ?? null;
    if (bv !== av) changes.push({ field, before: bv, after: av });
  }
  return changes;
}

/**
 * Real, checkable coverage-completeness signals — read directly against
 * coverage.js's own buildCoverageLedger output shape: `sources.matched`,
 * `sinks.callStatementSites`, `languages[].filesAnalyzed`. Returns an
 * array of reason strings naming exactly which completeness field
 * regressed (empty when none did — never a guess in the regression
 * direction).
 */
function _coverageRegressionReasons(coverageBefore, coverageAfter) {
  const b = coverageBefore ?? {};
  const a = coverageAfter ?? {};
  const reasons = [];

  const beforeMatched = b.sources?.matched ?? 0;
  const afterMatched = a.sources?.matched ?? 0;
  if (afterMatched < beforeMatched) {
    reasons.push(`sources.matched decreased (${beforeMatched} -> ${afterMatched})`);
  }

  const beforeSites = b.sinks?.callStatementSites ?? 0;
  const afterSites = a.sinks?.callStatementSites ?? 0;
  if (afterSites < beforeSites) {
    reasons.push(`sinks.callStatementSites decreased (${beforeSites} -> ${afterSites})`);
  }

  const beforeLangs = new Map((b.languages ?? []).map((l) => [l.language, l.filesAnalyzed]));
  for (const l of a.languages ?? []) {
    const prevAnalyzed = beforeLangs.get(l.language);
    if (prevAnalyzed != null && l.filesAnalyzed < prevAnalyzed) {
      reasons.push(`languages.${l.language}.filesAnalyzed decreased (${prevAnalyzed} -> ${l.filesAnalyzed})`);
    }
  }

  return reasons;
}

/**
 * Structural validation only — mirrors graph-snapshot.js's own
 * validateGraphSnapshot {valid, errors} shape and "never throws"
 * contract. Checks the record's own top-level shape plus each
 * added/removed/changed entry's own minimal shape; never cross-references
 * a real graph (this module's validator, like every §10.10 extension
 * contract's own validator, is a pure shape check).
 */
export function validateGraphDiff(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'GraphDiff record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('diff:')) {
    err('$.id', 'id is required and must start with "diff:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.beforeSnapshotId)) err('$.beforeSnapshotId', 'beforeSnapshotId is required');
  if (!_isNonEmptyString(record.afterSnapshotId)) err('$.afterSnapshotId', 'afterSnapshotId is required');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');

  if (!_isPlainObject(record.comparability)) {
    err('$.comparability', 'comparability is required and must be an object');
  } else {
    if (typeof record.comparability.comparable !== 'boolean') {
      err('$.comparability.comparable', 'comparability.comparable must be a boolean');
    }
    if (!Array.isArray(record.comparability.reasons)) {
      err('$.comparability.reasons', 'comparability.reasons must be an array');
    }
  }

  const _checkEntryArray = (bucketPath, arr, requireFirstSeen, requireLastSeen) => {
    if (!Array.isArray(arr)) {
      err(bucketPath, `${bucketPath} must be an array`);
      return;
    }
    arr.forEach((entry, i) => {
      const p = `${bucketPath}[${i}]`;
      if (!_isPlainObject(entry)) { err(p, `${p} must be an object`); return; }
      if (!_isNonEmptyString(entry.id)) err(`${p}.id`, `${p}.id is required`);
      if (!_isNonEmptyString(entry.causeClassification)) err(`${p}.causeClassification`, `${p}.causeClassification is required`);
      if (requireFirstSeen && !_isPlainObject(entry.firstSeen)) err(`${p}.firstSeen`, `${p}.firstSeen is required and must be an object`);
      if (requireLastSeen && !_isPlainObject(entry.lastSeen)) err(`${p}.lastSeen`, `${p}.lastSeen is required and must be an object`);
    });
  };

  if (!_isPlainObject(record.added)) {
    err('$.added', 'added is required and must be an object');
  } else {
    for (const key of ENTITY_ARRAYS) _checkEntryArray(`$.added.${key}`, record.added[key], true, false);
  }

  if (!_isPlainObject(record.removed)) {
    err('$.removed', 'removed is required and must be an object');
  } else {
    for (const key of ENTITY_ARRAYS) _checkEntryArray(`$.removed.${key}`, record.removed[key], false, true);
  }

  if (!_isPlainObject(record.changed)) {
    err('$.changed', 'changed is required and must be an object');
  } else if (!Array.isArray(record.changed.flows)) {
    err('$.changed.flows', 'changed.flows must be an array');
  } else {
    record.changed.flows.forEach((entry, i) => {
      const p = `$.changed.flows[${i}]`;
      if (!_isPlainObject(entry)) { err(p, `${p} must be an object`); return; }
      if (!_isNonEmptyString(entry.id)) err(`${p}.id`, `${p}.id is required`);
      if (!_isNonEmptyString(entry.causeClassification)) err(`${p}.causeClassification`, `${p}.causeClassification is required`);
      if (!Array.isArray(entry.changes) || entry.changes.length === 0) {
        err(`${p}.changes`, `${p}.changes must be a non-empty array naming which field(s) changed`);
      }
    });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Diffs two GraphSnapshot records. Refuses (throws, naming the real
 * reasons) on an incomparable pair — never silently diffs across one.
 *
 * added/removed: an ID-set diff across nodes/edges/dataElements/flows.
 * changed: flows ONLY — every flow id present in both snapshots whose
 * WATCHED_FLOW_FIELDS differ.
 *
 * Change-cause classification: every added/changed entry gets
 * 'application_change' (no other real signal exists for those — see this
 * file's own header). Every removed FLOW entry gets
 * 'possible_coverage_regression' when the AFTER snapshot's real coverage
 * is measurably lower on a real completeness field, otherwise
 * 'application_change'; every removed node/edge/dataElement entry gets
 * 'application_change' unconditionally (see judgment call #2 above).
 */
export function computeGraphDiff(snapshotBefore, snapshotAfter) {
  const { comparable, reasons } = snapshotsComparable(snapshotBefore, snapshotAfter);
  if (!comparable) {
    throw new Error(`computeGraphDiff: snapshots are not comparable — ${reasons.join('; ')}`);
  }

  const graphBefore = snapshotBefore.graph ?? {};
  const graphAfter = snapshotAfter.graph ?? {};

  const coverageRegressionReasons = _coverageRegressionReasons(snapshotBefore.coverage, snapshotAfter.coverage);
  const flowRemovalCause = coverageRegressionReasons.length ? 'possible_coverage_regression' : 'application_change';

  const added = {};
  const removed = {};
  const flowMaps = {};

  for (const key of ENTITY_ARRAYS) {
    const beforeMap = _idMap(graphBefore[key]);
    const afterMap = _idMap(graphAfter[key]);
    if (key === 'flows') {
      flowMaps.before = beforeMap;
      flowMaps.after = afterMap;
    }

    const { added: addedIds, removed: removedIds } = _idSetDiff(beforeMap, afterMap);
    added[key] = addedIds.map((id) => _addedEntry(id, snapshotAfter));

    if (key === 'flows') {
      removed[key] = removedIds.map((id) => {
        const extra = coverageRegressionReasons.length ? { coverageRegressionReasons } : {};
        return _removedEntry(id, snapshotBefore, flowRemovalCause, extra);
      });
    } else {
      removed[key] = removedIds.map((id) => _removedEntry(id, snapshotBefore, 'application_change'));
    }
  }

  const changedFlows = [];
  for (const [id, beforeFlow] of flowMaps.before) {
    const afterFlow = flowMaps.after.get(id);
    if (!afterFlow) continue; // removed — already handled above
    const changes = _diffFlowFields(beforeFlow, afterFlow);
    if (changes.length > 0) {
      changedFlows.push({ id, causeClassification: 'application_change', changes });
    }
  }
  changedFlows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const record = {
    id: diffId({ beforeSnapshotId: snapshotBefore.id, afterSnapshotId: snapshotAfter.id }),
    version: DIFF_VERSION,
    beforeSnapshotId: snapshotBefore.id,
    afterSnapshotId: snapshotAfter.id,
    comparability: { comparable: true, reasons: [] },
    added,
    removed,
    changed: { flows: changedFlows },
    generatedAt: new Date().toISOString(),
  };

  const { valid, errors } = validateGraphDiff(record);
  if (!valid) {
    throw new Error(`computeGraphDiff: internal error — produced an invalid GraphDiff: ${JSON.stringify(errors)}`);
  }
  return record;
}
