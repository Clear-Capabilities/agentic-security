export const FINDING_PROVENANCE_SCHEMA_VERSION = '1.0';

export const PROVENANCE_STATUS = Object.freeze({
  COMPLETE: 'complete',
  PARTIAL: 'partial',
  NOT_AVAILABLE: 'not_available',
  UNCOMMITTED: 'uncommitted',
  BUDGET_EXHAUSTED: 'budget_exhausted',
  ERROR: 'error',
});

export const PROVENANCE_METHOD = Object.freeze({
  SEMANTIC_REPLAY: 'semantic-history-replay',
  DEPENDENCY_GRAPH_DIFF: 'dependency-graph-diff',
  LINE_ATTRIBUTION: 'line-attribution',
  SCAN_HISTORY: 'scan-history',
  NONE: 'none',
});

export const CONFIDENCE_LEVEL = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'unknown' });

export const EVIDENCE_ROLE = Object.freeze({
  SOURCE: 'source', SINK: 'sink', GUARD: 'guard', REMOVED_GUARD: 'removed_guard',
  TRANSFORMATION: 'transformation', CONFIG: 'config', SECRET: 'secret',
  MANIFEST: 'manifest', LOCKFILE: 'lockfile', OTHER: 'other',
});

// M3: the AGE_BASIS enum, re-added now that M2 shipped its two consumers
// (mttr.js's ageBasis field, fix-history.js's provenanceAtFix.ageBasis) —
// both previously used bare string literals matching this vocabulary
// without importing a shared source of truth for it.
export const AGE_BASIS = Object.freeze({
  FINDING_ORIGIN: 'finding_origin',
  EARLIEST_OBSERVABLE: 'earliest_observable',
  FIRST_OBSERVED: 'first_observed',
  UNCOMMITTED: 'uncommitted',
});

// The `['complete', 'uncommitted']` "provenance is healthy enough to trust"
// check independently exists in THREE places today (bin/agentic-security.js's
// --require-provenance block, pipeline/assurance-mode.js's strict check, and
// mttr.js's/fix-history.js's own ageBasis tiering all re-derive the same
// status set locally). One shared predicate, so a future change to what
// counts as "healthy" is a one-line edit, not a grep-and-fix-N-places.
export function isProvenanceHealthy(findingProvenance) {
  return ['complete', 'uncommitted'].includes(findingProvenance?.status);
}

export function emptyProvenance(status, extra = {}) {
  return {
    schemaVersion: FINDING_PROVENANCE_SCHEMA_VERSION,
    status,
    findingOrigin: null,
    branchIntroduction: null,
    firstObserved: null,
    evidenceAttribution: [],
    method: PROVENANCE_METHOD.NONE,
    confidence: { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons: [] },
    historyCoverage: { complete: false, shallow: false, boundaryCommit: null, commitsConsidered: 0 },
    analysisBasis: { head: null, ruleset: null, detector: null, dirty: false },
    limitations: [],
    evidenceDigest: null,
    ...extra,
  };
}

export function redactFindingProvenance(fp, { includeEmail = false } = {}) {
  if (!fp) return null;
  const redactOrigin = (origin) => origin ? { ...origin, authorEmail: includeEmail ? origin.authorEmail : null } : null;
  return {
    ...fp,
    findingOrigin: redactOrigin(fp.findingOrigin),
  };
}
