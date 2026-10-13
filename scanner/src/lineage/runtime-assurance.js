// runtime-assurance.js — PRD "Runtime-Corroborated Security Twin" P0-8
// (Runtime Assurance). A pure aggregation over already-loaded observation
// imports and an already-computed `correlateObservations` result — never
// re-reads a file, never re-runs the match ladder. Honest by construction:
// the one rule this module exists to enforce is that a MISSING or STALE
// telemetry source can never collapse into "no runtime risk" — the
// `runtimeStatus` field is always exactly one of `'complete'`, `'partial'`,
// or `'unavailable'`, and `'unavailable'` is the answer whenever no
// observation store was consulted at all, never a silent empty report.
//
// `parseFailures` is always reported as 0, with an explicit note why:
// `dataflow observations import` REFUSES the whole import the moment any
// record fails to parse or validate (AC-29 clause 5) — a failed import is
// never persisted, so there is no on-disk history of parse failures for
// this module to read. This is a real, disclosed limitation, not a false
// "zero failures ever happened" claim.

export const RUNTIME_STATUS_VALUES = Object.freeze(['complete', 'partial', 'unavailable']);

function _isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _maxIso(list) {
  let best = null;
  let bestT = -Infinity;
  for (const s of list) {
    const t = Date.parse(s);
    if (Number.isFinite(t) && t > bestT) { bestT = t; best = s; }
  }
  return best;
}

function _minIso(list) {
  let best = null;
  let bestT = Infinity;
  for (const s of list) {
    const t = Date.parse(s);
    if (Number.isFinite(t) && t < bestT) { bestT = t; best = s; }
  }
  return best;
}

/**
 * `computeRuntimeAssurance(opts) -> RuntimeAssurance`
 *
 * `opts`:
 *   - `importRecords`: the `ObservationImport[]` read back from the store
 *     (`loadObservationImports`), or `null`/`undefined` when the store was
 *     never consulted at all (mirrors `correlateObservations`'s own
 *     `observations === null` convention).
 *   - `correlation`: the `CorrelationResult` from `correlateObservations`
 *     for the SAME graph/observations/window this call is reporting on.
 *   - `now`: an ISO-8601 string (defaults to `new Date().toISOString()`,
 *     injectable for deterministic tests).
 *   - `staleAfterHours`: how old the most recent observed event can be
 *     before freshness is reported stale (default 24 * 30 = 720, i.e. 30
 *     days — telemetry windows in this package's own fixtures/CLI default
 *     to month-long exports, so a 30-day staleness bar is the honest
 *     "this is still describing roughly the current system" line, not an
 *     arbitrary short window).
 *
 * Never throws.
 */
export function computeRuntimeAssurance(opts) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const now = typeof o.now === 'string' && Number.isFinite(Date.parse(o.now)) ? o.now : new Date().toISOString();
  const staleAfterHours = Number.isFinite(o.staleAfterHours) ? o.staleAfterHours : 720;

  const importRecords = Array.isArray(o.importRecords) ? o.importRecords : null;
  const correlation = _isPlainObject(o.correlation) ? o.correlation : null;

  const base = {
    runtimeStatus: 'unavailable',
    telemetryWindow: { start: null, end: null },
    freshness: { lastObservedAt: null, lastImportedAt: null, staleHours: null, stale: true },
    parseFailures: 0,
    parseFailuresNote: 'A failed import is refused in full and never persisted (AC-29 clause 5) — '
      + 'this count reflects the import store, not the history of every attempt. Check `runtime ingest`\'s '
      + 'own exit code/stderr at import time for parse failures.',
    mappingPercentage: null,
    unmatchedObservationCount: 0,
    totalObservationCount: 0,
    missingTelemetry: true,
    limitations: [],
  };

  // No store was ever consulted — the honest 'unavailable' case, never a
  // fabricated empty-but-fine report.
  if (importRecords === null || importRecords.length === 0 || !correlation || correlation.evaluated !== true) {
    base.limitations.push(
      'No runtime observation import exists for this scan — runtimeStatus is \'unavailable\', never \'complete\' '
      + 'or a silent absence of risk. Import telemetry with `runtime ingest` before relying on this report.',
    );
    return base;
  }

  const windowStart = _minIso(importRecords.map((r) => r?.windowStart));
  const windowEnd = _maxIso(importRecords.map((r) => r?.windowEnd));
  base.telemetryWindow = { start: windowStart, end: windowEnd };
  base.missingTelemetry = false;

  const allObservations = importRecords.flatMap((r) => (Array.isArray(r?.observations) ? r.observations : []));
  const total = allObservations.length;
  const unmatched = allObservations.filter((obs) => obs && obs.matchMethod === 'unmatched').length;
  base.totalObservationCount = total;
  base.unmatchedObservationCount = unmatched;
  base.mappingPercentage = total > 0 ? Math.round(((total - unmatched) / total) * 10000) / 100 : null;

  const lastObservedAt = _maxIso(allObservations.map((obs) => obs?.lastObservedAt));
  const lastImportedAt = _maxIso(importRecords.map((r) => r?.importedAt));
  base.freshness.lastObservedAt = lastObservedAt;
  base.freshness.lastImportedAt = lastImportedAt;
  if (lastObservedAt !== null) {
    const ageMs = Date.parse(now) - Date.parse(lastObservedAt);
    const ageHours = Math.round((ageMs / 3600000) * 100) / 100;
    base.freshness.staleHours = ageHours;
    base.freshness.stale = ageHours > staleAfterHours;
  }

  if (total === 0) {
    base.limitations.push('The import store exists but carries zero observation records.');
  }
  if (unmatched > 0) {
    base.limitations.push(`${unmatched} of ${total} imported observation(s) never matched any graph node (matchMethod 'unmatched') — these contribute no corroboration to any flow.`);
  }
  if (base.freshness.stale) {
    base.limitations.push(`The most recent observed event is ${base.freshness.staleHours} hour(s) old (beyond the ${staleAfterHours}-hour staleness bar) — this twin may no longer describe current production behavior.`);
  }

  const complete = total > 0 && unmatched === 0 && !base.freshness.stale;
  base.runtimeStatus = complete ? 'complete' : 'partial';

  return base;
}
