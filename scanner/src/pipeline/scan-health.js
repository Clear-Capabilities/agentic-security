// Scan health (assurance-hardening PRD, Milestone 0, FR-206).
//
// PRD principle: "Separate 'no findings' from 'analysis complete'." Before
// this module, a scan that hit an annotator exception, timed out on files, or
// silently downgraded deep-analysis mode reported the same shape as a clean
// complete scan — the only signals (`annotatorErrors`, `_scanMeta.filesTimedOut`)
// existed on the result object already, but nothing summarized them into a
// single status a caller could gate on or a human could read as a headline.
//
// This is additive-only (Milestone 0 scope): computeScanHealth() is a pure
// function over signals the engine already collects, and its output is a new
// field on the scan result. No existing gate, exit code, or CLI behavior
// changes when this field is added.
//
// `analyzers` (PRD section 10.3) went from a hardcoded `null` to a real,
// computed summary once FR-201 (every detector call site isolated,
// {file,analyzer,err} captured), FR-202 (real preemptive deadlines, a
// _timeout:true marker per killed file), and FR-203 (pipeline/
// coverage-ledger.js, the actual per-file x per-analyzer status
// computation) all existed for it to be computed FROM — reporting it
// before then would have looked more precise than the underlying analysis
// supported, which is exactly the failure mode this module exists to
// prevent (see this file's own header history in git blame for that
// reasoning, kept as a decision record even though the gap it names is
// now closed).

export const SCAN_HEALTH_SCHEMA_VERSION = 1;

/**
 * @param {object} input
 * @param {object|null} input.scanMeta - engine's `_scanMeta` (filesScanned, filesSkipped,
 *   filesDenseSkipped, filesTimedOut, checkpoint, ...).
 * @param {Array<{phase:string, err:string}>} input.annotatorErrors
 * @param {object} [input.engineErrors] - e.g. { cppDataflowParseErrors }
 * @param {object} [input.deepStatus] - { requested, enabled, inCi, ciOverrideAllowed, reason, failure }
 * @param {object} [input.analyzerCoverage] - coverage-ledger.js's
 *   summarizeCoverageForScanHealth() output: {expected, completed, failed,
 *   timedOut, skippedByPolicy}. Omitted (not just empty) is treated the
 *   same as the old `null` — a caller that hasn't wired FR-203's ledger in
 *   yet (e.g. a hand-built scan object in a test) gets `analyzers: null`,
 *   never a fabricated all-zero summary.
 * @returns {object} scanHealth per PRD §10.3, additive fields only.
 */
export function computeScanHealth({ scanMeta = null, annotatorErrors = [], engineErrors = null, deepStatus = null, analyzerCoverage = null } = {}) {
  const conditions = [];
  const safeAnnotatorErrors = Array.isArray(annotatorErrors) ? annotatorErrors : [];
  const filesTimedOut = Number(scanMeta?.filesTimedOut) || 0;

  if (safeAnnotatorErrors.length > 0) {
    conditions.push(`${safeAnnotatorErrors.length} annotator(s) threw and were skipped: ${
      [...new Set(safeAnnotatorErrors.map(e => e.phase))].join(', ')
    }`);
  }
  if (filesTimedOut > 0) {
    conditions.push(`${filesTimedOut} file(s) exceeded the per-file analysis timeout`);
  }
  if (engineErrors?.cppDataflowParseErrors > 0) {
    conditions.push(`${engineErrors.cppDataflowParseErrors} C/C++ dataflow parse error(s)`);
  }
  if (deepStatus?.failure) {
    conditions.push(`deep analysis (IR-taint) threw and fell back to pattern-only results: ${deepStatus.failure}`);
  }
  if (deepStatus?.requested && !deepStatus.enabled) {
    conditions.push(`deep analysis was requested but did not run: ${deepStatus.reason || 'unknown reason'}`);
  }
  // FR-203: a detector that threw on at least one file (captured via
  // FR-201's runDetector isolation) is a real analysis gap distinct from
  // an ANNOTATOR error above — annotators run post-detection over the
  // whole finding set; detectors run per-file and produce the findings
  // themselves, so a failed detector can mean a real vulnerability was
  // never even looked for. This condition did not exist before FR-203's
  // ledger made "which analyzer, how many files" computable.
  if (analyzerCoverage && analyzerCoverage.failed > 0) {
    conditions.push(`${analyzerCoverage.failed} analyzer(s) threw on at least one file`);
  }

  const status = conditions.length > 0 ? 'partial' : 'complete';

  return {
    schemaVersion: SCAN_HEALTH_SCHEMA_VERSION,
    status,
    files: {
      expected: scanMeta?.checkpoint?.total ?? null,
      scanned: scanMeta?.filesScanned ?? null,
      skipped: (Number(scanMeta?.filesSkipped) || 0) + (Number(scanMeta?.filesDenseSkipped) || 0),
      timedOut: filesTimedOut,
    },
    analyzers: analyzerCoverage || null,
    deepAnalysis: deepStatus
      ? {
          requested: !!deepStatus.requested,
          enabled: !!deepStatus.enabled,
          inCi: !!deepStatus.inCi,
          ciOverrideAllowed: !!deepStatus.ciOverrideAllowed,
          reason: deepStatus.reason ?? null,
          failure: deepStatus.failure ?? null,
        }
      : null,
    annotatorErrorCount: safeAnnotatorErrors.length,
    freshness: null,
    conditions,
  };
}

// FR-207 ("Add freshness checks for vulnerability feeds, calibration data,
// rulesets, and policies — stale dependencies are visible and can fail
// strict policy"). Deliberately NOT folded into computeScanHealth() itself:
// the five freshness signals (KEV, EPSS, calibration, custom rules,
// compliance evidence) are computed in two different places at two
// different times relative to computeScanHealth's own call site —
// engine.js has kev/epss/calibration/compliance available before it builds
// scanHealth, but the custom-rules pattern-DSL only runs in
// bin/agentic-security.js, AFTER scanHealth already exists on the scan
// object. A single merge/condition/status function usable from both call
// sites (once up front, once as a later patch) is simpler and less
// duplicative than threading a partial value through computeScanHealth
// twice. Each leg is additive: a leg not present in `freshnessPartial`
// leaves scanHealth's existing `freshness` object and conditions
// untouched, exactly like every other optional input this module accepts.
const FRESHNESS_CONDITION_BUILDERS = {
  kev: (f) => (f?.stale === true) ? `KEV catalog is stale (${f.ageDays} day(s) old) — recently-added CVEs may not be reflected` : null,
  epss: (f) => (f?.stale === true) ? `EPSS exploit-probability data is stale (${f.ageDays} day(s) old)` : null,
  calibration: (f) => (f?.stale === true) ? `calibration data is stale (${f.ageDays} day(s) old${f.generatedAt ? `, last generated ${f.generatedAt}` : ''})` : null,
  customRules: (f) => (f?.stale === true) ? `${f.staleFiles.length} custom rule file(s) exceed their configured review interval` : null,
  compliance: (f) => (Number(f?.stale) > 0) ? `${f.stale} compliance control(s) have stale evidence` : null,
};

export function applyFreshness(scanHealth, freshnessPartial) {
  if (!scanHealth || !freshnessPartial) return scanHealth;
  const freshness = { ...(scanHealth.freshness || {}), ...freshnessPartial };
  const newConditions = [];
  for (const [key, value] of Object.entries(freshnessPartial)) {
    const build = FRESHNESS_CONDITION_BUILDERS[key];
    const msg = build ? build(value) : null;
    if (msg) newConditions.push(msg);
  }
  if (!newConditions.length) return { ...scanHealth, freshness };
  return {
    ...scanHealth,
    freshness,
    conditions: [...scanHealth.conditions, ...newConditions],
    status: scanHealth.status === 'complete' ? 'partial' : scanHealth.status,
  };
}
