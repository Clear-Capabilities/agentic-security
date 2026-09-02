export const id = 1920;
export const ids = [1920,2238];
export const modules = {

/***/ 2238:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   I3: () => (/* binding */ recordFixAttempt),
/* harmony export */   fixDurationReport: () => (/* binding */ fixDurationReport),
/* harmony export */   renderFixDurationSummary: () => (/* binding */ renderFixDurationSummary),
/* harmony export */   sU: () => (/* binding */ loadFixAttempts)
/* harmony export */ });
/* unused harmony exports FIX_STAGES, bucketOf, summarizeFixDurations, _internals, summarizeFixAxes, renderFixAxes */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1174);
// Time-to-validated-fix (R5, the reporting half).
//
// `verifyFix` already RUNS the stages and `test-runner.js` already times the
// slowest one. What did not exist was anything durable to read afterwards, so
// "how long does a fix actually take to validate" had no answer from real runs
// — only an estimate (`time-to-fix.js` guesses engineering hours from family
// and patch shape, before anything runs). This module is the opposite: it
// records what the pipeline observed and reports the distribution.
//
// THE HONESTY RULES, which are most of why this file is longer than a mean:
//
//  1. A failed attempt is NOT a data point about how long a fix takes. Fixes
//     that fail verification fail fast (a re-scan that still sees the finding
//     never reaches the test suite), so blending them into one average makes
//     the pipeline look faster the worse it performs. Validated and failed
//     attempts are summarised separately and never merged.
//
//  2. "Tests skipped" is not "tests passed". A project with no detectable
//     suite can reach `ok:true` having run only the re-scan and the linter.
//     That is a weaker claim than a fix whose suite executed, and it is also
//     much faster, so counting the two together would quietly deflate the
//     headline. They get their own bucket: `validated` means the suite ran and
//     passed, `validatedWithoutTests` means there was no suite to run.
//
//  3. Every figure carries its `n`, and a percentile computed from too few
//     samples is labelled unreliable rather than omitted or silently reported.
//     Same precedent as the accuracy scorecard's `{n, d}` rates: a number
//     without its denominator is not a measurement.
//
// Storage is append-only JSONL at `<scanRoot>/.agentic-security/fix-metrics.jsonl`,
// one record per verification attempt. Nothing here throws (posture
// convention) — an unwritable or corrupt log degrades to "no metrics", never
// to a failed verification.





const LOG_FILE = 'fix-metrics.jsonl';

// Below this many samples a percentile is an artifact of the sample, not a
// property of the pipeline. Reported anyway (hiding it invites re-deriving it
// wrong downstream) but flagged, so a caller cannot quote it as settled.
const RELIABLE_N = 10;

// The stages verifyFix runs, in execution order. Kept here so the recorder and
// the summariser cannot drift apart on stage naming.
const FIX_STAGES = Object.freeze(['rescan', 'lint', 'tests', 'honesty', 'poc']);

function _logPath(scanRoot) {
  return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, LOG_FILE);
}

/**
 * Append one verification attempt. Best-effort and silent on failure: metrics
 * must never be able to fail a fix that otherwise verified.
 *
 * @returns {boolean} whether the record was written (for tests, not callers).
 */
function recordFixAttempt(scanRoot, record) {
  if (!scanRoot || !record || typeof record !== 'object') return false;
  try {
    const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .stateDir */ .Pn)(scanRoot);
    if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.isSafeStateDir)(dir)) return false;
    if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.stateWritesEnabled)()) return false;
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dir, { recursive: true });
    // One writeSync of one newline-terminated line: a concurrent reader sees
    // whole records or nothing, and a torn tail is dropped on read.
    node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(_logPath(scanRoot), JSON.stringify(record) + '\n', 'utf8');
    return true;
  } catch { return false; }
}

/**
 * Read every well-formed attempt. A line that does not parse is skipped, not
 * fatal — the last line of an interrupted write is the expected case.
 */
function loadFixAttempts(scanRoot) {
  try {
    const raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(_logPath(scanRoot), 'utf8');
    const out = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        if (rec && typeof rec === 'object' && typeof rec.totalMs === 'number') out.push(rec);
      } catch { /* torn or hand-edited line — drop it, keep the rest */ }
    }
    return out;
  } catch { return []; }
}

// Nearest-rank percentile over an ascending array. Nearest-rank rather than
// interpolated because these are observed durations, and an interpolated p50
// reports a duration that no run actually took.
function _pct(sorted, p) {
  if (!sorted.length) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

function _dist(values) {
  const v = values.filter(x => typeof x === 'number' && Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (!v.length) return { n: 0, minMs: null, p50Ms: null, p90Ms: null, maxMs: null, meanMs: null, reliable: false };
  const sum = v.reduce((a, b) => a + b, 0);
  return {
    n: v.length,
    minMs: v[0],
    p50Ms: _pct(v, 50),
    p90Ms: _pct(v, 90),
    maxMs: v[v.length - 1],
    meanMs: Math.round(sum / v.length),
    // Says whether the percentiles above may be quoted, not whether the count
    // is real. n and min/max/mean are exact at any sample size.
    reliable: v.length >= RELIABLE_N,
  };
}

// Which bucket an attempt belongs to. Deliberately total: every attempt lands
// in exactly one, so the bucket counts always sum to the attempt count and a
// mis-shaped record cannot silently vanish from the denominator.
function bucketOf(a) {
  if (!a?.ok) return 'failed';
  return a.testsRan ? 'validated' : 'validatedWithoutTests';
}

/**
 * Summarise a set of attempts into the reported distribution.
 *
 * `validated` is the headline: attempts that verified AND whose test suite
 * actually ran and passed. The other two buckets exist so that headline cannot
 * be inflated by counting weaker or faster outcomes inside it.
 */
function summarizeFixDurations(attempts) {
  const all = Array.isArray(attempts) ? attempts : [];
  const buckets = { validated: [], validatedWithoutTests: [], failed: [] };
  for (const a of all) buckets[bucketOf(a)].push(a);

  const byStage = {};
  for (const stage of FIX_STAGES) {
    // Per-stage timings come from validated runs only. A stage's duration in a
    // failed run is truncated by the failure (the pipeline stops), so mixing
    // them in would understate every stage after the first failure point.
    byStage[stage] = _dist(buckets.validated.map(a => a?.stages?.[stage]));
  }

  return {
    attempts: all.length,
    counts: {
      validated: buckets.validated.length,
      validatedWithoutTests: buckets.validatedWithoutTests.length,
      failed: buckets.failed.length,
    },
    timeToValidatedFix: _dist(buckets.validated.map(a => a.totalMs)),
    timeToValidatedFixWithoutTests: _dist(buckets.validatedWithoutTests.map(a => a.totalMs)),
    timeToFailure: _dist(buckets.failed.map(a => a.totalMs)),
    byStage,
    reliableAtOrAbove: RELIABLE_N,
  };
}

/** Read + summarise in one step. */
function fixDurationReport(scanRoot) {
  return summarizeFixDurations(loadFixAttempts(scanRoot));
}

function _ms(v) {
  if (v == null) return '—';
  return v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms`;
}

/**
 * One-paragraph human summary. Returns null when there is nothing measured —
 * callers print nothing rather than printing an empty table.
 */
function renderFixDurationSummary(sum) {
  if (!sum || !sum.attempts) return null;
  const d = sum.timeToValidatedFix;
  const parts = [];
  if (d.n) {
    parts.push(
      `time-to-validated-fix: median ${_ms(d.p50Ms)}, p90 ${_ms(d.p90Ms)} `
      + `(n=${d.n}${d.reliable ? '' : `, below ${sum.reliableAtOrAbove} — percentiles not yet reliable`})`,
    );
  } else {
    parts.push('time-to-validated-fix: no fix has both verified and had its test suite run yet');
  }
  if (sum.counts.validatedWithoutTests) {
    parts.push(`${sum.counts.validatedWithoutTests} verified with no detectable test suite (excluded from the median above)`);
  }
  if (sum.counts.failed) {
    parts.push(`${sum.counts.failed} failed verification, median ${_ms(sum.timeToFailure.p50Ms)} (counted separately)`);
  }
  return parts.join('; ') + '.';
}

const _internals = { _dist, _pct, RELIABLE_N };


// ── PRD F6.1 — score fixes on THREE AXES, not one ──────────────────────────
//
// The three axes the PRD names:
//   (a) does the finding disappear      — the rescan leg
//   (b) does the project's own suite pass — the tests leg
//   (c) does an independent verifier agree — the PoC re-check leg
//
// All three were already computed by verifyFixCore and then collapsed into one
// boolean, which is the problem: **(a) alone is satisfiable by deleting code.**
// A patch that removes the vulnerable function passes the rescan, has nothing
// left to fail, and — on a project with no detectable test suite — reaches
// ok:true having proven only that the detector went quiet.
//
// Reporting the axes separately makes that visible. `aOnly` is the number that
// matters most and the one nobody was publishing: attempts that satisfied ONLY
// the disappearance axis. A high aOnly with a high headline is the shape of a
// remediation feature that is deleting code and calling it a fix.
function summarizeFixAxes(attempts) {
  const list = Array.isArray(attempts) ? attempts.filter(Boolean) : [];
  const d = list.length;

  const rate = (pred) => ({ n: list.filter(pred).length, d });

  // Each axis is judged INDEPENDENTLY of the overall verdict, so a leg that
  // passed inside a failed attempt still counts for its own axis. Reading them
  // off `ok` would make the three axes three copies of the same number.
  const findingDisappeared = rate((a) => a.rescanOk === true || (a.ok === true && a.rescanOk !== false));
  const testsStillPass = rate((a) => a.testsRan === true && a.testsOk !== false);
  const verifierAgrees = rate((a) => a.pocOk === true);

  const satisfiesAll = rate((a) =>
    (a.rescanOk === true || (a.ok === true && a.rescanOk !== false))
    && a.testsRan === true && a.testsOk !== false
    && a.pocOk === true);

  // The honesty number: disappearance WITHOUT either corroborating axis.
  const aOnly = rate((a) => {
    const disappeared = a.rescanOk === true || (a.ok === true && a.rescanOk !== false);
    const corroborated = (a.testsRan === true && a.testsOk !== false) || a.pocOk === true;
    return disappeared && !corroborated;
  });

  return {
    total: d,
    findingDisappeared,
    testsStillPass,
    verifierAgrees,
    satisfiesAll,
    aOnly,
    meaning:
      'findingDisappeared = the detector went quiet; testsStillPass = the project suite ran AND passed; '
      + 'verifierAgrees = an independent PoC re-check confirmed the hole is shut. '
      + 'aOnly counts attempts that satisfied ONLY disappearance — the shape a code-deleting "fix" produces.',
    caveat: d === 0
      ? 'no attempts recorded; every rate is 0/0 and means nothing'
      : 'rates carry {n,d}; a small d is indicative, not settled',
  };
}

/** Markdown for a report. Denominators always attached. */
function renderFixAxes(sum) {
  if (!sum || !sum.total) return '_No fix attempts recorded._\n';
  const row = (label, r, note) => `| ${label} | ${r.n}/${r.d} | ${note} |`;
  return [
    '| Axis | Rate | Meaning |',
    '|---|---|---|',
    row('(a) finding disappeared', sum.findingDisappeared, 'the detector went quiet'),
    row('(b) project tests pass', sum.testsStillPass, 'the suite RAN and passed'),
    row('(c) verifier agrees', sum.verifierAgrees, 'an independent PoC re-check confirmed it'),
    row('all three', sum.satisfiesAll, 'the only row that means "fixed"'),
    row('(a) ALONE', sum.aOnly, 'satisfiable by deleting code — watch this number'),
    '',
  ].join('\n');
}


/***/ }),

/***/ 1920:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   productionFeedbackReport: () => (/* binding */ productionFeedbackReport),
/* harmony export */   renderProductionFeedbackSummary: () => (/* binding */ renderProductionFeedbackSummary)
/* harmony export */ });
/* unused harmony exports CATEGORIES, collectFeedbackEvents, summarizeFeedbackTrend, _internals */
/* harmony import */ var _suppressions_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(9277);
/* harmony import */ var _triage_memory_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1905);
/* harmony import */ var _sca_policy_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(123);
/* harmony import */ var _fix_history_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(4407);
/* harmony import */ var _fix_metrics_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(2238);
// FR-907 (assurance-hardening PRD): "Add longitudinal production feedback
// measurement | Metrics separate user suppression, accepted risk, invalid
// finding, fixed finding, and verification outcome."
//
// Read-only aggregation over 5 ALREADY-BUILT, separate mechanisms — this
// module invents no new storage of its own, only a unified view:
//
//   user-suppression     -> triage-memory.jsonl (decision:'wont-fix'),
//                            accepted.json (vibecoder soft-accept, dated),
//                            suppressions.yml (pro exception, undated)
//   invalid-finding       -> triage-memory.jsonl (decision:'false-positive')
//   accepted-risk         -> sca-policy.yml's accept-risk[] (undated snapshot
//                            — the policy file has no per-entry creation
//                            timestamp, only an optional future `expires`)
//   fixed-finding          -> fix-history/log.json (dated via `appliedAt`,
//                            status-tagged: applied/pending/reverted/failed)
//   verification-outcome  -> fix-metrics.jsonl (dated via `at`, ok-tagged)
//
// "Longitudinal" means: every event that HAS a real timestamp is usable in
// a time-bucketed trend; every event that does NOT (accept-risk entries,
// pro suppressions — neither schema records when the entry was added) is
// still counted in its category total but reported separately as
// "undated" rather than silently smeared across the time window or
// silently dropped. Same disclosed-gap discipline this codebase already
// uses elsewhere (privacy-framework.js's engine-gap bucket, accuracy-
// scorecard.js's excluded-from-denominator entries) — a number without
// its caveat is not a measurement.
//
// Never throws (posture convention): each of the 5 reads is wrapped
// independently, so a missing or malformed source degrades only that ONE
// category to empty, never blocks the other four. Every underlying reader
// (loadSoftAccepted, loadProSuppressions, loadMemory, loadScaPolicy,
// readLog, loadFixAttempts) already degrades gracefully on its own; the
// wrapping here is defense in depth against a reader whose contract
// changes later, not a claim that today's readers can throw.







const MS_PER_DAY = 86400000;

// The 5 categories named verbatim in FR-907's own acceptance criterion.
const CATEGORIES = Object.freeze([
  'user-suppression', 'accepted-risk', 'invalid-finding', 'fixed-finding', 'verification-outcome',
]);

function _safe(fn) {
  try { return fn(); } catch { return []; }
}

/**
 * One unified event per underlying record, tagged with which of the 5
 * PRD-named categories it belongs to. `at` is an ISO timestamp or null
 * when the source schema has no per-entry creation date. `raw` keeps the
 * original record for drill-down — never re-derived from the unified
 * shape, so nothing is lost in translation.
 */
function collectFeedbackEvents(scanRoot) {
  const events = [];

  for (const e of _safe(() => (0,_suppressions_js__WEBPACK_IMPORTED_MODULE_0__/* .loadSoftAccepted */ .gv)(scanRoot))) {
    events.push({
      category: 'user-suppression', source: 'suppressions.js:accepted.json',
      at: e.accepted_at || null, findingId: e.id || null, file: e.file || null,
      line: e.line ?? null, outcome: 'soft-accepted', raw: e,
    });
  }
  for (const e of _safe(() => (0,_suppressions_js__WEBPACK_IMPORTED_MODULE_0__/* .loadProSuppressions */ .KM)(scanRoot))) {
    events.push({
      category: 'user-suppression', source: 'suppressions.js:suppressions.yml',
      at: null, findingId: e.finding_id || null, file: e.file || null,
      line: null, outcome: 'pro-exception', raw: e,
    });
  }
  for (const e of _safe(() => (0,_triage_memory_js__WEBPACK_IMPORTED_MODULE_1__/* .loadMemory */ .ab)(scanRoot))) {
    if (e.decision === 'wont-fix') {
      events.push({
        category: 'user-suppression', source: 'triage-memory.js',
        at: e.at || null, findingId: e.id || null, file: e.file || null,
        line: e.line ?? null, outcome: 'wont-fix', raw: e,
      });
    } else if (e.decision === 'false-positive') {
      events.push({
        category: 'invalid-finding', source: 'triage-memory.js',
        at: e.at || null, findingId: e.id || null, file: e.file || null,
        line: e.line ?? null, outcome: 'false-positive', raw: e,
      });
    }
  }
  const scaPolicy = _safe(() => (0,_sca_policy_js__WEBPACK_IMPORTED_MODULE_2__/* .loadScaPolicy */ .IN)(scanRoot));
  const acceptRisk = scaPolicy && Array.isArray(scaPolicy.acceptRisk) ? scaPolicy.acceptRisk : [];
  for (const e of acceptRisk) {
    events.push({
      category: 'accepted-risk', source: 'sca-policy.js',
      at: null, findingId: e.cve || e.package || null, file: null,
      line: null, outcome: 'accept-risk', raw: e,
    });
  }
  for (const e of _safe(() => (0,_fix_history_js__WEBPACK_IMPORTED_MODULE_3__/* .readLog */ .x6)(scanRoot))) {
    events.push({
      category: 'fixed-finding', source: 'fix-history.js',
      at: e.appliedAt || null, findingId: e.findingId || e.stableId || null,
      file: e.file || null, line: null, outcome: e.status || 'unknown', raw: e,
    });
  }
  for (const e of _safe(() => (0,_fix_metrics_js__WEBPACK_IMPORTED_MODULE_4__/* .loadFixAttempts */ .sU)(scanRoot))) {
    events.push({
      category: 'verification-outcome', source: 'fix-metrics.js',
      at: e.at || null, findingId: e.stableId || null, file: null,
      line: null, outcome: e.ok ? 'verified' : 'not-verified', raw: e,
    });
  }

  return events;
}

/**
 * Bucket events by day within a rolling `sinceDays`-day window — the same
 * cutoff-window shape as posture/triage.js's own trend(). An event with no
 * timestamp (or an unparseable one) cannot be placed on a time axis: it is
 * counted once in `undated` per category rather than silently dropped or
 * silently smeared into the window.
 */
function summarizeFeedbackTrend(events, { sinceDays = 30, now = Date.now() } = {}) {
  const cutoff = now - sinceDays * MS_PER_DAY;
  const byCategory = {};
  for (const cat of CATEGORIES) byCategory[cat] = { total: 0, inWindow: 0, undated: 0 };

  const dayBuckets = new Map(); // 'YYYY-MM-DD' -> { category: count }
  for (const ev of Array.isArray(events) ? events : []) {
    if (!ev || !CATEGORIES.includes(ev.category)) continue;
    byCategory[ev.category].total++;
    const t = ev.at ? Date.parse(ev.at) : NaN;
    if (!Number.isFinite(t)) { byCategory[ev.category].undated++; continue; }
    if (t < cutoff) continue;
    byCategory[ev.category].inWindow++;
    const dayKey = new Date(t).toISOString().slice(0, 10);
    if (!dayBuckets.has(dayKey)) dayBuckets.set(dayKey, {});
    const bucket = dayBuckets.get(dayKey);
    bucket[ev.category] = (bucket[ev.category] || 0) + 1;
  }

  const series = [...dayBuckets.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([day, counts]) => ({ day, counts }));
  return { sinceDays, byCategory, series };
}

/**
 * Convenience wrapper: collect + summarize in one call — same pattern as
 * fix-metrics.js's fixDurationReport(scanRoot).
 */
function productionFeedbackReport(scanRoot, opts) {
  const events = collectFeedbackEvents(scanRoot);
  return { events, ...summarizeFeedbackTrend(events, opts) };
}

/**
 * One block of human-readable summary, or null when nothing was measured
 * at all — same "null when nothing measured" contract as
 * renderFixDurationSummary, so a caller can skip the section entirely
 * rather than print an empty header.
 */
function renderProductionFeedbackSummary(report) {
  if (!report || !Array.isArray(report.events) || !report.events.length) return null;
  const lines = [`Production feedback (last ${report.sinceDays}d):`];
  for (const cat of CATEGORIES) {
    const c = report.byCategory[cat];
    if (!c || c.total === 0) continue;
    const undatedNote = c.undated ? `, ${c.undated} undated` : '';
    lines.push(`  ${cat}: ${c.inWindow} in window / ${c.total} total${undatedNote}`);
  }
  return lines.length > 1 ? lines.join('\n') : null;
}

const _internals = { MS_PER_DAY };


/***/ })

};
