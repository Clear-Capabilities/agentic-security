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

import fs from 'node:fs';
import path from 'node:path';
import { isSafeStateDir, stateDir, statePath, stateWritesEnabled } from './state-dir.js';

const LOG_FILE = 'fix-metrics.jsonl';

// Below this many samples a percentile is an artifact of the sample, not a
// property of the pipeline. Reported anyway (hiding it invites re-deriving it
// wrong downstream) but flagged, so a caller cannot quote it as settled.
const RELIABLE_N = 10;

// The stages verifyFix runs, in execution order. Kept here so the recorder and
// the summariser cannot drift apart on stage naming.
export const FIX_STAGES = Object.freeze(['rescan', 'lint', 'tests', 'honesty', 'poc']);

function _logPath(scanRoot) {
  return statePath(scanRoot, LOG_FILE);
}

/**
 * Append one verification attempt. Best-effort and silent on failure: metrics
 * must never be able to fail a fix that otherwise verified.
 *
 * @returns {boolean} whether the record was written (for tests, not callers).
 */
export function recordFixAttempt(scanRoot, record) {
  if (!scanRoot || !record || typeof record !== 'object') return false;
  try {
    const dir = stateDir(scanRoot);
    if (!isSafeStateDir(dir)) return false;
    if (!stateWritesEnabled()) return false;
  fs.mkdirSync(dir, { recursive: true });
    // One writeSync of one newline-terminated line: a concurrent reader sees
    // whole records or nothing, and a torn tail is dropped on read.
    fs.appendFileSync(_logPath(scanRoot), JSON.stringify(record) + '\n', 'utf8');
    return true;
  } catch { return false; }
}

/**
 * Read every well-formed attempt. A line that does not parse is skipped, not
 * fatal — the last line of an interrupted write is the expected case.
 */
export function loadFixAttempts(scanRoot) {
  try {
    const raw = fs.readFileSync(_logPath(scanRoot), 'utf8');
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
export function bucketOf(a) {
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
export function summarizeFixDurations(attempts) {
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
export function fixDurationReport(scanRoot) {
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
export function renderFixDurationSummary(sum) {
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

export const _internals = { _dist, _pct, RELIABLE_N };


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
export function summarizeFixAxes(attempts) {
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
export function renderFixAxes(sum) {
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
