// Addition #6 — self-improving recall harness: PURE, I/O-free scoring core.
//
// Separated from the runner (runner.mjs) on purpose, exactly like
// bench/independent-eval/score.mjs: this file has NO I/O and NO scanner
// dependency, so its detection-rate math, the deterministic matcher, and the
// gate can be unit-tested deterministically (test/realworld-recall.test.js)
// without running a scan or an LLM. The runner supplies real emitted findings
// and (optionally) a judge verdict; the tests supply hand-constructed ones.
//
// What this harness measures — RECALL / detection-rate, not precision. Each
// corpus entry is a KNOWN vulnerability (ground truth) we expect the scanner to
// surface. We ask: did any emitted finding match it by CLASS + LOCATION +
// root-cause? The authoritative match is a semantic (LLM) judge (judge.mjs);
// when no judge verdict is available (offline, or the judge errored on the
// no-endpoint path) we fall back to this deterministic matcher. A genuine
// judge-error is recorded as `detected:null` and EXCLUDED from the denominator —
// you cannot count a sample you could not adjudicate.
//
// Null-not-zero discipline (mirrors independent-eval): an unmeasured rate is
// `null`, never `0`, so the gate can tell "no data" apart from "measured zero".

/** Normalize a path/component for cross-map comparison (strip ./, collapse \\). */
export function normPath(p) {
  return String(p == null ? '' : p).replace(/\\/g, '/').replace(/^\.\//, '');
}

/** Strip a trailing `:line` / `:line:col` locator so a location compares as a path. */
function stripLocator(s) {
  return normPath(s).replace(/:\d+(?::\d+)?$/, '');
}

/** Normalize a vuln-class token: lowercase, unify separators to '-'. */
function normClass(s) {
  return String(s == null ? '' : s).toLowerCase().trim().replace(/[\s_/]+/g, '-').replace(/-+/g, '-');
}

/** Extract the numeric part of a CWE id ("CWE-89" | "89" | "cwe89" → "89"). */
function cweNum(s) {
  if (s == null) return null;
  const m = String(s).match(/(\d+)/);
  return m ? m[1] : null;
}

function fileOf(x) {
  // Accept an expected entry's `location`/`file` or a finding's `file`/`location`.
  return stripLocator(x || '');
}

function round4(n) { return Number(n.toFixed(4)); }

/**
 * Does an emitted finding sit at the same file/component as the expected entry?
 * Location match is a bidirectional substring (per spec) on the path portion,
 * so `src/db/users.js` matches `/abs/project/src/db/users.js` and vice-versa.
 * A guard rejects trivially-short fragments to avoid accidental containment.
 */
export function sharesLocation(expected, finding) {
  const a = fileOf(expected && (expected.location != null ? expected.location : expected.file));
  const b = fileOf(finding && (finding.file != null ? finding.file : finding.location));
  if (!a || !b || a.length < 3 || b.length < 3) return false;
  return a === b || a.includes(b) || b.includes(a);
}

/**
 * Do the expected entry and the emitted finding describe the same vuln class?
 * Matches on class string (expected.type/family vs finding.family/vuln, with
 * separator/case normalization) OR on CWE-number equality.
 */
export function sharesClass(expected, finding) {
  if (!expected || !finding) return false;
  const et = normClass(expected.type || expected.family || expected.class);
  const ff = normClass(finding.family);
  const fv = normClass(finding.vuln);
  if (et && (et === ff || et === fv)) return true;
  const ec = cweNum(expected.cwe);
  const fc = cweNum(finding.cwe);
  if (ec != null && fc != null && ec === fc) return true;
  return false;
}

function findingId(f, i) {
  return f.id || f.stableId || f.finding_id || (f.file ? `${normPath(f.file)}:${f.line ?? '?'}` : `finding-${i}`);
}

/** Best deterministic match for an expected entry: same location AND same class,
 *  highest confidence wins. Returns { id, confidence } or null. */
function bestDeterministicMatch(expected, emittedFindings) {
  const candidates = (emittedFindings || [])
    .map((f, i) => ({ f, i }))
    .filter(({ f }) => sharesLocation(expected, f) && sharesClass(expected, f));
  if (!candidates.length) return null;
  candidates.sort((x, y) => (conf(y.f) - conf(x.f)));
  const top = candidates[0];
  return { id: findingId(top.f, top.i), confidence: conf(top.f) };
}

function conf(f) {
  if (f && typeof f.confidence === 'number') return f.confidence;
  if (f && typeof f.calibratedConfidence === 'number') return f.calibratedConfidence;
  return 0.5;
}

/**
 * Adjudicate ONE expected known-vuln against the emitted findings.
 *   matchExpected(expected, emittedFindings)            → deterministic fallback
 *   matchExpected(expected, emittedFindings, verdict)   → judge-authoritative
 *
 * `verdict` (from judge.mjs) is honoured when supplied:
 *   { detected: true }  → detected, matched = best deterministic id (or verdict.matched)
 *   { detected: false } → not detected
 *   { detected: null }  → JUDGE-ERROR → detected:null, UNLESS the reasoning is the
 *                         no-llm-endpoint sentinel, in which case we transparently
 *                         fall back to the deterministic matcher.
 *
 * Returns { detected: boolean|null, matched: emittedId|null, confidence }.
 */
export function matchExpected(expected, emittedFindings, verdict) {
  if (verdict && typeof verdict === 'object' && Object.prototype.hasOwnProperty.call(verdict, 'detected')) {
    const d = verdict.detected;
    if (d === true) {
      const best = bestDeterministicMatch(expected, emittedFindings);
      return {
        detected: true,
        matched: best ? best.id : (verdict.matched != null ? verdict.matched : null),
        confidence: best ? best.confidence : (typeof verdict.confidence === 'number' ? verdict.confidence : 0.75),
      };
    }
    if (d === false) {
      return { detected: false, matched: null, confidence: 0 };
    }
    if (d === null) {
      // The no-endpoint sentinel is NOT an adjudication failure — it explicitly
      // asks for the deterministic fallback. A real judge-error propagates null.
      if (!/^no-llm-endpoint/i.test(String(verdict.reasoning || ''))) {
        return { detected: null, matched: null, confidence: 0 };
      }
      // else: fall through to deterministic.
    }
  }
  const best = bestDeterministicMatch(expected, emittedFindings);
  if (best) return { detected: true, matched: best.id, confidence: best.confidence };
  return { detected: false, matched: null, confidence: 0 };
}

/**
 * Score a set of per-expected results.
 *   results: [{ id?, type|family?, detected: boolean|null, ... }]
 * Returns { total, detected, missed, judgeErrors, detectionRate, byType }.
 *   detectionRate = detected / (total - judgeErrors), or `null` if the
 *   denominator is 0 (guarded divide-by-zero) — never a misleading 0.
 */
export function scoreRecall(results) {
  const arr = Array.isArray(results) ? results : [];
  const total = arr.length;
  let detected = 0, missed = 0, judgeErrors = 0;
  const cells = {};
  for (const r of arr) {
    const type = (r && (r.type || r.family)) || 'unknown';
    const cell = (cells[type] ||= { total: 0, detected: 0, missed: 0, judgeErrors: 0 });
    cell.total++;
    if (r && r.detected === null) { judgeErrors++; cell.judgeErrors++; }
    else if (r && r.detected === true) { detected++; cell.detected++; }
    else { missed++; cell.missed++; }
  }
  const denom = total - judgeErrors;
  const detectionRate = denom > 0 ? round4(detected / denom) : null;
  const byType = {};
  for (const [t, c] of Object.entries(cells)) {
    const d = c.total - c.judgeErrors;
    byType[t] = { ...c, detectionRate: d > 0 ? round4(c.detected / d) : null };
  }
  return { total, detected, missed, judgeErrors, detectionRate, byType };
}

/**
 * Gate a recall score against thresholds. Returns an array of violation strings
 * (empty ⇒ pass). A metric that is `null` (unmeasured) when a threshold is set
 * for it counts as a VIOLATION — you cannot claim a recall bar you never
 * measured. Mirrors independent-eval's checkGate discipline, but returns the
 * bare violations array per this harness's spec.
 *
 * thresholds: {
 *   minDetectionRate,       // aggregate floor in [0,1]
 *   perTypeDetectionRate,   // applied to every observed vuln type
 *   minSamples,             // require >= N *measured* (non-judge-error) samples
 * }
 */
export function checkGate(score, thresholds = {}) {
  const v = [];
  if (!score || typeof score !== 'object') return ['score is missing'];
  const cmp = (label, val, min) => {
    if (min == null) return;
    if (val == null) { v.push(`${label} is unmeasured (null) but threshold ${min} is set`); return; }
    if (val < min) v.push(`${label}=${val} < ${min}`);
  };
  if (thresholds.minSamples != null) {
    const measured = (score.total || 0) - (score.judgeErrors || 0);
    if (measured < thresholds.minSamples) v.push(`measured samples ${measured} < minSamples ${thresholds.minSamples}`);
  }
  cmp('detectionRate', score.detectionRate, thresholds.minDetectionRate);
  if (thresholds.perTypeDetectionRate != null) {
    for (const [t, m] of Object.entries(score.byType || {})) {
      cmp(`byType[${t}].detectionRate`, m.detectionRate, thresholds.perTypeDetectionRate);
    }
  }
  return v;
}
