// Small, dependency-free statistics for repeated runs (PRD 6, requirement 6: never publish one lucky run as representative).
// Pure: no fs, no clock. A summary of fewer than MIN_REPRESENTATIVE_RUNS values carries `representative: false` and says why,
// so no consumer can print its mean as a headline without also printing that.

export const MIN_REPRESENTATIVE_RUNS = 3;

// two-sided 95% Student-t critical values for 1..30 degrees of freedom; 1.96 beyond
const T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042];

const finite = (xs) => xs.filter((x) => typeof x === 'number' && Number.isFinite(x));

export function median(xs) {
  const v = finite(xs).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

/** mean, sample standard deviation, range and a 95% interval of the mean. Unmeasured (null) values are excluded and counted. */
export function summarize(values) {
  const all = Array.isArray(values) ? values : [];
  const v = finite(all);
  const unmeasured = all.length - v.length;
  if (!v.length) return { n: 0, unmeasured, mean: null, stdev: null, min: null, max: null, ci95: null, representative: false, note: 'no measured value' };
  const n = v.length;
  const mean = v.reduce((a, b) => a + b, 0) / n;
  const stdev = n > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)) : null;
  const t = n > 1 ? (T95[n - 2] ?? 1.96) : null;
  const half = stdev == null ? null : t * stdev / Math.sqrt(n);
  const representative = n >= MIN_REPRESENTATIVE_RUNS;
  return {
    n, unmeasured, mean, stdev, min: Math.min(...v), max: Math.max(...v),
    ci95: half == null ? null : { low: mean - half, high: mean + half },
    representative,
    ...(representative ? {} : { note: `${n} run${n === 1 ? '' : 's'}: fewer than ${MIN_REPRESENTATIVE_RUNS}, not representative` }),
  };
}

export const ratio = (num, den) => (den > 0 ? num / den : null);
export const f1 = (p, r) => (p == null || r == null ? null : p + r === 0 ? 0 : (2 * p * r) / (p + r));
export const pct = (x, digits = 1) => (x == null ? 'n/a' : `${(x * 100).toFixed(digits)}%`);
