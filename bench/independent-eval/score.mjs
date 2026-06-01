// R16 — independent evaluation: pure scoring core.
//
// Separated from the runner (runner.mjs) on purpose: this file has NO I/O and
// NO scanner dependency, so its precision/recall/F1 and gate math can be
// unit-tested deterministically (test/independent-eval.test.js) without
// running a scan. The runner supplies real findings; the tests supply
// hand-constructed ones.
//
// Ground-truth model — each corpus entry is one labeled sample:
//   { id, path, language, cwe, family, label: 'vulnerable' | 'clean' }
// `family` (and optionally `cwe`) is the class the sample is labeled for.
//
// Scoring per entry, given the findings the scanner produced in that file:
//   label=vulnerable, a matching-family finding present  → TP
//   label=vulnerable, no matching finding                → FN  (a real miss)
//   label=clean,      a matching-family finding present  → FP
//   label=clean,      no matching finding                → TN
//
// This is the SARD/Juliet/OWASP-Benchmark scoring shape: recall comes from FN,
// which holdout-eval.js cannot see (it only scores findings that were emitted).

/** Normalize a path for cross-map comparison (strip leading ./, collapse \\). */
export function normPath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * Does a produced finding satisfy an entry's labeled class?
 * Matches on family string OR on CWE containment (the manifest may carry
 * either; the engine sets both `family` and `cwe`).
 */
export function matchFamily(entry, finding) {
  if (!entry || !finding) return false;
  if (entry.family && finding.family && entry.family === finding.family) return true;
  if (entry.cwe != null && finding.cwe != null) {
    const ec = String(entry.cwe).replace(/^cwe-?/i, '');
    const fc = String(finding.cwe).replace(/^cwe-?/i, '');
    if (ec && fc && (fc === ec || fc.split(/[^0-9]+/).includes(ec))) return true;
  }
  return false;
}

/** precision/recall/F1 from a confusion cell. Returns nulls when undefined
 *  (0/0) rather than a misleading 0, so the gate can distinguish "no data"
 *  from "measured zero". */
export function prf({ tp = 0, fp = 0, fn = 0 } = {}) {
  const dP = tp + fp;
  const dR = tp + fn;
  const precision = dP > 0 ? tp / dP : null;
  const recall = dR > 0 ? tp / dR : null;
  let f1;
  if (precision === null && recall === null) f1 = null;
  else if (!precision || !recall) f1 = 0;
  else f1 = (2 * precision * recall) / (precision + recall);
  return {
    precision: precision === null ? null : round4(precision),
    recall: recall === null ? null : round4(recall),
    f1: f1 === null ? null : round4(f1),
  };
}

function round4(n) { return Number(n.toFixed(4)); }

/**
 * Score a labeled corpus against per-file findings.
 *   entries:        [{ id, path, family, cwe, label }]
 *   findingsByFile: Map<normPath, [{ family, cwe, confidence }]>  (or plain obj)
 * Returns { n, perFamily: {fam:{tp,fp,fn,tn,...prf}}, aggregate:{tp,fp,fn,tn,...prf},
 *           calibration: [{family, language, predicted, actual}] }
 */
export function scoreCorpus(entries, findingsByFile) {
  const get = (p) => {
    const key = normPath(p);
    if (findingsByFile instanceof Map) return findingsByFile.get(key) || [];
    return (findingsByFile && findingsByFile[key]) || [];
  };
  const fams = {};
  const calibration = [];
  const ensure = (f) => (fams[f] ||= { tp: 0, fp: 0, fn: 0, tn: 0 });
  for (const e of entries || []) {
    const fam = e.family || 'unknown';
    const cell = ensure(fam);
    const findings = get(e.path);
    const matches = findings.filter((f) => matchFamily(e, f));
    const matched = matches.length > 0;
    const isVuln = e.label === 'vulnerable';
    if (isVuln && matched) cell.tp++;
    else if (isVuln && !matched) cell.fn++;
    else if (!isVuln && matched) cell.fp++;
    else cell.tn++;
    // Calibration pair: confidence of the strongest matching finding (0 if
    // none) vs the ground-truth label. Feeds holdout-eval (Brier/ECE).
    const predicted = matched
      ? Math.max(...matches.map((m) => (typeof m.confidence === 'number' ? m.confidence : 0.5)))
      : 0;
    calibration.push({ family: fam, language: e.language || 'unknown', predicted, actual: isVuln ? 1 : 0 });
  }
  const perFamily = {};
  const agg = { tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const [fam, c] of Object.entries(fams)) {
    perFamily[fam] = { ...c, ...prf(c) };
    agg.tp += c.tp; agg.fp += c.fp; agg.fn += c.fn; agg.tn += c.tn;
  }
  const aggregate = { ...agg, ...prf(agg) };
  return { n: (entries || []).length, perFamily, aggregate, calibration };
}

/**
 * Gate a scored result against thresholds. A metric that is `null` (no data)
 * when a threshold is set counts as a VIOLATION — you cannot claim a bar you
 * never measured. Returns { pass, violations: [string] }.
 *
 * thresholds: {
 *   aggregateF1, aggregatePrecision, aggregateRecall,  // numbers in [0,1]
 *   perFamilyF1, perFamilyRecall,                       // applied to every family
 *   minSamples,                                         // require >= N entries
 * }
 */
export function checkGate(result, thresholds = {}) {
  const v = [];
  const cmp = (label, val, min) => {
    if (min == null) return;
    if (val == null) { v.push(`${label} is unmeasured (null) but threshold ${min} is set`); return; }
    if (val < min) v.push(`${label}=${val} < ${min}`);
  };
  if (thresholds.minSamples != null && result.n < thresholds.minSamples) {
    v.push(`samples ${result.n} < minSamples ${thresholds.minSamples}`);
  }
  cmp('aggregate.f1', result.aggregate?.f1, thresholds.aggregateF1);
  cmp('aggregate.precision', result.aggregate?.precision, thresholds.aggregatePrecision);
  cmp('aggregate.recall', result.aggregate?.recall, thresholds.aggregateRecall);
  for (const [fam, m] of Object.entries(result.perFamily || {})) {
    cmp(`family[${fam}].f1`, m.f1, thresholds.perFamilyF1);
    cmp(`family[${fam}].recall`, m.recall, thresholds.perFamilyRecall);
  }
  return { pass: v.length === 0, violations: v };
}
