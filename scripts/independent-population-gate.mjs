// FR-902 (assurance-hardening PRD) — gate on the independent population's
// advisory-local precision, recall, and F1, plus per-language floors. "A
// material regression blocks release unless a signed exception explains it."
//
// bench/independent/RESULT.json is a COMMITTED artifact (scoring the
// population takes ~32 minutes, so it is not re-run inline in this gate —
// same reasoning scorecard-freshness already uses for the same file). This
// gate compares the COMMITTED measurement against a COMMITTED floor
// (bench/independent/gate-baseline.json): did someone commit a RESULT.json
// whose precision/recall/F1 — overall, or for any language the baseline
// already tracks — regressed, without acknowledging it.
//
// FLOOR, not equality (same shape as bench/cve-replay/corpus-baseline.json
// and bench/layer-recall/baseline.json): fails on a drop below the recorded
// value, silent on an improvement. Chosen over exact-equality because this
// population's per-language entry counts are small (single digits for some
// languages) and inherently noisy — layer-recall's own upgrade to exact
// equality was earned for a much larger, more stable taint-count population;
// blindly copying that here would fire on statistical noise, not signal.
//
// A language present in the baseline but MISSING from RESULT.json is also a
// regression — a naive "only compare what's present" gate would silently let
// an entire language's coverage vanish. A language NEW to RESULT.json (not
// yet in the baseline) is not gated — there is no floor to have fallen below.
//
// Waivable exactly the way calibration-holdout-check.mjs waives an
// unavoidable state: an explicit, reasoned, DATED entry that expires. Same
// anti-rot rules as .calibration-waiver.json / .dependency-holds.json — a
// reason nobody can evaluate, or a missing/expired reviewBy, fails the gate.

import fs from 'node:fs';
import path from 'node:path';

const RESULT_FILE = 'bench/independent/RESULT.json';
const BASELINE_FILE = 'bench/independent/gate-baseline.json';
const WAIVER_FILE = '.independent-population-waiver.json';

// A floating-point epsilon so a value that is bytewise-identical to the
// baseline (the overwhelmingly common no-change case) never fails on
// representation noise.
const EPSILON = 1e-9;

function readJson(p, fallback = null) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
}

function fmtPct(v) {
  return typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : 'n/a';
}

/**
 * @returns {{ok:boolean, detail:string, warnings?:string[], regressions?:string[]}}
 */
export function runIndependentPopulationGate(repo, { now = new Date() } = {}) {
  const resultPath = path.join(repo, RESULT_FILE);
  const baselinePath = path.join(repo, BASELINE_FILE);

  const result = readJson(resultPath);
  if (!result || !result.overall) {
    return { ok: false, detail: `${RESULT_FILE} is missing or unparseable — the independent population has never been measured. Run \`npm run bench:independent\` and commit the result.` };
  }
  const baseline = readJson(baselinePath);
  if (!baseline) {
    return { ok: false, detail: `${BASELINE_FILE} is missing — nothing to gate against. Run \`npm run bench:independent:update-gate-baseline\` once ${RESULT_FILE} reflects a reviewed measurement.` };
  }

  const regressions = [];

  const checkTriple = (label, cur, floor) => {
    if (!cur || !floor) return;
    for (const metric of ['precision', 'recall']) {
      const c = cur[metric]?.value;
      const f = floor[metric];
      if (typeof c === 'number' && typeof f === 'number' && c < f - EPSILON) {
        regressions.push(`${label} ${metric} dropped: ${fmtPct(c)} < baseline floor ${fmtPct(f)}`);
      }
    }
    const cf1 = cur.f1;
    const ff1 = floor.f1;
    if (typeof cf1 === 'number' && typeof ff1 === 'number' && cf1 < ff1 - EPSILON) {
      regressions.push(`${label} F1 dropped: ${cf1.toFixed(3)} < baseline floor ${ff1.toFixed(3)}`);
    }
  };

  checkTriple('overall', result.overall, baseline.overall);

  const curByLang = result.byLanguage || {};
  const baseByLang = baseline.byLanguage || {};
  for (const [lang, floor] of Object.entries(baseByLang)) {
    const cur = curByLang[lang];
    if (!cur) {
      regressions.push(`language '${lang}' is in the baseline (${floor.entries} entries) but missing from ${RESULT_FILE} entirely — a whole language's coverage vanished`);
      continue;
    }
    checkTriple(`language '${lang}'`, cur, floor);
  }

  if (regressions.length === 0) {
    return { ok: true, detail: `advisory-local precision/recall/F1 (overall + ${Object.keys(baseByLang).length} language floor(s)) held at or above the committed baseline.` };
  }

  const waiver = readJson(path.join(repo, WAIVER_FILE));
  const regressionSummary = regressions.join('; ');
  if (!waiver) {
    return {
      ok: false,
      detail: `independent-population regression(s): ${regressionSummary}. Fix the regression, run \`npm run bench:independent:update-gate-baseline\` if the drop is understood and intended, or record a dated exception in ${WAIVER_FILE}.`,
      regressions,
    };
  }
  const { reason, reviewBy } = waiver;
  if (typeof reason !== 'string' || reason.trim().length < 40) {
    return { ok: false, detail: `${WAIVER_FILE} needs a real reason — a waiver nobody can evaluate is indistinguishable from an oversight. Regression(s): ${regressionSummary}` };
  }
  if (!reviewBy || Number.isNaN(Date.parse(reviewBy))) {
    return { ok: false, detail: `${WAIVER_FILE} needs a reviewBy date. A waiver with no expiry becomes permanent. Regression(s): ${regressionSummary}` };
  }
  if (Date.parse(reviewBy) < now.getTime()) {
    return { ok: false, detail: `${WAIVER_FILE} expired on ${reviewBy}. Regression(s): ${regressionSummary}` };
  }
  return {
    ok: true,
    detail: `independent-population regression(s) waived until ${reviewBy}: ${regressionSummary}. ${reason.trim()}`,
    warnings: [`independent-population precision/recall/F1 regressed and is waived until ${reviewBy}; this is not evidence the regression is acceptable long-term.`],
    regressions,
  };
}

/**
 * Overwrite gate-baseline.json from the CURRENT committed RESULT.json.
 * A deliberate operator action (its own npm script), never run implicitly by
 * the gate itself — re-baselining silently would let a real regression
 * become the new floor unnoticed, the exact rot corpus-baseline.json's own
 * update flow is equally careful never to do automatically.
 */
export function updateGateBaseline(repo) {
  const result = readJson(path.join(repo, RESULT_FILE));
  if (!result || !result.overall) {
    throw new Error(`${RESULT_FILE} is missing or unparseable — nothing to baseline from.`);
  }
  const byLanguage = {};
  for (const [lang, v] of Object.entries(result.byLanguage || {})) {
    byLanguage[lang] = {
      entries: v.entries,
      precision: v.precision?.value ?? null,
      recall: v.recall?.value ?? null,
      f1: v.f1 ?? null,
    };
  }
  const baseline = {
    _comment: 'FR-902 (assurance-hardening PRD). Floor, not equality (same shape as corpus-baseline.json/layer-recall baseline.json) — fails on a drop below the recorded value, silent on an improvement. Re-baseline deliberately whenever RESULT.json is legitimately refreshed, never to silence a real regression.',
    source: RESULT_FILE,
    measuredAt: result.measuredAt || null,
    engineVersion: result.engineVersion || null,
    overall: {
      precision: result.overall.precision?.value ?? null,
      recall: result.overall.recall?.value ?? null,
      f1: result.overall.f1 ?? null,
    },
    byLanguage,
  };
  fs.writeFileSync(path.join(repo, BASELINE_FILE), JSON.stringify(baseline, null, 2) + '\n');
  return baseline;
}

// CLI entry: `node scripts/independent-population-gate.mjs [--update-baseline]`
if (import.meta.url === `file://${process.argv[1]}`) {
  const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
  if (process.argv.includes('--update-baseline')) {
    const b = updateGateBaseline(REPO);
    process.stdout.write(`✓ ${BASELINE_FILE} updated from ${RESULT_FILE}\n`);
    process.stdout.write(`  overall: precision ${fmtPct(b.overall.precision)}, recall ${fmtPct(b.overall.recall)}, f1 ${(b.overall.f1 ?? 0).toFixed(3)}\n`);
    process.exit(0);
  }
  const r = runIndependentPopulationGate(REPO);
  process.stdout.write(`${r.ok ? '✓' : '✖'} ${r.detail}\n`);
  for (const w of r.warnings || []) process.stderr.write(`  ⚠ ${w}\n`);
  process.exit(r.ok ? 0 : 1);
}
