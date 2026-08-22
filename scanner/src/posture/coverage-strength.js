// Measured evidence strength for a compliance control (PRD F10.2).
//
// THE PROBLEM THIS EXISTS FOR
// ---------------------------
// A control mapped to a detector with 5% recall is COVERED in the coverage map
// and UNCOVERED in reality. The map said "family:sql-injection → checked" and
// stopped there, so a reader could not tell a control backed by a detector that
// finds nearly everything from one backed by a detector that finds almost
// nothing. The PRD calls closing that its highest-integrity change, and this is
// the closing.
//
// THE JOIN
// --------
//   control → mapped family
//           → producing detector        (posture/family-registry.js)
//           → the CWEs that family carries   (bench/family-producers/OBSERVED.json)
//           → measured recall for those CWEs (bench/family-producers/RECALL.json)
//
// The recall numbers come from bench/independent: advisories mined from public
// sources, NOT authored here. That matters more than the numbers themselves —
// a control cannot look well-evidenced because the engine graded its own
// homework.
//
// WHAT "UNMEASURED" MEANS, AND WHY IT IS NOT "FINE"
// ------------------------------------------------
// A CWE the independent corpus never exercised has NO recall figure. That is
// unmeasured, and unmeasured is reported as unmeasured — never silently treated
// as passing, and never given a default number. Roughly half the observed
// families are in that state today. Saying so is the honest output; inventing a
// figure for them would be the failure this module exists to prevent.
//
// Every rate is carried as {n, d} and rendered through the caller's formatter,
// following posture/accuracy-scorecard.js: a percentage must never appear
// without its denominator, because "50% recall" over two samples is noise.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { producersOf } from './family-registry.js';
import { resolveFamilyKeys } from './family-resolve.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BENCH = path.join(HERE, '..', '..', '..', 'bench', 'family-producers');

// Thresholds. Deliberately coarse — the underlying denominators are small, and a
// finer scale would imply a precision the measurement does not have.
const WEAK_BELOW = 0.25;
const PARTIAL_BELOW = 0.60;

// Below this many scored entries a rate is reported but flagged as indicative,
// mirroring accuracy-scorecard.js's `reliable:false` treatment.
const RELIABLE_MIN_D = 5;

let _cache = null;

function _load() {
  if (_cache) return _cache;
  const read = (f, fallback) => {
    try { return JSON.parse(fs.readFileSync(path.join(BENCH, f), 'utf8')); }
    catch { return fallback; }
  };
  // A missing artifact must degrade to "unmeasured", never to a default rate —
  // same reasoning as the unmeasured tier itself.
  const observed = read('OBSERVED.json', { families: {} });
  const recall = read('RECALL.json', { byCwe: {} });
  _cache = { families: observed.families || {}, byCwe: recall.byCwe || {}, population: recall.population || null };
  return _cache;
}

/** Reset the memo. Tests only. */
export function _resetCache() { _cache = null; }

/**
 * The CWEs a family mapping was observed to carry, most frequent first.
 *
 * Resolves the mapping the SAME way the evaluator does — exact, alias, or
 * `<base>-<rule-slug>` suffix — via the shared resolver. Looking `family` up as
 * a literal key reported "unmeasured" for every aliased mapping: ASVS V5.1 maps
 * to `family:sqli`, nothing emits `sqli`, and the real family `sql-injection` IS
 * measured. That would be a false "no evidence" verdict on a control that has
 * evidence.
 */
export function cwesFor(family) {
  const { families } = _load();
  const keys = resolveFamilyKeys(family, Object.keys(families));
  const counts = new Map();
  for (const k of keys) {
    for (const [cwe, n] of Object.entries((families[k] || {}).cwes || {})) {
      counts.set(cwe, (counts.get(cwe) || 0) + n);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c);
}

/**
 * Measured strength of the detector(s) behind `family`.
 *
 * Returns { tier, recall:{n,d}|null, cwes, measuredCwes, reliable, producers, reason }.
 * `tier` ∈ 'measured' | 'partial' | 'weak' | 'unmeasured'.
 */
export function strengthOf(family) {
  const { byCwe } = _load();
  const cwes = cwesFor(family);
  const producers = producersOf(family);

  // Aggregate across every CWE this family carries that the independent corpus
  // actually exercised. Summing {n,d} weights by how much evidence each CWE has,
  // which is what we want — averaging the percentages would let a 1-of-1 CWE
  // outvote a 40-of-100 one.
  let n = 0, d = 0;
  const measuredCwes = [];
  for (const c of cwes) {
    const m = byCwe[c];
    if (!m || !m.recall || !m.recall.d) continue;
    n += m.recall.n; d += m.recall.d;
    measuredCwes.push(c);
  }

  if (!d) {
    return {
      tier: 'unmeasured',
      recall: null,
      cwes, measuredCwes: [], reliable: false, producers,
      reason: cwes.length
        ? 'no CWE this family carries was exercised by the independent corpus'
        : 'no CWE observed for this family — nothing to measure against',
    };
  }

  const rate = n / d;
  const tier = rate < WEAK_BELOW ? 'weak' : rate < PARTIAL_BELOW ? 'partial' : 'measured';
  return {
    tier,
    recall: { n, d },
    cwes, measuredCwes,
    reliable: d >= RELIABLE_MIN_D,
    producers,
    reason: `measured over ${d} independent advisor${d === 1 ? 'y' : 'ies'}`,
  };
}

/**
 * Strength for a control, taken across every family it maps to.
 *
 * The WEAKEST backing family wins. A control is only as evidenced as its
 * flimsiest leg: claiming the average would let a strong mapping hide a
 * mapping that finds nothing.
 */
export function strengthOfControl(control) {
  const families = (control && Array.isArray(control.mapsTo) ? control.mapsTo : [])
    .filter(m => typeof m === 'string' && m.startsWith('family:'))
    .map(m => m.slice('family:'.length).split(':')[0]);

  if (!families.length) return { tier: 'unmeasured', families: [], legs: [], reason: 'control has no family: mapping' };

  const legs = families.map(f => ({ family: f, ...strengthOf(f) }));
  const ORDER = { unmeasured: 0, weak: 1, partial: 2, measured: 3 };
  const weakest = legs.reduce((a, b) => (ORDER[b.tier] < ORDER[a.tier] ? b : a));
  return {
    tier: weakest.tier,
    families, legs,
    reason: `weakest backing family "${weakest.family}": ${weakest.reason}`,
  };
}

/**
 * True when a control should NOT be presented as cleanly evidenced, because the
 * detector behind it is weak or was never measured. This is the flag the
 * coverage map carries.
 */
export function isPartiallyEvidenced(control) {
  const s = strengthOfControl(control);
  return s.tier === 'weak' || s.tier === 'unmeasured';
}

/** Human-readable, denominator-carrying label for a report. */
export function formatStrength(s) {
  if (!s || s.tier === 'unmeasured') return 'unmeasured (no independent evidence)';
  const { n, d } = s.recall || (s.legs && s.legs.length ? s.legs[0].recall : null) || {};
  if (n == null) return `${s.tier} (no rate)`;
  const pct = Math.round((n / d) * 100);
  return `${s.tier} — recall ${n}/${d} (${pct}%)${s.reliable === false ? ', indicative only' : ''}`;
}
