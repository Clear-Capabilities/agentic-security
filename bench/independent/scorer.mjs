// The independent-population scorer (E1-03): a pure function from per-entry rows to a report with complete denominator accounting.
//
// Pure: no filesystem, no clock, no network, no randomness (the bootstrap is seeded from the protocol hash). The runner and
// merge-chunks.mjs hand it the rows they already produce; nothing here scans anything.
//
// WHAT IT KEEPS APART
//   * Three scoring DEFINITIONS, never blended: `localized` (a matching finding landed on the lines the fix changed: the advisory-local
//     claim), `file` (right CWE somewhere in the advisory's files: a diagnostic) and `wide` (right CWE anywhere in the package: a
//     diagnostic). Only `localized` may be quoted as accuracy.
//   * SCORED entries from UNSCORED ones. An entry that could not be fetched, parsed, scanned in time or located is excluded from every
//     denominator and counted by reason; it is never a miss and never a negative. The three numbers reconcile exactly:
//       manifest entries in scope = scored + unscored + unaccounted, and `unaccounted` must be 0 or the report says so.
//   * A rate from too few entries from a rate. Below MIN_ENTRIES_FOR_RATE scored entries the group's status is `insufficient_population`
//     and no percentage is headlined; the counts are still shown.
//
// NOT HERE: the scan itself, the matching rule, localisation (runner.mjs exports those) and the splits (splits.mjs).
import { groupedBootstrap, wilsonInterval, f1Of, precisionOf, recallOf } from '../../scanner/src/posture/evaluation/interval.js';
import { groupTargets } from '../../scanner/src/posture/evaluation/grouping.js';
import { targetsOf } from './splits.mjs';

// Declared in advance. 30 scored entries gives a Wilson half-width of about 0.18 on a proportion near one half: wide, but a rate. Below it
// the interval is wider than the effect anyone is trying to measure, so no rate is headlined.
export const MIN_ENTRIES_FOR_RATE = 30;

export const DEFINITIONS = Object.freeze({
  localized: { keys: { tp: 'tpLocal', fp: 'fpLocal', fn: 'fnLocal', tn: 'tnLocal' }, claim: true, meaning: 'a matching finding landed on code the fix changed (advisory-local)' },
  file: { keys: { tp: 'tp', fp: 'fp', fn: 'fn', tn: 'tn' }, claim: false, meaning: 'diagnostic: the labelled CWE appeared in the advisory files' },
  wide: { keys: { tp: 'tpWide', fp: 'fpWide', fn: 'fnWide', tn: 'tnWide' }, claim: false, meaning: 'diagnostic: the labelled CWE appeared anywhere in the package' },
});

/** Why an entry was not scored, from the free-text reasons the runner records. The classes are the PRD's acquisition/parse/timeout split. */
export function classifyUnscored(reason) {
  const r = String(reason || '');
  if (/not fetched|acquisition|clone|download|404|not found upstream/i.test(r)) return 'acquisition';
  if (/timed? ?out|exceeded|watchdog/i.test(r)) return 'timeout';
  if (/parse|syntax|unsupported language|no parser/i.test(r)) return 'parse';
  if (/scan failed|crash|exception|oom|out of memory/i.test(r)) return 'scan_failure';
  if (/absent|not in the materialised|file.*missing/i.test(r)) return 'scope_file_absent';
  if (/no cwe|unknown cwe|label/i.test(r)) return 'label_unusable';
  return 'other';
}

const ratio = (n, d) => ({ n, d, value: d > 0 ? n / d : null });
const zero = () => ({ tp: 0, fp: 0, fn: 0, tn: 0 });
const addInto = (a, c) => { a.tp += c.tp; a.fp += c.fp; a.fn += c.fn; a.tn += c.tn; return a; };

export function metricsOf(c) {
  const precision = ratio(c.tp, c.tp + c.fp);
  const recall = ratio(c.tp, c.tp + c.fn);
  return { ...c, precision, recall, f1: f1Of(c), precisionInterval: c.tp + c.fp > 0 ? wilsonInterval(c.tp, c.tp + c.fp) : { status: 'unmeasured', reason: 'nothing was reported' }, recallInterval: c.tp + c.fn > 0 ? wilsonInterval(c.tp, c.tp + c.fn) : { status: 'unmeasured', reason: 'no positives' } };
}

function groupMetrics(rows, pick, minEntries) {
  const c = zero();
  for (const r of rows) addInto(c, { tp: r[pick.tp] || 0, fp: r[pick.fp] || 0, fn: r[pick.fn] || 0, tn: r[pick.tn] || 0 });
  const m = metricsOf(c);
  const status = rows.length < minEntries ? 'insufficient_population' : 'reportable';
  return { entries: rows.length, status, ...(status === 'reportable' ? m : { tp: c.tp, fp: c.fp, fn: c.fn, tn: c.tn, note: `${rows.length} scored entries, below ${minEntries}: counts only, no rate` }) };
}

function bucket(rows, keyFn) {
  const out = {};
  for (const r of rows) (out[keyFn(r) || '(unknown)'] ||= []).push(r);
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}

/** Macro: mean of per-group F1 over REPORTABLE groups with a defined F1. Weighted: the same, weighted by scored entries. Micro: pooled counts. */
export function aggregatesOf(byGroup) {
  const usable = Object.values(byGroup).filter((g) => g.status === 'reportable' && g.f1 !== null);
  const macro = usable.length ? usable.reduce((s, g) => s + g.f1, 0) / usable.length : null;
  const weight = usable.reduce((s, g) => s + g.entries, 0);
  const weighted = weight ? usable.reduce((s, g) => s + g.f1 * g.entries, 0) / weight : null;
  return { macroF1: macro, weightedF1: weighted, groupsUsed: usable.length, groupsTotal: Object.keys(byGroup).length };
}

/**
 * @param {object} o
 * @param {object[]} o.rows             per-entry rows (runner.mjs `perEntry`)
 * @param {object[]} [o.unscored]       [{ id, reason }]
 * @param {object[]} o.manifestEntries  the entries that were in scope for this run
 * @param {object} [o.splits]           splits.json (adds a per-split block)
 * @param {string} [o.protocolHash]     seeds the bootstrap
 * @param {number} [o.minEntries]
 */
export function scorePopulation({ rows, unscored = [], manifestEntries, splits = null, protocolHash = 'sha256:unfrozen', minEntries = MIN_ENTRIES_FOR_RATE }) {
  // identity: one row per entry, ever
  const inScope = new Set(manifestEntries.map((e) => e.id));
  const seen = new Set(); const duplicates = []; const clean = [];
  for (const r of rows) { if (seen.has(r.id)) { duplicates.push(r.id); continue; } seen.add(r.id); if (inScope.has(r.id)) clean.push(r); }
  const unscoredIds = new Set();
  const dupUnscored = []; const cleanUnscored = [];
  for (const u of unscored) { if (unscoredIds.has(u.id) || seen.has(u.id)) { dupUnscored.push(u.id); continue; } unscoredIds.add(u.id); cleanUnscored.push({ ...u, class: classifyUnscored(u.reason) }); }
  const strangers = [...seen, ...unscoredIds].filter((id) => !inScope.has(id));
  const accounted = new Set([...seen, ...unscoredIds].filter((id) => inScope.has(id)));
  const unaccounted = manifestEntries.filter((e) => !accounted.has(e.id)).map((e) => e.id);
  const byReason = {};
  for (const u of cleanUnscored) byReason[u.class] = (byReason[u.class] || 0) + 1;

  const denominators = {
    inScope: manifestEntries.length,
    scored: clean.length,
    unscored: cleanUnscored.length,
    unscoredByClass: Object.fromEntries(Object.entries(byReason).sort()),
    unaccounted: unaccounted.length,
    unaccountedExamples: unaccounted.slice(0, 5),
    duplicateRows: duplicates.concat(dupUnscored),
    rowsNotInScope: strangers,
    reconciles: unaccounted.length === 0 && !duplicates.length && !dupUnscored.length && !strangers.length,
    rule: 'in scope = scored + unscored + unaccounted; an unscored entry is in no denominator and is never a miss or a negative',
  };

  const entryById = new Map(manifestEntries.map((e) => [e.id, e]));
  const { groupOf } = groupTargets(targetsOf(manifestEntries));
  const out = { schemaVersion: 1, minEntriesForRate: minEntries, denominators, definitions: {} };
  for (const [name, def] of Object.entries(DEFINITIONS)) {
    const pick = def.keys;
    const total = groupMetrics(clean, pick, minEntries);
    const byLanguage = Object.fromEntries(Object.entries(bucket(clean, (r) => r.language)).map(([k, v]) => [k, groupMetrics(v, pick, minEntries)]));
    const byCwe = Object.fromEntries(Object.entries(bucket(clean, (r) => r.cwe)).map(([k, v]) => [k, groupMetrics(v, pick, minEntries)]));
    const units = clean.map((r) => ({ id: r.id, language: r.language, tp: r[pick.tp] || 0, fp: r[pick.fp] || 0, fn: r[pick.fn] || 0, tn: r[pick.tn] || 0 }));
    const interval = (stat, label) => groupedBootstrap({ units, groupOf, statistic: ({ total: t }) => stat(t), name: `${name}:${label}`, protocolHash });
    const block = {
      claim: def.claim, meaning: def.meaning, total,
      // F1, precision and recall intervals resample whole GROUPS (repository, advisory, commit), never single entries
      intervals: total.status === 'reportable' ? { f1: interval(f1Of, 'f1'), precision: interval(precisionOf, 'precision'), recall: interval(recallOf, 'recall') } : { note: 'insufficient_population: no interval is computed' },
      byLanguage, byCwe,
      aggregates: { micro: total.status === 'reportable' ? total.f1 : null, ...aggregatesOf(byLanguage) },
    };
    if (splits) {
      const bySplit = {};
      for (const [s, rs] of Object.entries(bucket(clean, (r) => splits.assignment?.[r.id] || 'unassigned'))) bySplit[s] = groupMetrics(rs, pick, minEntries);
      block.bySplit = bySplit;
    }
    out.definitions[name] = block;
  }

  // pressure from the fixed side: how many findings of any kind the fixed version still produces
  const postCounts = clean.map((r) => r.postFindings).filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  out.fixedVersionPressure = {
    meaning: 'findings of ANY family on the fixed version, not only the labelled CWE: the alert burden a user would see',
    entriesMeasured: postCounts.length,
    total: postCounts.reduce((s, x) => s + x, 0),
    mean: postCounts.length ? postCounts.reduce((s, x) => s + x, 0) / postCounts.length : null,
    median: postCounts.length ? postCounts[Math.floor((postCounts.length - 1) / 2)] : null,
    p95: postCounts.length ? postCounts[Math.min(postCounts.length - 1, Math.ceil(0.95 * postCounts.length) - 1)] : null,
    entriesWithAnyFinding: postCounts.filter((x) => x > 0).length,
  };
  const localTps = clean.filter((r) => r.tpLocal === 1);
  const survived = localTps.filter((r) => r.survivedFix === 1).length;
  out.fixDiscrimination = { ...ratio(localTps.length - survived, localTps.length), meaning: 'localized true positives whose finding is gone from the lines the fix produced' };
  void entryById;
  return out;
}

/** The headline an external reader may quote: the localized definition, with its denominator, interval and status, or the reason there is none. */
export function headline(score) {
  const t = score.definitions.localized.total;
  if (t.status !== 'reportable') return { quotable: false, reason: `insufficient_population: ${t.entries} scored entries, below ${score.minEntriesForRate}`, counts: { tp: t.tp, fp: t.fp, fn: t.fn, tn: t.tn }, denominators: score.denominators };
  const i = score.definitions.localized.intervals;
  return { quotable: score.denominators.reconciles, definition: 'localized (advisory-local)', precision: t.precision, recall: t.recall, f1: t.f1, f1Interval: i.f1, scoredEntries: t.entries, denominators: score.denominators, ...(score.denominators.reconciles ? {} : { reason: 'the denominators do not reconcile' }) };
}
