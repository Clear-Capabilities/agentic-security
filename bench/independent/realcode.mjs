#!/usr/bin/env node
// Real-code regression policy (E1-07): pre-registered floors, and a check that cannot pass on missing or unhealthy evidence.
//
//   node bench/independent/realcode.mjs approve --run <runId> --reason "<why this run is the baseline>"
//   node bench/independent/realcode.mjs report  [--run <runId>]
//   node bench/independent/realcode.mjs check   --tier quick|release [--run <runId>]
//   npm run bench:realcode:report / bench:realcode:check
//
// A baseline is a finished run from bench/independent/runs/ that someone approves. Approving writes the floors: for every language with enough
// scored entries, the LOWER BOUND of the 95% interval on the baseline's localized recall and precision (so ordinary sampling noise cannot trip
// them), plus the minimum population a later run needs before it can be compared at all. Floors are written once. A later change is a
// successor with a stated reason, kept beside the original; nothing edits a floor in place.
//
// THE CHECK. It returns one of: passed, failed, blocked, insufficient_population, unmeasured. Only `passed` is green.
//   unmeasured               there is no run to check (no baseline approved, or no run given/found). A missing corpus can never pass.
//   blocked                  the run cannot support a comparison: its denominators do not reconcile, too many entries were unscored or unaccounted
//                            for, the measured commit was not clean, or the engine bundle does not match its digest
//   insufficient_population  a language (or the whole run) has fewer scored entries than the floor needs: reported, not compared, not green
//   failed                   a language that is comparable fell below its floor, or a floor language is absent
//   passed                   every comparable language is at or above its floor, and nothing above prevented the comparison
// The `quick` tier is DIAGNOSTIC: it computes the same verdict and exits 0 unless the run is blocked, because a small PR-sized sample cannot
// carry a gate. The `release` tier exits non-zero for anything but `passed`.
import { existsSync, readFileSync, readdirSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { atomicWriteJson } from '../../scripts/loop-engineering/lib/util.mjs';
import { MIN_ENTRIES_FOR_RATE } from './scorer.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
// AGENTIC_SECURITY_REALCODE_RUNS_DIR points the gate at another directory of runs (a test uses it to show that a worsened run fails)
export const RUNS = process.env.AGENTIC_SECURITY_REALCODE_RUNS_DIR || join(HERE, 'runs');
export const BASELINE_POINTER = join(RUNS, 'BASELINE.json');
export const MAX_UNHEALTHY_SHARE = 0.1;

const readJson = (p, fb = null) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };

/** Floors from an approved baseline result. Pure. */
export function buildFloors(result, { approvedBy = null, reason, at = new Date().toISOString() } = {}) {
  if (!reason || String(reason).length < 15) throw new Error('approving a baseline needs a stated reason');
  const loc = result.scoring.definitions.localized;
  const languages = {};
  for (const [lang, g] of Object.entries(loc.byLanguage)) {
    if (g.status !== 'reportable') { languages[lang] = { entries: g.entries, status: 'insufficient_population', note: 'no floor: too few scored entries at baseline' }; continue; }
    languages[lang] = {
      entries: g.entries, status: 'floor',
      recallFloor: g.recallInterval.status === 'measured' ? g.recallInterval.low : null,
      precisionFloor: g.precisionInterval.status === 'measured' ? g.precisionInterval.low : null,
      baseline: { recall: g.recall.value, precision: g.precision.value, f1: g.f1 },
    };
  }
  return {
    schemaVersion: 1, kind: 'agentic-security/realcode-floors',
    derivedFrom: { runId: result.runId, engineVersion: result.engineVersion, commit: result.identity?.sourceCommit ?? null, bundleSha256: result.identity?.bundleSha256 ?? null, measurementValid: result.identity?.measurementValid ?? false, measuredAt: result.mergedAt },
    rule: 'floor = lower bound of the 95% Wilson interval on the baseline localized recall and precision, per language with at least the declared minimum of scored entries',
    minEntriesForComparison: MIN_ENTRIES_FOR_RATE, maxUnhealthyShare: MAX_UNHEALTHY_SHARE,
    approvedAt: at, approvedBy, reason: String(reason).slice(0, 400),
    languages,
  };
}

/** The verdict for one run against the floors. Pure. */
export function evaluate({ floors, current, tier = 'release' }) {
  const checks = []; const regressions = [];
  const done = (status, why) => ({ status, why, tier, checks, regressions, green: status === 'passed' });
  if (!floors) return done('unmeasured', 'no baseline has been approved, so there are no floors to hold');
  if (!current) return done('unmeasured', 'there is no run to check');
  const d = current.scoring?.denominators;
  if (!d) return done('blocked', 'the run carries no denominator accounting');
  checks.push({ id: 'denominators-reconcile', status: d.reconciles ? 'passed' : 'blocked', detail: d.reconciles ? 'every entry in scope is accounted for' : `${d.unaccounted} unaccounted, ${d.duplicateRows.length} duplicate, ${d.rowsNotInScope.length} out of scope` });
  const unhealthy = d.inScope ? (d.unscored + d.unaccounted) / d.inScope : 1;
  checks.push({ id: 'scan-health', status: unhealthy <= floors.maxUnhealthyShare ? 'passed' : 'blocked', detail: `${(unhealthy * 100).toFixed(1)}% of entries were unscored or unaccounted (limit ${(floors.maxUnhealthyShare * 100).toFixed(0)}%)` });
  const id = current.identity;
  checks.push({ id: 'clean-measurement', status: id && id.measurementValid ? 'passed' : (tier === 'release' ? 'blocked' : 'warning'), detail: id ? (id.measurementValid ? `clean commit ${String(id.sourceCommit).slice(0, 10)}, bundle digest matches its sidecar` : `not valid: ${id.invalidReasons.join(', ')}`) : 'no measurement identity recorded' });
  const blocking = checks.filter((c) => c.status === 'blocked');
  if (blocking.length) return done('blocked', blocking.map((c) => `${c.id}: ${c.detail}`).join('; '));

  const loc = current.scoring.definitions.localized;
  let compared = 0; let insufficient = 0;
  for (const [lang, f] of Object.entries(floors.languages)) {
    if (f.status !== 'floor') continue;
    const g = loc.byLanguage[lang];
    if (!g) { regressions.push({ language: lang, metric: 'presence', detail: 'a language with a floor is absent from the run' }); continue; }
    if (g.status !== 'reportable' || g.entries < floors.minEntriesForComparison) { insufficient++; checks.push({ id: `language:${lang}`, status: 'insufficient_population', detail: `${g.entries} scored entries, the floor needs ${floors.minEntriesForComparison}` }); continue; }
    compared++;
    const bad = [];
    if (f.recallFloor !== null && g.recall.value < f.recallFloor) bad.push({ language: lang, metric: 'recall', value: g.recall.value, floor: f.recallFloor, n: g.recall.n, d: g.recall.d });
    if (f.precisionFloor !== null && g.precision.value !== null && g.precision.value < f.precisionFloor) bad.push({ language: lang, metric: 'precision', value: g.precision.value, floor: f.precisionFloor, n: g.precision.n, d: g.precision.d });
    regressions.push(...bad);
    checks.push({ id: `language:${lang}`, status: bad.length ? 'failed' : 'passed', detail: `recall ${g.recall.value === null ? 'n/a' : (g.recall.value * 100).toFixed(1)}% (floor ${f.recallFloor === null ? 'n/a' : (f.recallFloor * 100).toFixed(1)}%), precision ${g.precision.value === null ? 'n/a' : (g.precision.value * 100).toFixed(1)}% (floor ${f.precisionFloor === null ? 'n/a' : (f.precisionFloor * 100).toFixed(1)}%)` });
  }
  if (regressions.length) return done('failed', `${regressions.length} regression(s): ${regressions.map((r) => `${r.language} ${r.metric}`).join(', ')}`);
  if (!compared) return done('insufficient_population', 'no language had enough scored entries to be compared with its floor');
  if (insufficient) return done('insufficient_population', `${compared} language(s) held their floor; ${insufficient} had too few scored entries to compare, so the run is not green`);
  return done('passed', `${compared} language(s) at or above their pre-registered floors`);
}

export function exitCodeFor(verdict) {
  if (verdict.tier === 'quick') return verdict.status === 'blocked' ? 1 : 0;
  return verdict.green ? 0 : verdict.status === 'failed' ? 1 : 2;
}

// ---- files ---------------------------------------------------------------------------------------------------------------------

export function loadBaseline(runsDir = RUNS) {
  const p = readJson(join(runsDir, 'BASELINE.json'));
  if (!p) return null;
  const floors = readJson(join(runsDir, p.floorsFile));
  return floors ? { pointer: p, floors } : null;
}

export function approve(runId, { reason, approvedBy = null, supersede = false, runsDir = RUNS } = {}) {
  const result = readJson(join(runsDir, runId, 'RESULT.json'));
  if (!result) throw new Error(`run ${runId} has no RESULT.json`);
  const existing = readJson(join(runsDir, 'BASELINE.json'));
  if (existing && !supersede) throw new Error(`a baseline (${existing.runId}) is already approved; its floors are not edited. Use --supersede with a reason to record a successor.`);
  const floors = buildFloors(result, { reason, approvedBy });
  const floorsFile = `floors-${runId}.json`;
  mkdirSync(runsDir, { recursive: true });
  atomicWriteJson(join(runsDir, floorsFile), floors);
  const pointer = { runId, floorsFile, approvedAt: floors.approvedAt, reason: floors.reason, supersedes: existing ? { runId: existing.runId, floorsFile: existing.floorsFile } : null, history: [...(existing?.history || []), ...(existing ? [{ runId: existing.runId, floorsFile: existing.floorsFile, approvedAt: existing.approvedAt }] : [])] };
  atomicWriteJson(join(runsDir, 'BASELINE.json'), pointer);
  return { pointer, floors };
}

export function latestRunId(runsDir = RUNS) {
  if (!existsSync(runsDir)) return null;
  const ids = readdirSync(runsDir, { withFileTypes: true }).filter((e) => e.isDirectory() && existsSync(join(runsDir, e.name, 'RESULT.json'))).map((e) => ({ id: e.name, at: readJson(join(runsDir, e.name, 'RESULT.json'))?.mergedAt || '' })).sort((a, b) => (a.at < b.at ? 1 : -1));
  return ids[0]?.id || null;
}

export function report(runId, { runsDir = RUNS } = {}) {
  const result = readJson(join(runsDir, runId, 'RESULT.json'));
  if (!result) return null;
  const loc = result.scoring.definitions.localized;
  const L = [`Independent run ${runId}`, `  engine ${result.engineVersion}; commit ${result.identity?.sourceCommit?.slice(0, 10) ?? 'unknown'}; measurement ${result.identity?.measurementValid ? 'valid' : `NOT valid (${(result.identity?.invalidReasons || ['no identity']).join(', ')})`}`];
  const d = result.scoring.denominators;
  L.push(`  entries in scope ${d.inScope}: scored ${d.scored}, unscored ${d.unscored}, unaccounted ${d.unaccounted}; reconciles ${d.reconciles}`);
  L.push(`  headline (localized): ${result.headline.quotable ? `precision ${(result.headline.precision.value * 100).toFixed(1)}% (${result.headline.precision.n}/${result.headline.precision.d}), recall ${(result.headline.recall.value * 100).toFixed(1)}% (${result.headline.recall.n}/${result.headline.recall.d})` : `not quotable: ${result.headline.reason}`}`);
  for (const [lang, g] of Object.entries(loc.byLanguage)) L.push(`  ${lang.padEnd(11)} ${String(g.entries).padStart(4)} scored  ${g.status === 'reportable' ? `recall ${(g.recall.value * 100).toFixed(1)}% precision ${g.precision.value === null ? 'n/a' : `${(g.precision.value * 100).toFixed(1)}%`}` : 'insufficient_population (counts only)'}`);
  return L.join('\n');
}

const arg = (a, k, d = null) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : d; };
if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, ...a] = process.argv.slice(2);
  const runsDir = a.includes('--runs-dir') ? resolve(arg(a, '--runs-dir')) : RUNS;
  try {
    if (cmd === 'approve') {
      const r = approve(arg(a, '--run'), { reason: arg(a, '--reason'), supersede: a.includes('--supersede'), runsDir });
      console.log(`baseline approved: run ${r.pointer.runId}; floors for ${Object.values(r.floors.languages).filter((l) => l.status === 'floor').length} language(s)`);
      process.exit(0);
    }
    if (cmd === 'report') {
      const id = arg(a, '--run') || loadBaseline(runsDir)?.pointer.runId || latestRunId(runsDir);
      const out = id ? report(id, { runsDir }) : null;
      console.log(out || 'no independent run has been recorded: accuracy is unmeasured');
      process.exit(out ? 0 : 0);
    }
    if (cmd === 'check') {
      const tier = arg(a, '--tier', 'release');
      const base = loadBaseline(runsDir);
      const id = arg(a, '--run') || latestRunId(runsDir);
      const current = id ? readJson(join(runsDir, id, 'RESULT.json')) : null;
      const v = evaluate({ floors: base?.floors || null, current, tier });
      console.log(`realcode ${tier}: ${v.status.toUpperCase()} - ${v.why}`);
      for (const c of v.checks) console.log(`  ${c.status.padEnd(23)} ${c.id}: ${c.detail}`);
      process.exit(exitCodeFor(v));
    }
    console.error('usage: realcode.mjs approve --run <id> --reason <text> [--supersede] | report [--run id] | check --tier quick|release [--run id]');
    process.exit(2);
  } catch (e) { console.error(`realcode: ${e.message}`); process.exit(2); }
}
