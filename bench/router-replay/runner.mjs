#!/usr/bin/env node
// Router-replay benchmark — RouterBench-style evaluation of the model-cost
// optimizer (hooks/model-cost-advisor.js) against a labelled corpus.
//
// WHY: the optimizer advises a cheaper model+depth per prompt, but until now
// nothing measured whether that advice is *good* — only that the classifier
// returns a bucket. RouterBench (arXiv:2403.12031) shows routing is easy to get
// wrong and must be scored against an oracle. This is that score.
//
// METHOD (non-circular by construction):
//   • Corpus entries carry a HUMAN `trueTier` (simple|medium|complex) — the
//     ground-truth difficulty. The oracle model for an entry is the cheapest
//     model sufficient for that tier (TIER_RECO[trueTier]).
//   • The ROUTER under test is the classifier's choice:
//     TIER_RECO[classifyTier(prompt)] — what the optimizer would steer you to.
//   • trueTier drives cost + oracle (independent of the classifier); the
//     classifier's prediction is what we grade. No feedback loop.
//
// METRICS:
//   • downgrade-regret rate (HEADLINE): fraction of prompts the router sent to a
//     model WEAKER than the oracle needs — i.e. advice that would have failed.
//   • tier accuracy, overspend rate, sufficiency (quality) with a Wilson 95% CI.
//   • hull advantage: router quality minus the non-decreasing convex hull of the
//     three single-model baselines at the router's mean cost. ≤ 0 means the
//     router is dominated by just picking one model — RouterBench's null result.
//
// HONESTY: the `trueTier` labels are hand-authored (like bench/cve-replay). This
// measures the classifier against our own judgement of difficulty, not against
// measured per-model answer quality. It is a regression gate + a sanity check on
// routing value, NOT proof of real-world quality. Replace labels with measured
// outcomes to make the AIQ real.
//
// Usage:
//   node bench/router-replay/runner.mjs                  # full report
//   node bench/router-replay/runner.mjs --json           # machine-readable
//   node bench/router-replay/runner.mjs --update-baseline # record per-entry verdicts
//   node bench/router-replay/runner.mjs --check-baseline  # gate: fail on drift

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import advisor from '../../hooks/model-cost-advisor.js';
import { wilsonInterval } from '../../scanner/src/posture/calibration.js';

const { classifyTier, TIER_RECO, estimateCost } = advisor;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = path.join(HERE, 'corpus.jsonl');
const BASELINE_PATH = path.join(HERE, 'baseline.json');

// Capability ordering (cheap → capable) and the representative effort each model
// runs at for cost purposes (mirrors TIER_RECO efforts).
const RANK = { 'claude-haiku-4-5': 0, 'claude-sonnet-4-6': 1, 'claude-opus-4-8': 2 };
const COST_EFFORT = { 'claude-haiku-4-5': null, 'claude-sonnet-4-6': 'low', 'claude-opus-4-8': 'high' };
const MODEL_ORDER = ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-8'];

function args() {
  const a = process.argv.slice(2);
  const out = { json: false, updateBaseline: false, checkBaseline: false };
  for (const x of a) {
    if (x === '--json') out.json = true;
    else if (x === '--update-baseline') out.updateBaseline = true;
    else if (x === '--check-baseline') out.checkBaseline = true;
  }
  return out;
}

function loadCorpus() {
  const raw = fs.readFileSync(CORPUS_PATH, 'utf8');
  const entries = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const e = JSON.parse(t);
    if (!e.id || !e.prompt || !TIER_RECO[e.trueTier]) {
      throw new Error(`bad corpus entry: ${t.slice(0, 80)}`);
    }
    entries.push(e);
  }
  return entries;
}

// Score one entry. Pure — no I/O.
function scoreEntry(e) {
  const oracleModel = TIER_RECO[e.trueTier].model;
  const predictedTier = classifyTier(e.prompt);
  const routerModel = TIER_RECO[predictedTier].model;

  const cost = (model) => estimateCost(model, e.trueTier, COST_EFFORT[model]);
  const routerCost = cost(routerModel);
  const sufficient = RANK[routerModel] >= RANK[oracleModel] ? 1 : 0;

  let decision;
  if (RANK[routerModel] < RANK[oracleModel]) decision = 'regret';        // under-routed → would fail
  else if (RANK[routerModel] > RANK[oracleModel]) decision = 'overspend'; // fine quality, wasted money
  else decision = 'optimal';

  return {
    id: e.id, trueTier: e.trueTier, predictedTier, oracleModel, routerModel,
    routerCost, sufficient, decision,
    tierCorrect: predictedTier === e.trueTier ? 1 : 0,
    verdict: decision === 'regret' ? 'regret' : 'pass', // baseline gate unit
    perModelCost: Object.fromEntries(MODEL_ORDER.map(m => [m, cost(m)])),
    oracleCost: cost(oracleModel),
  };
}

// Non-decreasing convex hull of (cost, quality) over the single-model baselines,
// then the quality the hull offers at an arbitrary cost (clamped/interpolated).
function hullQualityAt(points, x) {
  const pts = [...points].sort((a, b) => a.cost - b.cost);
  // non-decreasing: a later (higher-cost) point may not have lower quality
  const mono = [];
  let best = -Infinity;
  for (const p of pts) { best = Math.max(best, p.q); mono.push({ cost: p.cost, q: best }); }
  if (x <= mono[0].cost) return mono[0].q;
  if (x >= mono[mono.length - 1].cost) return mono[mono.length - 1].q;
  for (let i = 1; i < mono.length; i++) {
    if (x <= mono[i].cost) {
      const a = mono[i - 1], b = mono[i];
      const t = (x - a.cost) / (b.cost - a.cost || 1);
      return a.q + t * (b.q - a.q);
    }
  }
  return mono[mono.length - 1].q;
}

function evaluate() {
  const corpus = loadCorpus();
  const rows = corpus.map(scoreEntry);
  const n = rows.length;

  const counts = { optimal: 0, overspend: 0, regret: 0 };
  let tierCorrect = 0, suff = 0, routerCostSum = 0;
  const perModelCostSum = Object.fromEntries(MODEL_ORDER.map(m => [m, 0]));
  let oracleCostSum = 0;
  const perModelSuff = Object.fromEntries(MODEL_ORDER.map(m => [m, 0]));

  for (const r of rows) {
    counts[r.decision]++;
    tierCorrect += r.tierCorrect;
    suff += r.sufficient;
    routerCostSum += r.routerCost;
    oracleCostSum += r.oracleCost;
    for (const m of MODEL_ORDER) {
      perModelCostSum[m] += r.perModelCost[m];
      perModelSuff[m] += RANK[m] >= RANK[r.oracleModel] ? 1 : 0;
    }
  }

  const router = { meanCost: routerCostSum / n, quality: suff / n };
  const oracle = { meanCost: oracleCostSum / n, quality: 1 };
  const baselines = Object.fromEntries(MODEL_ORDER.map(m => [m, {
    meanCost: perModelCostSum[m] / n, quality: perModelSuff[m] / n,
  }]));

  const hullPoints = MODEL_ORDER.map(m => ({ cost: baselines[m].meanCost, q: baselines[m].quality }));
  const hullAtRouter = hullQualityAt(hullPoints, router.meanCost);
  const hullAdvantage = router.quality - hullAtRouter;

  const [ciLower, ciUpper] = wilsonInterval(suff, n);

  return {
    n,
    tierAccuracy: tierCorrect / n,
    regretRate: counts.regret / n,
    overspendRate: counts.overspend / n,
    optimalRate: counts.optimal / n,
    counts,
    router, oracle, baselines,
    hullAdvantage,
    sufficiencyCI: { lower: ciLower, upper: ciUpper },
    rows,
  };
}

function usd(n) { return `$${n.toFixed(4)}`; }
function pct(n) { return `${(n * 100).toFixed(1)}%`; }

function printReport(m) {
  console.log('\nRouter-replay — model-cost optimizer vs oracle');
  console.log(`  corpus: ${m.n} labelled prompts\n`);
  console.log(`  tier accuracy        ${pct(m.tierAccuracy)}`);
  console.log(`  sufficiency (quality) ${pct(m.router.quality)}  [95% CI ${pct(m.sufficiencyCI.lower)}–${pct(m.sufficiencyCI.upper)}]`);
  console.log(`  ▶ downgrade-regret    ${pct(m.regretRate)}  (${m.counts.regret}/${m.n} advised a model too weak)`);
  console.log(`  overspend            ${pct(m.overspendRate)}  (${m.counts.overspend}/${m.n})`);
  console.log(`  optimal (== oracle)  ${pct(m.optimalRate)}  (${m.counts.optimal}/${m.n})\n`);
  console.log('  cost / quality points (mean over corpus):');
  console.log(`    oracle              ${usd(m.oracle.meanCost)}  q=${pct(m.oracle.quality)}`);
  console.log(`    router (optimizer)  ${usd(m.router.meanCost)}  q=${pct(m.router.quality)}`);
  for (const model of MODEL_ORDER) {
    const b = m.baselines[model];
    console.log(`    always ${model.padEnd(18)} ${usd(b.meanCost)}  q=${pct(b.quality)}`);
  }
  const verdict = m.hullAdvantage > 0
    ? `+${pct(m.hullAdvantage)} ABOVE the single-model frontier — routing adds value`
    : `${pct(m.hullAdvantage)} — DOMINATED by a single model (RouterBench null result)`;
  console.log(`\n  hull advantage       ${verdict}`);
  console.log('\n  per-entry (predicted→router vs oracle):');
  for (const r of m.rows) {
    const flag = r.decision === 'regret' ? '✗ regret' : r.decision === 'overspend' ? '· over' : '✓ opt';
    console.log(`    ${flag.padEnd(9)} ${r.id.padEnd(26)} ${r.predictedTier}/${r.routerModel.replace('claude-', '')} vs ${r.trueTier}/${r.oracleModel.replace('claude-', '')}`);
  }
  console.log('');
}

function verdictMap(rows) {
  return Object.fromEntries(rows.map(r => [r.id, r.verdict]).sort(([a], [b]) => a.localeCompare(b)));
}

function main() {
  const opts = args();
  const m = evaluate();

  if (opts.json) { console.log(JSON.stringify(m, null, 2)); return; }

  if (opts.updateBaseline) {
    const baseline = {
      generatedAt: new Date().toISOString().slice(0, 10),
      total: m.n,
      passing: m.rows.filter(r => r.verdict === 'pass').length,
      metrics: {
        tierAccuracy: +m.tierAccuracy.toFixed(4),
        regretRate: +m.regretRate.toFixed(4),
        routerQuality: +m.router.quality.toFixed(4),
        routerMeanCost: +m.router.meanCost.toFixed(6),
        hullAdvantage: +m.hullAdvantage.toFixed(4),
      },
      entries: verdictMap(m.rows),
    };
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
    console.log(`\n✓ baseline updated: ${baseline.passing}/${baseline.total} entries no-regret → ${path.relative(process.cwd(), BASELINE_PATH)}`);
    return;
  }

  if (opts.checkBaseline) {
    if (!fs.existsSync(BASELINE_PATH)) {
      console.error(`✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run --update-baseline first.`);
      process.exit(2);
    }
    const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
    const now = verdictMap(m.rows);
    const regressed = [], newFail = [], missing = [], newPass = [];
    for (const [id, v] of Object.entries(now)) {
      const base = baseline.entries[id];
      if (base === undefined) { (v === 'pass' ? newPass : newFail).push(id); }
      else if (base === 'pass' && v !== 'pass') regressed.push(id);
    }
    for (const id of Object.keys(baseline.entries)) if (now[id] === undefined) missing.push(id);

    console.log('\nRouter-replay baseline check:');
    if (regressed.length) console.log(`  ✗ REGRESSED to downgrade-regret (${regressed.length}): ${regressed.join(', ')}`);
    if (newFail.length) console.log(`  ✗ NEW ENTRY WITH REGRET (${newFail.length}): ${newFail.join(', ')}`);
    if (missing.length) console.log(`  ✗ BASELINED ENTRY MISSING (${missing.length}): ${missing.join(', ')}`);
    if (newPass.length) console.log(`  + new no-regret entries (${newPass.length}, refresh baseline): ${newPass.join(', ')}`);
    if (regressed.length || newFail.length || missing.length) {
      console.error('\n✗ router-replay baseline drift — failing build. If intentional, run `npm run bench:router-replay:update-baseline`.');
      process.exit(1);
    }
    console.log(`  ✓ no drift — ${baseline.passing}/${baseline.total} entries still no-regret (regret rate ${pct(m.regretRate)})`);
    return;
  }

  printReport(m);
}

main();
