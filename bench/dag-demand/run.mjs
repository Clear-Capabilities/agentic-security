#!/usr/bin/env node
// DAG-02 benchmark: full-analysis vs demand-driven sink-query analysis.
//
// Workloads
//   synthetic  a generated multi-module project (many independent feature
//              modules plus a shared utility module with high fan-in)
//   own        the repository's own scanner/src tree (902 files at the time of
//              writing), a real, irregular code base with few real flows
//
// For each workload it measures
//   full_ms          one complete runTaintEngine over every function (what a
//                    sink question costs when nothing is selected); median of
//                    --repeat runs
//   demand_ms        per sink query: frontier build + runTaintEngine over the
//                    selected region; median of --repeat runs per query
//   speedup_single   full_ms / median(demand_ms)  (answering ONE sink question
//                    cold, the comparison the PRD target is about)
//   break_even       how many distinct queries the demand total takes before it
//                    costs as much as one full run that answers all of them
//   parity           every sampled query's demand findings vs the full run's
//   lost coverage    queries that fell back to full, ended partial, or carry
//                    unresolved callees
//
// Parsing and call-graph construction are shared by both modes and are timed
// but excluded from both sides. Raw numbers go to bench/dag-demand/results/.
// Nothing here is asserted: a speedup below the 2x target is reported as is.
//
// Usage: node bench/dag-demand/run.mjs [--modules 120] [--queries 30] [--repeat 3] [--skip-own] [--out <dir>]

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SCANNER = path.join(REPO, 'scanner');
const { programFromFiles } = await import(path.join(SCANNER, 'test/helpers/demand-programs.js'));
const D = await import(path.join(SCANNER, 'src/dataflow/demand-query.js'));
const { runTaintEngine } = await import(path.join(SCANNER, 'src/dataflow/engine.js'));

const argv = process.argv.slice(2);
const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
const MODULES = Number(arg('modules', 120));
const QUERIES = Number(arg('queries', 30));
const REPEAT = Number(arg('repeat', 3));
const SKIP_OWN = argv.includes('--skip-own');
const OUT = arg('out', path.join(HERE, 'results'));

const now = () => Number(process.hrtime.bigint()) / 1e6;
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); const n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; };
const timeIt = (fn) => { const t = now(); const v = fn(); return [now() - t, v]; };

// ---------------------------------------------------------------- synthetic
function syntheticFiles(m) {
  const files = {};
  files['util.js'] = [
    "'use strict';",
    'function trim(x) { return x; }',
    'function wrap(x) { return x; }',
    'function tag(x) { return x; }',
    'module.exports = { trim, wrap, tag };',
  ].join('\n') + '\n';
  for (let i = 0; i < m; i++) {
    const L = [];
    L.push("const cp = require('child_process');");
    L.push("const util = require('./util');");
    L.push(`function load_${i}(req) { return req.query.q_${i}; }`);
    L.push(`function normalize_${i}(x) { return util.trim(x); }`);
    L.push(`function run_${i}(c) { cp.exec(c); }`);
    L.push(`function handler_${i}(req, res) { const v = load_${i}(req); run_${i}(normalize_${i}(v)); }`);
    L.push(`function audit_${i}() { cp.exec('audit-${i}'); }`);
    L.push(`function cleanRun_${i}() { run_${i}('static-${i}'); }`);
    L.push(`function render_${i}(res, t) { res.send('<p>' + t + '</p>'); }`);
    L.push(`function page_${i}(req, res) { render_${i}(res, req.query.t_${i}); }`);
    for (let j = 0; j < 7; j++) L.push(`function filler_${i}_${j}(a, b) { const c = a + b; return util.wrap(c) + '${j}'; }`);
    L.push(`function chain_${i}(a) { return filler_${i}_0(a, filler_${i}_1(a, filler_${i}_2(a, 'k'))); }`);
    L.push(`function config_${i}() { return { a: chain_${i}('x'), b: util.tag('y') }; }`);
    files[`mod_${i}.js`] = L.join('\n') + '\n';
  }
  return files;
}

function runWorkload(name, files, opts = {}) {
  const log = (...a) => console.log(`[${name}]`, ...a);
  const [parseMs, prog] = timeIt(() => programFromFiles(files));
  const functions = prog.callGraph.functions.size;
  log(`files=${Object.keys(files).length} functions=${functions} parse+callgraph=${parseMs.toFixed(0)}ms`);
  const engineOpts = { fnLimit: 1e6 };
  const [digestMs] = timeIt(() => D.graphDigest(prog.callGraph));
  // one-time selector index (incoming call sites for the whole graph); cached per call graph
  const [indexMs] = timeIt(() => D.buildIncomingIndex(prog.callGraph));

  const sinkQueries = D.enumerateSinkQueries(prog.callGraph);
  // deterministic pseudo-random sample (seeded LCG shuffle) so the sample is not
  // aligned with the generator's per-module layout
  const order = sinkQueries.map((_, i) => i);
  let seed = 12345;
  for (let i = order.length - 1; i > 0; i--) { seed = (seed * 1103515245 + 12345) % 2147483648; const j = seed % (i + 1); [order[i], order[j]] = [order[j], order[i]]; }
  const sample = order.slice(0, QUERIES).sort((a, b) => a - b).map((i) => sinkQueries[i]);

  const fullTimes = [];
  let fullRaw = null;
  for (let r = 0; r < REPEAT; r++) {
    const [ms, raw] = timeIt(() => runTaintEngine(prog.perFileIR, prog.callGraph, engineOpts));
    fullTimes.push(ms); fullRaw = raw;
  }
  const fullMs = median(fullTimes);
  log(`full runs ms=${fullTimes.map((x) => x.toFixed(0)).join(',')} findings=${fullRaw.length} sinks=${sinkQueries.length} sampled=${sample.length}`);

  const rows = [];
  for (const q of sample) {
    const times = [];
    let res = null;
    for (let r = 0; r < REPEAT; r++) {
      const [ms, v] = timeIt(() => D.runDemandSinkQuery(prog.perFileIR, prog.callGraph, q, { cache: false, graphDigest: 'bench', configDigest: 'bench', engineOpts }));
      times.push(ms); res = v;
    }
    // the full reference answer comes from the single full run above, filtered the same way
    const ref = D.runFullSinkQuery(prog.perFileIR, prog.callGraph, q, { graphDigest: 'bench', configDigest: 'bench', engine: () => fullRaw });
    const cmp = D.compareToFull(res, ref);
    rows.push({
      file: q.file, line: q.line, sinkId: q.sinkId,
      demandMs: median(times), demandRunsMs: times,
      selected: res.analyzedFunctions, total: res.selectorCoverage.totalFunctions,
      selectedFraction: res.selectorCoverage.selectedFraction,
      fallback: res.fallback ? res.fallback.reason : null,
      verdict: res.verdict, status: res.completion.status, reasons: res.completion.reasons,
      findings: res.findings.length, parity: cmp.equal,
      unresolvedCallees: res.selectorCoverage.unresolvedCallees.length,
    });
  }
  // The same sample answered as ONE batch (runDemandQueries): fallbacks share a
  // single full engine run. Measured, not derived; compared with answering every
  // question independently (the sum of the single-query medians above) and with
  // running the full analysis once.
  const batchTimes = [];
  let batchRes = null;
  for (let r = 0; r < REPEAT; r++) {
    const [ms, v] = timeIt(() => D.runDemandQueries(prog.perFileIR, prog.callGraph, sample, { cache: false, graphDigest: 'bench', configDigest: 'bench', engineOpts }));
    batchTimes.push(ms); batchRes = v;
  }
  const batchMs = median(batchTimes);
  const batchParity = batchRes.every((res, i) => D.compareToFull(res, D.runFullSinkQuery(prog.perFileIR, prog.callGraph, sample[i], { graphDigest: 'bench', configDigest: 'bench', engine: () => fullRaw })).equal);
  const dem = rows.map((r) => r.demandMs);
  const demMedian = median(dem);
  const demMean = dem.reduce((a, b) => a + b, 0) / (dem.length || 1);
  const summary = {
    workload: name,
    files: Object.keys(files).length, functions, sinkSites: sinkQueries.length, sampledQueries: rows.length,
    parseAndCallGraphMs: parseMs, graphDigestMs: digestMs, incomingIndexMs: indexMs,
    fullMs, fullRunsMs: fullTimes,
    demandMedianMs: demMedian, demandMeanMs: demMean,
    demandMinMs: Math.min(...dem), demandMaxMs: Math.max(...dem),
    speedupSingleQuery: fullMs / demMedian,
    speedupSingleQueryMean: fullMs / demMean,
    speedupSingleQueryColdIndex: fullMs / (demMedian + indexMs),
    // the strictest single-query figure: also pays the graph digest a first query computes
    speedupSingleQueryColdAll: fullMs / (demMedian + indexMs + digestMs),
    // fallbacks included: the mean over the sample, one index and digest paid on top
    speedupMeanColdAll: fullMs / (demMean + indexMs + digestMs),
    batchMeasuredMs: batchMs, batchRunsMs: batchTimes, batchParity,
    batchVsIndependent: dem.reduce((a, b) => a + b, 0) / batchMs,
    batchVsFullOnce: fullMs / batchMs,
    breakEvenQueries: fullMs / demMean,
    batchSpeedup: fullMs / (demMean * rows.length),
    batchSpeedupIncludingIndex: fullMs / (indexMs + demMean * rows.length),
    meanSelectedFraction: rows.reduce((a, r) => a + r.selectedFraction, 0) / (rows.length || 1),
    parityAll: rows.every((r) => r.parity),
    parityFailures: rows.filter((r) => !r.parity).length,
    lostCoverage: {
      fellBackToFull: rows.filter((r) => r.fallback).length,
      partial: rows.filter((r) => r.status === 'partial').length,
      withUnresolvedCallees: rows.filter((r) => r.unresolvedCallees > 0).length,
      negativeClaimWithheld: rows.filter((r) => r.verdict === 'unknown').length,
    },
    queriesWithFlow: rows.filter((r) => r.findings > 0).length,
  };
  log(`full=${fullMs.toFixed(0)}ms demand median=${demMedian.toFixed(1)}ms mean=${demMean.toFixed(1)}ms speedup(single warm index)=${summary.speedupSingleQuery.toFixed(2)}x cold-index=${summary.speedupSingleQueryColdIndex.toFixed(2)}x index=${indexMs.toFixed(0)}ms cold-all=${summary.speedupSingleQueryColdAll.toFixed(2)}x mean+index=${summary.speedupMeanColdAll.toFixed(2)}x batch(${rows.length}) measured=${batchMs.toFixed(0)}ms (${summary.batchVsIndependent.toFixed(2)}x vs independent, ${summary.batchVsFullOnce.toFixed(2)}x vs one full run, parity=${batchParity}) parity=${summary.parityAll} fallbacks=${summary.lostCoverage.fellBackToFull} partial=${summary.lostCoverage.partial}`);
  return { summary, rows };
}

// -------------------------------------------------------------------- main
const results = { schema: 'dag-demand-bench/1', node: process.version, startedAt: new Date().toISOString(), params: { MODULES, QUERIES, REPEAT, SKIP_OWN }, workloads: [] };
results.workloads.push(runWorkload(`synthetic-${MODULES}-modules`, syntheticFiles(MODULES)));

if (!SKIP_OWN) {
  const files = {};
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (e.name.endsWith('.js')) files[path.relative(SCANNER, p)] = fs.readFileSync(p, 'utf8'); } };
  walk(path.join(SCANNER, 'src'));
  results.workloads.push(runWorkload('own-scanner-src', files));
}

results.finishedAt = new Date().toISOString();
const TARGET = 2; // judged on the conservative cold-index single-query figure
results.target = { speedup: TARGET, note: 'PRD DAG-02 target: at least 2x faster sink-query analysis than the full-analysis baseline. A miss is reported, not hidden.' };
for (const w of results.workloads) w.summary.meetsTarget = w.summary.speedupSingleQueryColdIndex >= TARGET && w.summary.parityAll;
fs.mkdirSync(OUT, { recursive: true });
const file = path.join(OUT, 'latest.json');
fs.writeFileSync(file, JSON.stringify(results, null, 2) + '\n');
console.log(`wrote ${path.relative(REPO, file)}`);
for (const w of results.workloads) {
  const s = w.summary;
  console.log(`${s.workload}: single-query speedup ${s.speedupSingleQuery.toFixed(2)}x warm / ${s.speedupSingleQueryColdIndex.toFixed(2)}x cold-index (target ${TARGET}x, ${s.meetsTarget ? 'MET' : 'NOT MET'}); batch speedup ${s.batchSpeedup.toFixed(2)}x; parity ${s.parityAll ? 'all equal' : s.parityFailures + ' differ'}`);
}
