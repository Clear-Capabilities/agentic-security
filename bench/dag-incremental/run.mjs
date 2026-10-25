// DAG-05: warm versus cold deep analysis on localized edits.
//
// What it measures. The cross-scan cache (scanner/src/dataflow/incremental*.js) accelerates ONE stage
// of a scan: the interprocedural taint engine. Parsing to IR and the dependency fingerprints are
// rebuilt on every scan (the fingerprints are what the cache is validated against), and every other
// detector in a full scan is outside it. So this bench reports, with raw timings:
//
//   cold            deep analysis with the cache off
//   cold+commit     deep analysis, cache on, first run (pays fingerprinting and persistence)
//   warm-same       deep analysis after an unchanged re-scan
//   warm-edit       deep analysis after ONE localized edit, repeated for EDITS different random
//                   edits (a distribution, not a hand-picked best case)
//   ir              parse to IR + call graph (not cached; runs every scan)
//
// and, for each warm run checked, that the findings equal a fresh cold run on the same edited tree
// (a fast wrong answer is not a result).
//
//   node bench/dag-incremental/run.mjs [--files 300] [--fns 8] [--edits 8] [--reps 3]
//                                      [--self-dir scanner/src/sast] [--parity 3] [--default-budget] [--out <dir>]
//
// Raw numbers go to bench/dag-incremental/results/<label>.json. The 3x target is reported as met or
// not met per measurement; nothing is claimed that a run did not produce.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SRC = path.join(REPO, 'scanner', 'src');

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(`--${name}`); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt; };
const FILES = Number(opt('files', 300));
const FNS = Number(opt('fns', 8));
const REPS = Number(opt('reps', 3));
const EDITS = Number(opt('edits', 8));
const PARITY = Number(opt('parity', 3));
const SEED = Number(opt('seed', 20260101));
const SELF_DIR = args.includes('--self-dir') ? opt('self-dir', 'scanner/src') : (args.includes('--self-src') ? 'scanner/src' : null);
const NO_SYNTHETIC = args.includes('--no-synthetic');
const OUT = path.resolve(opt('out', path.join(HERE, 'results')));
// The CLI analyses at most 5000 functions per scan. The bench raises the limit so every function is analysed in both modes.
const FN_LIMIT = Number(opt('fn-limit', 1000000));

process.env.AGENTIC_SECURITY_DEEP_TIMEOUT_MS = process.env.AGENTIC_SECURITY_DEEP_TIMEOUT_MS || '1800000';
// The engine stops computing new callee summaries after 5000 per scan (the result is then incomplete and a cache refuses to reuse it).
// A project with more functions than that is therefore always cold by default; the bench raises the budget so the cache can be
// measured on a large project. `--default-budget` keeps the engine default and shows the cold fallback.
const DEFAULT_BUDGET = args.includes('--default-budget');
if (!DEFAULT_BUDGET) process.env.AGENTIC_SECURITY_SUMMARY_BUDGET = process.env.AGENTIC_SECURITY_SUMMARY_BUDGET || '100000000';

const { buildProjectIR } = await import(path.join(SRC, 'ir', 'index.js'));
const { runDeepAnalysis } = await import(path.join(SRC, 'dataflow', 'index.js'));

const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };
const round = (n) => Math.round(n * 10) / 10;
let seedState = SEED;
const rnd = () => { seedState = (seedState * 1664525 + 1013904223) >>> 0; return seedState / 4294967296; };

/**
 * A layered project: FILES modules, each with LAYERS layers of WIDTH functions. A function calls two
 * functions of the next layer and the leaf of the previous module, so the call graph is a DAG about
 * LAYERS + 2 deep (a call chain hundreds deep overflows the JS stack and makes even a cold run
 * non-deterministic, which would make any comparison meaningless). Every function carries a few
 * statements of string work; one in five modules has a handler that reads a request value into a SQL sink.
 */
function synthetic(files, fns) {
  const LAYERS = 4;
  const WIDTH = Math.max(1, Math.round(fns / LAYERS));
  const out = {};
  for (let i = 0; i < files; i++) {
    const lines = [];
    if (i > 0) lines.push(`const { leaf_${i - 1} } = require('./m${i - 1}');`);
    for (let l = LAYERS - 1; l >= 0; l--) {
      for (let w = 0; w < WIDTH; w++) {
        const name = `f_${i}_${l}_${w}`;
        const body = [`const a = v + ${l};`, `const b = String(a).trim();`, `let c = b.length > ${w} ? b : a;`];
        if (l === LAYERS - 1) {
          if (w === 0) lines.push(`function leaf_${i}(v) { const t = String(v); return t.trim(); }`);
          lines.push(`function ${name}(v) { ${body.join(' ')} return c; }`);
        } else {
          const callees = [`f_${i}_${l + 1}_${w}(c)`, `f_${i}_${l + 1}_${(w + 1) % WIDTH}(b)`];
          if (l === 0 && i > 0) callees.push(`leaf_${i - 1}(a)`);
          lines.push(`function ${name}(v) { ${body.join(' ')} const d = ${callees.join(' + ')}; return d; }`);
        }
      }
    }
    if (i % 5 === 0) lines.push(`function entry_${i}(req, res) { const q = f_${i}_0_0(req.query.id); db.query("SELECT * FROM t WHERE a = " + q); }`);
    else lines.push(`function entry_${i}(v) { return f_${i}_0_0(v); }`);
    lines.push(`module.exports = { entry_${i}, leaf_${i} };`);
    out[`src/m${i}.js`] = lines.join('\n') + '\n';
  }
  return out;
}

function selfTree(dir) {
  const out = {};
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p); }
      else if (/\.js$/.test(e.name)) out[path.relative(REPO, p).split(path.sep).join('/')] = fs.readFileSync(p, 'utf8');
    }
  };
  walk(path.join(REPO, dir));
  return out;
}

/** EDITS random localized edits: in a random file, the first `return <expr>;` becomes `return String(<expr>);`. */
function randomEdits(files, count) {
  const keys = Object.keys(files).filter((k) => /\n\s*(?:\w[^\n]*\{\s*)?return [^;\n]+;/.test(files[k]));
  const edits = [];
  let guard = 0;
  while (edits.length < count && guard++ < count * 50) {
    const k = keys[Math.floor(rnd() * keys.length)];
    if (edits.some((e) => e.file === k)) continue;
    const next = files[k].replace(/(return )([^;\n]+);/, '$1String($2);');
    if (next === files[k]) continue;
    edits.push({ file: k, files: { ...files, [k]: next } });
  }
  return edits;
}

const normalize = (list) => list.map((f) => JSON.stringify({ ...f, cacheProvenance: undefined })).sort();

function freshRoot(label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `dag05-${label}-`));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"bench","version":"1.0.0"}');
  return root;
}

function stage(files, root, incremental) {
  const t0 = performance.now();
  const { perFile, callGraph } = buildProjectIR(files);
  const t1 = performance.now();
  if (incremental) process.env.AGENTIC_SECURITY_INCREMENTAL = '1'; else delete process.env.AGENTIC_SECURITY_INCREMENTAL;
  const findings = runDeepAnalysis(perFile, callGraph, { scanRoot: root, fileContents: files, fnLimit: FN_LIMIT });
  const t2 = performance.now();
  return { findings, irMs: t1 - t0, deepMs: t2 - t1, functions: callGraph.functions.size };
}

function copyDir(from, to) { fs.rmSync(to, { recursive: true, force: true }); fs.cpSync(from, to, { recursive: true }); }

function summarize(st) {
  if (!st) return null;
  return {
    mode: st.mode, reason: st.reason, provenance: st.provenance,
    invalidation: st.invalidation && { clean: st.invalidation.cleanFunctions, dirty: st.invalidation.dirtyFunctions, byReason: st.invalidation.dirtyByReason },
    timing: st.timing, model: st.model && { functions: st.model.functions, edges: st.model.edges, coupled: st.model.coupled, fingerprintMs: st.model.fingerprintMs }, persistedMs: st.persisted && st.persisted.ms,
  };
}

function measure(label, base, kind) {
  const edits = randomEdits(base, EDITS);
  const result = { label, kind, summaryBudget: DEFAULT_BUDGET ? 'engine default (5000)' : process.env.AGENTIC_SECURITY_SUMMARY_BUDGET, files: Object.keys(base).length, functions: null, reps: REPS, edits: edits.length, runs: {}, perEdit: [] };
  const coldRoot = freshRoot('cold');
  const coldRuns = [];
  for (let r = 0; r < REPS; r++) coldRuns.push(stage(base, coldRoot, false));
  result.functions = coldRuns[0].functions;
  result.runs.cold = { irMs: coldRuns.map((x) => round(x.irMs)), deepMs: coldRuns.map((x) => round(x.deepMs)) };
  const coldBaseNorm = normalize(coldRuns[0].findings);

  const root = freshRoot('warm');
  const first = stage(base, root, true);
  result.runs.coldCommit = { irMs: [round(first.irMs)], deepMs: [round(first.deepMs)], stats: summarize(first.findings._incrementalStats) };
  const snapshot = path.join(os.tmpdir(), `dag05-snap-${process.pid}-${label}`);
  copyDir(path.join(root, '.agentic-security', 'incremental'), snapshot);

  const sameRuns = [];
  for (let r = 0; r < REPS; r++) { copyDir(snapshot, path.join(root, '.agentic-security', 'incremental')); sameRuns.push(stage(base, root, true)); }
  result.runs.warmSame = { irMs: sameRuns.map((x) => round(x.irMs)), deepMs: sameRuns.map((x) => round(x.deepMs)), stats: summarize(sameRuns[0].findings._incrementalStats) };
  const sameParity = JSON.stringify(normalize(sameRuns[0].findings)) === JSON.stringify(coldBaseNorm);

  let parityChecked = 0; let parityOk = sameParity;
  const coldDeep = median(result.runs.cold.deepMs); const coldIr = median(result.runs.cold.irMs);
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i];
    const runs = [];
    for (let r = 0; r < REPS; r++) { copyDir(snapshot, path.join(root, '.agentic-security', 'incremental')); runs.push(stage(e.files, root, true)); }
    const deepMs = median(runs.map((x) => x.deepMs)); const irMs = median(runs.map((x) => x.irMs));
    const rec = {
      file: e.file, deepMs: round(deepMs), irMs: round(irMs),
      deepSpeedup: round(coldDeep / deepMs), endToEndSpeedup: round((coldIr + coldDeep) / (irMs + deepMs)),
      stats: summarize(runs[0].findings._incrementalStats),
    };
    if (i < PARITY) {
      const cold = stage(e.files, freshRoot('c-edit'), false);
      rec.parityWithCold = JSON.stringify(normalize(runs[0].findings)) === JSON.stringify(normalize(cold.findings));
      parityChecked++; parityOk = parityOk && rec.parityWithCold;
    }
    result.perEdit.push(rec);
  }
  const ds = result.perEdit.map((r) => r.deepSpeedup); const es = result.perEdit.map((r) => r.endToEndSpeedup);
  const warmDeeps = result.perEdit.map((r) => r.deepMs);
  result.summary = {
    coldDeepMsMedian: coldDeep, coldIrMsMedian: coldIr,
    warmSameDeepMsMedian: median(result.runs.warmSame.deepMs), warmSameDeepSpeedup: round(coldDeep / median(result.runs.warmSame.deepMs)),
    warmEditDeepMsMedian: median(warmDeeps),
    deepSpeedup: { median: median(ds), min: Math.min(...ds), max: Math.max(...ds) },
    endToEndSpeedup: { median: median(es), min: Math.min(...es), max: Math.max(...es) },
    targetSpeedup: 3,
    editsMeetingTarget: { deepStage: `${ds.filter((x) => x >= 3).length}/${ds.length}`, endToEnd: `${es.filter((x) => x >= 3).length}/${es.length}` },
    metTargetAtMedian: { deepStage: median(ds) >= 3, endToEnd: median(es) >= 3 },
    parity: { editsChecked: parityChecked, unchangedRescanEqualsCold: sameParity, holds: parityOk },
  };
  fs.rmSync(snapshot, { recursive: true, force: true });
  return result;
}

fs.mkdirSync(OUT, { recursive: true });
const results = [];
if (!NO_SYNTHETIC) results.push(measure(`synthetic-${FILES}x${FNS}`, synthetic(FILES, FNS), 'generated layered project'));
if (SELF_DIR) results.push(measure(`self-${SELF_DIR.replace(/[\\/]/g, '-')}`, selfTree(SELF_DIR), `this repository's ${SELF_DIR}`));
for (const r of results) {
  const file = path.join(OUT, `${r.label}${DEFAULT_BUDGET ? '-default-budget' : ''}.json`);
  fs.writeFileSync(file, JSON.stringify({ ...r, node: process.version, platform: `${process.platform}-${process.arch}`, cpus: os.cpus().length, seed: SEED, generatedBy: 'bench/dag-incremental/run.mjs' }, null, 2) + '\n');
  const s = r.summary;
  const met = (b) => (b ? 'met' : 'NOT met');
  console.log(`${r.label}: ${r.files} files, ${r.functions} functions, ${r.edits} random edits, ${REPS} reps each`);
  console.log(`  cold deep stage ${s.coldDeepMsMedian} ms (ir ${s.coldIrMsMedian} ms); warm, nothing changed: ${s.warmSameDeepMsMedian} ms (${s.warmSameDeepSpeedup}x)`);
  console.log(`  deep stage   warm-edit median ${s.warmEditDeepMsMedian} ms; speedup median ${s.deepSpeedup.median}x (min ${s.deepSpeedup.min}x, max ${s.deepSpeedup.max}x); edits at or over 3x: ${s.editsMeetingTarget.deepStage}; target at median: ${met(s.metTargetAtMedian.deepStage)}`);
  console.log(`  end to end   speedup median ${s.endToEndSpeedup.median}x (min ${s.endToEndSpeedup.min}x, max ${s.endToEndSpeedup.max}x); edits at or over 3x: ${s.editsMeetingTarget.endToEnd}; target at median: ${met(s.metTargetAtMedian.endToEnd)}`);
  console.log(`  parity with a cold run: ${s.parity.holds ? 'holds' : 'FAILS'} (${s.parity.editsChecked} edits + unchanged re-scan)`);
  console.log(`  wrote ${path.relative(REPO, file)}`);
}
process.exit(results.every((r) => r.summary.parity.holds) ? 0 : 1);
