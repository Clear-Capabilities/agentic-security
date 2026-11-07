// Haskell coverage accounting (PRD FR 02).
//
// Answers "what actually ran" for Haskell, counted in separate stages so a
// recognised extension, a successful parse and a completed data-flow analysis
// are never conflated:
//
//   read -> parse -> ruleEvaluation -> graphInclusion -> flowAnalysis
//
// Every eligible file is in the denominator whether it parsed or not. A file
// excluded by policy, a size cap or an excluded directory is listed with its
// reason and is not eligible. Nothing here reads a file, runs a tool or
// executes project code: it summarises results the engine already produced.
//
// Pure: inputs in, one record out.

import * as path from 'node:path';
import { parseCabalFile, parseHpackFile } from './haskell-manifests.js';

export const COVERAGE_SCHEMA = 'haskell-coverage/1';
export const DEFAULT_THRESHOLDS = Object.freeze({ parseRate: 0.95, semanticRate: 0.90 });

const HS_FORM = /\.(lhs-boot|hs-boot|lhs|hs|hsig|hsc)$/i;
const norm = (p) => String(p || '').replace(/\\/g, '/');
export const formOf = (f) => { const m = HS_FORM.exec(norm(f)); return m ? m[1].toLowerCase() : null; };
const isPlainHs = (f) => formOf(f) === 'hs';

/** Rule families the Haskell pipeline can run. `needsDeep` ones only run under the IR layer. */
export const RULE_FAMILIES = Object.freeze([
  { id: 'hs-security-rules', label: 'crypto, randomness, resource, XML and sensitive-logging rules', needsDeep: false },
  { id: 'hs-web', label: 'web routes and authorization', needsDeep: false },
  { id: 'hs-llm', label: 'LLM usage rules', needsDeep: false },
  { id: 'ir-taint', label: 'interprocedural taint (SQL, command, path, SSRF, ...)', needsDeep: true },
  { id: 'hs-sca', label: 'dependency manifests and advisories', needsDeep: false },
]);

function packageIndex(files) {
  const roots = [];
  for (const [p, text] of Object.entries(files)) {
    const np = norm(p);
    const base = np.split('/').pop();
    let r = null;
    try {
      if (/\.cabal$/i.test(base)) r = parseCabalFile(text, { file: np });
      else if (base === 'package.yaml') r = parseHpackFile(text, { file: np });
    } catch { r = null; }
    if (r) roots.push({ dir: path.posix.dirname(np) === '.' ? '' : path.posix.dirname(np), name: (r.package && r.package.name) || path.posix.basename(path.posix.dirname(np)) || '(root)', manifest: np });
  }
  return roots.sort((a, b) => b.dir.length - a.dir.length);
}

function packageOf(file, index, sourceMap) {
  const f = norm(file);
  if (sourceMap && sourceMap.packages) {
    let best = null;
    for (const [name, prefixes] of Object.entries(sourceMap.packages)) {
      for (const pre of [].concat(prefixes)) {
        const p = norm(pre).replace(/\/+$/, '');
        if ((f === p || f.startsWith(p + '/')) && (!best || p.length > best.len)) best = { name, len: p.length };
      }
    }
    if (best) return { name: best.name, source: 'source-map' };
  }
  for (const r of index) if (r.dir === '' || f.startsWith(r.dir + '/')) return { name: r.name, source: 'manifest' };
  return { name: '(unassigned)', source: 'none' };
}

const rate = (n, d) => (d > 0 ? n / d : null);

/**
 * @param {object} i
 * @param {Record<string,string>} i.files       sources and manifests the scan read
 * @param {Map<string,object>|Record<string,object>} [i.parses]  file -> parseHaskell result
 * @param {object|null} [i.ir]                  buildHaskellIR result, or null when no graph was built
 * @param {boolean} i.deepEnabled
 * @param {Record<string,{ran:boolean, failed?:string, findings?:number}>} [i.ruleRuns]
 * @param {{file:string,bytes:number,cap:number}[]} [i.sizeSkipped]
 * @param {string[]} [i.policyExcluded]
 * @param {string[]} [i.excludedPaths]          language-excluded build-output paths seen
 * @param {{packages:Record<string,string|string[]>}|null} [i.sourceMap]
 * @param {{parseRate:number, semanticRate:number}} [i.thresholds]
 */
export function buildHaskellCoverage(i) {
  const files = i.files || {};
  const th = { ...DEFAULT_THRESHOLDS, ...(i.thresholds || {}) };
  const parses = i.parses instanceof Map ? i.parses : new Map(Object.entries(i.parses || {}));
  const ir = i.ir || null;
  const index = packageIndex(files);
  const byFile = {};
  const skipped = [];

  const sizeSkipped = new Map((i.sizeSkipped || []).filter((x) => formOf(x.file)).map((x) => [norm(x.file), x]));
  const policy = new Set((i.policyExcluded || []).map(norm).filter((f) => formOf(f)));
  const excl = new Set((i.excludedPaths || []).map(norm).filter((f) => formOf(f)));
  const present = Object.keys(files).map(norm).filter((f) => formOf(f));

  const add = (file, status) => { byFile[file] = { form: formOf(file), package: packageOf(file, index, i.sourceMap).name, ...status }; };

  for (const f of [...sizeSkipped.keys()]) {
    const s = sizeSkipped.get(f);
    add(f, { eligible: true, read: 'oversize', parse: 'not-attempted', ruleEvaluation: 'not-run', graphInclusion: 'not-in-graph', flowAnalysis: 'not-run', reason: `over the read cap (${s.bytes} > ${s.cap} bytes)` });
  }
  for (const f of policy) if (!byFile[f]) { add(f, { eligible: false, read: 'not-read', reason: 'default-ignored directory' }); skipped.push({ file: f, reason: 'default-ignored directory' }); }
  for (const f of excl) if (!byFile[f]) { add(f, { eligible: false, read: 'not-read', reason: 'build-output directory' }); skipped.push({ file: f, reason: 'build-output directory' }); }

  const familyRan = (id) => !!(i.ruleRuns && i.ruleRuns[id] && i.ruleRuns[id].ran);
  const staticRulesRan = familyRan('hs-security-rules') && familyRan('hs-web');

  for (const f of present.sort()) {
    if (byFile[f]) continue;
    const form = formOf(f);
    const p = parses.get(f);
    const parse = !p ? 'not-attempted' : p.status; // parsed | parsed_with_errors | failed | budget_exceeded | missing_grammar
    const parsedOk = parse === 'parsed' || parse === 'parsed_with_errors';
    // The rule modules and the IR read `.hs` only; every other form is parse-only and is said to be.
    const plain = form === 'hs';
    const ruleEvaluation = !plain ? 'unsupported-form' : !parsedOk ? 'not-run' : (staticRulesRan ? 'evaluated' : 'not-run');
    const irFile = ir && ir.perFile && ir.perFile[f];
    const graphInclusion = !plain ? 'parse-only' : (irFile ? 'included' : 'not-in-graph');
    let flowAnalysis;
    let fnDiscovered = p && Array.isArray(p.functions) ? p.functions.length : 0;
    let fnLowered = 0; let fnIncomplete = 0;
    if (irFile) {
      const fns = irFile.functions.filter((x) => !(x.hs && x.hs.kind === 'module-init'));
      fnLowered = fns.length; fnIncomplete = fns.filter((x) => x.hs && x.hs.incomplete).length;
      fnDiscovered = Math.max(fnDiscovered, fnLowered);
    }
    const capped = ir && (ir.diagnostics || []).some((d) => d.file === f && (d.kind === 'function-cap' || d.kind === 'ir-lowering-failure' || d.kind === 'ir-parse-failure'));
    if (!plain) flowAnalysis = 'unsupported-form';
    else if (!i.deepEnabled) flowAnalysis = 'not-run:deep-analysis-disabled';
    else if (graphInclusion !== 'included') flowAnalysis = 'not-run:not-in-graph';
    else if (capped || fnIncomplete > 0 || parse === 'parsed_with_errors') flowAnalysis = 'partial';
    else flowAnalysis = 'completed';
    const boundaries = p && Array.isArray(p.boundaries) ? [...new Set(p.boundaries.map((b) => b.kind))].sort() : [];
    add(f, {
      eligible: true, read: 'read', parse, ruleEvaluation, graphInclusion, flowAnalysis,
      functions: { discovered: fnDiscovered, lowered: fnLowered, incomplete: fnIncomplete },
      ...(boundaries.length ? { boundaries } : {}),
      ...(p && p.errors && p.errors.length ? { parseErrors: p.errors.length } : {}),
    });
  }

  const rows = Object.entries(byFile);
  const eligible = rows.filter(([, r]) => r.eligible);
  const eligibleHs = eligible.filter(([f]) => isPlainHs(f));

  const byForm = {};
  for (const [f, r] of rows) { const k = r.form; (byForm[k] = byForm[k] || { discovered: 0, eligible: 0, parsed: 0, parsedWithErrors: 0, failed: 0 }); byForm[k].discovered++; if (r.eligible) byForm[k].eligible++; if (r.parse === 'parsed') byForm[k].parsed++; else if (r.parse === 'parsed_with_errors') byForm[k].parsedWithErrors++; else if (r.eligible) byForm[k].failed++; }

  const byPackage = {};
  for (const [, r] of rows) {
    const e = (byPackage[r.package] = byPackage[r.package] || { discovered: 0, eligible: 0, parsed: 0, semanticComplete: 0 });
    e.discovered++; if (r.eligible) e.eligible++; if (r.parse === 'parsed') e.parsed++; if (r.flowAnalysis === 'completed') e.semanticComplete++;
  }

  const parsedHs = eligibleHs.filter(([, r]) => r.parse === 'parsed').length;
  const semanticHs = eligibleHs.filter(([, r]) => r.flowAnalysis === 'completed').length;
  const fn = { discovered: 0, lowered: 0, incomplete: 0 };
  for (const [, r] of eligible) if (r.functions) { fn.discovered += r.functions.discovered; fn.lowered += r.functions.lowered; fn.incomplete += r.functions.incomplete; }
  const unresolvedCalls = ir && ir.callGraph && Array.isArray(ir.callGraph.unresolved) ? ir.callGraph.unresolved.length : (ir ? 0 : null);

  const families = RULE_FAMILIES.map((fam) => {
    const run = (i.ruleRuns && i.ruleRuns[fam.id]) || null;
    const ranDeep = fam.needsDeep ? (i.deepEnabled && !!ir) : true;
    const ran = !!(run && run.ran) && ranDeep;
    // A caller that did not report rule runs (a direct assurance call, not an engine scan) gets 'not-reported': unknown, not a failure.
    if (!i.ruleRuns) return { id: fam.id, label: fam.label, ran: null, status: 'not-reported', findings: null };
    return { id: fam.id, label: fam.label, ran, status: ran ? 'executed' : (fam.needsDeep && !i.deepEnabled ? 'not-run:deep-analysis-disabled' : (run && run.failed ? `failed:${run.failed}` : 'not-run')), findings: run && Number.isInteger(run.findings) ? run.findings : null };
  });

  const reasons = [];
  const limitations = [];
  if (present.length + sizeSkipped.size > 0) {
    if (!i.deepEnabled) reasons.push('deep analysis is disabled: no Haskell data-flow analysis ran');
    for (const f of families) if (f.ran === false && !(f.id === 'ir-taint' && !i.deepEnabled) && f.id !== 'hs-sca') reasons.push(`rule family ${f.id} did not run (${f.status})`);
    const pr = rate(parsedHs, eligibleHs.length);
    const sr = rate(semanticHs, eligibleHs.length);
    if (pr !== null && pr < th.parseRate) reasons.push(`parse success ${(pr * 100).toFixed(1)}% is below ${(th.parseRate * 100)}% of eligible .hs files`);
    if (sr !== null && sr < th.semanticRate) reasons.push(`semantic analysis completed for ${(sr * 100).toFixed(1)}% of eligible .hs files, below ${(th.semanticRate * 100)}%`);
    const nonHs = eligible.filter(([f]) => !isPlainHs(f)).length;
    if (nonHs) limitations.push(`${nonHs} eligible file(s) in a non-.hs form (.lhs, .hs-boot, .hsig, .hsc) are parse-only: no rules or data-flow analysis`);
  }

  const incompleteEntries = eligibleHs.filter(([, r]) => r.parse !== 'parsed' || r.flowAnalysis !== 'completed')
    .map(([file, r]) => ({ file, parse: r.parse, flowAnalysis: r.flowAnalysis })).slice(0, 500);
  const mains = [];
  if (ir && ir.callGraph && ir.callGraph.functions) {
    for (const f of ir.callGraph.functions.values()) if (/\.main$/.test(f.name || '') && byFile[f.file] && byFile[f.file].flowAnalysis !== 'completed') mains.push({ name: f.name, file: f.file, flowAnalysis: byFile[f.file].flowAnalysis });
  }

  // Work completed and work remaining when a limit stopped the analysis (PRD FR 02). A file is remaining when its parse hit a
  // budget or its flow analysis did not complete. Nothing is sampled: the lists are exhaustive up to the cap, in path order, so a
  // rerun over the same inputs names the same files. `resume` says only what the scanner can do today.
  const remaining = eligibleHs.filter(([, r]) => r.parse === 'budget_exceeded' || (r.parse === 'parsed' && r.flowAnalysis !== 'completed' && r.flowAnalysis !== 'not-applicable'))
    .map(([file, r]) => ({ file, parse: r.parse, flowAnalysis: r.flowAnalysis })).sort((a, b) => (a.file < b.file ? -1 : 1));
  const budget = {
    exhausted: eligibleHs.some(([, r]) => r.parse === 'budget_exceeded'),
    completedFiles: eligibleHs.length - remaining.length,
    remainingFiles: remaining.length,
    remaining: remaining.slice(0, 500),
    remainingTruncated: remaining.length > 500,
    resume: 'rerun with --resume to reuse the files already analysed; the remaining files are not skipped silently and the capability stays incomplete until they are analysed',
  };
  const hasHaskell = present.length + sizeSkipped.size + policy.size + excl.size > 0;
  return {
    schema: COVERAGE_SCHEMA,
    present: hasHaskell,
    // `complete` only when every stage that was required ran to completion; never inferred from a zero-finding scan.
    capability: { status: !hasHaskell ? 'not-applicable' : (reasons.length || sizeSkipped.size) ? 'incomplete' : 'complete', reasons, limitations },
    totals: { discovered: rows.length, eligible: eligible.length, eligibleHs: eligibleHs.length, skipped: skipped.length },
    byForm, byPackage,
    stages: {
      parse: { success: parsedHs, partial: eligibleHs.filter(([, r]) => r.parse === 'parsed_with_errors').length, failed: eligibleHs.filter(([, r]) => !['parsed', 'parsed_with_errors'].includes(r.parse)).length, rate: rate(parsedHs, eligibleHs.length) },
      semantic: { completed: semanticHs, rate: rate(semanticHs, eligibleHs.length) },
    },
    functions: fn,
    unresolvedCalls,
    ruleFamilies: families,
    thresholds: th,
    meetsThresholds: hasHaskell ? ((rate(parsedHs, eligibleHs.length) ?? 1) >= th.parseRate && (rate(semanticHs, eligibleHs.length) ?? 1) >= th.semanticRate) : null,
    incompleteEntries,
    incompleteMains: mains,
    budget,
    skipped: skipped.slice(0, 500),
    byFile,
  };
}
