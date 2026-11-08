export const id = 5856;
export const ids = [5856];
export const modules = {

/***/ 25856:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  assessLanguageAssurance: () => (/* binding */ assessLanguageAssurance)
});

// UNUSED EXPORTS: ASSURANCE_VERSION, OPTIONAL_MODES, REQUIRED_CAPABILITIES

// EXTERNAL MODULE: ./src/language/contracts.js
var contracts = __webpack_require__(43790);
// EXTERNAL MODULE: ./src/language/haskell-parser.js + 1 modules
var haskell_parser = __webpack_require__(99864);
// EXTERNAL MODULE: ./src/language/haskell-grammar.js
var haskell_grammar = __webpack_require__(50029);
;// CONCATENATED MODULE: ./src/language/haskell-adapter.js
// Adapter that plugs the Haskell parser into the language pipeline contracts
// (CORE-003), so parse outcomes reach scan health instead of staying inside the
// parser. A missing or corrupt grammar becomes `missing_grammar`, a budget bound
// becomes `timed_out` (deadline) or `unresolved` (size/depth), and syntax errors
// and opaque boundaries become `unresolved-branch` outcomes. Findings from other
// languages are never touched.





const HASKELL_PARSE_PRODUCER = 'language:haskell-parse';

// Boundaries whose content the parser could not see. cpp and ffi are disclosed on
// the parse result but do not make the file unresolved: both CPP branches are
// parsed and a foreign declaration's own Haskell signature is. `th-safe-splice` and `quasiquote-inert` are matched by a
// closed, sound pattern (haskell-boundaries.js) and stay disclosed as assumptions; every other TH/quasi-quote boundary is opaque.
const OPAQUE_BOUNDARIES = new Set(['th-splice', 'th-quote', 'th-name-quote', 'th-top-level-splice', 'quasiquote', 'hsc', 'generated']);

function ensureHaskellParseProducer() {
  if (!(0,contracts/* isRegisteredLanguageProducer */.dO)(HASKELL_PARSE_PRODUCER)) {
    (0,contracts/* registerLanguageProducer */.OQ)({ id: HASKELL_PARSE_PRODUCER, language: 'haskell', capability: 'parse', evidenceKinds: ['source'], version: '1' });
  }
  return HASKELL_PARSE_PRODUCER;
}

/**
 * @param {{grammarSource?:Function, budgets?:object, mode?:string, cpp?:object, onParse?:(file:string, parse:object)=>void}} [opts]
 */
function createHaskellAdapter(opts = {}) {
  ensureHaskellParseProducer();
  return {
    id: HASKELL_PARSE_PRODUCER,
    language: 'haskell',
    hasGrammar: () => (0,haskell_grammar/* loadHaskellGrammar */.UP)({ grammarSource: opts.grammarSource }).available,
    analyze(file, content) {
      const parse = (0,haskell_parser/* parseHaskell */.cX)(content, { file, grammarSource: opts.grammarSource, budgets: opts.budgets, mode: opts.mode, cpp: opts.cpp });
      if (typeof opts.onParse === 'function') opts.onParse(file, parse);
      if (parse.status === 'budget_exceeded' && parse.budget && parse.budget.name === 'deadlineMs') {
        throw Object.assign(new Error(`Haskell parser deadline exceeded for ${file}`), { code: 'LANG_TIMEOUT' });
      }
      const unresolved = [];
      if (parse.status === 'budget_exceeded') unresolved.push({ line: 1, reason: `parser budget exceeded: ${parse.budget.name}` });
      else if (parse.status === 'failed') throw new Error(parse.errors[0] ? parse.errors[0].detail : 'Haskell parse failed');
      else {
        for (const e of parse.errors) unresolved.push({ line: e.span ? e.span.startLine : 1, reason: `syntax-error: ${e.kind}` });
        for (const b of parse.boundaries) if (OPAQUE_BOUNDARIES.has(b.kind)) unresolved.push({ line: b.span.startLine, reason: `opaque-boundary: ${b.kind}` });
      }
      return { findings: [], unresolved, parse };
    },
  };
}

// EXTERNAL MODULE: ./src/language/haskell-cpp.js
var haskell_cpp = __webpack_require__(92777);
// EXTERNAL MODULE: ./src/language/nix-ir.js
var nix_ir = __webpack_require__(67772);
// EXTERNAL MODULE: ./src/language/nix-grammar.js
var nix_grammar = __webpack_require__(46910);
;// CONCATENATED MODULE: ./src/language/nix-adapter.js
// Adapter that plugs the Nix parser and config IR into the language pipeline
// contracts (CORE-003), so parse outcomes reach scan health instead of staying
// inside the parser. A missing or corrupt grammar becomes `missing_grammar`, a
// deadline hit becomes `timed_out`, and syntax errors, dynamic attributes,
// dynamic imports, lazy recursion and IR/parser budget hits become `unresolved`
// outcomes. Findings from other languages are never touched.





const NIX_PARSE_PRODUCER = 'language:nix-parse';

function ensureNixParseProducer() {
  if (!(0,contracts/* isRegisteredLanguageProducer */.dO)(NIX_PARSE_PRODUCER)) {
    (0,contracts/* registerLanguageProducer */.OQ)({ id: NIX_PARSE_PRODUCER, language: 'nix', capability: 'parse', evidenceKinds: ['source'], version: '1' });
  }
  return NIX_PARSE_PRODUCER;
}

/**
 * @param {{grammarSource?:Function, budgets?:object, irBudgets?:object, onParse?:(file:string, result:object)=>void}} [opts]
 */
function createNixAdapter(opts = {}) {
  ensureNixParseProducer();
  return {
    id: NIX_PARSE_PRODUCER,
    language: 'nix',
    hasGrammar: () => (0,nix_grammar/* loadNixGrammar */.T$)({ grammarSource: opts.grammarSource }).available,
    analyze(file, content) {
      const result = (0,nix_ir/* analyzeNix */.KL)(content, { file, grammarSource: opts.grammarSource, budgets: opts.budgets, irBudgets: opts.irBudgets });
      if (typeof opts.onParse === 'function') opts.onParse(file, result);
      const { parse, ir } = result;
      if (parse.status === 'budget_exceeded' && parse.budget && parse.budget.name === 'deadlineMs') {
        throw Object.assign(new Error(`Nix parser deadline exceeded for ${file}`), { code: 'LANG_TIMEOUT' });
      }
      if (parse.status === 'failed' && !parse.errors.length) throw new Error('Nix parse failed');
      const unresolved = ir.unresolved.map((u) => ({ line: u.span ? u.span.startLine : 1, reason: `${u.kind}: ${u.detail}` }));
      return { findings: [], unresolved, parse, ir };
    },
  };
}

// EXTERNAL MODULE: ./src/language/haskell-manifests.js
var haskell_manifests = __webpack_require__(16522);
// EXTERNAL MODULE: ./src/language/haskell-models.js
var haskell_models = __webpack_require__(54084);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
;// CONCATENATED MODULE: ./src/language/haskell-coverage.js
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




const COVERAGE_SCHEMA = 'haskell-coverage/1';
const DEFAULT_THRESHOLDS = Object.freeze({ parseRate: 0.95, semanticRate: 0.90 });

const HS_FORM = /\.(lhs-boot|hs-boot|lhs|hs|hsig|hsc)$/i;
const norm = (p) => String(p || '').replace(/\\/g, '/');
const formOf = (f) => { const m = HS_FORM.exec(norm(f)); return m ? m[1].toLowerCase() : null; };
const isPlainHs = (f) => formOf(f) === 'hs';

/** Rule families the Haskell pipeline can run. `needsDeep` ones only run under the IR layer. */
const RULE_FAMILIES = Object.freeze([
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
      if (/\.cabal$/i.test(base)) r = (0,haskell_manifests/* parseCabalFile */.r7)(text, { file: np });
      else if (base === 'package.yaml') r = (0,haskell_manifests/* parseHpackFile */.pJ)(text, { file: np });
    } catch { r = null; }
    if (r) roots.push({ dir: external_node_path_.posix.dirname(np) === '.' ? '' : external_node_path_.posix.dirname(np), name: (r.package && r.package.name) || external_node_path_.posix.basename(external_node_path_.posix.dirname(np)) || '(root)', manifest: np });
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
function buildHaskellCoverage(i) {
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
  // rerun over the same inputs names the same files. `resume` says only what the scanner can do today (assurance.js adds the
  // effective budgets and the comparison with the previous scan's record, language/haskell-budget-state.js).
  const remaining = eligibleHs.filter(([, r]) => r.parse === 'budget_exceeded' || (r.parse === 'parsed' && r.flowAnalysis !== 'completed' && r.flowAnalysis !== 'not-applicable'))
    .map(([file, r]) => ({ file, parse: r.parse, flowAnalysis: r.flowAnalysis })).sort((a, b) => (a.file < b.file ? -1 : 1));
  const budget = {
    exhausted: eligibleHs.some(([, r]) => r.parse === 'budget_exceeded'),
    completedFiles: eligibleHs.length - remaining.length,
    remainingFiles: remaining.length,
    remaining: remaining.slice(0, 500),
    remainingTruncated: remaining.length > 500,
    // The Haskell pass parses every eligible file on every scan: nothing is reused from a previous run, so there is no resume.
    resume: { supported: false, toFinish: 'raise the named parse budget with AGENTIC_SECURITY_HASKELL_PARSE_BUDGETS (name=value,...) and rescan; a file whose flow analysis did not run needs deep analysis on. The remaining files are never skipped silently, and the capability stays incomplete until they are analysed' },
  };
  // The full list (not capped) for the persisted record in haskell-budget-state.js; non-enumerable so the report shape is unchanged.
  Object.defineProperty(budget, 'remainingAll', { value: remaining, enumerable: false });
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

// EXTERNAL MODULE: ./src/language/haskell-budget-state.js
var haskell_budget_state = __webpack_require__(80291);
// EXTERNAL MODULE: ./src/language/haskell-ir.js + 1 modules
var haskell_ir = __webpack_require__(18821);
;// CONCATENATED MODULE: ./src/language/assurance.js
// Scan health and assurance for Haskell and Nix analysis (X-007).
//
// Collects every way language analysis can be incomplete into ONE `languageCoverage` input for computeScanHealth,
// so the existing advisory / standard / strict policy and the "Safe to deploy" verdict apply unchanged:
//
//   required capabilities   parser, SAST, taint, SCA, secrets (Haskell); parser, config, taint, secrets, supply (Nix).
//                           A required capability that is disabled, unavailable or failed is a CONDITION.
//   expected static limits  an opaque boundary (Template Haskell, quasi-quotes, FFI, CPP, hsc) is a documented limit
//                           of a static analysis, not a failure. It is listed under `limitations`, never as a
//                           condition, and never hides the files it touches (they stay `unresolved` in the ledger).
//   optional modes          nix-eval, cabal-plan, hackage-live. Their state is separate: `not_selected` (no
//                           condition), `not_run` (selected but absent: a condition, never reported as run), `failed`
//                           (a condition; static findings are retained untouched), `ok`.
//   data currency           a stale or missing advisory snapshot, a malformed manifest, a partial effective NixOS
//                           configuration.
//
// Independent findings are never dropped here: this module only produces health inputs and returns the findings it
// was given by reference, with a count, so a caller can prove retention.












const ASSURANCE_VERSION = 'language-assurance/1';

const REQUIRED_CAPABILITIES = Object.freeze({
  haskell: Object.freeze(['parser', 'sast', 'taint', 'sca', 'secrets']),
  nix: Object.freeze(['parser', 'config', 'taint', 'secrets', 'supply']),
});
const OPTIONAL_MODES = Object.freeze(['nix-eval', 'cabal-plan', 'hackage-live']);

const MALFORMED_MANIFEST = new Set(['malformed_manifest', 'malformed_yaml', 'parser_failure', 'read_failed', 'malformed_dependency', 'malformed_lock_entry', 'malformed_constraint', 'malformed_extra_dep', 'invalid_version_range', 'empty_manifest']);
const LANGS = Object.keys(REQUIRED_CAPABILITIES);
const langOf = (f) => (/\.l?hs$|\.hs-boot$|\.hsc$/i.test(f) ? 'haskell' : /\.nix$/i.test(f) ? 'nix' : null);
const isManifest = (f) => /(?:^|\/)(?:[^/]+\.cabal|cabal\.project(?:\.freeze|\.local)?|package\.yaml|stack\.yaml(?:\.lock)?)$/i.test(f);

function optionalState(name, cfg) {
  const c = cfg && cfg[name];
  if (!c || !c.selected) return { name, selected: false, status: 'not_selected', ran: false, reason: 'the mode is opt-in and was not selected', condition: null };
  const r = c.result;
  if (!r) return { name, selected: true, status: 'not_run', ran: false, reason: c.reason || 'selected, but no result was produced', condition: `optional mode "${name}" was selected but did not run` };
  if (r.status === 'ok' && r.ran !== false) return { name, selected: true, status: 'ok', ran: true, reason: null, condition: null };
  return { name, selected: true, status: r.status || 'failed', ran: false, reason: r.reason || null, condition: `optional mode "${name}" ${r.status === 'timed_out' ? 'timed out' : 'failed'}${r.reason ? ` (${r.reason})` : ''}; static results are retained` };
}

/**
 * @param {object} input
 * @param {Record<string,string>} input.files      rel path -> content: sources and manifests
 * @param {object[]} [input.adapters]              override the default parse adapters (tests inject hung or corrupt ones)
 * @param {number}  [input.timeoutMs]              per-file adapter deadline
 * @param {string[]} [input.disabled]              capability ids switched off, "<language>:<capability>"
 * @param {Record<string,string[]>} [input.required]  override of REQUIRED_CAPABILITIES
 * @param {object|null} [input.advisoryDb]         a Hackage AdvisoryDb (haskell-sca.js), or null when none loaded
 * @param {object[]} [input.effectiveConfigs]      NixOS effective-config reports (nixos-module-resolver.js)
 * @param {Record<string,{selected:boolean, result?:object, reason?:string}>} [input.optional]
 * @param {object[]} [input.findings]              findings already produced; returned untouched
 */
async function assessLanguageAssurance(input = {}) {
  const files = input.files || {};
  const present = new Set(Object.keys(files).map(langOf).filter(Boolean));
  const manifests = Object.entries(files).filter(([f]) => isManifest(f));
  if (manifests.length) present.add('haskell');
  const required = input.required || REQUIRED_CAPABILITIES;
  const disabled = new Set(input.disabled || []);
  const findings = Array.isArray(input.findings) ? input.findings : [];
  const conditions = [];
  const limitations = [];

  // 1. parse adapters over every language source
  // Boundaries that do not make a file unresolved but that a reader must be told about: CPP (every branch was parsed, the
  // chosen one is not known) and FFI (the foreign code is not analysed).
  const DISCLOSED_KINDS = new Set(['cpp', 'ffi', 'th-safe-splice', 'quasiquote-inert']);
  const disclosed = new Map();   // boundary kind -> {count, files:Set}
  const projectModules = new Set(); const importedModules = new Map();   // module -> files
  const parsesByFile = new Map();
  const onParse = (file, parse) => {
    parsesByFile.set(file, parse);
    if (parse && parse.module && parse.module.name) projectModules.add(parse.module.name);
    for (const i of (parse && parse.imports) || []) if (i && i.module) { const e = importedModules.get(i.module) || new Set(); e.add(file); importedModules.set(i.module, e); }
    for (const b of (parse && parse.boundaries) || []) {
      if (!DISCLOSED_KINDS.has(b.kind)) continue;
      const e = disclosed.get(b.kind) || { count: 0, files: new Set(), decided: 0, undecided: 0, assumptions: new Set() };
      e.count += b.count || 1; e.files.add(file);
      if (b.kind === 'cpp') { e.decided += b.decided || 0; e.undecided += b.undecided || 0; for (const a of b.assumptions || []) e.assumptions.add(a); }
      disclosed.set(b.kind, e);
    }
  };
  const adapters = input.adapters || [createHaskellAdapter({ onParse, cpp: (0,haskell_cpp/* deriveCppContext */.uP)(files), budgets: input.parseBudgets || undefined }), createNixAdapter()];
  const run = await (0,contracts/* runLanguageAnalysis */.i5)({ files, adapters, timeoutMs: input.timeoutMs || 0 });
  const reconcile = (0,contracts/* reconcileLanguageLedger */.SA)(run.ledger, files);
  const base = (0,contracts/* languageHealth */.bX)({ ledger: run.ledger, outcomes: run.outcomes });
  const byKind = { ...base.byKind };

  // outcome classification: expected static limits are not conditions
  const opaque = run.outcomes.filter((o) => o.kind === 'unresolved-branch' && /^opaque-boundary/.test(String(o.detail || '')));
  const otherUnresolved = run.outcomes.filter((o) => o.kind === 'unresolved-branch' && !/^opaque-boundary/.test(String(o.detail || '')));
  if (byKind['missing-grammar']) conditions.push(`${byKind['missing-grammar']} language file(s) skipped: grammar unavailable or corrupt`);
  if (byKind['adapter-exception']) conditions.push(`${byKind['adapter-exception']} language adapter exception(s)`);
  if (byKind['timeout']) conditions.push(`${byKind['timeout']} language file(s) timed out`);
  if (otherUnresolved.length) conditions.push(`${otherUnresolved.length} unresolved language construct(s) (syntax errors, dynamic attributes or imports)`);
  if (byKind['unregistered-producer']) conditions.push(`${byKind['unregistered-producer']} result(s) from an unregistered language producer were discarded`);
  if (opaque.length) {
    const kinds = {};
    for (const o of opaque) { const k = String(o.detail).replace(/^opaque-boundary:\s*/, ''); kinds[k] = (kinds[k] || 0) + 1; }
    for (const [k, n] of Object.entries(kinds).sort()) limitations.push({ kind: 'opaque-boundary', boundary: k, count: n, note: 'a documented limit of static analysis: this code is not analysed, and is not reported clean' });
  }
  const DISCLOSED_NOTE = {
    cpp: 'preprocessor conditionals: a conditional the file or the project decides keeps only its live branch, every other one keeps all of its branches, and which branch is compiled is then not known',
    ffi: 'foreign declarations: the foreign code is not analysed and its effects are not modelled',
    'th-safe-splice': 'declaration-level Template Haskell splices of a known generator applied to names and literals only: assumed to be the upstream generator, nothing is run and the generated declarations are not modelled',
    'quasiquote-inert': 'quasi-quotes of a known raw-string or non-interpolating quoter: read as a string literal on the assumption that the quoter is the upstream one',
  };
  for (const [k, e] of [...disclosed.entries()].sort()) {
    const extra = k === 'cpp' ? { decidedConditionals: e.decided, undecidedConditionals: e.undecided, ...(e.assumptions.size ? { assumptions: [...e.assumptions].sort() } : {}) } : {};
    const assumed = k === 'cpp' && e.assumptions.size ? `; some conditionals were decided on a stated project assumption (${[...e.assumptions].sort().join(', ')}), so a branch dead under it was not analysed` : '';
    limitations.push({ kind: 'opaque-boundary', boundary: k, count: e.count, files: [...e.files].sort().slice(0, 20), ...extra, note: `a documented limit of static analysis (${DISCLOSED_NOTE[k]}${assumed})` });
  }
  // Imported modules this scan has no model for: their functions are ordinary, opaque calls (never a source, sink or
  // sanitizer), so a taint flow through them is widened and disclosed on the finding. Listed so a reader knows how much of the
  // import surface the models cover. A limitation, not a condition: most real projects import unmodelled modules.
  const unmodeled = [...importedModules.keys()].filter((m) => !projectModules.has(m) && !(0,haskell_models/* packageOfModule */.KF)(m)).sort();
  if (unmodeled.length) limitations.push({ kind: 'unmodeled-imports', count: unmodeled.length, modules: unmodeled.slice(0, 30), note: 'no security model exists for these imported modules: their functions are analysed as ordinary calls, so a flow through them is widened and disclosed on the finding' });
  // Sources the default ignore list kept out of the scan (tests, specs, mocks, bin, build, dist, vendor): the same
  // policy every language has, but stated here so an unscanned Haskell/Nix file is never invisible.
  // Sources and manifests over the read cap were NOT analysed: unlike a default-ignored directory, that is a gap in the analysis,
  // so it is a condition (the verdict cannot be complete), listed with the path, its size and the cap.
  const sizeSkipped = Array.isArray(input.sizeSkipped) ? input.sizeSkipped : [];
  if (sizeSkipped.length) conditions.push(`${sizeSkipped.length} Haskell/Nix source or manifest file(s) exceed the size cap and were not analysed: ${sizeSkipped.slice(0, 3).map((x) => `${x.file} (${x.bytes} bytes > ${x.cap})`).join(', ')}${sizeSkipped.length > 3 ? ', ...' : ''}`);
  const policyExcluded = Array.isArray(input.policyExcluded) ? input.policyExcluded : [];
  if (policyExcluded.length) limitations.push({ kind: 'default-ignore', count: policyExcluded.length, files: policyExcluded.slice(0, 20), note: 'Haskell/Nix files under a default-ignored directory (tests, specs, mocks, bin, build, dist, vendor) are not scanned; this is the project-wide default for every language' });
  // Nix-built images and declared OCI services are not image-layer or base-image scanned: the container analyzers read
  // Dockerfile and compose SOURCE. Stated whenever such a declaration is present, so its absence from the findings is
  // never read as a clean image.
  const ociFiles = Object.entries(files).filter(([f, t]) => /\.nix$/i.test(f) && typeof t === 'string' && /oci-containers|dockerTools\.(?:buildImage|buildLayeredImage|streamLayeredImage)|virtualisation\.(?:docker|podman)/.test(t)).map(([f]) => f);
  if (ociFiles.length) limitations.push({ kind: 'container-image-scan', files: ociFiles.sort(), note: 'Nix-built images and declared OCI services are analysed as configuration only: image layers and base-image vulnerabilities are NOT scanned' });
  if (!reconcile.ok) conditions.push(`language ledger does not reconcile with the inputs: ${reconcile.errors[0]}`);

  // Buck-built Haskell: its dependency graph is not resolved by this scanner, so version-based advisory matching has nothing to match.
  // Stated as a coverage gap (PRD FR 08) rather than left looking like "no vulnerable dependencies".
  const buckHaskell = Object.entries(files).filter(([f, t]) => /(?:^|\/)(?:BUCK|TARGETS)(?:\.v2)?$/.test(f) && typeof t === 'string' && /\bhaskell_(?:library|binary|test|ghci)\b|\bprebuilt_haskell_library\b/.test(t)).map(([f]) => f).sort();
  if (present.has('haskell') && buckHaskell.length) conditions.push(`${buckHaskell.length} Buck target file(s) declare Haskell dependencies this scan does not resolve (${buckHaskell.slice(0, 3).join(', ')}): dependency advisories were not matched for them`);

  // Declared project models (PRD FR 03): a rejected declaration means a wrapper the project meant to model is still opaque.
  const pm = input.projectModels;
  if (pm && pm.present) {
    if (pm.rejected.length) conditions.push(`${pm.rejected.length} Haskell project model(s) were rejected and have no effect: ${pm.rejected.slice(0, 3).map((r) => `${r.id} (${r.reason})`).join('; ')}`);
    if (pm.accepted.length) limitations.push({ kind: 'project-models', count: pm.accepted.length, ids: pm.accepted.map((m) => m.id).sort(), note: 'wrappers modelled by reviewed project declarations (.agentic-security/haskell-models.json); each carries provenance and a paired positive and negative test' });
  }

  // 2. manifests
  if (manifests.length) {
    let m = null;
    try { m = (0,haskell_manifests/* analyzeHaskellManifests */.JS)(manifests.map(([path, text]) => ({ path, text })), {}); } catch (e) { conditions.push(`Haskell manifest analysis failed: ${String((e && e.message) || e)}`); }
    if (m) {
      const bad = m.diagnostics.filter((d) => MALFORMED_MANIFEST.has(d.kind));
      if (bad.length) conditions.push(`${bad.length} malformed Haskell manifest entr${bad.length === 1 ? 'y' : 'ies'}: ${[...new Set(bad.map((d) => d.kind))].join(', ')}`);
      if (m.coverage && m.coverage.failed) conditions.push(`${m.coverage.failed} Haskell manifest(s) could not be parsed`);
    }
  }

  // 3. advisory feed currency (only meaningful when Haskell dependencies are in play and SCA is required)
  const scaRequired = (required.haskell || []).includes('sca') && !disabled.has('haskell:sca');
  if (present.has('haskell') && scaRequired && manifests.length) {
    const db = input.advisoryDb;
    if (!db) conditions.push(`no Hackage advisory snapshot is loaded: Haskell dependency vulnerabilities were not assessed${input.advisoryReason ? `. ${input.advisoryReason}` : ''}`);
    else if (db.stale) conditions.push(`the Hackage advisory snapshot is stale (${db.ageDays == null ? 'age unknown' : `${Math.floor(db.ageDays)} day(s) old`}, limit ${db.maxAgeDays})`);
  }

  // 3b. resolved dependency data and the Nix closure: a stale, malformed or unchecked input is stated, never silently dropped
  for (const g of input.supplyGaps || []) {
    if (!g || !g.kind) continue;
    if (/unavailable|stale|malformed|failed|unverified|refused|contradicts/.test(g.kind)) conditions.push(`${g.kind.replace(/^(?:resolved|closure)-/, '')}: ${String(g.detail || '').slice(0, 220)}`);
    else limitations.push({ kind: 'supply-gap', gap: g.kind, note: String(g.detail || '').slice(0, 220) });
  }

  if (input.licenseUnavailable) limitations.push({ kind: 'license-data-unavailable', count: input.licenseUnavailable, note: 'Haskell and Nix dependency records carry no license data, so no license policy was applied to them; this is not a statement that they are acceptable' });

  // 4. effective NixOS configuration
  for (const r of input.effectiveConfigs || []) {
    if (r && r.completeness === 'partial') conditions.push(`the effective NixOS configuration for ${(r.target && r.target.name) || 'a target'} is partial: ${(r.unresolved || []).length} unresolved, ${(r.truncated || []).length} truncated`);
  }

  // 5. required capabilities
  const capabilities = {};
  for (const lang of LANGS) {
    if (!present.has(lang)) continue;
    capabilities[lang] = {};
    for (const cap of required[lang] || []) {
      const id = `${lang}:${cap}`;
      let status = 'ran'; let detail = null;
      if (disabled.has(id)) { status = 'disabled'; detail = 'switched off by configuration'; }
      else if (cap === 'parser') {
        const counts = Object.values(run.ledger.byAnalyzer).filter((a) => a.language === lang);
        const failed = counts.reduce((s, a) => s + a.failed + a.timedOut + a.missingGrammar, 0);
        if (failed) { status = 'failed'; detail = `${failed} file(s) not parsed`; }
      }
      capabilities[lang][cap] = { required: true, status, detail };
      if (status === 'disabled') conditions.push(`required analyzer "${id}" is disabled`);
    }
  }

  // 5b. Haskell coverage accounting (FR 02): per-file stages, rates against the eligible denominator, rule families executed.
  let haskellCoverage = null;
  if (present.has('haskell')) {
    try {
      let ir = null;
      if (input.deepEnabled !== false) {
        try { const hs = Object.fromEntries(Object.entries(files).filter(([f]) => /\.hs$/i.test(f))); if (Object.keys(hs).length) ir = (0,haskell_ir/* buildHaskellIR */.Y)(hs); } catch { ir = null; }
      }
      haskellCoverage = buildHaskellCoverage({
        files, parses: parsesByFile, ir, deepEnabled: input.deepEnabled !== false && !disabled.has('haskell:taint'),
        ruleRuns: input.ruleRuns || null, sizeSkipped: input.sizeSkipped, policyExcluded: input.policyExcluded,
        excludedPaths: run.ledger.excludedFiles, sourceMap: input.sourceMap || null,
      });
      // Effective parse budgets, operator overrides that were refused, and the persisted record of work left (haskell-budget-state.js).
      const b = haskellCoverage.budget;
      b.budgets = { ...haskell_parser/* DEFAULT_PARSE_BUDGETS */.$e, ...(input.parseBudgets || {}) };
      if (Array.isArray(input.parseBudgetRejected) && input.parseBudgetRejected.length) {
        b.rejectedOverrides = input.parseBudgetRejected;
        conditions.push(`Haskell parse budget override refused: ${input.parseBudgetRejected.map((r) => `${r.entry} (${r.reason})`).join('; ')}`);
      }
      const budgetOf = (file) => { const p = parsesByFile.get(file); return p && p.budget ? { budgetName: p.budget.name } : {}; };
      const remainingAll = (b.remainingAll || []).map((r) => ({ ...r, ...budgetOf(r.file) }));
      const previous = (0,haskell_budget_state/* loadBudgetState */.p6)(input.scanRoot);
      const { record, sinceLast } = (0,haskell_budget_state/* budgetRecord */.Zg)({ remaining: remainingAll, completedFiles: b.completedFiles, budgets: b.budgets, files, previous });
      b.remaining = b.remaining.map((r) => ({ ...r, ...budgetOf(r.file) }));
      b.sinceLast = sinceLast;
      if (record.remainingFiles || previous) b.recorded = (0,haskell_budget_state/* saveBudgetState */.Qg)(input.scanRoot, record);
      // Only a measured shortfall is a condition. A parse-only form is a stated limitation, not a gap in what was asked.
      for (const r of haskellCoverage.capability.reasons) if (!/deep analysis is disabled/.test(r)) conditions.push(`Haskell coverage: ${r}`);
      for (const l of haskellCoverage.capability.limitations) limitations.push({ kind: 'haskell-parse-only', note: l });
    } catch (e) { conditions.push(`Haskell coverage accounting failed: ${String((e && e.message) || e).slice(0, 160)}`); }
  }

  // 6. optional modes
  const optionalModes = {};
  for (const name of OPTIONAL_MODES) {
    const st = optionalState(name, input.optional);
    optionalModes[name] = { selected: st.selected, status: st.status, ran: st.ran, reason: st.reason };
    if (st.condition) conditions.push(st.condition);
  }

  return {
    version: ASSURANCE_VERSION,
    languageCoverage: { totals: base.totals, byKind, conditions, limitations, capabilities, optionalModes, ...(haskellCoverage ? { haskell: haskellCoverage } : {}) },
    ledger: { reconciled: reconcile.ok, errors: reconcile.errors, byAnalyzer: run.ledger.byAnalyzer },
    outcomes: run.outcomes,
    retained: { findings: findings.length, findingsRef: findings },
    conditions,
    limitations,
    optionalModes,
    capabilities,
  };
}


/***/ })

};
