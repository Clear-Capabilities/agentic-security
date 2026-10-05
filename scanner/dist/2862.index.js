export const id = 2862;
export const ids = [2862];
export const modules = {

/***/ 72862:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  assessLanguageAssurance: () => (/* binding */ assessLanguageAssurance)
});

// UNUSED EXPORTS: ASSURANCE_VERSION, OPTIONAL_MODES, REQUIRED_CAPABILITIES

// EXTERNAL MODULE: ./src/language/contracts.js
var contracts = __webpack_require__(43790);
// EXTERNAL MODULE: ./src/language/haskell-parser.js
var haskell_parser = __webpack_require__(41745);
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
// parsed and a foreign declaration's own Haskell signature is.
const OPAQUE_BOUNDARIES = new Set(['th-splice', 'th-quote', 'th-name-quote', 'th-top-level-splice', 'quasiquote', 'hsc', 'generated']);

function ensureHaskellParseProducer() {
  if (!(0,contracts/* isRegisteredLanguageProducer */.dO)(HASKELL_PARSE_PRODUCER)) {
    (0,contracts/* registerLanguageProducer */.OQ)({ id: HASKELL_PARSE_PRODUCER, language: 'haskell', capability: 'parse', evidenceKinds: ['source'], version: '1' });
  }
  return HASKELL_PARSE_PRODUCER;
}

/**
 * @param {{grammarSource?:Function, budgets?:object, mode?:string, onParse?:(file:string, parse:object)=>void}} [opts]
 */
function createHaskellAdapter(opts = {}) {
  ensureHaskellParseProducer();
  return {
    id: HASKELL_PARSE_PRODUCER,
    language: 'haskell',
    hasGrammar: () => (0,haskell_grammar/* loadHaskellGrammar */.UP)({ grammarSource: opts.grammarSource }).available,
    analyze(file, content) {
      const parse = (0,haskell_parser/* parseHaskell */.cX)(content, { file, grammarSource: opts.grammarSource, budgets: opts.budgets, mode: opts.mode });
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
  const disclosed = new Map();   // boundary kind -> {count, files:Set}
  const projectModules = new Set(); const importedModules = new Map();   // module -> files
  const onParse = (file, parse) => {
    if (parse && parse.module && parse.module.name) projectModules.add(parse.module.name);
    for (const i of (parse && parse.imports) || []) if (i && i.module) { const e = importedModules.get(i.module) || new Set(); e.add(file); importedModules.set(i.module, e); }
    for (const b of (parse && parse.boundaries) || []) if (b.kind === 'cpp' || b.kind === 'ffi') { const e = disclosed.get(b.kind) || { count: 0, files: new Set() }; e.count += b.count || 1; e.files.add(file); disclosed.set(b.kind, e); }
  };
  const adapters = input.adapters || [createHaskellAdapter({ onParse }), createNixAdapter()];
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
  const DISCLOSED_NOTE = { cpp: 'preprocessor conditionals: every branch was parsed, but which branch is compiled is not known', ffi: 'foreign declarations: the foreign code is not analysed and its effects are not modelled' };
  for (const [k, e] of [...disclosed.entries()].sort()) limitations.push({ kind: 'opaque-boundary', boundary: k, count: e.count, files: [...e.files].sort().slice(0, 20), note: `a documented limit of static analysis (${DISCLOSED_NOTE[k]})` });
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

  // 6. optional modes
  const optionalModes = {};
  for (const name of OPTIONAL_MODES) {
    const st = optionalState(name, input.optional);
    optionalModes[name] = { selected: st.selected, status: st.status, ran: st.ran, reason: st.reason };
    if (st.condition) conditions.push(st.condition);
  }

  return {
    version: ASSURANCE_VERSION,
    languageCoverage: { totals: base.totals, byKind, conditions, limitations, capabilities, optionalModes },
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
