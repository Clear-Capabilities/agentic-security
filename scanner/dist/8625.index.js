export const id = 8625;
export const ids = [8625];
export const modules = {

/***/ 4196:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   F: () => (/* binding */ buildCorpus),
/* harmony export */   T: () => (/* binding */ scoreRule)
/* harmony export */ });
/* harmony import */ var _mutation_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(47911);
/* harmony import */ var _ir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(30739);
/* harmony import */ var _custom_rules_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(49592);
// Automatic corpus creation and scoring for ONE candidate rule.
//
// Positive corpus: the original vulnerable snippet plus its generated sibling variants (mutation.js).
// Negative corpus: an explicit patched/clean variant the caller supplies, nearby clean patterns, protected
// (sanitizer/guard) variants, and the NEGATIVE mutations of those (same mutators, applied to the safe side) — a
// candidate rule must decline on ALL of them, not just the one hand-picked negative.
//
// Scoring reuses the exact runtime matcher (`runRule` in `../custom-rules.js`), never a second implementation —
// the score a rule gets here is the score it will actually produce once promoted.




/** The rule exactly as the scanner would load it: through the loader's own normalizer, not a second implementation. */
function toRuntimeRule(ir) {
  const { ok, doc, errs } = (0,_ir_js__WEBPACK_IMPORTED_MODULE_1__/* .compileToCustomRule */ .Mo)(ir);
  if (!ok) throw new Error(`cannot build corpus for an invalid rule IR: ${errs.join('; ')}`);
  return (0,_custom_rules_js__WEBPACK_IMPORTED_MODULE_2__/* .normalizeCustomRule */ .Lj)(doc);
}

const EXT = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

function buildCorpus(ir, { originalCode, patchedCode = null, nearbyCleanCode = [], protectedVariantsCode = [] } = {}) {
  const positives = [{ label: 'original', code: originalCode }];
  for (const v of (0,_mutation_js__WEBPACK_IMPORTED_MODULE_0__/* .generateVariants */ .G4)(originalCode)) positives.push({ label: `sibling:${v.mutator}`, code: v.code });

  const negatives = [];
  if (patchedCode) {
    negatives.push({ label: 'patched', code: patchedCode });
    for (const v of (0,_mutation_js__WEBPACK_IMPORTED_MODULE_0__/* .generateVariants */ .G4)(patchedCode)) negatives.push({ label: `patched-sibling:${v.mutator}`, code: v.code });
  }
  // The safe side is mutated too (rename, wrapper, equivalent API, ALTERNATE SANITIZER, framework variant, ...): a rule keyed to one
  // sanitizer's name or one framework's accessor fires on the sibling that uses another, and that is a protected-negative failure.
  nearbyCleanCode.forEach((code, i) => {
    negatives.push({ label: `nearby-clean-${i}`, code });
    for (const v of (0,_mutation_js__WEBPACK_IMPORTED_MODULE_0__/* .generateVariants */ .G4)(code)) negatives.push({ label: `nearby-clean-${i}-sibling:${v.mutator}`, code: v.code });
  });
  protectedVariantsCode.forEach((code, i) => {
    negatives.push({ label: `protected-${i}`, code });
    for (const v of (0,_mutation_js__WEBPACK_IMPORTED_MODULE_0__/* .generateVariants */ .G4)(code)) negatives.push({ label: `protected-${i}-sibling:${v.mutator}`, code: v.code });
  });

  return { positives, negatives };
}

function scoreRule(ir, corpus) {
  const rule = toRuntimeRule(ir);
  const lang = ir.languages[0] || 'javascript';
  const file = EXT[lang] || 'x.txt';
  const run = (code) => (0,_custom_rules_js__WEBPACK_IMPORTED_MODULE_2__/* .runRule */ .OA)(rule, file, code).length > 0;

  const posResults = corpus.positives.map((p) => ({ ...p, fired: run(p.code) }));
  const negResults = corpus.negatives.map((n) => ({ ...n, fired: run(n.code) }));

  const tp = posResults.filter((p) => p.fired).length;
  const fn = posResults.length - tp;
  const fp = negResults.filter((n) => n.fired).length;
  const tn = negResults.length - fp;
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = corpus.positives.length === 0 ? null : tp / corpus.positives.length;
  // "Protected negative failures" per PRD 3: a rule firing on a sanitizer/guard-carrying variant specifically.
  const protectedFailures = negResults.filter((n) => n.label.startsWith('protected-') && n.fired).length;

  return { precision, recall, tp, fp, tn, fn, protectedFailures, positives: posResults, negatives: negResults };
}


/***/ }),

/***/ 30739:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   GE: () => (/* binding */ ruleIRDigest),
/* harmony export */   Mo: () => (/* binding */ compileToCustomRule),
/* harmony export */   UQ: () => (/* binding */ RULE_STATES),
/* harmony export */   g: () => (/* binding */ validateRuleIR),
/* harmony export */   pc: () => (/* binding */ draftRuleIR)
/* harmony export */ });
/* harmony import */ var _proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(54079);
/* harmony import */ var _custom_rules_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(49592);
// Rule intermediate representation: compiles DOWN into the existing pattern-rule engine
// (`../custom-rules.js`), never a parallel matcher. "Compile" here means "emit a
// custom-rules.js-compatible document" — detection at runtime is 100% the already-proven
// regex/allOf/notMatch/window engine; this module only adds PROVENANCE metadata around it.
//
// A rule's match semantics are deliberately the same closed vocabulary custom-rules.js
// already supports (pattern | allOf+window | notMatch, plus the structural fields below): no
// separate matching engine is introduced, so a promoted rule is exactly as auditable as a hand-written one.
//
// The structural fields are REAL, not annotations: each is a regular expression and each compiles to a constraint the
// runtime matcher enforces.
//   source, propagator, sink   together they become a windowed co-occurrence (allOf) anchored on the SINK; a sink alone is the pattern
//   sanitizer, dominatingGuard a hit is dropped when either matches within `guardWindow` lines before (or on) it
//   frameworkConstraint        a file-level precondition (the file must contain it, wherever it is)
//   exclusions                 a hit is dropped when its own line matches one
//   languages                  the rule only runs on files of those languages
// An explicit `match` always wins over a derived one. An AST pattern is NOT a field: the existing engine has no AST matcher for rules to
// compile to, and a field the matcher ignored would be the old mistake (an annotation that looks like a constraint).



const RULE_IR_SCHEMA = 'agentic-security/rule-ir';
const RULE_IR_VERSION = 1;
const RULE_STATES = Object.freeze(['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED', 'DEPRECATED', 'ROLLED_BACK']);
const VALID_LANGS = new Set(['javascript', 'typescript', 'python', 'go', 'ruby', 'java', 'rust', 'csharp', 'php', 'any']);

const isStr = (v) => typeof v === 'string' && v.length > 0;

/** Problems with a draft rule IR; an empty list means it is well-formed (not yet validated/promoted). */
function validateRuleIR(ir) {
  const errs = [];
  if (!ir || typeof ir !== 'object') return ['rule IR must be an object'];
  if (ir.schema !== RULE_IR_SCHEMA) errs.push('unknown schema');
  if (ir.version !== RULE_IR_VERSION) errs.push('unsupported rule IR version');
  if (!isStr(ir.id) || !/^[a-z][a-z0-9-]{2,79}$/.test(ir.id)) errs.push('id must be a lowercase kebab-case string');
  if (!isStr(ir.title)) errs.push('title required');
  if (!['critical', 'high', 'medium', 'low'].includes(ir.severity)) errs.push('severity must be critical|high|medium|low');
  if (!isStr(ir.cwe) || !/^CWE-\d+$/.test(ir.cwe)) errs.push('cwe must look like CWE-###');
  if (!isStr(ir.family)) errs.push('family required');
  if (!Array.isArray(ir.languages) || !ir.languages.length || !ir.languages.every((l) => VALID_LANGS.has(l))) errs.push('languages must be a non-empty array from the supported set');
  const m = ir.match;
  if (m == null && !isStr(ir.sink)) errs.push('match required (or at least a sink, from which one is derived)');
  else if (m != null && typeof m !== 'object') errs.push('match must be an object');
  else if (m) {
    const hasPattern = isStr(m.pattern);
    const hasAllOf = Array.isArray(m.allOf) && m.allOf.length > 0 && m.allOf.every(isStr);
    if (!hasPattern && !hasAllOf) errs.push('match needs a pattern or a non-empty allOf');
    if (m.notMatch != null && !isStr(m.notMatch)) errs.push('notMatch must be a string');
    if (m.window != null && !(Number.isInteger(m.window) && m.window > 0 && m.window <= 200)) errs.push('window must be an integer in 1..200');
    for (const re of [m.pattern, ...(m.allOf || []), m.notMatch].filter(isStr)) {
      try { new RegExp(re); } catch { errs.push(`invalid regex: ${re}`); }
    }
  }
  // Structural fields: each is a regular expression the matcher enforces (see the header). Free text is rejected, so a field can
  // never look like a constraint while being ignored.
  for (const k of ['sink', 'source', 'propagator', 'sanitizer', 'dominatingGuard', 'frameworkConstraint']) {
    if (ir[k] == null) continue;
    if (!isStr(ir[k])) { errs.push(`${k} must be a regular-expression string when present`); continue; }
    try { new RegExp(ir[k]); } catch { errs.push(`${k} is not a valid regular expression`); }
  }
  if ((ir.source || ir.propagator) && !ir.sink && !ir.match) errs.push('a source or propagator needs a sink');
  if (ir.window != null && !(Number.isInteger(ir.window) && ir.window > 0 && ir.window <= 200)) errs.push('window must be an integer in 1..200');
  if (ir.guardWindow != null && !(Number.isInteger(ir.guardWindow) && ir.guardWindow > 0 && ir.guardWindow <= 200)) errs.push('guardWindow must be an integer in 1..200');
  if (ir.exclusions != null) {
    if (!(Array.isArray(ir.exclusions) && ir.exclusions.every(isStr))) errs.push('exclusions must be an array of regular-expression strings');
    else for (const re of ir.exclusions) { try { new RegExp(re); } catch { errs.push(`invalid exclusion regex: ${re}`); } }
  }
  if (!ir.provenance || typeof ir.provenance !== 'object') errs.push('provenance required');
  else {
    if (!isStr(ir.provenance.originatingFindingId)) errs.push('provenance.originatingFindingId required');
    if (ir.provenance.originatingCommit != null && !isStr(ir.provenance.originatingCommit)) errs.push('provenance.originatingCommit must be a string');
    if (!['execution-proven', 'taint-proven', 'deterministic-corroboration'].includes(ir.provenance.evidenceState)) errs.push('provenance.evidenceState must be execution-proven|taint-proven|deterministic-corroboration');
  }
  return errs;
}

function ruleIRDigest(ir) {
  const { state: _s, ...rest } = ir;
  return (0,_proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)(JSON.stringify(rest, Object.keys(rest).sort()));
}

/** Build a DRAFT rule IR. Caller supplies the candidate pattern — this module never invents one. */
function draftRuleIR({ id, title, severity, cwe, family, languages, match, remediation, originatingFindingId, originatingCommit, evidenceState, model = null, promptConfigVersion = null, ...hints }) {
  const ir = {
    schema: RULE_IR_SCHEMA, version: RULE_IR_VERSION, id, title, severity, cwe, family, languages, match,
    remediation: remediation ?? null, state: 'DRAFT',
    ...hints,
    provenance: { originatingFindingId, originatingCommit: originatingCommit ?? null, evidenceState, model, promptConfigVersion },
  };
  return ir;
}

/** Compile a rule IR into a custom-rules.js-compatible document. Caller writes the YAML. */
function compileToCustomRule(ir) {
  const errs = validateRuleIR(ir);
  if (errs.length) return { ok: false, errs };
  const alt = (...parts) => { const p = parts.filter(isStr); return p.length ? p.map((x) => `(?:${x})`).join('|') : null; };
  // the base match: explicit wins; otherwise source -> propagator -> sink as a windowed co-occurrence, or a sink alone
  let base = ir.match;
  if (!base) {
    // the SINK leads: the matcher anchors on the first pattern, and the finding, the guard window and the line exclusions all belong at
    // the sink, where the flaw manifests. The window is symmetric, so the order of the others does not affect co-occurrence.
    const chain = [ir.sink, ir.propagator, ir.source].filter(isStr);
    base = chain.length > 1 ? { allOf: chain, window: ir.window ?? 8 } : { pattern: ir.sink };
  }
  const guard = alt(ir.sanitizer, ir.dominatingGuard);
  const doc = {
    id: `rule-compiler/${ir.id}`,
    title: ir.title,
    severity: ir.severity,
    cwe: ir.cwe,
    languages: ir.languages,
    match: {
      ...(base.pattern ? { pattern: base.pattern } : {}),
      ...(base.allOf ? { allOf: base.allOf, window: base.window ?? 5 } : {}),
      ...(base.notMatch ? { notMatch: base.notMatch } : {}),
      ...(isStr(ir.frameworkConstraint) ? { fileRequires: [ir.frameworkConstraint] } : {}),
      ...(guard ? { guardedBy: guard, guardWindow: ir.guardWindow ?? base.window ?? 5 } : {}),
      ...(Array.isArray(ir.exclusions) && ir.exclusions.length ? { excludeLine: ir.exclusions } : {}),
    },
    message: ir.remediation || `${ir.title} (${ir.cwe}, compiled from ${ir.provenance.originatingFindingId})`,
  };
  // The loader has its own safety checks (nested quantifiers and so on). A rule it would refuse must not be reported as compiled,
  // or it would score well here and silently never fire in a scan.
  const origError = console.error; let loaderSaid = '';
  console.error = (...a) => { loaderSaid = a.join(' '); };
  let normalized; try { normalized = (0,_custom_rules_js__WEBPACK_IMPORTED_MODULE_1__/* .normalizeCustomRule */ .Lj)(doc); } finally { console.error = origError; }
  if (!normalized) return { ok: false, errs: [`the scanner's rule loader would reject this rule${loaderSaid ? `: ${loaderSaid.replace(/^agentic-security:\s*/, '').slice(0, 160)}` : ''}`] };
  return { ok: true, doc };
}


/***/ }),

/***/ 47911:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   G4: () => (/* binding */ generateVariants),
/* harmony export */   xv: () => (/* binding */ mutatorCoverage)
/* harmony export */ });
/* unused harmony exports variableRename, wrapInFunction, equivalentApi, alternateSanitizer, frameworkVariant, reorderStatements, MUTATOR_NAMES */
// Bounded structural mutation for ONE candidate rule's own corpus — not bench/mutation's engine-wide verdict-flip
// harness (a different scope: the whole deterministic+taint engine against curated adversarial cases). This module
// exists only to answer PRD 3's "unseen sibling" question for a single rule: does the candidate still fire on a
// structurally different variant of the same vulnerable shape, and does it still decline on a structurally
// different variant of a mitigated shape.
//
// Mutations are SYNTACTIC, deterministic, seed-free and language-agnostic: variable rename, wrap-in-function,
// reorder-adjacent-statements, insert-indirection (a pass-through local variable). No semantics are changed on
// purpose — a mutation that silently changed behavior would make a "same vulnerability, different shape" claim
// false.
const RESERVED = new Set(['if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'import', 'from', 'def', 'class', 'req', 'res']);

function identifiers(code) {
  const seen = new Set();
  for (const m of code.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) if (!RESERVED.has(m[1]) && !/^[A-Z_]+$/.test(m[1])) seen.add(m[1]);
  return [...seen];
}

function renameOne(code, from, to) {
  if (!from || code.includes(to)) return null;
  return code.replace(new RegExp(`\\b${from}\\b`, 'g'), to);
}

function variableRename(code, { suffix = '_v2' } = {}) {
  const ids = identifiers(code);
  const target = ids.find((id) => id.length > 1);
  if (!target) return null;
  return renameOne(code, target, `${target}${suffix}`);
}

function wrapInFunction(code, { name = 'wrapped_v2' } = {}) {
  if (!String(code).trim()) return null;
  const indented = code.split('\n').map((l) => (l ? `  ${l}` : l)).join('\n');
  return `function ${name}() {\n${indented}\n}\n${name}();\n`;
}

/** Insert a pass-through local for the first simple right-hand-side identifier assigned with `=` (indirection,
 * no behavior change): `x = y;` becomes `const indirectN = y; x = indirectN;`. */
function insertIndirection(code) {
  const m = /^(\s*)([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*;/m.exec(code);
  if (!m) return null;
  const [whole, indent, lhs, rhs] = m;
  const varName = `indirect_${Math.abs(_hash(rhs)) % 1000}`;
  if (code.includes(varName)) return null;
  return code.replace(whole, `${indent}const ${varName} = ${rhs};\n${indent}${lhs} = ${varName};`);
}

function _hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

// ---- the four mutators the PRD lists beyond rename / wrapper / indirection --------------------------------------------------
// Each is a deterministic, table-driven textual rewrite that returns null when it does not apply. Tables are deliberately
// small and conservative: an entry is here only when both sides are the same API family used the same way, so the claim "same
// vulnerability, different shape" stays true. They are applied to the vulnerable side (does the rule still fire?) and to the safe
// side (does it still decline?); the safe side is where a rule keyed to ONE sanitizer's name is caught.

// equivalent APIs: the same operation through a sibling entry point
const EQUIVALENT_APIS = Object.freeze([
  [/\bchild_process\.exec\(/, 'child_process.execSync('], [/\bexecSync\(/, 'exec('], [/\bos\.system\(/, 'os.popen('],
  [/\bdb\.query\(/, 'db.execute('], [/\bconnection\.query\(/, 'connection.execute('], [/\bcursor\.execute\(/, 'cursor.executemany('],
  [/\bfs\.readFile\(/, 'fs.readFileSync('], [/\bfs\.readFileSync\(/, 'fs.readFile('], [/\bfs\.writeFile\(/, 'fs.writeFileSync('],
  [/\bhttp\.get\(/, 'https.get('], [/\baxios\.get\(/, 'axios.request('], [/\bres\.send\(/, 'res.end('],
  [/\bos\.Open\(/, 'os.OpenFile('], [/\bsubprocess\.call\(/, 'subprocess.run('], [/\bsubprocess\.run\(/, 'subprocess.call('],
]);
function equivalentApi(code) {
  for (const [from, to] of EQUIVALENT_APIS) if (from.test(code)) return code.replace(from, to);
  return null;
}

// alternate sanitizers: a different, equally valid way to neutralize the same input
const ALTERNATE_SANITIZERS = Object.freeze([
  [/\bescapeHtml\(/, 'validator.escape('], [/\bvalidator\.escape\(/, 'escapeHtml('], [/\bDOMPurify\.sanitize\(/, 'sanitizeHtml('], [/\bsanitizeHtml\(/, 'DOMPurify.sanitize('],
  [/\bshlex\.quote\(/, 'pipes.quote('], [/\bhtml\.escape\(/, 'markupsafe.escape('], [/\bhtml\.EscapeString\(/, 'template.HTMLEscapeString('],
  [/\bencodeURIComponent\(/, 'encodeURI('], [/\bpath\.basename\(/, 'path.parse('], [/\bparseInt\(/, 'Number('], [/\bNumber\(/, 'parseInt('],
  [/\bstrconv\.Atoi\(/, 'strconv.ParseInt('], [/\bint\(/, 'abs('],
]);
function alternateSanitizer(code) {
  for (const [from, to] of ALTERNATE_SANITIZERS) if (from.test(code)) return code.replace(from, to);
  return null;
}

// framework variants: the same untrusted input reached through another framework's accessor
const FRAMEWORK_VARIANTS = Object.freeze([
  [/\breq\.body\./g, 'ctx.request.body.'], [/\breq\.query\./g, 'ctx.query.'], [/\breq\.params\./g, 'ctx.params.'],
  [/\brequest\.args\.get\(/g, 'request.form.get('], [/\brequest\.form\.get\(/g, 'request.args.get('], [/\$_GET\[/g, '$_REQUEST['], [/\$_POST\[/g, '$_REQUEST['],
  [/\br\.URL\.Query\(\)\.Get\(/g, 'r.FormValue('], [/\brequest\.getParameter\(/g, 'request.getHeader('],
]);
function frameworkVariant(code) {
  for (const [from, to] of FRAMEWORK_VARIANTS) if (from.test(code)) { from.lastIndex = 0; return code.replace(from, to); }
  return null;
}

// reordering: swap the first pair of ADJACENT simple statements that share no identifier, so neither feeds the other. This is a
// syntactic independence test, not a data-flow proof; it is applied to rule-corpus snippets, where a swap of two unrelated
// statements is what a different author's version of the same code would plausibly look like.
const CONTROL = /^\s*(?:if|else|for|while|switch|case|return|try|catch|finally|do|break|continue|throw|function|def|class|import|from|package|\}|\{|@|\/\/|#)\b|^\s*[}{]\s*$/;
function reorderStatements(code) {
  const lines = code.split('\n');
  const simple = (l) => l.trim() && !CONTROL.test(l) && /[;)]\s*$|^[^=]*=[^=].*[^{]$/.test(l.trim()) && !/[{]\s*$/.test(l);
  const ids = (l) => new Set([...l.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\b/g)].map((m) => m[0]).filter((x) => !RESERVED.has(x)));
  for (let i = 0; i + 1 < lines.length; i++) {
    if (!simple(lines[i]) || !simple(lines[i + 1])) continue;
    const a = ids(lines[i]); const b = ids(lines[i + 1]);
    if ([...a].some((x) => b.has(x))) continue;
    const out = [...lines]; [out[i], out[i + 1]] = [out[i + 1], out[i]];
    return out.join('\n');
  }
  return null;
}

const MUTATORS = Object.freeze({
  'variable-rename': variableRename, 'wrap-in-function': wrapInFunction, 'insert-indirection': insertIndirection,
  'equivalent-api': equivalentApi, 'reorder-statements': reorderStatements, 'alternate-sanitizer': alternateSanitizer, 'framework-variant': frameworkVariant,
});
const MUTATOR_NAMES = Object.freeze(Object.keys(MUTATORS));

/** Every mutator applied to `code`; mutators that don't apply (return null) are omitted, never silently skipped without saying so. */
function generateVariants(code) {
  const out = [];
  for (const [name, fn] of Object.entries(MUTATORS)) {
    let variant = null;
    try { variant = fn(code); } catch { variant = null; }
    if (variant && variant !== code) out.push({ mutator: name, code: variant });
  }
  return out;
}

/** Which of the seven mutators produced a variant for this code, and which did not (so a report can say what was not exercised). */
function mutatorCoverage(code) {
  const applied = new Set(generateVariants(code).map((v) => v.mutator));
  return { applied: MUTATOR_NAMES.filter((n) => applied.has(n)), notApplicable: MUTATOR_NAMES.filter((n) => !applied.has(n)) };
}


/***/ }),

/***/ 5455:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   V2: () => (/* binding */ PROMOTION_DEFAULTS),
/* harmony export */   kx: () => (/* binding */ evaluateRule),
/* harmony export */   r_: () => (/* binding */ checkLeakage),
/* harmony export */   z: () => (/* binding */ gatePromotion)
/* harmony export */ });
/* harmony import */ var _corpus_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(4196);
// Promotion gate (PRD 3 "Promotion Gate"): precision/recall thresholds, zero protected-negative failures, zero
// benchmark leakage. A candidate rule does NOT automatically become a production rule — `evaluateRule` only
// scores; `gatePromotion` only judges; the lifecycle ledger (`lifecycle.js`) is the one place a PROMOTED state is
// actually recorded, and nothing in this module writes to it.


const PROMOTION_DEFAULTS = Object.freeze({ minPrecision: 0.95, minRecall: 0.80, maxProtectedFailures: 0 });

// Deliberately independent of posture/evaluation/custody.js: that module's term list and guard are reserved for
// the evaluation custodian's sealed-label boundary (QA-002.AC03), and a test enforces that nothing outside
// posture/evaluation/ may import it. The anti-cheating need here is smaller and different in kind — a rule
// synthesis prompt/corpus must not embed a benchmark name or an advisory id — so it gets its own small, independent
// checker rather than reaching across that isolation boundary.
const ADVISORY_ID = /\b(?:CVE|GHSA|CWE)-[A-Za-z0-9-]+\b/i;

// What a synthesis agent must never see (PRD 3, anti-cheating): benchmark answer keys, hidden test labels, CWE-bearing hidden file
// names, vulnerability comments and protected test metadata. These defaults are always applied; a caller adds its own benchmark names.
const DEFAULT_BENCHMARK_NAMES = Object.freeze(['owasp benchmark', 'juliet', 'sard test', 'cve-replay', 'corpus-baseline', 'answer key', 'ground truth', 'adjudicated', 'hidden test', 'expectedresults']);
const CWE_FILENAME = /(^|[\\/])[^\\/]*cwe[-_]?\d+[^\\/]*$/i;
const ANSWER_KEY_FILENAME = /(^|[\\/])(?:labels?|answers?|expected|ground[-_]?truth|answer[-_]?key|oracle|result)[^\\/]*\.(?:json|jsonl|ya?ml|csv|txt)$/i;
const VULNERABILITY_COMMENT = /(?:\/\/|#|\/\*|^\s*\*)\s*(?:POTENTIAL FLAW|FLAW\b|INCIDENTAL|BAD\b|GOOD\b|vulnerab\w*|insecure|exploit\w*)/im;

/**
 * Anti-cheating gate. Fails closed: any hit makes `ok` false, and the synthesis loop will not report a pass.
 * @param {string} promptText everything the synthesis agent would be shown (corpus code, spec text)
 * @param {{benchmarkNames?: string[], fileNames?: string[]}} opts
 */
function checkLeakage(promptText, { benchmarkNames = [], fileNames = [] } = {}) {
  const hay = String(promptText ?? '');
  const lower = hay.toLowerCase();
  const offending = [];
  for (const name of [...DEFAULT_BENCHMARK_NAMES, ...benchmarkNames]) if (name && lower.includes(String(name).toLowerCase())) offending.push(`benchmark name: ${name}`);
  const m = ADVISORY_ID.exec(hay);
  if (m) offending.push(`identifier: ${m[0]}`);
  if (VULNERABILITY_COMMENT.test(hay)) offending.push('a comment that describes the vulnerability');
  for (const f of fileNames) {
    if (CWE_FILENAME.test(String(f))) offending.push(`weakness-bearing file name: ${f}`);
    if (ANSWER_KEY_FILENAME.test(String(f))) offending.push(`answer-key file name: ${f}`);
  }
  return { ok: offending.length === 0, offendingTerms: offending };
}

function evaluateRule(ir, corpus, thresholds = PROMOTION_DEFAULTS) {
  const score = (0,_corpus_js__WEBPACK_IMPORTED_MODULE_0__/* .scoreRule */ .T)(ir, corpus);
  const t = { ...PROMOTION_DEFAULTS, ...thresholds };
  const reasons = [];
  if (score.precision === null) reasons.push('precision unmeasured (no positive or negative corpus fired)');
  else if (score.precision < t.minPrecision) reasons.push(`precision ${(score.precision * 100).toFixed(1)}% below ${(t.minPrecision * 100).toFixed(0)}%`);
  if (score.recall === null) reasons.push('recall unmeasured (empty positive corpus)');
  else if (score.recall < t.minRecall) reasons.push(`recall ${(score.recall * 100).toFixed(1)}% below ${(t.minRecall * 100).toFixed(0)}%`);
  if (score.protectedFailures > t.maxProtectedFailures) reasons.push(`${score.protectedFailures} protected-negative failure(s) (max ${t.maxProtectedFailures})`);
  return { pass: reasons.length === 0, reasons, score, thresholds: t };
}

/** The one promotion decision. Never auto-applied: a caller still has to act on `pass:true` by recording a
 * lifecycle transition. Localization ("acceptable") is a human/caller judgment this function cannot make from
 * line/column alone; it is surfaced for review, never silently assumed. */
function gatePromotion({ ir, corpus, leakageCheck, thresholds } = {}) {
  const evalResult = evaluateRule(ir, corpus, thresholds);
  const reasons = [...evalResult.reasons];
  if (!leakageCheck || leakageCheck.ok !== true) reasons.push(leakageCheck ? `leakage check failed: ${leakageCheck.offendingTerms.join(', ')}` : 'leakage check was not run');
  return { pass: reasons.length === 0, reasons, evaluation: evalResult };
}


/***/ }),

/***/ 51006:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Ry: () => (/* binding */ generalizeLine),
/* harmony export */   _7: () => (/* binding */ synthesizeCandidate)
/* harmony export */ });
/* unused harmony exports proposeCandidates, safeNames */
/* harmony import */ var _ir_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(30739);
/* harmony import */ var _corpus_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(4196);
/* harmony import */ var _promotion_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(5455);
// The synthesis loop for the rule compiler (PRD 3, requirement 5): propose, compile, test positives, test negatives, mutation test,
// score, revise, repeat with bounded attempts, emit a candidate.
//
// "Models propose rules. Evidence promotes rules." A model's proposal (a `match` in the spec) is tried first when there is one.
// When there is none, or it fails, this module proposes deterministically from the two pieces of evidence it has: the vulnerable
// code and its patched twin. The lines that exist only in the vulnerable version say what the flaw looks like; the calls that exist
// only in the patched version say what a safe version looks like (and become the `notMatch` that keeps the rule quiet on safe files).
// No model is consulted here and nothing here promotes a rule: the loop returns attempts and a best candidate, and promotion stays
// with the gate and the lifecycle ledger.
//
// Every attempt is scored against the real corpus (positives with their mutations, negatives with theirs) by the same matcher the
// rule will run on once promoted. An attempt that does not clear the gate is revised from WHY it failed: low recall generalizes,
// a negative that fires adds the safe version's names to `notMatch`.




const esc = (s) => s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
const KEYWORDS = new Set(['if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'new', 'await', 'async', 'try', 'catch', 'throw', 'typeof', 'def', 'class', 'import', 'from', 'with', 'in', 'of', 'and', 'or', 'not', 'is', 'func', 'fn', 'public', 'private', 'static', 'void', 'int', 'string']);
const SOURCES = [
  String.raw`req(?:uest)?\.(?:body|query|params|headers|cookies)\b`, String.raw`ctx\.(?:query|params|request\.body)\b`, String.raw`request\.(?:args|form|values|json|GET|POST)\b`,
  String.raw`\$_(?:GET|POST|REQUEST|COOKIE)\b`, String.raw`process\.argv\b`, String.raw`os\.Args\b`, String.raw`\bgetParameter\s*\(`, String.raw`r\.(?:URL\.Query\(\)|FormValue)\b`,
];

const meaningful = (l) => { const t = l.trim(); return t.length >= 8 && !/^(?:\/\/|#|\/\*|\*|[{}()\];,]+$)/.test(t); };

/** Lines (trimmed) present only in `a`. */
function onlyIn(a, b) {
  const bs = new Set(String(b ?? '').split('\n').map((l) => l.trim()));
  return String(a ?? '').split('\n').filter((l) => meaningful(l) && !bs.has(l.trim())).map((l) => l.trim());
}

/** Call names (a.b.c) in some code, in order of appearance, without keywords. */
function callNames(code) {
  const out = [];
  for (const m of String(code).matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g)) if (!KEYWORDS.has(m[1]) && !out.includes(m[1])) out.push(m[1]);
  return out;
}

/** A regular expression for one source line: the call names stay, strings and the other identifiers become classes. */
function generalizeLine(line) {
  const keep = new Set(callNames(line));
  let out = ''; let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (/\s/.test(c)) { const before = line[i - 1] ?? ''; while (/\s/.test(line[i] ?? '')) i++; out += /[\w$]/.test(before) && /[\w$]/.test(line[i] ?? '') ? String.raw`\s+` : String.raw`\s*`; continue; }
    if (c === '"' || c === "'" || c === '`') { const q = c; let j = i + 1; while (j < line.length && line[j] !== q) j += line[j] === '\\' ? 2 : 1; out += q === '`' ? '`[^`]*`' : `(?:'[^']*'|"[^"]*")`; i = j + 1; continue; }
    const id = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/.exec(line.slice(i));
    if (id) { const tok = id[0]; const isCall = line[i + tok.length] === '(' || keep.has(tok); out += isCall || KEYWORDS.has(tok) ? esc(tok) : String.raw`[A-Za-z_$][\w$.]*`; i += tok.length; continue; }
    const num = /^\d+(?:\.\d+)?/.exec(line.slice(i));
    if (num) { out += String.raw`\d+(?:\.\d+)?`; i += num[0].length; continue; }
    out += esc(c); i++;
  }
  return out;
}

const sinkOf = (line) => callNames(line).filter((n) => !/^(?:console|logger|log)\b/.test(n))[0] ?? null;
const interpolation = String.raw`(?:\+|\$\{|%s|%d|\.format\s*\(|\bf["']|\|\|)`;

/** Ordered proposals, most specific first. Each is {strategy, match}; `match.notMatch` is added by `withSafeNames`. */
function proposeCandidates({ vulnerableCode, patchedCode = null }) {
  const vuln = onlyIn(vulnerableCode, patchedCode);
  const lines = vuln.length ? vuln : String(vulnerableCode).split('\n').filter(meaningful).map((l) => l.trim()).filter((l) => callNames(l).length);
  const out = []; const seen = new Set();
  const add = (strategy, match, structure = null) => { const k = JSON.stringify([match, structure]); if (!seen.has(k)) { seen.add(k); out.push({ strategy, ...(match ? { match } : {}), ...(structure ? { structure } : {}) }); } };
  for (const l of lines.slice(0, 3)) add('line-shape', { pattern: generalizeLine(l) });
  for (const l of lines.slice(0, 3)) {
    const sink = sinkOf(l);
    if (sink) add('sink-with-interpolation', { pattern: `${esc(sink)}\\s*\\([^)\\n]*${interpolation}` });
  }
  const sink = lines.map(sinkOf).find(Boolean);
  const src = SOURCES.find((s) => new RegExp(s).test(vulnerableCode));
  if (sink && src) add('source-and-sink', { allOf: [`${esc(sink)}\\s*\\(`, src], window: 6 });
  // the same evidence as an explicit structure: a source and a sink the matcher enforces, so a sanitizer found in the patched code can
  // later be added as a LOCAL guard (dropping one hit) instead of a file-level exclusion (silencing the whole file)
  if (sink && src) add('structural', null, { source: src, sink: `${esc(sink)}\\s*\\(`, window: 6 });
  if (sink) add('sink-call', { pattern: `${esc(sink)}\\s*\\(` });
  return out;
}

/** Names that appear in the patched code and not in the vulnerable code: the safe version's vocabulary. */
function safeNames({ vulnerableCode, patchedCode }) {
  if (!patchedCode) return [];
  const v = new Set(callNames(vulnerableCode));
  const names = callNames(patchedCode).filter((n) => !v.has(n));
  if (/\?['"`]?\s*[,)]/.test(patchedCode) && !/\?['"`]?\s*[,)]/.test(vulnerableCode)) names.push('?');
  return names;
}

const PLACEHOLDER_RE = '\\?[\'"`]?\\s*[,)]';
const safeRegex = (names) => (names.length ? names.map((n) => (n === '?' ? PLACEHOLDER_RE : esc(n))).join('|') : null);

const summary = (score) => ({ precision: score.precision, recall: score.recall, tp: score.tp, fp: score.fp, fn: score.fn, tn: score.tn, protectedFailures: score.protectedFailures });
const quality = (e) => (e.pass ? 10 : 0) + (e.score.precision ?? 0) * (e.score.recall ?? 0) - e.score.protectedFailures * 0.5;

/**
 * @param {object} o
 * @param {object} o.base      the IR fields that are not the match: id, title, severity, cwe, family, languages, remediation, evidence
 * @param {object} o.corpusSpec  { originalCode, patchedCode?, nearbyCleanCode?, protectedVariantsCode? }
 * @param {object|null} o.proposed  a match supplied by a model or a person, tried first
 * @returns {{attempts: object[], best: object|null, exhausted: boolean}}
 */
function synthesizeCandidate({ base, corpusSpec, proposed = null, maxAttempts = 6, thresholds, leakageOk = true }) {
  const cap = Math.max(1, Math.min(12, maxAttempts));
  const queue = [];
  if (proposed) queue.push({ strategy: 'proposed', match: proposed });
  for (const p of proposeCandidates({ vulnerableCode: corpusSpec.originalCode, patchedCode: corpusSpec.patchedCode })) queue.push(p);
  const names = safeNames({ vulnerableCode: corpusSpec.originalCode, patchedCode: corpusSpec.patchedCode });
  const attempts = []; const tried = new Set();
  const tryOne = (strategy, match, structure = null) => {
    const key = JSON.stringify([match, structure]);
    if (tried.has(key) || attempts.length >= cap) return null;
    tried.add(key);
    const ir = (0,_ir_js__WEBPACK_IMPORTED_MODULE_0__/* .draftRuleIR */ .pc)({ ...base, ...(match ? { match } : {}), ...(structure ?? {}) });
    const errs = (0,_ir_js__WEBPACK_IMPORTED_MODULE_0__/* .validateRuleIR */ .g)(ir);
    if (errs.length) { attempts.push({ n: attempts.length + 1, strategy, match: match ?? null, structure, valid: false, errors: errs, pass: false, reasons: errs }); return null; }
    const corpus = (0,_corpus_js__WEBPACK_IMPORTED_MODULE_1__/* .buildCorpus */ .F)(ir, corpusSpec);
    const ev = (0,_promotion_js__WEBPACK_IMPORTED_MODULE_2__/* .evaluateRule */ .kx)(ir, corpus, thresholds);
    const rec = { n: attempts.length + 1, strategy, match: match ?? null, structure, valid: true, pass: ev.pass && leakageOk, reasons: ev.reasons, score: summary(ev.score), ir, corpusSizes: { positives: corpus.positives.length, negatives: corpus.negatives.length } };
    attempts.push(rec);
    return { rec, ev };
  };
  for (let qi = 0; qi < queue.length && attempts.length < cap; qi++) {
    const q = queue[qi];
    const first = tryOne(q.strategy, q.match, q.structure);
    if (!first) continue;
    if (first.rec.pass) break;
    // revise from the failure: a negative that fired means the safe version is not excluded yet
    const fired = first.ev.score.negatives.filter((n) => n.fired);
    const rx = safeRegex(names);
    if (fired.length && rx && q.structure && !q.structure.sanitizer) { const r = tryOne(`${q.strategy}+sanitizer`, null, { ...q.structure, sanitizer: rx }); if (r?.rec.pass) break; }
    else if (fired.length && rx && q.match && !q.match.notMatch) { const r = tryOne(`${q.strategy}+exclude-safe`, { ...q.match, notMatch: rx }); if (r?.rec.pass) break; }
  }
  const valid = attempts.filter((a) => a.valid);
  const best = valid.length ? [...valid].sort((a, b) => quality({ pass: b.pass, score: b.score }) - quality({ pass: a.pass, score: a.score }))[0] : null;
  return { attempts: attempts.map(({ ir, ...rest }) => rest), best: best ? { strategy: best.strategy, match: best.match, structure: best.structure, pass: best.pass, score: best.score, reasons: best.reasons } : null, exhausted: !attempts.some((a) => a.pass) };
}


/***/ })

};
