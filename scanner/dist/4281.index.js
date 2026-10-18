export const id = 4281;
export const ids = [4281];
export const modules = {

/***/ 12090:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   KF: () => (/* binding */ toProofTier),
/* harmony export */   g3: () => (/* binding */ stateRank),
/* harmony export */   jn: () => (/* binding */ fromProofTier),
/* harmony export */   np: () => (/* binding */ advance)
/* harmony export */ });
/* unused harmony exports EVIDENCE_STATES, COMPLETENESS */
// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);


/***/ }),

/***/ 84281:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdRules: () => (/* binding */ cmdRules)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/ir.js
// Rule intermediate representation: compiles DOWN into the existing pattern-rule engine
// (`../custom-rules.js`), never a parallel matcher. "Compile" here means "emit a
// custom-rules.js-compatible document" — detection at runtime is 100% the already-proven
// regex/allOf/notMatch/window engine; this module only adds PROVENANCE metadata around it.
//
// A rule's match semantics are deliberately the same closed vocabulary custom-rules.js
// already supports (pattern | allOf+window | notMatch) — no new matching primitive is
// introduced, so a promoted rule is exactly as auditable as a hand-written one.


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
  if (!m || typeof m !== 'object') errs.push('match required');
  else {
    const hasPattern = isStr(m.pattern);
    const hasAllOf = Array.isArray(m.allOf) && m.allOf.length > 0 && m.allOf.every(isStr);
    if (!hasPattern && !hasAllOf) errs.push('match needs a pattern or a non-empty allOf');
    if (m.notMatch != null && !isStr(m.notMatch)) errs.push('notMatch must be a string');
    if (m.window != null && !(Number.isInteger(m.window) && m.window > 0 && m.window <= 200)) errs.push('window must be an integer in 1..200');
    for (const re of [m.pattern, ...(m.allOf || []), m.notMatch].filter(isStr)) {
      try { new RegExp(re); } catch { errs.push(`invalid regex: ${re}`); }
    }
  }
  // Declarative-only hint fields (sink/source/propagator/sanitizer/dominatingGuard/frameworkConstraint): free text,
  // never executable, carried for provenance/review only and NOT consulted by the matcher.
  for (const k of ['sink', 'source', 'propagator', 'sanitizer', 'dominatingGuard', 'frameworkConstraint']) {
    if (ir[k] != null && !isStr(ir[k])) errs.push(`${k} must be a string when present`);
  }
  if (ir.exclusions != null && !(Array.isArray(ir.exclusions) && ir.exclusions.every(isStr))) errs.push('exclusions must be an array of strings');
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
  return (0,reproducer/* sha256 */.sc)(JSON.stringify(rest, Object.keys(rest).sort()));
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
  const doc = {
    id: `rule-compiler/${ir.id}`,
    title: ir.title,
    severity: ir.severity,
    cwe: ir.cwe,
    languages: ir.languages,
    match: { ...(ir.match.pattern ? { pattern: ir.match.pattern } : {}), ...(ir.match.allOf ? { allOf: ir.match.allOf, window: ir.match.window ?? 5 } : {}), ...(ir.match.notMatch ? { notMatch: ir.match.notMatch } : {}) },
    message: ir.remediation || `${ir.title} (${ir.cwe}, compiled from ${ir.provenance.originatingFindingId})`,
  };
  return { ok: true, doc };
}

// EXTERNAL MODULE: ./src/posture/proof-fabric/states.js
var states = __webpack_require__(12090);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/eligibility.js
// X-eligibility (PRD 3 "Eligibility"): a finding may enter synthesis only with a stable id, a vulnerable span, a
// CWE/family, code-flow evidence, and deterministic corroboration OR exploit proof. Reuses the existing
// vocabularies rather than inventing a third: proof-fabric's evidence-state ladder when present, else the older
// proof-tier (`taint-proven`/`execution-proven`), else the finding's own `parser` (an IR-TAINT/MULTI-SINK parser
// origin is code-flow evidence even with no execution).


const ANALYSED_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);

function checkEligibility(finding, { proofState = null } = {}) {
  const reasons = [];
  if (!finding?.stableId && !finding?.id) reasons.push('no stable id');
  if (finding?.file == null || finding?.line == null) reasons.push('no vulnerable span (file:line)');
  if (!finding?.cwe && !finding?.family) reasons.push('no CWE or family');
  const hasFlowEvidence = ANALYSED_PARSERS.has(finding?.parser) || !!finding?.snippet;
  if (!hasFlowEvidence) reasons.push('no code-flow evidence (parser not IR-TAINT/MULTI-SINK, no snippet)');

  let evidenceState = 'none';
  if (proofState && (0,states/* stateRank */.g3)(proofState) >= (0,states/* stateRank */.g3)('EXPLOIT_CONFIRMED')) evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'execution-proven') evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'taint-proven' || ANALYSED_PARSERS.has(finding?.parser)) evidenceState = 'taint-proven';
  if (evidenceState === 'none') reasons.push('no deterministic corroboration or exploit proof');

  return { eligible: reasons.length === 0, reasons, evidenceState };
}

;// CONCATENATED MODULE: ./src/posture/rule-compiler/mutation.js
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

// EXTERNAL MODULE: ./src/posture/custom-rules.js + 1 modules
var custom_rules = __webpack_require__(9049);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/corpus.js
// Automatic corpus creation and scoring for ONE candidate rule.
//
// Positive corpus: the original vulnerable snippet plus its generated sibling variants (mutation.js).
// Negative corpus: an explicit patched/clean variant the caller supplies, nearby clean patterns, protected
// (sanitizer/guard) variants, and the NEGATIVE mutations of those (same mutators, applied to the safe side) — a
// candidate rule must decline on ALL of them, not just the one hand-picked negative.
//
// Scoring reuses the exact runtime matcher (`runRule` in `../custom-rules.js`), never a second implementation —
// the score a rule gets here is the score it will actually produce once promoted.




function toRuntimeRule(ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) throw new Error(`cannot build corpus for an invalid rule IR: ${errs.join('; ')}`);
  const regexes = doc.match.allOf ? doc.match.allOf.map((p) => new RegExp(p, 'g')) : [new RegExp(doc.match.pattern, 'g')];
  return {
    id: doc.id, title: doc.title, severity: doc.severity, cwe: doc.cwe, languages: doc.languages, message: doc.message,
    regexes, requireAll: !!doc.match.allOf, windowLines: doc.match.window ?? 5,
    notMatch: doc.match.notMatch ? new RegExp(doc.match.notMatch) : null,
  };
}

const EXT = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

function buildCorpus(ir, { originalCode, patchedCode = null, nearbyCleanCode = [], protectedVariantsCode = [] } = {}) {
  const positives = [{ label: 'original', code: originalCode }];
  for (const v of generateVariants(originalCode)) positives.push({ label: `sibling:${v.mutator}`, code: v.code });

  const negatives = [];
  if (patchedCode) {
    negatives.push({ label: 'patched', code: patchedCode });
    for (const v of generateVariants(patchedCode)) negatives.push({ label: `patched-sibling:${v.mutator}`, code: v.code });
  }
  // The safe side is mutated too (rename, wrapper, equivalent API, ALTERNATE SANITIZER, framework variant, ...): a rule keyed to one
  // sanitizer's name or one framework's accessor fires on the sibling that uses another, and that is a protected-negative failure.
  nearbyCleanCode.forEach((code, i) => {
    negatives.push({ label: `nearby-clean-${i}`, code });
    for (const v of generateVariants(code)) negatives.push({ label: `nearby-clean-${i}-sibling:${v.mutator}`, code: v.code });
  });
  protectedVariantsCode.forEach((code, i) => {
    negatives.push({ label: `protected-${i}`, code });
    for (const v of generateVariants(code)) negatives.push({ label: `protected-${i}-sibling:${v.mutator}`, code: v.code });
  });

  return { positives, negatives };
}

function scoreRule(ir, corpus) {
  const rule = toRuntimeRule(ir);
  const lang = ir.languages[0] || 'javascript';
  const file = EXT[lang] || 'x.txt';
  const run = (code) => (0,custom_rules/* runRule */.OA)(rule, file, code).length > 0;

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

;// CONCATENATED MODULE: ./src/posture/rule-compiler/promotion.js
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
  const score = scoreRule(ir, corpus);
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

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/lifecycle.js
// Rule lifecycle ledger: DRAFT -> CANDIDATE -> VALIDATED -> PROMOTED -> DEPRECATED/ROLLED_BACK.
//
// Append-only, hash-chained (same idiom as remediation-ledger.js / invariants/lifecycle.js): each entry links the
// previous entry's hash, so a dropped or edited middle record breaks the chain and `verifyLedger` catches it. A
// rule cannot promote itself: `transition` only records a transition a caller already decided; `advance`-style
// guarding on VALID edges lives here so no caller can jump DRAFT straight to PROMOTED.



const LEDGER_SCHEMA = 'agentic-security/rule-lifecycle-ledger';
const EDGES = Object.freeze({
  DRAFT: ['CANDIDATE'], CANDIDATE: ['VALIDATED', 'DRAFT'], VALIDATED: ['PROMOTED', 'DRAFT'],
  PROMOTED: ['DEPRECATED', 'ROLLED_BACK'], DEPRECATED: [], ROLLED_BACK: ['CANDIDATE'],
});

const hashOf = (entry) => (0,external_node_crypto_.createHash)('sha256').update(JSON.stringify(entry)).digest('hex');

function newLedger() { return { schema: LEDGER_SCHEMA, entries: [] }; }

function currentState(ledger, ruleId) {
  for (let i = ledger.entries.length - 1; i >= 0; i--) if (ledger.entries[i].ruleId === ruleId) return ledger.entries[i].to;
  return null;
}

/**
 * Record a transition. Refuses an edge not in EDGES, and refuses DRAFT->DRAFT re-entry for a rule that has never
 * existed (the first entry for a rule id must be `from: null, to: 'DRAFT'`).
 */
function recordTransition(ledger, { ruleId, from, to, reason, evidence = null, actor }) {
  if (!RULE_STATES.includes(to)) return { ok: false, reason: `unknown target state: ${to}` };
  const cur = currentState(ledger, ruleId);
  if (cur === null) {
    if (from !== null || to !== 'DRAFT') return { ok: false, reason: 'first transition for a rule must be null -> DRAFT' };
  } else {
    if (from !== cur) return { ok: false, reason: `stale transition: current state is ${cur}, not ${from}` };
    if (!EDGES[cur].includes(to)) return { ok: false, reason: `cannot go from ${cur} to ${to}` };
  }
  const prevHash = ledger.entries.length ? ledger.entries[ledger.entries.length - 1].entryHash : null;
  const entry = { ruleId, from: cur, to, reason: reason ?? null, evidence, actor: actor ?? 'unknown', at: new Date().toISOString(), prevHash };
  entry.entryHash = hashOf({ ...entry, entryHash: undefined });
  ledger.entries.push(entry);
  return { ok: true, entry };
}

function verifyLedger(ledger) {
  let prevHash = null;
  for (const e of ledger.entries) {
    if (e.prevHash !== prevHash) return { ok: false, reason: 'chain broken: prevHash mismatch' };
    const recomputed = hashOf({ ...e, entryHash: undefined });
    if (recomputed !== e.entryHash) return { ok: false, reason: `entry hash mismatch for ${e.ruleId} at ${e.at}` };
    prevHash = e.entryHash;
  }
  return { ok: true };
}

function historyFor(ledger, ruleId) { return ledger.entries.filter((e) => e.ruleId === ruleId); }
function stateOf(ledger, ruleId) { return currentState(ledger, ruleId); }

// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/store.js
// Persistence for the rule compiler: one directory per rule under `.agentic-security/rule-compiler/<id>/`
// (`ir.json`, `ledger.json`, `evaluation.json`), the promoted custom-rule document at
// `.agentic-security/rules/<id>.yml` (so the EXISTING `loadCustomRules`/`rule test` machinery picks it up with no
// change), and a regression fixture pair at `.agentic-security/rule-compiler/fixtures/<id>/{vulnerable,clean}/`
// using the SAME filename convention `runRuleTests` already reads (`vulnerable`/`clean` in the path).






const DIR = 'rule-compiler';
const store_EXT = { javascript: 'js', typescript: 'ts', python: 'py', go: 'go', ruby: 'rb', java: 'java', rust: 'rs', csharp: 'cs', php: 'php', any: 'txt' };

function ruleDir(scanRoot, id) { return (0,state_dir.statePath)(scanRoot, DIR, id); }

function loadLedger(scanRoot) {
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  if (!external_node_fs_.existsSync(f)) return newLedger();
  try {
    const ledger = JSON.parse(external_node_fs_.readFileSync(f, 'utf8'));
    const v = verifyLedger(ledger);
    return v.ok ? ledger : { ...newLedger(), tampered: true, tamperReason: v.reason };
  } catch { return newLedger(); }
}

function saveLedger(scanRoot, ledger) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(ledger, null, 2)) };
}

function saveIR(scanRoot, ir) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, ir.id), 'ir.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(ir, null, 2)), file: f };
}

function loadIR(scanRoot, id) {
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'ir.json');
  try { return JSON.parse(external_node_fs_.readFileSync(f, 'utf8')); } catch { return null; }
}

function saveJson(scanRoot, id, name, doc) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, id), name);
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(doc, null, 2)), file: f };
}
function loadJson(scanRoot, id, name) { try { return JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(ruleDir(scanRoot, id), name), 'utf8')); } catch { return null; } }
/** The corpus a rule was synthesized on, kept so `rules evaluate <id>` needs no flag and the evidence is the same corpus. */
const saveCorpus = (r, id, spec) => saveJson(r, id, 'corpus.json', spec);
const loadCorpus = (r, id) => loadJson(r, id, 'corpus.json');
/** Every synthesis attempt: strategy, match, score and why it did not pass. */
const saveSynthesis = (r, id, syn) => saveJson(r, id, 'synthesis.json', syn);
const loadSynthesis = (r, id) => loadJson(r, id, 'synthesis.json');
/** The rule's provenance record (PRD 3 requirement 7). */
const saveProvenance = (r, id, doc) => saveJson(r, id, 'provenance.json', doc);
const loadProvenance = (r, id) => loadJson(r, id, 'provenance.json');

function saveEvaluation(scanRoot, id, evaluation) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'evaluation.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(evaluation, null, 2)) };
}

/** Write the regression fixtures a promoted rule needs: the SAME vulnerable/clean convention `runRuleTests`
 * already reads, scored against the exact corpus the rule was promoted on. */
function writeFixtures(scanRoot, ir, corpus) {
  const ext = store_EXT[ir.languages[0]] || 'txt';
  const base = external_node_path_.join(ruleDir(scanRoot, ir.id), 'fixtures');
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const written = [];
  for (const p of corpus.positives) {
    const f = external_node_path_.join(base, 'vulnerable', `${p.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir.safeWriteState)(f, p.code)) written.push(f);
  }
  for (const n of corpus.negatives) {
    const f = external_node_path_.join(base, 'clean', `${n.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir.safeWriteState)(f, n.code)) written.push(f);
  }
  return { ok: true, written, glob: external_node_path_.join(base, '**', '*') };
}

/** Promote: write the compiled custom-rule document to the live rules directory. Does not touch the ledger —
 * the caller records the PROMOTED transition itself, so a failed write here can never produce an inconsistent
 * "promoted but not live" or "live but not recorded" state silently. */
function publishCustomRule(scanRoot, ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) return { ok: false, reason: `invalid rule IR: ${errs.join('; ')}` };
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${ir.id}.yml`);
  const yamlText = [
    `# Compiled by the rule compiler from finding ${ir.provenance.originatingFindingId} (${ir.provenance.evidenceState}).`,
    `- id: ${doc.id}`,
    `  title: ${JSON.stringify(doc.title)}`,
    `  severity: ${doc.severity}`,
    `  cwe: ${doc.cwe}`,
    `  languages: [${doc.languages.join(', ')}]`,
    `  match:`,
    ...(doc.match.pattern ? [`    pattern: ${JSON.stringify(doc.match.pattern)}`] : []),
    ...(doc.match.allOf ? [`    allOf:`, ...doc.match.allOf.map((p) => `      - ${JSON.stringify(p)}`), `    window: ${doc.match.window}`] : []),
    ...(doc.match.notMatch ? [`    notMatch: ${JSON.stringify(doc.match.notMatch)}`] : []),
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: (0,state_dir.safeWriteState)(f, yamlText), file: f };
}

function unpublishCustomRule(scanRoot, id) {
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${id}.yml`);
  try { if (external_node_fs_.existsSync(f)) external_node_fs_.unlinkSync(f); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}

;// CONCATENATED MODULE: ./src/posture/rule-compiler/proposal.js
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
  const add = (strategy, match) => { const k = JSON.stringify(match); if (!seen.has(k)) { seen.add(k); out.push({ strategy, match }); } };
  for (const l of lines.slice(0, 3)) add('line-shape', { pattern: generalizeLine(l) });
  for (const l of lines.slice(0, 3)) {
    const sink = sinkOf(l);
    if (sink) add('sink-with-interpolation', { pattern: `${esc(sink)}\\s*\\([^)\\n]*${interpolation}` });
  }
  const sink = lines.map(sinkOf).find(Boolean);
  const src = SOURCES.find((s) => new RegExp(s).test(vulnerableCode));
  if (sink && src) add('source-and-sink', { allOf: [`${esc(sink)}\\s*\\(`, src], window: 6 });
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
  const tryOne = (strategy, match) => {
    const key = JSON.stringify(match);
    if (tried.has(key) || attempts.length >= cap) return null;
    tried.add(key);
    const ir = draftRuleIR({ ...base, match });
    const errs = validateRuleIR(ir);
    if (errs.length) { attempts.push({ n: attempts.length + 1, strategy, match, valid: false, errors: errs, pass: false, reasons: errs }); return null; }
    const corpus = buildCorpus(ir, corpusSpec);
    const ev = evaluateRule(ir, corpus, thresholds);
    const rec = { n: attempts.length + 1, strategy, match, valid: true, pass: ev.pass && leakageOk, reasons: ev.reasons, score: summary(ev.score), ir, corpusSizes: { positives: corpus.positives.length, negatives: corpus.negatives.length } };
    attempts.push(rec);
    return { rec, ev };
  };
  for (let qi = 0; qi < queue.length && attempts.length < cap; qi++) {
    const first = tryOne(queue[qi].strategy, queue[qi].match);
    if (!first) continue;
    if (first.rec.pass) break;
    // revise from the failure: a negative that fired means the safe version is not excluded yet
    const fired = first.ev.score.negatives.filter((n) => n.fired);
    const rx = safeRegex(names);
    if (fired.length && rx && !queue[qi].match.notMatch) { const r = tryOne(`${queue[qi].strategy}+exclude-safe`, { ...queue[qi].match, notMatch: rx }); if (r?.rec.pass) break; }
  }
  const valid = attempts.filter((a) => a.valid);
  const best = valid.length ? [...valid].sort((a, b) => quality({ pass: b.pass, score: b.score }) - quality({ pass: a.pass, score: a.score }))[0] : null;
  return { attempts: attempts.map(({ ir, ...rest }) => rest), best: best ? { strategy: best.strategy, match: best.match, pass: best.pass, score: best.score, reasons: best.reasons } : null, exhausted: !attempts.some((a) => a.pass) };
}

;// CONCATENATED MODULE: ./src/posture/rule-compiler/cli.js
// CLI surface: `agentic-security rules synthesize|evaluate|promote|status|rollback`.
//
// Distinct from the pre-existing `labs synthesize-rule` (posture/rule-synthesis.js), which proposes SUPPRESSION
// rules from repeated false-positive triage verdicts — a different input, a different output and a different
// command group on purpose, so the two are never confused at the CLI.
//
// Non-interactive by construction: no command reads stdin, every corpus evaluation is bounded (no network, no
// model call — this is the deterministic half; a model may PROPOSE the candidate pattern this CLI is handed, but
// it never decides promotion).












function loadFinding(root, id) {
  const p = (0,state_dir.statePath)(root, 'last-scan.json');
  if (!external_node_fs_.existsSync(p)) return null;
  const last = JSON.parse(external_node_fs_.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function readJsonArg(pathOrInline) {
  if (!pathOrInline) return null;
  try { return JSON.parse(external_node_fs_.existsSync(pathOrInline) ? external_node_fs_.readFileSync(pathOrInline, 'utf8') : pathOrInline); } catch { return null; }
}

async function cmdRules(args, root) {
  const sub = args._[1];
  if (sub === 'synthesize') return cmdSynthesize(args, root);
  if (sub === 'evaluate') return cmdEvaluate(args, root);
  if (sub === 'promote') return cmdPromote(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'rollback') return cmdRollback(args, root);
  if (sub === 'cost') return cmdCost(args, root);
  console.error('usage: rules synthesize <finding-id> --spec <file.json> [--auto] [--max-attempts N] | evaluate <rule-id> | promote <rule-id> | status [rule-id] | rollback <rule-id> | cost <rule-id>');
  return 4;
}

// `--spec` carries exactly what a model or a human proposed: id/title/severity/cwe/family/languages/match/
// remediation plus the corpus inputs (originalCode/patchedCode/nearbyCleanCode/protectedVariantsCode). This
// command never invents a pattern; it only drafts the IR, checks eligibility and records DRAFT->CANDIDATE.
async function cmdSynthesize(args, root) {
  const findingId = args._[2];
  const spec = readJsonArg(args.flags.spec);
  if (!findingId || !spec) { console.error('usage: rules synthesize <finding-id> --spec <file.json>'); return 4; }
  const finding = loadFinding(root, findingId);
  if (!finding) { console.error(`Finding ${findingId} not found in last scan.`); return 4; }
  const elig = checkEligibility(finding, { proofState: args.flags['proof-state'] || null });
  if (!elig.eligible) { console.error(`Not eligible for rule synthesis: ${elig.reasons.join('; ')}`); return 4; }

  // The candidate pattern is the model's or the person's, when they gave one. Without one, or with --auto, the synthesis loop proposes
  // from the vulnerable and patched code, scores each attempt on the real corpus and its mutations, and revises (see proposal.js).
  let finalSpec = spec; let synthesis = null;
  const corpusSpec = { originalCode: spec.originalCode, patchedCode: spec.patchedCode ?? null, nearbyCleanCode: spec.nearbyCleanCode ?? [], protectedVariantsCode: spec.protectedVariantsCode ?? [] };
  const leak = checkLeakage(JSON.stringify(corpusSpec), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: spec.fileNames ?? [] });
  if (!leak.ok) { console.error(`Refusing: the material for this rule shows benchmark or answer-key signals (${leak.offendingTerms.join('; ')}). Nothing was written.`); return 4; }
  if (args.flags.auto || !spec.match) {
    if (!cli_isStr(spec.originalCode)) { console.error('Automatic proposal needs originalCode (the vulnerable snippet) in the spec.'); return 4; }
    const { id, title, severity, cwe, family, languages, remediation } = spec;
    synthesis = synthesizeCandidate({ base: { id, title, severity, cwe, family, languages, remediation, originatingFindingId: finding.stableId ?? finding.id, evidenceState: elig.evidenceState }, corpusSpec, proposed: spec.match ?? null, maxAttempts: Number(args.flags['max-attempts']) || 6, leakageOk: true });
    for (const a of synthesis.attempts) console.log(`  attempt ${a.n}: ${a.strategy.padEnd(34)} ${a.valid ? `precision ${fmtPct(a.score.precision)}  recall ${fmtPct(a.score.recall)}  protected-failures ${a.score.protectedFailures}${a.pass ? '  PASS' : ''}` : `invalid (${a.errors[0]})`}`);
    if (!synthesis.best) { console.error('No valid candidate could be proposed from this material.'); return 1; }
    finalSpec = { ...spec, match: synthesis.best.match };
    console.log(synthesis.best.pass ? `  candidate meets the promotion gate on this corpus (not yet recorded as VALIDATED).` : `  no attempt met the gate; the best is kept as a CANDIDATE only: ${synthesis.best.reasons.join('; ')}`);
  }
  const ir = draftRuleIR({ ...finalSpec, originatingFindingId: finding.stableId ?? finding.id, originatingCommit: spec.originatingCommit ?? null, evidenceState: elig.evidenceState });
  const errs = validateRuleIR(ir);
  if (errs.length) { console.error(`Invalid rule: ${errs.join('; ')}`); return 4; }

  const ledger = loadLedger(root);
  const draft = recordTransition(ledger, { ruleId: ir.id, from: null, to: 'DRAFT', reason: `drafted from ${findingId}`, actor: args.flags.actor || 'agent' });
  if (!draft.ok) { console.error(draft.reason); return 4; }
  const cand = recordTransition(ledger, { ruleId: ir.id, from: 'DRAFT', to: 'CANDIDATE', reason: 'eligibility passed', evidence: { eligibility: elig }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveIR(root, { ...ir, state: 'CANDIDATE' });
  saveCorpus(root, ir.id, { ...corpusSpec, fileNames: spec.fileNames ?? [], discoveryCost: spec.discoveryCost ?? (args.flags['discovery-cost-usd'] ? { usd: Number(args.flags['discovery-cost-usd']), tokens: Number(args.flags['discovery-tokens']) || null, model: spec.model ?? null } : null) });
  if (synthesis) saveSynthesis(root, ir.id, { attempts: synthesis.attempts, best: synthesis.best });
  console.log(`Rule ${ir.id}: DRAFT -> CANDIDATE (digest ${ruleIRDigest(ir).slice(0, 12)})`);
  if (!cand.ok) console.error(cand.reason);
  return 0;
}

async function cmdEvaluate(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules evaluate <rule-id> --corpus <file.json>'); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}. Run rules synthesize first.`); return 4; }
  const corpusSpec = readJsonArg(args.flags.corpus) ?? loadCorpus(root, id);
  if (!corpusSpec) { console.error('No corpus supplied. Pass --corpus <file.json> with originalCode (and optionally patchedCode/nearbyCleanCode/protectedVariantsCode).'); return 4; }
  const corpus = buildCorpus(ir, corpusSpec);
  const leakage = checkLeakage(JSON.stringify({ ...corpusSpec, fileNames: undefined, discoveryCost: undefined }), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: corpusSpec.fileNames ?? [] });
  const gate = gatePromotion({ ir, corpus, leakageCheck: leakage, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : PROMOTION_DEFAULTS });

  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (gate.pass && cur === 'CANDIDATE') recordTransition(ledger, { ruleId: id, from: 'CANDIDATE', to: 'VALIDATED', reason: 'promotion gate passed', evidence: { score: gate.evaluation.score }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveEvaluation(root, id, gate);
  const corpusHash = (list) => (0,reproducer/* sha256 */.sc)(JSON.stringify(list.map((x) => [x.label, x.code]).sort()));
  const prev = loadProvenance(root, id);
  saveProvenance(root, id, {
    schema: 'agentic-security/rule-provenance', version: 1, ruleId: id, ruleVersion: 1, ruleHash: ruleIRDigest(ir),
    originatingFinding: ir.provenance.originatingFindingId, originatingCommit: ir.provenance.originatingCommit, evidenceState: ir.provenance.evidenceState,
    generatingModel: ir.provenance.model, promptConfigVersion: ir.provenance.promptConfigVersion,
    positiveCorpusHash: corpusHash(corpus.positives), negativeCorpusHash: corpusHash(corpus.negatives),
    benchmarkResults: { precision: gate.evaluation.score.precision, recall: gate.evaluation.score.recall, tp: gate.evaluation.score.tp, fp: gate.evaluation.score.fp, fn: gate.evaluation.score.fn, tn: gate.evaluation.score.tn, protectedFailures: gate.evaluation.score.protectedFailures, thresholds: gate.evaluation.thresholds, gate: gate.pass ? 'passed' : 'failed', reasons: gate.reasons },
    leakageCheck: leakage, mutatorCoverage: mutatorCoverage(corpusSpec.originalCode), discoveryCost: corpusSpec.discoveryCost ?? prev?.discoveryCost ?? null,
    promotionEvent: prev?.promotionEvent ?? null, evaluatedAt: new Date().toISOString(),
  });
  if (args.flags.json) console.log(JSON.stringify(gate, null, 2));
  else {
    console.log(`Rule ${id}: ${gate.pass ? 'VALIDATED' : 'gate FAILED'}`);
    console.log(`  precision ${fmtPct(gate.evaluation.score.precision)}  recall ${fmtPct(gate.evaluation.score.recall)}  protected-failures ${gate.evaluation.score.protectedFailures}`);
    for (const r of gate.reasons) console.log(`  - ${r}`);
  }
  if (gate.pass) { const f = writeFixtures(root, ir, corpus); if (f.ok) console.log(`  regression fixtures written: ${f.written.length} file(s) under .agentic-security/rule-compiler/${id}/fixtures/`); }
  return gate.pass ? 0 : 1;
}
function cli_isStr(v) { return typeof v === 'string' && v.length > 0; }
const fmtPct = (n) => (n == null ? 'unmeasured' : `${(n * 100).toFixed(1)}%`);

async function cmdPromote(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules promote <rule-id>'); return 4; }
  const ledger = loadLedger(root);
  if (ledger.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${ledger.tamperReason}).`); return 4; }
  if (stateOf(ledger, id) !== 'VALIDATED') { console.error(`Rule ${id} is not VALIDATED (run rules evaluate first); refusing to promote.`); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}.`); return 4; }
  const pub = publishCustomRule(root, ir);
  if (!pub.ok) { console.error(`Promotion refused: ${pub.reason}`); return 4; }
  const t = recordTransition(ledger, { ruleId: id, from: 'VALIDATED', to: 'PROMOTED', reason: args.flags.reason || 'promoted', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  const prov = loadProvenance(root, id);
  if (prov) saveProvenance(root, id, { ...prov, promotionEvent: { at: new Date().toISOString(), actor: args.flags.actor || 'operator', reason: args.flags.reason || 'promoted', ruleHash: ruleIRDigest(ir) } });
  console.log(`Rule ${id}: VALIDATED -> PROMOTED. Published to ${pub.file}.`);
  if (!t.ok) console.error(t.reason);
  return 0;
}

async function cmdRollback(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules rollback <rule-id> [--reason text]'); return 4; }
  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (cur !== 'PROMOTED') { console.error(`Rule ${id} is not PROMOTED (current: ${cur ?? 'unknown'}); nothing to roll back.`); return 4; }
  const un = unpublishCustomRule(root, id);
  const t = recordTransition(ledger, { ruleId: id, from: 'PROMOTED', to: 'ROLLED_BACK', reason: args.flags.reason || 'operator rollback', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  console.log(`Rule ${id}: PROMOTED -> ROLLED_BACK.${un.ok ? '' : ` (warning: could not remove published rule file: ${un.reason})`}`);
  return t.ok ? 0 : 1;
}

async function cmdStatus(args, root) {
  const ledger = loadLedger(root);
  const id = args._[2];
  if (id) {
    const h = historyFor(ledger, id);
    if (!h.length) { console.error(`No history for rule ${id}.`); return 4; }
    if (args.flags.json) console.log(JSON.stringify(h, null, 2));
    else { console.log(`Rule ${id}: ${stateOf(ledger, id)}`); for (const e of h) console.log(`  ${e.at}  ${e.from ?? '(new)'} -> ${e.to}  (${e.reason || ''})`); 
      const syn = loadSynthesis(root, id);
      if (syn?.attempts?.length) { console.log(`  synthesis: ${syn.attempts.length} attempt(s), best ${syn.best ? `${syn.best.strategy}${syn.best.pass ? ' (met the gate)' : ' (did not meet the gate)'}` : 'none'}`); }
    }
    return 0;
  }
  const ids = [...new Set(ledger.entries.map((e) => e.ruleId))];
  if (args.flags.json) { console.log(JSON.stringify(ids.map((rid) => ({ id: rid, state: stateOf(ledger, rid) })), null, 2)); return 0; }
  if (!ids.length) { console.log('No rules in the lifecycle ledger yet.'); return 0; }
  for (const rid of ids) console.log(`  ${rid.padEnd(40)} ${stateOf(ledger, rid)}`);
  return 0;
}

// PRD 3 business metric: what the first, model-assisted discovery cost, against what every later deterministic detection costs.
// The discovery cost is whatever the agent run reported for it (recorded at synthesis); a deterministic detection makes no model
// call and is $0 of model spend. The count of later detections is read from the LAST scan only, so it is a floor, not a history.
async function cmdCost(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules cost <rule-id>'); return 4; }
  const prov = loadProvenance(root, id);
  if (!prov) { console.error(`No provenance for ${id}. Run rules evaluate first.`); return 4; }
  let detections = null;
  try { const last = JSON.parse(external_node_fs_.readFileSync((0,state_dir.statePath)(root, 'last-scan.json'), 'utf8')); detections = (last.findings || []).filter((f) => String(f.id || '').startsWith(`custom:rule-compiler/${id}:`)).length; } catch { /* no scan */ }
  const first = prov.discoveryCost;
  const out = { ruleId: id, firstDiscovery: first ? { usd: first.usd ?? null, tokens: first.tokens ?? null, model: first.model ?? null } : null, laterDeterministicDetections: detections, laterDeterministicModelUsd: 0, state: prov.promotionEvent ? 'promoted' : 'not promoted' };
  if (args.flags.json) { console.log(JSON.stringify(out, null, 2)); return 0; }
  console.log(`Rule ${id} (${out.state})`);
  console.log(first ? `  first discovery: ${first.usd != null ? `$${first.usd}` : 'cost not recorded'}${first.tokens ? `, ${first.tokens} tokens` : ''}${first.model ? `, ${first.model}` : ''}` : '  first discovery: cost was not recorded for this rule');
  console.log(`  later detections by this rule in the last scan: ${detections ?? 'no scan available'}, each at $0 of model spend`);
  if (first?.usd != null && detections) console.log(`  discovery cost spread over ${detections + 1} detection(s): $${(first.usd / (detections + 1)).toFixed(4)} each, falling with every further one`);
  return 0;
}


/***/ })

};
