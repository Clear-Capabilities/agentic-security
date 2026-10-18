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
import { sha256 } from '../proof-fabric/reproducer.js';
import { normalizeCustomRule } from '../custom-rules.js';

const RULE_IR_SCHEMA = 'agentic-security/rule-ir';
const RULE_IR_VERSION = 1;
export const RULE_STATES = Object.freeze(['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED', 'DEPRECATED', 'ROLLED_BACK']);
const VALID_LANGS = new Set(['javascript', 'typescript', 'python', 'go', 'ruby', 'java', 'rust', 'csharp', 'php', 'any']);

const isStr = (v) => typeof v === 'string' && v.length > 0;

/** Problems with a draft rule IR; an empty list means it is well-formed (not yet validated/promoted). */
export function validateRuleIR(ir) {
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

export function ruleIRDigest(ir) {
  const { state: _s, ...rest } = ir;
  return sha256(JSON.stringify(rest, Object.keys(rest).sort()));
}

/** Build a DRAFT rule IR. Caller supplies the candidate pattern — this module never invents one. */
export function draftRuleIR({ id, title, severity, cwe, family, languages, match, remediation, originatingFindingId, originatingCommit, evidenceState, model = null, promptConfigVersion = null, ...hints }) {
  const ir = {
    schema: RULE_IR_SCHEMA, version: RULE_IR_VERSION, id, title, severity, cwe, family, languages, match,
    remediation: remediation ?? null, state: 'DRAFT',
    ...hints,
    provenance: { originatingFindingId, originatingCommit: originatingCommit ?? null, evidenceState, model, promptConfigVersion },
  };
  return ir;
}

/** Compile a rule IR into a custom-rules.js-compatible document. Caller writes the YAML. */
export function compileToCustomRule(ir) {
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
  let normalized; try { normalized = normalizeCustomRule(doc); } finally { console.error = origError; }
  if (!normalized) return { ok: false, errs: [`the scanner's rule loader would reject this rule${loaderSaid ? `: ${loaderSaid.replace(/^agentic-security:\s*/, '').slice(0, 160)}` : ''}`] };
  return { ok: true, doc };
}
