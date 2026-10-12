// Rule intermediate representation: compiles DOWN into the existing pattern-rule engine
// (`../custom-rules.js`), never a parallel matcher. "Compile" here means "emit a
// custom-rules.js-compatible document" — detection at runtime is 100% the already-proven
// regex/allOf/notMatch/window engine; this module only adds PROVENANCE metadata around it.
//
// A rule's match semantics are deliberately the same closed vocabulary custom-rules.js
// already supports (pattern | allOf+window | notMatch) — no new matching primitive is
// introduced, so a promoted rule is exactly as auditable as a hand-written one.
import { sha256 } from '../proof-fabric/reproducer.js';

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
