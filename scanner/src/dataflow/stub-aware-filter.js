// Type-stub-aware taint filter (v0.73).
//
// v0.70 added scanner/src/ir/type-stubs.js but only wired it into the
// receiver-context lookup. This post-pass closes the loop: after the
// taint engine emits findings, we consult the stubs map to demote
// findings whose source/sink type pair is provably incompatible with
// the vulnerability class.
//
// Example: a source that returns `number` (per stub signature) flowing
// to an XSS sink is suppressable — a number coerced to string can only
// produce digits/decimal/sign, which can't form the metacharacters
// (<, >, ', ") required to break out of an HTML context.
//
// Rules per vuln family:
//   XSS (CWE-79):       source type ∈ {number, boolean, Date, RegExp} → demote
//   SQL inj (CWE-89):   source type ∈ {number, boolean, Date}         → demote
//   Cmd inj (CWE-78):   source type ∈ {number, boolean}               → demote
//   Path trav (CWE-22): source type ∈ {number, boolean}               → demote
//
// Demotion lowers confidence + confidenceTier + exploitabilityTier by one
// step and sets `_stubTypeDemoted: true` with a `_stubTypeReason` — the
// same recall-preserving shape every other precision annotator in this
// directory uses (proof-gate.js, verification-separation.js). Severity is
// never touched and findings are never DROPPED — the stub-aware reason is
// shown to the operator so they can override if the stub is wrong or out
// of date. (This module used to mutate severity directly; that violated
// the convention and was flagged, not designed — see dataflow/CLAUDE.md.)

const FAMILY_SAFE_TYPES = {
  'CWE-79':  new Set(['number', 'boolean', 'Date', 'RegExp', 'bigint']),
  'CWE-89':  new Set(['number', 'boolean', 'Date', 'bigint']),
  'CWE-78':  new Set(['number', 'boolean', 'bigint']),
  'CWE-22':  new Set(['number', 'boolean']),
  'CWE-918': new Set(['number', 'boolean']),
};

/**
 * Try to resolve the type of the finding's source from the type-stubs map.
 * The lookup chain: (1) the finding's source.label or trace[0].sourceLabel
 * is the catalog source id; (2) the stub signature for the source's
 * underlying function. Returns the type string ('string', 'number', …)
 * or null if unknown.
 */
function _sourceTypeFromStubs(finding, stubs) {
  if (!stubs || !stubs.signatures) return null;
  const trace = Array.isArray(finding.trace) ? finding.trace : [];
  const src = trace[0] || finding.source;
  const label = src?.sourceLabel || src?.label || '';
  // The label is shaped like 'req.body' / 'request.GET' / etc. The
  // underlying function lookup uses the LAST identifier as a callable name.
  const tail = String(label).split('.').pop();
  if (!tail) return null;
  const sig = stubs.signatures.get(tail);
  if (!sig) return null;
  return _normalizeType(sig.returnType);
}

function _normalizeType(t) {
  if (!t) return null;
  const trimmed = String(t).trim().toLowerCase();
  if (trimmed === 'number' || trimmed === 'numeric' || /^int(8|16|32|64)?$/.test(trimmed)) return 'number';
  if (trimmed === 'bigint') return 'bigint';
  if (trimmed === 'boolean' || trimmed === 'bool') return 'boolean';
  if (trimmed === 'date')   return 'Date';
  if (trimmed === 'regexp') return 'RegExp';
  if (trimmed === 'string' || trimmed === 'str') return 'string';
  if (trimmed.endsWith('[]') || trimmed.startsWith('array<')) return 'array';
  return trimmed;
}

// Tier ladders, lowest → highest — identical shape to proof-gate.js's, kept
// as a local copy rather than importing that module's test-only `_internals`
// across a module boundary.
const CONFIDENCE_TIERS = ['very-low', 'low', 'medium', 'high'];
const EXPLOITABILITY_TIERS = ['low', 'medium', 'high', 'critical'];
const CONFIDENCE_DEMOTE_FACTOR = 0.4;

function _demoteTier(tier, ladder) {
  const i = ladder.indexOf(tier);
  if (i <= 0) return ladder[0];
  return ladder[i - 1];
}

function _demote(f) {
  if (typeof f.confidence === 'number') {
    f._confidenceBeforeStubFilter = f.confidence;
    f.confidence = Math.max(0.01, Number((f.confidence * CONFIDENCE_DEMOTE_FACTOR).toFixed(4)));
  }
  if (f.confidenceTier) f.confidenceTier = _demoteTier(f.confidenceTier, CONFIDENCE_TIERS);
  if (f.exploitabilityTier) f.exploitabilityTier = _demoteTier(f.exploitabilityTier, EXPLOITABILITY_TIERS);
}

/**
 * Post-pass entry. Mutates findings in place: adds `_stubTypeDemoted`,
 * `_stubTypeReason`, demotes confidence/confidenceTier/exploitabilityTier
 * by one step when the source type is in the family-safe set for the
 * finding's CWE. Severity is never touched (recall-preserving).
 *
 * Returns the (mutated) findings array with `_stubFilterStats` non-
 * enumerable sidecar.
 */
const TYPE_GUARD_PATTERNS = [
  { re: /typeof\s+(\w+)\s*===?\s*['"]number['"]/, type: 'number' },
  { re: /typeof\s+(\w+)\s*===?\s*['"]boolean['"]/, type: 'boolean' },
  { re: /Number\.isInteger\s*\(\s*(\w+)\s*\)/, type: 'number' },
  { re: /Number\.isFinite\s*\(\s*(\w+)\s*\)/, type: 'number' },
  { re: /!isNaN\s*\(\s*(\w+)\s*\)/, type: 'number' },
];

function _extractTypeGuardType(condExpr) {
  if (!condExpr) return null;
  const condStr = _exprToString(condExpr);
  if (!condStr) return null;
  for (const { re, type } of TYPE_GUARD_PATTERNS) {
    if (re.test(condStr)) return type;
  }
  return null;
}

function _exprToString(expr) {
  if (!expr) return null;
  if (expr.kind === 'literal') return String(expr.value || '');
  if (expr.kind === 'ident') return expr.name;
  if (expr.kind === 'binary') return `${_exprToString(expr.left)} ${expr.op} ${_exprToString(expr.right)}`;
  if (expr.kind === 'call') return `${typeof expr.callee === 'string' ? expr.callee : _exprToString(expr.callee)}(${(expr.args || []).map(_exprToString).join(',')})`;
  if (expr.kind === 'member') return `${_exprToString(expr.object)}.${expr.prop}`;
  if (expr.kind === 'unknown') return 'typeof';
  return null;
}

function _hasTypeGuardOnPath(finding, perFileIR) {
  if (!perFileIR || !finding.file) return null;
  const ir = perFileIR[finding.file];
  if (!ir || !ir.functions) return null;
  const fn = ir.functions.find(f => {
    const sinkLine = finding.line || 0;
    return sinkLine >= f.line && sinkLine <= f.line + Object.keys(f.cfg.nodes).length * 3;
  });
  if (!fn) return null;
  for (const node of Object.values(fn.cfg.nodes)) {
    if (node.kind === 'if' && node.cond) {
      const guardType = _extractTypeGuardType(node.cond);
      if (guardType) return guardType;
    }
  }
  return null;
}

export function applyStubAwareFilter(findings, stubs, perFileIR) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  let demoted = 0;
  for (const f of findings) {
    if (!f || f.parser !== 'IR-TAINT') continue;
    const safeSet = FAMILY_SAFE_TYPES[f.cwe];
    if (!safeSet) continue;
    // Check 1: stub-based type demotion
    const sourceType = stubs ? _sourceTypeFromStubs(f, stubs) : null;
    if (sourceType && safeSet.has(sourceType)) {
      f._stubTypeDemoted = true;
      f._stubTypeReason = `source type ${sourceType} cannot carry ${f.cwe} metacharacters`;
      _demote(f);
      demoted++;
      continue;
    }
    // Check 2: type-guard narrowing on CFG path
    const guardType = _hasTypeGuardOnPath(f, perFileIR);
    if (guardType && safeSet.has(guardType)) {
      f._stubTypeDemoted = true;
      f._stubTypeReason = `type guard narrows to ${guardType}, safe for ${f.cwe}`;
      _demote(f);
      demoted++;
    }
  }
  Object.defineProperty(findings, '_stubFilterStats', {
    value: { demoted, totalConsidered: findings.length },
    enumerable: false,
  });
  return findings;
}

export const _internal = { FAMILY_SAFE_TYPES, _sourceTypeFromStubs, _normalizeType, CONFIDENCE_TIERS, EXPLOITABILITY_TIERS, _demoteTier };
