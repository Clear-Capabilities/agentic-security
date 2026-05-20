// Probabilistic / soft taint (v0.70 #6).
//
// Today taint is binary: a value is either tainted or clean. Sanitizers
// clear taint entirely. Reality: many sanitizers reduce but don't eliminate
// exploitation probability. `escape_html()` blocks reflected XSS but
// leaves attribute-context XSS open. `Number(x)` blocks SQL/XSS for numeric
// columns but does nothing for text columns.
//
// Soft taint carries a [0,1] probability through the path:
//   - Source emits at p = 1.0 (fully tainted)
//   - Each sanitizer in the path multiplies by (1 - effectiveness)
//   - Threshold gates the final emission: findings below
//     AGENTIC_SECURITY_SOFT_TAINT_THRESHOLD (default 0.5) get demoted to
//     low-confidence rather than dropped
//
// This module annotates AFTER the taint engine runs. It walks each
// finding's trace + chain, looks up sanitizer effectiveness from the
// catalog, and emits `f.taintProbability` + `f.taintProbabilityWhy`.
//
// Engine-level lattice extension to {tainted, p} is v0.71. For v0.70 the
// post-pass shape captures the high-value case (sanitizer-in-path
// downweighting) without rewriting the core lattice.

import { CATALOG } from './catalog.js';

// Hand-curated effectiveness. 1.0 = full block; 0.0 = no effect.
// Conservative — when uncertain, lean toward 0.9 so findings don't
// silently disappear.
const DEFAULT_EFFECTIVENESS = {
  // Strong sanitizers — proven by spec to block the family.
  'DOMPurify.sanitize': 0.98,
  'sanitize':           0.95,
  'escape':             0.85,   // depends on context
  'htmlspecialchars':   0.90,
  'encodeURIComponent': 0.99,
  'encodeURI':          0.95,
  'JSON.stringify':     0.92,   // blocks most code-injection but not all
  'parameterize':       1.00,
  'AddWithValue':       1.00,
  'addWithValue':       1.00,
  'setString':          1.00,
  'setInt':             1.00,
  'setLong':            1.00,
  'bindParam':          1.00,
  'bindValue':          1.00,
  'quote_plus':         0.99,
  'escape_filter_chars':0.97,    // LDAP
  'shlex.quote':        0.99,
  // Numeric coercion — blocks injection of non-numeric metacharacters.
  'parseInt':           0.95,
  'parseFloat':         0.95,
  'Number':             0.90,
  'toInt':              0.95,
  // Weak / context-dependent.
  'trim':               0.05,
  'toLowerCase':        0.05,
  'toUpperCase':        0.05,
  'replace':            0.30,    // depends entirely on the regex
};

/**
 * Look up sanitizer effectiveness for a callee. Falls back to catalog
 * entries with `sanitizerEffectiveness` field; otherwise uses the
 * curated DEFAULT_EFFECTIVENESS table; otherwise returns null (unknown,
 * no downweight applied).
 */
export function effectivenessFor(callee) {
  if (!callee || typeof callee !== 'string') return null;
  // Tail of dotted callee.
  const tail = callee.split('.').pop();
  // Look in catalog first.
  for (const e of CATALOG) {
    if (e.kind !== 'sanitizer') continue;
    if (typeof e.sanitizerEffectiveness !== 'number') continue;
    if (e.match && e.match.callee === callee) return e.sanitizerEffectiveness;
    if (e.match && e.match.callee === tail)   return e.sanitizerEffectiveness;
  }
  if (callee in DEFAULT_EFFECTIVENESS) return DEFAULT_EFFECTIVENESS[callee];
  if (tail in DEFAULT_EFFECTIVENESS)   return DEFAULT_EFFECTIVENESS[tail];
  return null;
}

/**
 * Compute residual taint probability for a finding by walking its
 * trace + chain, looking up each callee's effectiveness, and applying
 * product of (1 - effectiveness).
 *
 * Returns { p, why: [...] } where why lists which sanitizers contributed.
 */
export function computeSoftTaintProbability(finding) {
  let p = 1.0;
  const why = [];
  const trace = Array.isArray(finding.trace) ? finding.trace : [];
  const chain = Array.isArray(finding.chain) ? finding.chain : [];
  const pathCalls = Array.isArray(finding.pathSteps) ? finding.pathSteps : [];
  const all = [...trace, ...chain, ...pathCalls];
  for (const step of all) {
    const callee = step.callee || step.label;
    if (!callee) continue;
    const eff = effectivenessFor(callee);
    if (eff == null) continue;
    p *= Math.max(0, Math.min(1, 1 - eff));
    why.push({ callee, effectiveness: eff });
    if (p < 1e-6) break;
  }
  return { p, why };
}

/**
 * Annotate every IR-TAINT finding with `taintProbability` and
 * `taintProbabilityWhy`. Findings below
 * AGENTIC_SECURITY_SOFT_TAINT_THRESHOLD (default 0.5) get demoted to
 * lower severity but are NOT dropped — auditors see the demotion +
 * the sanitizer that earned it.
 */
export function annotateSoftTaint(findings, opts = {}) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  const threshold = Number(opts.threshold ?? process.env.AGENTIC_SECURITY_SOFT_TAINT_THRESHOLD) || 0.5;
  let demoted = 0;
  for (const f of findings) {
    if (!f || f.parser !== 'IR-TAINT') continue;
    const r = computeSoftTaintProbability(f);
    f.taintProbability = r.p;
    f.taintProbabilityWhy = r.why;
    if (r.p < threshold) {
      f._softTaintDemoted = true;
      f._softTaintOriginalSeverity = f.severity;
      const downgrade = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
      if (downgrade[f.severity]) f.severity = downgrade[f.severity];
      demoted++;
    }
  }
  Object.defineProperty(findings, '_softTaintStats', {
    value: { demoted, threshold },
    enumerable: false,
  });
  return findings;
}

export const _internal = { DEFAULT_EFFECTIVENESS };
