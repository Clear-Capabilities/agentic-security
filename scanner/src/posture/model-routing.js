// Capability-based model routing for cost-sensitive subagent dispatch.
//
// A declarative CWE/severity → model policy. When the orchestrator is about to
// dispatch a delegable, cost-sensitive subagent for a finding (fixer, triager,
// PoC generator, attack-chain synthesizer), it can ask this module which model
// tier the work actually warrants — spend Opus reasoning on the hard classes
// (crypto, auth, deserialization, XXE, cross-file taint) and let Haiku handle
// the mechanical hardening findings.
//
// Mirrors the model IDs + tier vocabulary of hooks/model-cost-advisor.js:
//   strongest = claude-opus-4-8   (high effort)
//   mid       = claude-sonnet-4-6 (medium effort)
//   cheapest  = claude-haiku-4-5  (low effort)
//
// This is a *preference*, not a ceiling — a caller may always upgrade when the
// specific task clearly needs more capability (same spirit as the
// subagentOverride contract documented in the root CLAUDE.md).
//
// Pure + deterministic — no I/O, no network, never throws.

// Model IDs (module-local; the public API is the routing functions below).
const MODEL_STRONGEST = 'claude-opus-4-8';
const MODEL_MID = 'claude-sonnet-4-6';
const MODEL_CHEAPEST = 'claude-haiku-4-5';

const LABEL = {
  [MODEL_STRONGEST]: 'Opus 4.8',
  [MODEL_MID]: 'Sonnet 4.6',
  [MODEL_CHEAPEST]: 'Haiku 4.5',
};

// Hard classes — subtle, high-blast-radius bugs where a wrong fix is worse than
// no fix: auth, TLS/cert validation, weak crypto/hashing/randomness, signature
// verification, unsafe deserialization, XXE. Worth Opus when they land at high
// or critical severity.
const HARD_CWES = new Set([
  'CWE-287', // improper authentication
  'CWE-295', // improper certificate validation
  'CWE-327', // broken / risky crypto algorithm
  'CWE-328', // weak hash
  'CWE-330', // use of insufficiently random values
  'CWE-347', // improper verification of cryptographic signature
  'CWE-502', // deserialization of untrusted data
  'CWE-611', // XML external entity (XXE)
]);

// Mid classes — the common injection / traversal / CSRF / SSRF families.
// Well-understood remediations; Sonnet handles them cost-effectively.
const MID_CWES = new Set([
  'CWE-22',  // path traversal
  'CWE-78',  // OS command injection
  'CWE-79',  // cross-site scripting
  'CWE-89',  // SQL injection
  'CWE-94',  // code injection
  'CWE-352', // cross-site request forgery
  'CWE-434', // unrestricted file upload
  'CWE-601', // open redirect
  'CWE-918', // server-side request forgery
]);

// Extract the canonical `CWE-<n>` token from a finding.cwe value that may be a
// bare id ("CWE-89") or a descriptive string ("CWE-89: SQL Injection").
// Returns the uppercased id, or null when nothing parseable is present.
export function parseCwe(raw) {
  if (typeof raw !== 'string') return null;
  const m = raw.match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : null;
}

// Route a single finding to a model tier. First match wins.
// Returns { model, effort, reason }.
export function routeModelForFinding(finding) {
  const f = finding || {};
  const severity = typeof f.severity === 'string' ? f.severity.toLowerCase() : '';
  const cwe = parseCwe(f.cwe);
  const multiFile = f.multiFile === true || f.isCrossFile === true;
  const highOrCritical = severity === 'high' || severity === 'critical';

  // ── Tier 1: strongest (Opus, high effort) ──
  if (severity === 'critical') {
    return { model: MODEL_STRONGEST, effort: 'high',
      reason: `Critical severity — worth ${LABEL[MODEL_STRONGEST]} at high effort.` };
  }
  if (cwe && HARD_CWES.has(cwe) && highOrCritical) {
    return { model: MODEL_STRONGEST, effort: 'high',
      reason: `${cwe} at ${severity} severity is a hard class (crypto / auth / deserialization / XXE) — ${LABEL[MODEL_STRONGEST]} at high effort.` };
  }
  if (multiFile) {
    return { model: MODEL_STRONGEST, effort: 'high',
      reason: `Cross-file finding — needs ${LABEL[MODEL_STRONGEST]} at high effort to reason across files.` };
  }

  // ── Tier 2: mid (Sonnet, medium effort) ──
  if (cwe && MID_CWES.has(cwe)) {
    return { model: MODEL_MID, effort: 'medium',
      reason: `${cwe} is a common injection / traversal class — ${LABEL[MODEL_MID]} at medium effort.` };
  }
  if (severity === 'high') {
    return { model: MODEL_MID, effort: 'medium',
      reason: `High severity — ${LABEL[MODEL_MID]} at medium effort.` };
  }

  // ── Tier 3: cheapest (Haiku, low effort) ──
  return { model: MODEL_CHEAPEST, effort: 'low',
    reason: `${cwe ? `${cwe} at ` : ''}${severity || 'low'} severity is a simple / hardening class — ${LABEL[MODEL_CHEAPEST]} at low effort.` };
}

// Route a list of findings. Returns [{ finding, model, effort, reason }, …].
export function routeModelForFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  return list.map((finding) => ({ finding, ...routeModelForFinding(finding) }));
}

// Tally how many findings land on each model tier.
// Returns { 'claude-opus-4-8': n, 'claude-sonnet-4-6': n, 'claude-haiku-4-5': n }.
export function summarizeRouting(findings) {
  const counts = {
    [MODEL_STRONGEST]: 0,
    [MODEL_MID]: 0,
    [MODEL_CHEAPEST]: 0,
  };
  for (const { model } of routeModelForFindings(findings)) {
    if (model in counts) counts[model] += 1;
  }
  return counts;
}
