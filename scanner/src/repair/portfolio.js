// Candidate portfolios (verified-remediation PRD FR-09, M2-01, M2-02): structural deduplication, cross-execution and deterministic ranking.
//
//   structuralKey     Two candidates that differ only in whitespace and comments are the same strategy: the key is a digest of each
//                     changed file with comments and whitespace removed. A structural duplicate consumes an attempt and is not run.
//   crossInputs       Every counterexample any candidate of the round produced (a development attack that disclosed a secret or
//                     broke a state check) becomes an extra attack request for every OTHER surviving candidate. A candidate that
//                     passed its own run but fails a sibling's counterexample is rejected before ranking (T-26). Sealed failures are
//                     never shared: their content does not leave the coordinator.
//   rankSurvivors     Deterministic order over candidates that passed every development obligation and the cross-execution:
//                     fewer material-risk categories, fewer files, fewer edited lines, generator preference (deterministic recipe,
//                     then user-supplied, then model), then candidate id. No model-supplied score is read.
import { digestOf } from '../posture/assurance/identity.js';

const stripComments = (t) => String(t)
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1')
  .replace(/(^|\n)\s*#[^\n]*/g, '$1');

export function structuralKey(files) {
  const norm = {};
  for (const [rel, t] of Object.entries(files || {}).sort(([a], [b]) => a.localeCompare(b))) norm[rel] = t === null ? null : stripComments(t).replace(/\s+/g, '');
  return digestOf(norm);
}

const GENERATOR_ORDER = { 'deterministic-recipe': 0, 'user-supplied': 1, 'configured-model': 2 };

export function rankSurvivors(survivors) {
  const key = (s) => [
    s.candidate.scope?.material?.categories?.length ?? 0,
    s.candidate.scope?.totals?.files ?? 99,
    s.candidate.scope?.totals?.editedLines ?? 1e9,
    GENERATOR_ORDER[s.candidate.generator] ?? 9,
  ];
  return [...survivors].sort((a, b) => {
    const ka = key(a); const kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
    return a.candidate.candidateId.localeCompare(b.candidate.candidateId);
  });
}

/**
 * The attack requests that disclosed a planted secret in a failed run, as shareable requests (`cross_<n>` ids). Only disclosure attacks are
 * shared: a durable-state attack is judged by an object-level check the sibling runs anyway. Content stays inside the coordinator.
 */
export function sharedAttacksFrom(inputs, details, extra = []) {
  const byId = Object.fromEntries(inputs.requests.map((r) => [r.id, r]));
  const out = [];
  for (const v of details?.attackViolations || []) {
    if (v.effect !== 'secret-disclosed') continue;
    const r = byId[v.id];
    if (r && r.role === 'attack') out.push(r);
  }
  for (const r of extra) if (r && r.role === 'attack' && r.forbid?.secrets?.length) out.push(r);
  return out;
}

/** Inputs carrying ONLY the controls and the shared attacks (deduplicated by request shape), for the cross-execution run. */
export function crossInputs(inputs, shared) {
  const seen = new Set(); const attacks = [];
  for (const r of shared) {
    const k = digestOf({ m: r.method, p: r.path, b: r.body ?? null, h: r.headers ?? {} });
    if (seen.has(k)) continue;
    seen.add(k);
    attacks.push({ ...r, id: `cross_${attacks.length}` });
  }
  return { ...inputs, requests: [...inputs.requests.filter((r) => r.role === 'control'), ...attacks], stateChecks: [] };
}
