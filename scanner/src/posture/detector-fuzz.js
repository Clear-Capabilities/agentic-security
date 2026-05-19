// FR-ADV-6 — Adversarial fuzzing of detectors.
//
// Take a known-vuln fixture, mutate it across N strategies (using the
// adversarial-self-test mutator), and ask "does the scanner still catch
// every mutation?" Mutations that escape detection become regression fixtures.
//
// This module is the bench-side orchestrator. The mutation library lives in
// adversarial-self-test.js. The runner here is purely structural — it does
// NOT execute the scanner against the mutated text; that's the caller's
// responsibility (the runner has access to the scanner; this module is pure
// data).
//
// Public API:
//   prepareFuzzCorpus(fixtures)  → returns the mutation matrix ready to run
//   recordOutcome(matrixEntry, detected) → folds result back into matrix
//   summarize(matrix) → per-family escape rate

import { mutateSnippet } from './adversarial-self-test.js';

export function prepareFuzzCorpus(fixtures) {
  if (!Array.isArray(fixtures)) return [];
  const out = [];
  for (const fx of fixtures) {
    if (!fx || !fx.family || !fx.code) continue;
    const mutations = mutateSnippet(fx.code, fx.family);
    for (let i = 0; i < mutations.length; i++) {
      out.push({
        fixtureId: fx.id || `${fx.family}-${fx.file || 'inline'}`,
        family: fx.family,
        mutationIndex: i,
        mutationStrategy: `mut-${i + 1}`,
        mutatedCode: mutations[i],
        detected: null,
      });
    }
  }
  return out;
}

export function recordOutcome(entry, detected) {
  if (!entry || typeof entry !== 'object') return;
  entry.detected = !!detected;
}

export function summarize(matrix) {
  if (!Array.isArray(matrix)) return { perFamily: {}, totalEscaped: 0 };
  const perFamily = {};
  let totalEscaped = 0;
  for (const e of matrix) {
    if (e.detected === null) continue;
    if (!perFamily[e.family]) perFamily[e.family] = { run: 0, escaped: 0, detected: 0 };
    perFamily[e.family].run++;
    if (e.detected) perFamily[e.family].detected++;
    else { perFamily[e.family].escaped++; totalEscaped++; }
  }
  for (const k of Object.keys(perFamily)) {
    const v = perFamily[k];
    v.escapeRate = v.run ? Number((v.escaped / v.run).toFixed(2)) : 0;
  }
  return { perFamily, totalEscaped };
}
