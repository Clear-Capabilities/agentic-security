// Human ⇆ LLM grader calibration (eval-post recommendation #5).
//
// The Anthropic eval-post quote we're implementing:
//   "LLM-based rubrics should be frequently calibrated against expert
//    human judgment to grade these agents effectively."
//
// We have two grader streams in this codebase already:
//   - HUMAN: `/triage` writes per-finding verdicts (tp/fp/wontfix) to
//     `.agentic-security/triage-feedback.json`, keyed by stableId.
//   - LLM:   `llm-validator` writes per-finding verdicts (accept/reject/
//     escalate) to its cache under `.agentic-security/llm-cache/*.json`,
//     plus `validator_verdict` on each finding in `last-scan.json`.
//
// This module joins them on stableId and reports inter-rater agreement
// (Cohen's κ) over the overlap. κ < 0.6 means the LLM rubric is drifting
// from human judgment — operator should re-tune the prompt or escalate
// human review.
//
// Verdict mapping (TP/FP are the only ones κ measures):
//   HUMAN tp        ↔ LLM accept   ("real finding")
//   HUMAN fp        ↔ LLM reject   ("false positive")
//   HUMAN wontfix   → excluded from κ (not a quality signal)
//   LLM escalate    → excluded from κ (deliberate "I don't know")
//   LLM unvalidated → excluded from κ (validator didn't run)

import * as fs from 'node:fs';
import * as path from 'node:path';


import { statePath } from './state-dir.js';
function _loadTriageFeedback(scanRoot) {
  const fp = statePath(scanRoot, 'triage-feedback.json');
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')).entries || []; }
  catch { return []; }
}

function _loadScanVerdicts(scanRoot) {
  const fp = statePath(scanRoot, 'last-scan.json');
  if (!fs.existsSync(fp)) return [];
  try {
    const scan = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return (scan.findings || []).map(f => ({
      stableId: f.stableId || null,
      verdict: f.validator_verdict || null,
      confidence: typeof f.llm_confidence === 'number' ? f.llm_confidence : null,
    })).filter(e => e.stableId && e.verdict);
  } catch { return []; }
}

// Cohen's κ for two binary raters:
//   p_o = observed agreement = (concordant) / n
//   p_e = expected by chance = sum over classes c of (p_human_c * p_llm_c)
//   κ   = (p_o - p_e) / (1 - p_e)
// κ = 1: perfect agreement. κ = 0: chance. κ < 0: worse than chance.
// Common threshold: κ >= 0.6 is "substantial agreement" (Landis & Koch).
export function cohensKappa(pairs) {
  if (!Array.isArray(pairs) || pairs.length === 0) return { kappa: null, reason: 'no-pairs' };
  let agree = 0, hPos = 0, lPos = 0, n = pairs.length;
  for (const { human, llm } of pairs) {
    if (human === llm) agree++;
    if (human === 'positive') hPos++;
    if (llm === 'positive') lPos++;
  }
  const pO = agree / n;
  const pHumanPos = hPos / n, pLlmPos = lPos / n;
  const pE = pHumanPos * pLlmPos + (1 - pHumanPos) * (1 - pLlmPos);
  if (pE >= 0.9999) {
    // All raters agree on the same class — κ is undefined (1-pE → 0). Report
    // perfect or majority agreement honestly without dividing by ~0.
    return { kappa: pO === 1 ? 1 : null, reason: pO === 1 ? 'perfect-agreement' : 'pE-saturated', pO, pE, n };
  }
  const kappa = (pO - pE) / (1 - pE);
  return { kappa, pO, pE, n };
}

// Join human triage with LLM verdicts on stableId. Returns:
//   { pairs: [{ stableId, human, llm }], ... }
// where `human` and `llm` are mapped into the {positive, negative} binary used
// for κ. Findings that fall into the excluded buckets (wontfix, escalate,
// unvalidated) are stripped from `pairs` but counted under `excluded`.
export function joinHumanLlm(triageEntries, validatorEntries) {
  // Most-recent triage entry wins per stableId.
  const latestHuman = new Map();
  for (const e of triageEntries) {
    if (!e.stableId) continue;
    const prev = latestHuman.get(e.stableId);
    if (!prev || String(e.at || '').localeCompare(String(prev.at || '')) > 0) {
      latestHuman.set(e.stableId, e);
    }
  }
  const llmById = new Map();
  for (const v of validatorEntries) llmById.set(v.stableId, v);

  const pairs = [];
  const excluded = { human_wontfix: 0, llm_escalate: 0, llm_unvalidated: 0, llm_not_applicable: 0, no_llm_for_this_stableid: 0 };
  for (const [stableId, hum] of latestHuman) {
    const llm = llmById.get(stableId);
    if (!llm) { excluded.no_llm_for_this_stableid++; continue; }
    if (hum.verdict === 'wontfix') { excluded.human_wontfix++; continue; }
    if (llm.verdict === 'escalate') { excluded.llm_escalate++; continue; }
    if (llm.verdict === 'unvalidated') { excluded.llm_unvalidated++; continue; }
    if (llm.verdict === 'not-applicable') { excluded.llm_not_applicable++; continue; }
    // Map to binary.
    const humanBin = hum.verdict === 'tp' ? 'positive' : hum.verdict === 'fp' ? 'negative' : null;
    const llmBin   = llm.verdict === 'accept' ? 'positive' : llm.verdict === 'reject' ? 'negative' : null;
    if (!humanBin || !llmBin) continue;
    pairs.push({ stableId, human: humanBin, llm: llmBin, llmConfidence: llm.confidence });
  }
  return { pairs, excluded, totalTriaged: latestHuman.size, totalValidated: llmById.size };
}

// Full calibration report for a scanRoot.
//
// alarmAt: the κ threshold below which the operator should re-tune. Default
// 0.6 matches the "substantial agreement" cutoff in Landis & Koch (1977).
// MIN_N_FOR_ALARM: don't alarm on n<10; the CI on a small sample swamps κ.
const MIN_N_FOR_ALARM = 10;

export function calibrateGraders(scanRoot, { alarmAt = 0.6 } = {}) {
  const triage = _loadTriageFeedback(scanRoot);
  const llm = _loadScanVerdicts(scanRoot);
  const join = joinHumanLlm(triage, llm);
  const kapp = cohensKappa(join.pairs);
  const alarm = kapp.kappa !== null && kapp.n >= MIN_N_FOR_ALARM && kapp.kappa < alarmAt;
  return {
    when: new Date().toISOString(),
    triageEntries: triage.length,
    validatorEntries: llm.length,
    overlap: join.pairs.length,
    excluded: join.excluded,
    kappa: kapp.kappa,
    pObserved: kapp.pO,
    pExpected: kapp.pE,
    kappaInterpretation: _interpretKappa(kapp.kappa, kapp.n),
    alarm,
    alarmThreshold: alarmAt,
    note: alarm
      ? `LLM verdicts diverging from human triage (κ=${kapp.kappa?.toFixed(3)} < ${alarmAt}). Re-tune the validator prompt or escalate human review.`
      : kapp.kappa === null
        ? `Insufficient overlap (n=${kapp.n ?? 0}); skip calibration until more triage feedback accumulates.`
        : `Validator and human triage substantially agree (κ=${kapp.kappa.toFixed(3)}, n=${kapp.n}).`,
  };
}

function _interpretKappa(k, n) {
  if (k === null) return 'undefined';
  if (n < MIN_N_FOR_ALARM) return 'insufficient-sample';
  if (k < 0)    return 'worse-than-chance';
  if (k < 0.2)  return 'slight';
  if (k < 0.4)  return 'fair';
  if (k < 0.6)  return 'moderate';
  if (k < 0.8)  return 'substantial';
  return 'almost-perfect';
}
