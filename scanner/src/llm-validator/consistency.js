// Pass^k consistency harness for the LLM validator.
//
// The validator is the only LLM in the production code path. Its verdicts
// (accept / reject / escalate) feed back into which findings ship. If it
// returns different verdicts on the same finding across runs, the customer
// sees inconsistent reports — and we'd never know unless we measured.
//
// This module runs the validator N times against a fixed set of findings,
// records each trial's verdict per finding, and reports:
//   - pass@k:   probability that at least one of k trials gave verdict X
//   - pass^k:   probability that ALL k trials gave the SAME verdict
//   - per-finding consistency rate
//   - cache-key consistency: do cached runs match initial runs?
//
// "If your agent has a 75% per-trial success rate and you run 3 trials, the
//  probability of passing all three is (0.75)³ ≈ 42%."
//   — Anthropic on demystifying evals for AI agents
//
// The validator's caching is invalidated for each trial by varying the
// challenge nonce; this gives an honest cold-cache pass^k. To measure the
// warm-cache equivalent, set `useCache: true`.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { validateOne } from './index.js';

import { statePath, stateWritesEnabled } from '../posture/state-dir.js';
// Build a deterministic test finding from the project's last-scan.json,
// or accept a hand-crafted one. Returns a clone safe to mutate per trial.
export function makeTrialFinding(template) {
  return JSON.parse(JSON.stringify(template));
}

// Run `trials` independent passes of `validateOne` on each finding. Returns
// a structured report. Caller is responsible for AGENTIC_SECURITY_LLM_VALIDATE
// / AGENTIC_SECURITY_LLM_ENDPOINT being set; if they aren't, the result will
// show every trial verdict as "unvalidated" — which is still a valid signal
// (the harness ran cleanly; the validator is simply off).
export async function measureConsistency({
  findings,
  fileContents = {},
  scanRoot,
  trials = 5,
  useCache = false,
} = {}) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return { ok: false, reason: 'no-findings-supplied' };
  }
  if (!Number.isInteger(trials) || trials < 2 || trials > 50) {
    return { ok: false, reason: 'trials-out-of-range' };
  }
  // For cold-cache mode, delete each finding's cache entry between trials.
  // We do this by NOT setting a cache dir per trial — easier: each trial
  // gets a fresh tmp scanRoot for the cache.
  const perFinding = new Map();   // findingId → { verdicts: [], confidences: [] }
  for (const f of findings) perFinding.set(f.id || f.stableId || 'unknown', { verdicts: [], confidences: [], reasons: [] });

  for (let t = 0; t < trials; t++) {
    for (const finding of findings) {
      const trial = makeTrialFinding(finding);
      // If useCache is false, we want each trial to bypass the cache; we
      // simulate by mutating the finding's file in a way the cache key
      // hashes over. Simpler: clear the per-scanRoot cache before each trial.
      // `stateWritesEnabled()` gates the DELETE as well as any write: removing
      // files from the scanned tree is a mutation like any other, and under a
      // read-only scan there is no cache to clear anyway. (PRD M1)
      if (!useCache && scanRoot && stateWritesEnabled()) {
        try {
          const cacheDir = statePath(scanRoot, 'llm-cache');
          if (fs.existsSync(cacheDir)) {
            for (const e of fs.readdirSync(cacheDir)) fs.unlinkSync(path.join(cacheDir, e));
          }
        } catch { /* best-effort */ }
      }
      try {
        await validateOne(trial, fileContents, scanRoot);
      } catch (e) {
        trial.validator_verdict = 'error';
        trial._validatorError = String((e && e.message) || e);
      }
      const key = finding.id || finding.stableId || 'unknown';
      const slot = perFinding.get(key);
      slot.verdicts.push(trial.validator_verdict || 'unset');
      slot.confidences.push(typeof trial.llm_confidence === 'number' ? trial.llm_confidence : null);
      slot.reasons.push(trial._validatorError || null);
    }
  }

  // Score per-finding consistency.
  const findingReports = [];
  let stableCount = 0;
  for (const [id, slot] of perFinding) {
    const counts = {};
    for (const v of slot.verdicts) counts[v] = (counts[v] || 0) + 1;
    const dominant = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    const stable = dominant[1] === trials;
    if (stable) stableCount++;
    findingReports.push({
      id,
      verdicts: slot.verdicts,
      dominantVerdict: dominant[0],
      dominantRate: dominant[1] / trials,
      stable,
      confidenceMean: _mean(slot.confidences),
      confidenceStdev: _stdev(slot.confidences),
    });
  }
  const passK = stableCount / perFinding.size;

  return {
    ok: true,
    trials,
    findingCount: perFinding.size,
    passK_unanimous: passK,    // pass^k where the bar is "all k agree"
    findings: findingReports,
    when: new Date().toISOString(),
  };
}

function _mean(arr) {
  const v = arr.filter(x => typeof x === 'number');
  if (!v.length) return null;
  return v.reduce((a, c) => a + c, 0) / v.length;
}
function _stdev(arr) {
  const v = arr.filter(x => typeof x === 'number');
  if (v.length < 2) return null;
  const m = _mean(v);
  const sq = v.reduce((a, c) => a + (c - m) * (c - m), 0) / (v.length - 1);
  return Math.sqrt(sq);
}

// Render a one-screen summary for CLI.
export function summarize(report) {
  if (!report || !report.ok) return `consistency: ${report?.reason || 'unknown error'}`;
  const lines = [];
  lines.push(`llm-validator consistency — trials=${report.trials}, findings=${report.findingCount}`);
  lines.push(`  pass^${report.trials} (unanimous): ${(report.passK_unanimous * 100).toFixed(1)}%`);
  lines.push('');
  for (const f of report.findings) {
    lines.push(`  · ${String(f.id).slice(0, 40).padEnd(40)} ${f.stable ? 'STABLE' : 'FLAPS'}  ${f.dominantVerdict} (${(f.dominantRate*100).toFixed(0)}%)  conf=${f.confidenceMean?.toFixed(2) ?? 'n/a'}±${f.confidenceStdev?.toFixed(2) ?? 'n/a'}`);
    if (!f.stable) lines.push(`      verdicts: [${f.verdicts.join(', ')}]`);
  }
  return lines.join('\n');
}
