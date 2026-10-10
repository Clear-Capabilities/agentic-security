// SYNTHETIC routing outcomes for exercising the routing machinery. Not a test file.
//
// Nothing here is a real routing outcome. No model was called, no reviewer adjudicated anything, and the "accuracy" of each fake model is
// a number the test chose. Every record is flagged `synthetic: true`, which is what makes the calibration refuse to call any estimate
// from it `reliable` (only `reliable-synthetic`) and the promotion population gate read `unmeasured`. A figure computed from these is a
// property of the generator, never of a model.

import { unitOf } from './evaluation-generated.js';
import { buildRoutingTask, deriveRoutingLabel, buildRoutingOutcome } from '../../src/posture/routing/outcomes.js';

export const HELD_OUT_FROM = '2026-04-01T00:00:00Z';
export const DEV_DATE = '2026-02-10T12:00:00Z';
export const HELD_DATE = '2026-05-10T12:00:00Z';

export const ADJUDICATION = (n = 'a') => ({ kind: 'independent-adjudication', reviewerKind: 'human', reviewerId: `synthetic-reviewer-${n}`, adjudicationVersion: 'synthetic-protocol-1' });

export function taskOf(i, over = {}) {
  const r = buildRoutingTask({ taskId: `syn-task-${i}`, taskKind: 'repair', language: 'javascript', vulnClass: 'CWE-89', contextTokens: 3000, requiredCapabilities: ['code-reasoning'], dataClass: 'source-code', synthetic: true, ...over });
  if (!r.ok) throw new Error(`fixture task invalid: ${JSON.stringify(r.errors)}`);
  return r.task;
}

/** One validated outcome record. `correct: null` leaves it unlabelled (`unknown`, or `delayed` with delayed:true). */
export function outcomeOf({ task, model, version = '1', correct = true, status = 'completed', observedAt = HELD_DATE, group = null, costUsd = 0.01, latencyMs = 800, delayed = false, runId = 'run-1', evidence = ADJUDICATION(), synthetic = true }) {
  let label = null; let outcome = delayed ? 'delayed' : 'unknown';
  if (correct !== null) {
    const d = deriveRoutingLabel({ task, model, outcome: correct ? 'correct' : 'incorrect', evidence });
    if (!d.accepted) throw new Error(`fixture label refused: ${d.reason}`);
    label = d.label; outcome = label.outcome;
  }
  const r = buildRoutingOutcome({
    runId, task, model, modelVersion: version, status, outcome, label, adjudicationVersion: label && label.labelSource === 'adjudication' ? evidence.adjudicationVersion : null,
    group: group || `grp-${task.taskId}`, usage: { inputTokens: 3000, outputTokens: 400, cachedInputTokens: null, retries: 0, source: 'measured' },
    costUsd, costStatus: costUsd === null ? 'unknown' : 'measured', latencyMs, cacheState: 'unknown', observedAt, synthetic,
  });
  if (!r.ok) throw new Error(`fixture outcome invalid: ${JSON.stringify(r.errors)}`);
  return r.outcome;
}

/**
 * A population: `dev` tasks before the split and `held` tasks after it, every task answered by every model, each task its own group
 * (or `groupSize` tasks per group). `models` is `[{ id, version, acc, costUsd, latencyMs }]`; a model is correct on a task when a
 * seeded unit draw falls under its accuracy.
 */
export function syntheticPopulation({ dev = 40, held = 240, models, groupSize = 1, strata = [{}], synthetic = true, startIndex = 0 }) {
  const outs = []; const tasks = [];
  const total = dev + held;
  for (let i = startIndex; i < startIndex + total; i++) {
    const isHeld = i - startIndex >= dev;
    const task = taskOf(i, { ...strata[i % strata.length], synthetic });
    tasks.push(task);
    const group = `grp-${isHeld ? 'h' : 'd'}-${Math.floor(i / groupSize)}`;
    for (const m of models) {
      outs.push(outcomeOf({
        task, model: m.id, version: m.version ?? '1', correct: unitOf(task.taskId, m.id) < m.acc, observedAt: isHeld ? HELD_DATE : DEV_DATE, group,
        costUsd: m.costUsd ?? 0.01, latencyMs: m.latencyMs ?? 800, synthetic,
      }));
    }
  }
  return { outcomes: outs, tasks };
}

export const BASE_CONFIG = Object.freeze({ id: 'syn-cal', version: '1', baselineModel: 'model-a', timeSplit: { heldOutFrom: HELD_OUT_FROM }, replicates: 200 });
