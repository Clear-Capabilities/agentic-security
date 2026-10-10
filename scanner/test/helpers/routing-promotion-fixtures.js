// GENERATED paired shadow/replay scenarios for exercising the routing-promotion ARITHMETIC. Not a test file.
//
// No model was called and nobody adjudicated anything: every correctness bit is a seeded draw against an accuracy the test chose, and
// every cost and latency is a number the test chose. A scenario built with `synthetic: false` is NOT evidence about any model; it is the
// only way to reach the non-synthetic branches (insufficient-population, fail, pass, invalid) of a gate that must refuse synthetic data.

import { unitOf } from './evaluation-generated.js';
import { outcomeOf, taskOf } from './routing-fixtures.js';
import { freezeTaskSet } from '../../src/posture/routing/promotion.js';

export const BASE = 'model-base';
export const CAND = 'model-cand';
export const LANGS = ['javascript', 'python'];

/**
 * `n` tasks over two strata (language), each answered by a baseline arm and a proposed arm.
 * `base` and `cand` are `{ acc, costUsd, latencyMs }`. `propose(i)` returns the proposed model id, or null to leave the task unserved.
 */
export function pairedScenario({ n = 240, synthetic = false, base = { acc: 0.8, costUsd: 0.1, latencyMs: 1000 }, cand = { acc: 0.8, costUsd: 0.05, latencyMs: 1000 }, propose = () => CAND, versionOf = () => '1', failEvery = 0, shared = true } = {}) {
  const tasks = []; const outcomes = []; const shadowRecords = [];
  for (let i = 0; i < n; i++) {
    const task = taskOf(i, { language: LANGS[i % 2], synthetic });
    tasks.push(task);
    const make = (model, spec) => {
      const jitter = 0.9 + 0.2 * unitOf(task.taskId, `jitter-${model}`);
      const fail = failEvery > 0 && model === CAND && i % failEvery === 0;
      return outcomeOf({
        task, model, version: versionOf(model), correct: fail ? null : unitOf(task.taskId, shared ? 'shared-draw' : model) < spec.acc, status: fail ? 'provider-error' : 'completed',
        costUsd: spec.costUsd === null ? null : spec.costUsd * jitter, latencyMs: spec.latencyMs * jitter, group: `grp-${task.taskId}`, synthetic,
      });
    };
    outcomes.push(make(BASE, base));
    const proposed = propose(i);
    if (proposed === CAND) outcomes.push(make(CAND, cand));
    shadowRecords.push(Object.freeze({
      schema: 'agentic-security/routing-shadow-record', taskId: task.taskId, stratum: task.stratum, production: Object.freeze({ model: BASE }),
      proposed: Object.freeze({ status: proposed ? 'routed' : 'blocked', code: proposed ? null : 'no-compliant-model', model: proposed, modelVersion: proposed ? versionOf(proposed) : null, via: proposed ? 'optimized' : null, policyVersion: 'policy-1', decisionHash: `sha256:fixture-${i}` }),
      synthetic, paidCalls: 0,
    }));
  }
  const f = freezeTaskSet(tasks);
  if (!f.ok) throw new Error(`fixture freeze failed: ${f.reason}`);
  return { tasks, outcomes, shadowRecords, frozen: f.frozen };
}
