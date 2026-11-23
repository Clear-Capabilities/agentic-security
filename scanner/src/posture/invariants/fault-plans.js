// Security fault plans on the business-state harness (contract-driven verification, Epic E).
//
// THE DETERMINISM BOUNDARY, stated precisely. The harness controls: the seed, the order of steps, an explicit schedule (a permutation)
// for a group of up to four steps started together, repeated delivery of the same request (same arguments, same request id), and the
// durable store and effect log the oracle reads. It does NOT control: wall-clock time inside the application, native or background
// work, a dependency's responses (the harness offers no dependency stub), process interruption between two writes, or disk and
// transaction failure points. A plan that needs anything outside that boundary is `unsupported` with the reason, never approximated;
// a run whose two fresh replays disagree is reported nondeterministic by the oracle, never as a verdict.
//
// Supported plans, compiled onto a base scenario with `deriveScenario` (so the derived scenario has its own content id):
//   duplicate-delivery   the attack's first step delivered `copies` times (at-least-once delivery, a retried request)
//   reorder              the attack's steps as one group started together under an explicit schedule
//   revocation-between   a step that changes a role or tenant placed between the authorization-bearing step and the mutation, in an
//                        explicit order (needs the plan to name the revoking step: the application must expose it)
// Unsupported here: dependency-timeout, dependency-failure, process-interruption, disk-failure, virtual-time.
import { deriveScenario, runScenario } from './scenarios.js';
import { digestOf } from '../assurance/identity.js';

export const SUPPORTED_FAULTS = Object.freeze(['duplicate-delivery', 'reorder', 'revocation-between']);
export const UNSUPPORTED_FAULTS = Object.freeze({
  'dependency-timeout': 'the harness offers no dependency stub, so a dependency response cannot be controlled',
  'dependency-failure': 'the harness offers no dependency stub, so a dependency response cannot be controlled',
  'process-interruption': 'the harness cannot stop the application between two writes and resume it',
  'disk-failure': 'the in-memory store has no failure point the harness can trigger',
  'virtual-time': 'the application\'s clock is not instrumented; time-dependent behaviour is outside the deterministic claim',
});

const isPerm = (s, n) => Array.isArray(s) && s.length === n && [...s].sort((a, b) => a - b).every((x, i) => x === i);

/** Compile a plan onto a scenario. Returns `{ status: 'ok', scenario, plan, schedule }` or `{ status: 'unsupported'|'rejected', reason }`. */
export function applyFaultPlan(base, plan) {
  if (!plan || typeof plan.kind !== 'string') return { status: 'rejected', reason: 'a plan names its kind' };
  if (UNSUPPORTED_FAULTS[plan.kind]) return { status: 'unsupported', reason: UNSUPPORTED_FAULTS[plan.kind], plan };
  if (!SUPPORTED_FAULTS.includes(plan.kind)) return { status: 'rejected', reason: `unknown fault ${plan.kind}` };
  const attack = base.inputs.attack.filter((it) => !it.parallel);
  if (!attack.length) return { status: 'unsupported', reason: 'the base scenario has no sequential attack step to fault', plan };
  let items; let schedule = null;
  if (plan.kind === 'duplicate-delivery') {
    const copies = Number.isInteger(plan.copies) ? plan.copies : 2;
    if (copies < 2 || copies > 4) return { status: 'rejected', reason: 'duplicate delivery repeats a step 2 to 4 times' };
    const step = plan.step ?? attack[0];
    items = Array.from({ length: copies }, () => JSON.parse(JSON.stringify(step)));
  } else if (plan.kind === 'reorder') {
    const steps = (plan.steps ?? attack).slice(0, 4);
    if (steps.length < 2) return { status: 'unsupported', reason: 'reordering needs at least two steps', plan };
    schedule = plan.schedule ?? steps.map((_, i) => steps.length - 1 - i);
    if (!isPerm(schedule, steps.length)) return { status: 'rejected', reason: 'the schedule must be a permutation of the group' };
    items = [{ parallel: steps, schedule }];
  } else {
    if (!plan.revokeStep || !plan.authorizedStep || !plan.mutationStep) return { status: 'unsupported', reason: 'revocation between authorization and mutation needs the application\'s own revoking step, an authorized step and the mutation', plan };
    items = [plan.authorizedStep, plan.revokeStep, plan.mutationStep];
  }
  const scenario = deriveScenario(base, { ...base.inputs, attack: items });
  return { status: 'ok', scenario, plan: { ...plan, kind: plan.kind }, schedule, planDigest: digestOf({ plan, items }) };
}

/**
 * Run a compiled fault scenario twice in fresh boundary runs and record a replay artifact: seed, plan, explicit schedule, outcome of
 * each run, and whether they agree. A disagreement is reported as such; it is never resolved by picking one.
 */
export async function replayFaultScenario(compiled, { fixture, commit, config, runOptions } = {}) {
  if (compiled.status !== 'ok') return { status: compiled.status, reason: compiled.reason, artifact: null };
  const runs = [];
  for (let i = 0; i < 2; i++) runs.push(await runScenario(compiled.scenario, { fixture, commit, config, runOptions }));
  const outcomes = runs.map((r) => (r.status === 'completed' ? r.outcome : `${r.status}`));
  const reproduced = outcomes[0] === outcomes[1] && runs.every((r) => r.status === 'completed');
  const artifact = {
    schema: 'agentic-security/fault-replay', scenarioId: compiled.scenario.id, seed: compiled.scenario.seed, plan: compiled.plan, planDigest: compiled.planDigest,
    schedule: compiled.schedule, fixtureDigest: compiled.scenario.fixtureDigest, commit, determinism: compiled.scenario.determinism, outcomes, reproduced,
    boundary: { controlled: ['seed', 'step order', 'explicit group schedule', 'repeated delivery', 'durable store'], notControlled: Object.keys(UNSUPPORTED_FAULTS) },
  };
  return { status: reproduced ? 'reproduced' : 'not-reproduced', artifact, runs };
}

/** What changed between two plans' artifacts, for the record (E-AC02). */
export function diffFaultArtifacts(a, b) {
  const changes = [];
  if (a.plan?.kind !== b.plan?.kind) changes.push({ field: 'plan.kind', from: a.plan?.kind, to: b.plan?.kind });
  if (JSON.stringify(a.schedule) !== JSON.stringify(b.schedule)) changes.push({ field: 'schedule', from: a.schedule, to: b.schedule });
  if (a.planDigest !== b.planDigest) changes.push({ field: 'planDigest', from: a.planDigest, to: b.planDigest });
  if (a.outcomes[0] !== b.outcomes[0]) changes.push({ field: 'outcome', from: a.outcomes[0], to: b.outcomes[0] });
  return changes;
}
