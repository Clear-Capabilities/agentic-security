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
import { shrinkScenario, verifyShrinkRecord, judgeCandidate } from './shrink.js';
import { digestOf } from '../assurance/identity.js';

const SUPPORTED_FAULTS = Object.freeze(['duplicate-delivery', 'reorder', 'revocation-between']);
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
export async function replayFaultScenario(compiled, { fixture, commit, config, runOptions, runs: runCount = 2, runner = runScenario } = {}) {
  if (compiled.status !== 'ok') return { status: compiled.status, reason: compiled.reason, artifact: null };
  const runs = [];
  for (let i = 0; i < Math.max(2, runCount); i++) runs.push(await runner(compiled.scenario, { fixture, commit, config, runOptions }));
  const outcomes = runs.map((r) => (r.status === 'completed' ? r.outcome : `${r.status}`));
  const reproduced = outcomes.every((x) => x === outcomes[0]) && runs.every((r) => r.status === 'completed');
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

// ---- profiles (E-04, E-AC06) ------------------------------------------------------------------------------------------------------
//
// Two bounded profiles. `fast` is the one a pull request can afford; `extended` is chosen by an operator. Each declares its caps on
// plans, fresh runs per plan, wall time, concurrent boundary processes and the size of the artifacts it keeps, and the runner holds
// them: a plan the caps leave out is listed as skipped with the cap that stopped it, never dropped. Plans run one at a time, so the
// boundary never runs more than one process for this runner; the profile records that as observed, not assumed. More plans or more
// runs per plan is more exercised behaviour; neither profile is exhaustive, and the record says so.
export const FAULT_PROFILES = Object.freeze({
  fast: Object.freeze({ maxPlans: 6, runsPerPlan: 2, maxWallMs: 90_000, maxProcesses: 1, maxArtifactBytes: 256 * 1024 }),
  extended: Object.freeze({ maxPlans: 48, runsPerPlan: 4, maxWallMs: 15 * 60_000, maxProcesses: 1, maxArtifactBytes: 4 * 1024 * 1024 }),
});

/**
 * Run fault plans on a base scenario under a profile. Returns a record with the profile and its caps, every plan's result, what was
 * skipped and why, the time and bytes used, and `truncated` when any cap bit. `now` and `runner` are injectable for tests.
 */
export async function runFaultProfile(base, plans, { profile = 'fast', tighten = null, fixture, commit, config, runOptions, now = Date.now, runner = runScenario } = {}) {
  const declared = FAULT_PROFILES[profile];
  if (!declared) return { status: 'rejected', reason: `unknown profile ${profile}; one of ${Object.keys(FAULT_PROFILES).join(', ')}` };
  // An operator may lower a cap for one run, never raise one: a larger budget is a different profile, declared above.
  for (const [k, v] of Object.entries(tighten || {})) {
    if (!(k in declared) || !Number.isInteger(v) || v < 1 || v > declared[k]) return { status: 'rejected', reason: `tighten.${k} must be an integer from 1 to the profile's ${declared[k] ?? 'cap'}` };
  }
  const caps = Object.freeze({ ...declared, ...(tighten || {}) });
  const started = now();
  const results = []; const skipped = []; let bytes = 0; let maxConcurrent = 0; let running = 0;
  const counted = async (scenario, o) => { running += 1; maxConcurrent = Math.max(maxConcurrent, running); try { return await runner(scenario, o); } finally { running -= 1; } };
  for (const [i, plan] of (plans || []).entries()) {
    if (results.length >= caps.maxPlans) { skipped.push({ index: i, kind: plan?.kind ?? null, cap: 'maxPlans' }); continue; }
    const compiled = applyFaultPlan(base, plan);
    // A plan starts only if its worst case fits: each fresh run is bounded by the scenario's own time budget, which the boundary
    // enforces, so `runsPerPlan` of them must fit in what is left of the wall budget. Nothing is started that could overrun it.
    const worstMs = compiled.status === 'ok' ? (compiled.scenario.limits?.timeBudgetMs ?? caps.maxWallMs) * caps.runsPerPlan : 0;
    if (now() - started + worstMs > caps.maxWallMs) { skipped.push({ index: i, kind: plan?.kind ?? null, cap: 'maxWallMs', worstCaseMs: worstMs }); continue; }
    const r = await replayFaultScenario(compiled, { fixture, commit, config, runOptions, runs: caps.runsPerPlan, runner: counted });
    let artifact = r.artifact; let size = artifact ? Buffer.byteLength(JSON.stringify(artifact)) : 0; let compacted = false;
    // Storage: an artifact that would take the run past its byte cap is kept as its identity and outcomes only, and says so.
    if (artifact && bytes + size > caps.maxArtifactBytes) {
      artifact = { schema: artifact.schema, scenarioId: artifact.scenarioId, planDigest: artifact.planDigest, outcomes: artifact.outcomes, reproduced: artifact.reproduced, compacted: true };
      size = Buffer.byteLength(JSON.stringify(artifact)); compacted = true;
      if (bytes + size > caps.maxArtifactBytes) { skipped.push({ index: i, kind: plan?.kind ?? null, cap: 'maxArtifactBytes', ran: true, status: r.status }); continue; }
    }
    bytes += size;
    results.push({ index: i, kind: plan?.kind ?? null, status: r.status, reason: r.reason ?? null, artifact, bytes: size, compacted });
  }
  const elapsedMs = now() - started;
  return {
    schema: 'agentic-security/fault-profile-run', profile, caps, tightened: tighten ? Object.keys(tighten).sort() : [],
    plansDeclared: (plans || []).length, plansRun: results.length, skipped, results,
    used: { elapsedMs, artifactBytes: bytes, maxConcurrentProcesses: maxConcurrent, runsPerPlan: caps.runsPerPlan },
    withinCaps: maxConcurrent <= caps.maxProcesses && bytes <= caps.maxArtifactBytes && elapsedMs <= caps.maxWallMs,
    truncated: skipped.length > 0 || results.some((x) => x.compacted),
    coverage: { reproduced: results.filter((x) => x.status === 'reproduced').length, notReproduced: results.filter((x) => x.status === 'not-reproduced').length, unsupported: results.filter((x) => x.status === 'unsupported').length, rejected: results.filter((x) => x.status === 'rejected').length },
    note: 'a bounded profile; more plans or runs per plan exercise more behaviour and prove nothing exhaustively',
  };
}

// ---- shrinking a faulted scenario (E-AC03) ----------------------------------------------------------------------------------------
//
// The existing shrinker removes units only and keeps a candidate only when it settles `confirmed` on the same authoritative failing
// assertion. A faulted scenario is an ordinary derived scenario, so it shrinks the same way (four duplicate deliveries of a
// double-credit step shrink to the two that still credit twice). This joins the result to the fault's own identities: the plan
// digest, the original and minimized scenario ids, the shrink record and its verification, and a fresh fault replay of the minimized
// scenario, which must reproduce with the same outcome. A shrink that changes the assertion or loses the reproduction is reported
// as such, never as a minimized fault.
export async function shrinkFaultScenario(compiled, { fixture, commit, config, budget, runOptions } = {}) {
  if (compiled?.status !== 'ok') return { status: compiled?.status ?? 'rejected', reason: compiled?.reason ?? 'not a compiled plan' };
  const shrunk = await shrinkScenario(compiled.scenario, { fixture, commit, config, budget, runOptions });
  if (shrunk.status !== 'minimized') return { status: shrunk.status, reason: shrunk.reason, code: shrunk.code, shrink: shrunk };
  const verified = verifyShrinkRecord({ record: shrunk.record, original: compiled.scenario, minimized: shrunk.minimized });
  const replay = await replayFaultScenario({ ...compiled, scenario: shrunk.minimized }, { fixture, commit, config, runOptions });
  // Each fresh replay of the minimized scenario is judged against the ORIGINAL run's authoritative assertion by the shrinker's own
  // judge: kept means it settled confirmed, every precondition held, and the first violated assertion is the same one.
  const judged = (replay.runs || []).map((r) => judgeCandidate(r, shrunk.preserved.assertion));
  const sameAssertion = judged.length >= 2 && judged.every((j) => j.kept);
  const ok = verified.ok && replay.status === 'reproduced' && sameAssertion && replay.artifact.outcomes.every((x) => x === shrunk.record.original.outcome);
  return {
    status: ok ? 'minimized' : 'not-preserved',
    reason: ok ? null : !verified.ok ? `the shrink record does not verify: ${verified.errors[0].code}` : !sameAssertion ? 'the minimized scenario fails a different assertion' : 'the minimized scenario did not reproduce on a fresh fault replay',
    identity: {
      planDigest: compiled.planDigest, plan: compiled.plan,
      originalScenarioId: compiled.scenario.id, minimizedScenarioId: shrunk.minimized.id,
      shrinkRecordId: shrunk.record.id, invariant: shrunk.record.invariant, assertion: shrunk.preserved.assertion,
      replay: replay.artifact ? { scenarioId: replay.artifact.scenarioId, outcomes: replay.artifact.outcomes, reproduced: replay.artifact.reproduced } : null,
    },
    judged: judged.map((j) => ({ kept: j.kept, code: j.code ?? null })), recordVerified: verified, shrink: shrunk, replay,
  };
}
