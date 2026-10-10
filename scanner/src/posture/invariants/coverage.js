// Bounded business-logic coverage (X-407).
//
// "We ran scenarios" is not "the business logic is covered". This turns the contracts a project has and the runs it made into a
// report that says what was exercised AND what was not, and keeps every gap explicit:
//
//   inventory    approved versus proposed (and rejected, superseded, unrecorded) contracts, judged by the VERIFIED approval ledger:
//                a document that merely claims approval is listed as proposed-by-ledger with the claim noted;
//   exercised    which actors, states and declared transitions the executed scenarios actually drove, against what each contract
//                declares;
//   gaps         untested transitions, actors and states; the sequence depth the scenarios were bounded to; races a contract
//                class cannot model (and the cooperative-scheduling limit where one was run); scenarios that could not be built
//                or did not settle; and absent contracts (a class with no contract at all, or no contracts whatsoever).
//
// It never claims exhaustive correctness: the report states, in a field and in the text, that it describes a bounded sample.
// A run that did not execute contributes nothing to "exercised": an unsupported or inconclusive scenario is a gap, never
// coverage.
//
// Additive output. `invariantCoverageFields` is the one place a surface (the JSON/CLI report) asks for the fields: it returns
// `{}` unless the `invariant-scenarios` feature is on AND a coverage object was supplied, so a default scan's report is
// byte-identical to what it was (pinned in `test/fixtures/invariant-compat/`). The key is `invariantCoverage`.
import { SCHEMA_VERSION, isPlainObject } from '../assurance/schema-kit.js';
import { featureStatus, resolveAssuranceConfig } from '../assurance/config.js';
import { INVARIANT_CLASSES } from './schema.js';
import { verifyLedger } from './lifecycle.js';
import { FEATURE, HARD_BOUNDS, KINDS_BY_CLASS } from './scenarios.js';
import { NOT_EXHAUSTIVE } from './export.js';

export const COVERAGE_SCHEMA = 'agentic-security/business-coverage';
export const GAP_CODES = Object.freeze([
  'absent-contract', 'unapproved-contract', 'not-executed', 'untested-transition', 'untested-actor', 'untested-state',
  'bounded-depth', 'unsupported-scenario', 'unsettled-scenario', 'unsupported-race', 'cooperative-scheduling',
]);

const sorted = (set) => [...set].sort();

function declaredStates(inv) {
  const wf = inv.forbidden.find((f) => f.op === 'transition-outside');
  if (wf) return sorted(new Set(wf.allowed.flatMap((t) => [t.from, t.to])));
  return sorted(new Set(inv.resources.map((r) => r.id)));
}

function exercisedStates(inv, steps) {
  const wf = inv.forbidden.find((f) => f.op === 'transition-outside');
  const keyToId = new Map(inv.resources.map((r) => [r.key, r.id]));
  const out = new Set();
  if (wf) {
    const declared = new Set(declaredStates(inv));
    const reached = steps.filter((s) => s.to && declared.has(s.to));
    if (reached.length) out.add(wf.allowed[0].from); // the seeded initial state is where a workflow starts
    for (const s of reached) out.add(s.to);
  } else {
    for (const s of steps) if (s.key && keyToId.has(s.key)) out.add(keyToId.get(s.key));
  }
  return sorted(out);
}

/**
 * @param {object} p
 * @param {Array<{ invariant: object, result?: object }>} p.entries  each contract, with the `verifyInvariant` result of its run (or none)
 * @param {object} [p.ledger]   the approval ledger; without a verifying one no contract is approved
 * @param {object} [p.signer]   ledger signer (test seam)
 * @returns {object} the coverage report (plain data, deterministic: no clock)
 */
export function businessCoverage({ entries, ledger, signer } = {}) {
  const list = (Array.isArray(entries) ? entries : []).filter((e) => isPlainObject(e) && isPlainObject(e.invariant) && Array.isArray(e.invariant.actors));
  const verified = verifyLedger(ledger, { signer });
  const stateOf = (inv) => (verified.ok ? (verified.states[inv.id] ?? 'unrecorded') : 'unrecorded');
  const gaps = [];
  const gap = (code, detail, extra = {}) => gaps.push({ code, detail, ...extra });
  const invariants = [];
  const inventory = { approved: [], proposed: [], rejected: [], superseded: [], unrecorded: [] };
  let maxDepth = 0; let maxRequests = 0; let truncated = 0;
  const totals = { actors: { declared: 0, exercised: 0 }, transitions: { declared: 0, exercised: 0 }, states: { declared: 0, exercised: 0 } };

  for (const { invariant: inv, result } of list) {
    const state = stateOf(inv);
    const ref = { id: inv.id, key: inv.key, revision: inv.revision, class: inv.class };
    inventory[state === 'approved' ? 'approved' : state === 'proposed' ? 'proposed' : state === 'rejected' ? 'rejected' : state === 'superseded' ? 'superseded' : 'unrecorded'].push(ref);
    const claimsApproval = inv.review?.state === 'approved' && state !== 'approved';

    const runs = Array.isArray(result?.results) ? result.results : [];
    const executed = runs.filter((r) => r.status === 'completed');
    const decided = executed.filter((r) => r.outcome === 'confirmed' || r.outcome === 'refuted');
    const steps = executed.flatMap((r) => [...(r.exercise?.control || []), ...(r.exercise?.attack || [])]);
    for (const r of executed) {
      maxDepth = Math.max(maxDepth, r.limits?.depth ?? 0); maxRequests = Math.max(maxRequests, r.limits?.requests ?? 0);
      if (r.limits?.truncated) truncated++;
    }

    const actorsDeclared = sorted(new Set(inv.actors.map((a) => a.id)));
    const actorsExercised = sorted(new Set(steps.map((s) => s.actor).filter((a) => actorsDeclared.includes(a))));
    const keyOf = new Map(inv.resources.map((r) => [r.id, r.key]));
    const transitionsDeclared = inv.transitions.map((t) => t.id);
    const transitionsExercised = inv.transitions.filter((t) => steps.some((s) => t.actors.includes(s.actor) && s.action === t.action && s.key === keyOf.get(t.resource))).map((t) => t.id);
    const statesDeclared = declaredStates(inv);
    const statesExercised = exercisedStates(inv, steps);

    const mine = { id: inv.id, key: inv.key };
    if (!executed.length) {
      gap('not-executed', `no scenario for '${inv.key}' was executed${result?.status && result.status !== 'ok' ? ` (${result.status}: ${result.reason ?? 'no reason given'})` : ''}`, mine);
    } else {
      for (const t of transitionsDeclared.filter((x) => !transitionsExercised.includes(x))) gap('untested-transition', `declared transition '${t}' of '${inv.key}' was not exercised by any executed scenario`, { ...mine, transition: t });
      for (const a of actorsDeclared.filter((x) => !actorsExercised.includes(x))) gap('untested-actor', `declared actor '${a}' of '${inv.key}' performed no step in any executed scenario`, { ...mine, actor: a });
      for (const s of statesDeclared.filter((x) => !statesExercised.includes(x))) gap('untested-state', `declared state '${s}' of '${inv.key}' was not reached by any executed scenario`, { ...mine, state: s });
    }
    for (const u of result?.unsupported || []) gap('unsupported-scenario', `${u.kind ?? 'scenario'} for '${inv.key}' could not be built: ${u.reason}`, { ...mine, kind: u.kind ?? null });
    for (const r of runs.filter((x) => x.status !== 'completed' || !['confirmed', 'refuted'].includes(x.outcome))) {
      gap('unsettled-scenario', `${r.kind} for '${inv.key}' did not settle (${r.status === 'completed' ? `outcome '${r.outcome}'` : `status '${r.status}'`})${r.reason ? `: ${String(r.reason).slice(0, 160)}` : ''}`, { ...mine, kind: r.kind });
    }
    // races: a class with no concurrent family cannot be race-tested here; one that has it needs an executed, settled run
    const hasRaceFamily = (KINDS_BY_CLASS[inv.class] || []).includes('concurrent-operations');
    const raceRuns = decided.filter((r) => r.kind === 'concurrent-operations');
    if (!hasRaceFamily) gap('unsupported-race', `no concurrent-operations scenario exists for the '${inv.class}' class, so races against '${inv.key}' are not tested`, mine);
    else if (!raceRuns.length) gap('unsupported-race', `no concurrent-operations scenario for '${inv.key}' settled, so races against it are not tested`, mine);
    else gap('cooperative-scheduling', `races against '${inv.key}' were exercised under cooperative scheduling in one process with a fixed start order; parallel execution and other interleavings are not covered`, mine);
    if (state !== 'approved') gap('unapproved-contract', `'${inv.key}' is ${state}${claimsApproval ? ' (its document claims approval; only the verified ledger counts)' : ''}: a violation of it would be an advisory candidate, not a failure of a requirement`, mine);

    totals.actors.declared += actorsDeclared.length; totals.actors.exercised += actorsExercised.length;
    totals.transitions.declared += transitionsDeclared.length; totals.transitions.exercised += transitionsExercised.length;
    totals.states.declared += statesDeclared.length; totals.states.exercised += statesExercised.length;
    invariants.push({
      ...ref, name: inv.name, state, claimsApproval,
      declared: { actors: actorsDeclared, transitions: transitionsDeclared, states: statesDeclared },
      exercised: { actors: actorsExercised, transitions: transitionsExercised, states: statesExercised },
      scenarios: { total: runs.length, executed: executed.length, decided: decided.length, unsupported: (result?.unsupported || []).length },
      violations: { approved: runs.filter((r) => r.classification?.kind === 'approved-violation').length, candidate: runs.filter((r) => r.classification?.kind === 'candidate-violation').length },
    });
  }

  // contracts that do not exist are gaps too
  if (!list.length) gap('absent-contract', 'no contract was supplied: no business-logic behaviour is covered');
  else for (const cls of INVARIANT_CLASSES) {
    if (!list.some((e) => e.invariant.class === cls)) gap('absent-contract', `no contract exists for the '${cls}' class: that kind of behaviour is not covered at all`, { class: cls });
  }
  const executedAny = invariants.some((i) => i.scenarios.executed > 0);
  if (executedAny) gap('bounded-depth', `scenarios were bounded to at most ${maxDepth} attack step(s) and ${maxRequests} request(s) (hard ceilings: depth ${HARD_BOUNDS.depth}, requests ${HARD_BOUNDS.requests})${truncated ? `; ${truncated} scenario(s) were truncated to fit` : ''}; longer sequences are not explored`, { maxDepth, maxRequests, truncated });

  const counts = Object.fromEntries(Object.entries(inventory).map(([k, v]) => [k, v.length]));
  const lines = [
    `Business-logic coverage (bounded sample, not exhaustive): ${counts.approved} approved, ${counts.proposed} proposed, ${counts.rejected + counts.superseded + counts.unrecorded} other contract(s)`,
    `  Exercised: ${totals.actors.exercised}/${totals.actors.declared} actors, ${totals.states.exercised}/${totals.states.declared} states, ${totals.transitions.exercised}/${totals.transitions.declared} transitions`,
    `  Gaps: ${gaps.length}${gaps.length ? ` (${[...new Set(gaps.map((g) => g.code))].sort().join(', ')})` : ''}`,
    `  ${NOT_EXHAUSTIVE}`,
  ];
  return {
    schema: COVERAGE_SCHEMA, schemaVersion: SCHEMA_VERSION,
    ledger: { verified: verified.ok, note: verified.ok ? 'approval state comes from the verified ledger' : 'no verifying approval ledger: no contract counts as approved' },
    inventory, counts, invariants, totals, gaps,
    bounds: { maxDepth, maxRequests, truncatedScenarios: truncated, hard: HARD_BOUNDS },
    claims: { exhaustive: false, statement: NOT_EXHAUSTIVE },
    lines,
  };
}

/**
 * The fields a report adds for business coverage: `{ invariantCoverage }`, or `{}` when the feature is off or there is nothing to
 * report. ADDITIVE: with the feature off (the default) a report is byte-identical to what it was.
 */
export function invariantCoverageFields(coverage, { config } = {}) {
  if (!isPlainObject(coverage) || coverage.schema !== COVERAGE_SCHEMA) return {};
  const cfg = config || resolveAssuranceConfig({ env: process.env });
  if (featureStatus(cfg, FEATURE).status !== 'ok') return {};
  return { invariantCoverage: coverage };
}
