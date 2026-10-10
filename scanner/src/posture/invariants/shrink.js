// Dependency-aware scenario shrinking (X-405).
//
// A scenario that reproduces a violation usually carries steps that have nothing to do with it. Shrinking finds a smaller
// sequence that still reproduces THE SAME violation, so a reviewer reads three steps instead of eleven. It is a search over
// REMOVALS only, verified by execution:
//
//   - A candidate is the original scenario with one unit taken out (an attack step, one member of a parallel group, a control
//     step, or a seed record). Nothing is edited, reordered, added or substituted, so the actor behind every surviving step, the
//     tenants, roles, forbidden outcomes, the pinned fixture and the invariant it asserts cannot change.
//   - A candidate is KEPT only if its replay (through `runScenario`, so a replay manifest, the trust boundary and a verifier
//     receipt as for every other run) settles `confirmed`, with every precondition held (the control flow visibly worked, was
//     clean and cleaned up, and the attack reproduced itself across two fresh runs), and with the SAME authoritative failing
//     assertion as the original. A removal that loses the verdict, swaps it for another assertion or removes the evidence that the
//     application was working is rejected, and the reason is recorded.
//   - A unit the surviving steps still reference is never offered for removal (a seed record a step reads, a record that carries a
//     marker the assertions look for): that is a setup dependency, and the attempt is recorded as guarded rather than skipped
//     silently. Everything removed is listed, so no precondition disappears without a trace.
//
// "Authoritative failing assertion": the first violated assertion of the original run, attack phase first, in the contract's own
// forbidden-outcome order. It is identified by the contract's forbidden-outcome id and the phase.
//
// Budget. A fixed number of replays and a wall-clock ceiling, both with hard limits; a shrink that runs out of either returns
// the best scenario found so far and says `minimal: false`. `minimal: true` means a full pass over the remaining units found
// nothing more to remove (1-minimal within these removal units), not that no smaller reproduction exists. One further replay
// of the final scenario confirms reproduction on the pinned fixture and sits outside the shrink budget.
//
// Reproduction limits, reported rather than hidden. If the original does not reproduce, or the minimized scenario does not
// reproduce on its confirming replay, the result says why: a parallel group means cooperative scheduling inside one process
// (the oracle compares two fresh runs and refuses a verdict when they disagree), and the fixture is scanned for signals of
// randomness, clocks, timers and network or process access that a disposable, network-less replay cannot hold constant. Those
// signals are pattern checks over the fixture text, a disclosure and not a proof either way.
//
// Linkage. The result carries a content-addressed record joining the original and the minimized scenario by digest, replay
// manifest id, verification record id and receipt digest, plus every attempt. `verifyShrinkRecord` recomputes those links and
// calls `checkMinimization`, which re-derives from the two scenarios alone that the minimized one is an order-preserving subset
// of the original with the invariant, actors, fixture and assertions untouched.
//
// Limits: receipts are in-process objects; the record carries their digests, not signatures (signing belongs to the signer
// domain). Linux is not claimed.
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isPlainObject } from '../assurance/schema-kit.js';
import { featureStatus, resolveAssuranceConfig } from '../assurance/config.js';
import { runScenario, deriveScenario, FEATURE } from './scenarios.js';

const SHRINK_SCHEMA = 'agentic-security/scenario-shrink';
export const SHRINK_HARD_BUDGET = Object.freeze({ maxRuns: 40, timeBudgetMs: 120_000 });
const DEFAULT_BUDGET = Object.freeze({ maxRuns: 24, timeBudgetMs: 60_000 });
const RECORD_ID_FIELDS = ['invariant', 'fixtureDigest', 'original', 'minimized', 'removed', 'attempts', 'minimal'];
const PRECONDITIONS = ['controlRan', 'controlDurableEffect', 'controlClean', 'cleanedUp', 'deterministic'];

const clone = (v) => JSON.parse(JSON.stringify(v));

/** Validate and complete a shrink budget. Nothing is clamped silently. */
export function resolveShrinkBudget(input = {}) {
  const errors = [];
  const budget = { ...DEFAULT_BUDGET };
  if (!isPlainObject(input)) return { ok: false, budget, errors: ['budget must be an object'] };
  for (const [k, v] of Object.entries(input)) {
    if (!(k in SHRINK_HARD_BUDGET)) { errors.push(`unknown budget '${k}'`); continue; }
    if (!Number.isInteger(v) || v < 1) errors.push(`budget '${k}' must be a positive integer`);
    else if (v > SHRINK_HARD_BUDGET[k]) errors.push(`budget '${k}' (${v}) exceeds the ceiling of ${SHRINK_HARD_BUDGET[k]}`);
    else budget[k] = v;
  }
  return { ok: errors.length === 0, budget, errors };
}

// ---------------------------------------------------------------- units and candidates

const stepsOf = (items) => items.flatMap((it) => (it.parallel ? it.parallel : [it]));
const keyOf = (step) => (Array.isArray(step.args) && typeof step.args[0] === 'string' ? step.args[0] : null);
const label = (step) => `${step.actor}.${step.action}(${keyOf(step) ?? ''})`;
const opCountOf = (items) => items.reduce((n, it) => n + (it.parallel ? it.parallel.length : 1), 0);

function withoutIndex(list, i) { return list.filter((_, j) => j !== i); }

/** Every removal unit of an input set, in the order they are tried. A unit is `{ unit, why?, build }`; `why` marks a guard. */
function unitsOf(inputs) {
  const out = [];
  const retained = stepsOf([...inputs.attack, ...inputs.control]);
  const referenced = new Set(retained.map(keyOf).filter(Boolean));
  const markers = new Set((inputs.markers || []).map((m) => m.marker));

  inputs.attack.forEach((it, i) => {
    if (it.parallel) {
      out.push({ unit: `attack[${i}] parallel group of ${it.parallel.length}`, kind: 'attack', blocked: inputs.attack.length < 2, why: 'the attack sequence must keep at least one item', build: (x) => ({ ...x, attack: withoutIndex(x.attack, i) }) });
      it.parallel.forEach((s, j) => {
        out.push({
          unit: `attack[${i}] member ${j} ${label(s)}`, kind: 'attack', blocked: it.parallel.length <= 2, why: 'a parallel group keeps at least two members: below that it is no longer a concurrency scenario',
          build: (x) => {
            const g = x.attack[i];
            const members = withoutIndex(g.parallel, j);
            const schedule = g.schedule.filter((idx) => idx !== j).map((idx) => (idx > j ? idx - 1 : idx));
            return { ...x, attack: x.attack.map((item, k) => (k === i ? { parallel: members, schedule } : item)) };
          },
        });
      });
    } else {
      out.push({ unit: `attack[${i}] ${label(it)}`, kind: 'attack', blocked: inputs.attack.length < 2, why: 'the attack sequence must keep at least one step', build: (x) => ({ ...x, attack: withoutIndex(x.attack, i) }) });
    }
  });
  inputs.control.forEach((it, i) => {
    const text = it.parallel ? `control[${i}] parallel group of ${it.parallel.length}` : `control[${i}] ${label(it)}`;
    out.push({ unit: text, kind: 'control', blocked: inputs.control.length < 2, why: 'the control flow is the evidence the application works and must keep at least one step', build: (x) => ({ ...x, control: withoutIndex(x.control, i) }) });
  });
  inputs.seed.forEach((rec, i) => {
    const byStep = referenced.has(rec.key);
    const byMarker = typeof rec.value?.marker === 'string' && markers.has(rec.value.marker);
    out.push({
      unit: `seed ${rec.key}`, kind: 'seed', blocked: byStep || byMarker,
      why: byStep ? 'a surviving step reads or writes this record (a setup dependency)' : 'this record carries a marker the assertions look for (a setup dependency)',
      build: (x) => ({ ...x, seed: withoutIndex(x.seed, i) }),
    });
  });
  return out;
}

// ---------------------------------------------------------------- what a run established

function authoritativeOf(report) {
  const hit = (report?.assertions || []).filter((a) => a.violated);
  const first = hit.find((a) => a.phase === 'attack') || hit[0];
  return first ? { id: first.id, phase: first.phase } : null;
}

const heldAll = (report) => PRECONDITIONS.every((k) => report?.preconditions?.[k] === true);
const reproducesAssertion = (report, a) => !!a && (report?.assertions || []).some((x) => x.violated && x.id === a.id && x.phase === a.phase);

/** Decide whether a candidate's replay may replace the current scenario. Exported so the rules are testable one by one. */
export function judgeCandidate(run, assertion) {
  if (!run || run.status !== 'completed' || !run.executed) {
    return { kept: false, code: 'candidate-not-executable', reason: run?.errors?.[0]?.message || run?.record?.reason || `the candidate did not execute (status '${run?.status}')` };
  }
  if (run.outcome !== 'confirmed') {
    const nondet = run.report?.preconditions?.deterministic === false;
    return { kept: false, code: nondet ? 'nondeterministic' : 'verdict-lost', reason: nondet ? 'the candidate did not reproduce itself across two fresh runs, so no verdict was formed' : `the candidate settled '${run.outcome}', not confirmed` };
  }
  if (!heldAll(run.report)) {
    const lost = PRECONDITIONS.filter((k) => run.report?.preconditions?.[k] !== true);
    return { kept: false, code: 'precondition-lost', reason: `the candidate no longer shows: ${lost.join(', ')}` };
  }
  if (!reproducesAssertion(run.report, assertion)) {
    const now = authoritativeOf(run.report);
    return { kept: false, code: 'assertion-changed', reason: `the candidate violates ${now ? `'${now.id}'` : 'a different assertion'}, not '${assertion.id}'` };
  }
  return { kept: true, code: null, reason: null };
}

// ---------------------------------------------------------------- reproducibility disclosure

const NONDETERMINISM = [
  [/\bMath\.random\b/, 'Math.random'], [/\bDate\.now\b|\bnew Date\b/, 'wall clock'], [/\bsetTimeout\b|\bsetInterval\b/, 'timers'],
  [/\brandomUUID\b|\brandomBytes\b|\brandomInt\b/, 'crypto randomness'], [/\bperformance\.now\b/, 'performance.now'],
];
const EXTERNAL = [
  [/\bfetch\s*\(/, 'fetch'], [/\bprocess\.env\b/, 'process.env'],
  [/from\s+['"]node:(net|http|https|http2|dns|dgram|tls|child_process|worker_threads|cluster)['"]/, 'node network/process module'],
  [/from\s+['"](?!\.{1,2}\/|node:)[^'"]+['"]/, 'third-party package import'], [/\brequire\s*\(\s*['"](?!\.{1,2}\/|node:)/, 'third-party package require'],
];

/** Signals in the fixture text that a disposable, network-less replay cannot hold constant. Pattern checks: a disclosure, not a proof. */
export function reproductionSignals(files) {
  const nondeterminism = []; const external = [];
  for (const [file, text] of Object.entries(isPlainObject(files) ? files : {})) {
    if (typeof text !== 'string') continue;
    for (const [re, what] of NONDETERMINISM) if (re.test(text)) nondeterminism.push({ file, signal: what });
    for (const [re, what] of EXTERNAL) if (re.test(text)) external.push({ file, signal: what });
  }
  return { nondeterminism, external };
}

function reproducibility(scenario, run, files) {
  const sig = reproductionSignals(files);
  const concurrency = scenario.inputs.attack.some((it) => it.parallel);
  const reproduced = run?.status === 'completed' && run.outcome === 'confirmed';
  const blockedBy = [];
  if (!reproduced) {
    const nondet = run?.report?.preconditions?.deterministic === false;
    if (nondet && concurrency) blockedBy.push({ code: 'concurrency', detail: 'the parallel group did not reproduce itself across two fresh runs: scheduling here is cooperative inside one process, so an interleaving-dependent defect can fail to reproduce deterministically' });
    else if (nondet) blockedBy.push({ code: 'nondeterministic-behaviour', detail: 'the two fresh runs of the same sequence disagreed' });
    if (sig.external.length) blockedBy.push({ code: 'external-dependency', detail: `the fixture shows ${[...new Set(sig.external.map((s) => s.signal))].join(', ')}, which a network-less disposable replay cannot reproduce` });
    if (sig.nondeterminism.length) blockedBy.push({ code: 'nondeterminism-source', detail: `the fixture reads ${[...new Set(sig.nondeterminism.map((s) => s.signal))].join(', ')}` });
    if (run && run.status !== 'completed') blockedBy.push({ code: 'prerequisite-unmet', detail: (run.prerequisites || []).map((p) => `${p.kind} ${p.id} (${p.state})`).join('; ') || run.errors?.[0]?.message || 'the replay did not execute' });
  }
  return {
    reproduced, deterministic: run?.report?.preconditions?.deterministic ?? null, concurrency,
    schedulingModel: concurrency ? 'cooperative-fixed-start-order (one process, interleavings at await points)' : 'sequential',
    blockedBy, signals: sig,
  };
}

// ---------------------------------------------------------------- the structural check

const same = (a, b) => digestOf(a) === digestOf(b);

function isSubsequence(small, big, eq) {
  let j = 0;
  for (const x of small) { while (j < big.length && !eq(x, big[j])) j++; if (j >= big.length) return false; j++; }
  return true;
}
const sameItem = (a, b) => same(a, b);
const sameGroupSubset = (a, b) => Array.isArray(a.parallel) && Array.isArray(b.parallel) && isSubsequence(a.parallel, b.parallel, same);

/**
 * Re-derive, from the two scenarios alone, that `minimized` is a pure removal-subset of `original`: same invariant, fixture,
 * entry, seed, actors, tenants, markers, forbidden outcomes and cleanup; every surviving step, group and seed record equal to
 * one of the original's, in the original's order; nothing added; no emptied sequence. Never throws.
 * @returns {{ ok: boolean, errors: Array<{ code: string, message: string }> }}
 */
export function checkMinimization(original, minimized) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  try {
    if (!isPlainObject(original) || !isPlainObject(minimized) || !isPlainObject(original.inputs) || !isPlainObject(minimized.inputs)) return { ok: false, errors: [{ code: 'malformed', message: 'both scenarios must be scenario objects' }] };
    if (!same(original.invariant, minimized.invariant)) fail('invariant-changed', 'minimization cannot change the invariant a scenario asserts');
    if (!same(original.inputs.invariant, minimized.inputs.invariant)) fail('invariant-changed', 'the invariant in the run inputs differs');
    if (original.fixtureDigest !== minimized.fixtureDigest || original.entry !== minimized.entry || original.seed !== minimized.seed || original.kind !== minimized.kind) fail('fixture-changed', 'the pinned fixture, entry, seed or scenario family differs');
    if (!same(original.inputs.actors, minimized.inputs.actors)) fail('actor-changed', 'the actors (identity, tenant, role) must be exactly the original\'s');
    if (!same(original.inputs.forbidden, minimized.inputs.forbidden) || !same(original.inputs.markers, minimized.inputs.markers) || !same(original.inputs.cleanup, minimized.inputs.cleanup) || original.inputs.export !== minimized.inputs.export) fail('assertion-changed', 'the forbidden outcomes, markers, cleanup or entry export differ');
    for (const seq of ['attack', 'control']) {
      const a = original.inputs[seq]; const m = minimized.inputs[seq];
      if (!Array.isArray(m) || m.length === 0) { fail('precondition-removed', `the ${seq} sequence cannot be emptied`); continue; }
      let ok = true;
      let j = 0;
      for (const item of m) {
        let found = false;
        while (j < a.length) {
          const cand = a[j++];
          if (sameItem(item, cand) || (item.parallel && cand.parallel && sameGroupSubset(item, cand) && groupScheduleConsistent(item, cand))) { found = true; break; }
        }
        if (!found) { ok = false; break; }
      }
      if (!ok) fail('step-added', `the minimized ${seq} sequence holds a step or group that is not, in order, a part of the original`);
      if (opCountOf(m) > opCountOf(a)) fail('step-added', `the minimized ${seq} sequence is longer than the original`);
    }
    if (!isSubsequence(minimized.inputs.seed, original.inputs.seed, same)) fail('step-added', 'the minimized seed holds a record the original does not');
    // a surviving step may not lose the record it reads: a required precondition cannot vanish silently
    const have = new Set(minimized.inputs.seed.map((r) => r.key));
    const origKeys = new Set(original.inputs.seed.map((r) => r.key));
    for (const s of stepsOf([...minimized.inputs.attack, ...minimized.inputs.control])) {
      const k = keyOf(s);
      if (k && origKeys.has(k) && !have.has(k)) fail('precondition-removed', `a surviving step ${label(s)} reads '${k}', which was removed from the seed`);
    }
    for (const m of minimized.inputs.markers || []) {
      const rec = original.inputs.seed.find((r) => r.value?.marker === m.marker);
      if (rec && !have.has(rec.key)) fail('precondition-removed', `the record carrying marker '${m.marker}' was removed from the seed`);
    }
  } catch (e) {
    fail('malformed', `the check could not complete: ${String(e?.message || e).slice(0, 120)}`);
  }
  return { ok: errors.length === 0, errors };
}

// A reduced group keeps the original's relative start order for the members it kept. Members can be identical, so the question is
// whether SOME choice of original positions explains the reduced group (groups hold at most 4 members: at most 16 choices).
function groupScheduleConsistent(small, big) {
  const n = big.parallel.length;
  for (let mask = 0; mask < (1 << n); mask++) {
    const at = [];
    for (let i = 0; i < n; i++) if (mask & (1 << i)) at.push(i);
    if (at.length !== small.parallel.length || !at.every((pos, k) => same(small.parallel[k], big.parallel[pos]))) continue;
    const order = big.schedule.filter((idx) => at.includes(idx)).map((idx) => at.indexOf(idx));
    if (same(order, small.schedule)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- the shrink

const failure = (status, code, reason, extra = {}) => ({ status, code, reason, minimized: null, record: null, ...extra });

/**
 * Shrink one failing scenario within a fixed budget. Never throws.
 *
 * @param {object} scenario  from `generateScenarios` (or a derived one); must reproduce a violation when replayed
 * @param {object} o
 * @param {{ files: object }} o.fixture  the disposable fixture the scenario was generated from
 * @param {string} o.commit              exact commit (a decided verdict needs one)
 * @param {object} [o.config]            assurance config; `invariant-scenarios` and `verification-oracles` must be enabled
 * @param {object} [o.budget]            { maxRuns, timeBudgetMs }, see `SHRINK_HARD_BUDGET`
 * @param {object} [o.runOptions]        oracle runner seams (test)
 * @returns {Promise<object>} { status: 'minimized'|'not-reproduced'|'disabled'|'rejected', code, reason, minimized, minimal, record, ... }
 */
export async function shrinkScenario(scenario, o = {}) {
  const config = o.config || resolveAssuranceConfig({ env: process.env });
  const gate = featureStatus(config, FEATURE);
  if (gate.status !== 'ok') return failure('disabled', gate.code || 'disabled', `${FEATURE} is not available: ${gate.reason}`);
  const rb = resolveShrinkBudget(o.budget);
  if (!rb.ok) return failure('rejected', 'bad-budget', 'the shrink budget is not valid', { errors: rb.errors });
  if (!isPlainObject(scenario) || !isPlainObject(scenario.inputs) || !Array.isArray(scenario.inputs.attack) || !Array.isArray(scenario.inputs.control) || !Array.isArray(scenario.inputs.seed)) {
    return failure('rejected', 'bad-scenario', 'not a generated scenario');
  }
  const { budget } = rb;
  const files = o.fixture?.files;
  const started = Date.now();
  let runs = 0; let ops = 0;
  const replay = async (scn) => {
    const run = await runScenario(scn, { fixture: o.fixture, commit: o.commit, config, runOptions: o.runOptions });
    runs++;
    if (run.executed) ops += opCountOf(scn.inputs.attack) + opCountOf(scn.inputs.control);
    return run;
  };
  const summaryOf = (scn, run, extra = {}) => ({
    scenarioId: scn.id, scenarioDigest: digestOf(scn), manifestId: run?.manifestId ?? null, recordId: run?.record?.id ?? null,
    receiptDigest: run?.receipt?.receiptDigest ?? null, outcome: run?.outcome ?? null, limits: scn.limits, ...extra,
  });

  // ---- the original must reproduce, or there is nothing to preserve
  const ref = await replay(scenario);
  if (ref.status === 'rejected') return failure('rejected', ref.errors?.[0]?.code || 'rejected', ref.errors?.[0]?.message || 'the scenario was rejected', { reproducibility: reproducibility(scenario, ref, files), cost: { runs, requests: ops, elapsedMs: Date.now() - started } });
  const assertion = ref.outcome === 'confirmed' ? authoritativeOf(ref.report) : null;
  if (ref.status !== 'completed' || ref.outcome !== 'confirmed' || !assertion || !heldAll(ref.report)) {
    const code = ref.status !== 'completed' ? 'prerequisite-unmet' : ref.outcome === 'confirmed' ? 'preconditions-unproven' : `original-${ref.outcome}`;
    return failure('not-reproduced', code, ref.status !== 'completed'
      ? `the original scenario did not execute: ${(ref.prerequisites || []).map((p) => `${p.kind} ${p.id} (${p.state})`).join('; ') || ref.record?.reason || 'unavailable'}`
      : `the original scenario settled '${ref.outcome}'${ref.record?.reason ? `: ${String(ref.record.reason).slice(0, 200)}` : ''}; there is no reproduced violation to preserve`, {
      original: summaryOf(scenario, ref), reproducibility: reproducibility(scenario, ref, files), cost: { runs, requests: ops, elapsedMs: Date.now() - started },
    });
  }

  // ---- greedy removal passes: after a kept removal the unit list is rebuilt and the same position is tried again; a pass that
  // keeps nothing proves the scenario 1-minimal over these units. A candidate whose content was already tried is not run twice.
  let current = scenario;
  let currentRun = ref;
  const attempts = []; const removed = { attack: [], control: [], seed: [] };
  const tried = new Set([scenario.id]); const guardedSeen = new Set();
  let exhausted = false;
  const outOfBudget = () => runs >= budget.maxRuns || Date.now() - started >= budget.timeBudgetMs;
  let changed = true;
  while (changed && !exhausted) {
    changed = false;
    let units = unitsOf(current.inputs);
    let i = 0;
    while (i < units.length) {
      const u = units[i];
      if (u.blocked) {
        if (!guardedSeen.has(u.unit)) { guardedSeen.add(u.unit); attempts.push({ unit: u.unit, decision: 'guarded', code: 'required-precondition', reason: u.why, candidateId: null, recordId: null, receiptDigest: null }); }
        i++; continue;
      }
      const cand = deriveScenario(current, u.build(clone(current.inputs)));
      if (tried.has(cand.id)) { i++; continue; }
      if (outOfBudget()) { exhausted = true; break; }
      tried.add(cand.id);
      const run = await replay(cand);
      const verdict = judgeCandidate(run, assertion);
      attempts.push({ unit: u.unit, decision: verdict.kept ? 'removed' : 'rejected', code: verdict.code, reason: verdict.reason, candidateId: cand.id, recordId: run.record?.id ?? null, receiptDigest: run.receipt?.receiptDigest ?? null });
      if (verdict.kept) {
        removed[u.kind].push(u.unit);
        current = cand; currentRun = run; changed = true;
        units = unitsOf(current.inputs);
      } else i++;
    }
  }
  const cleanPass = !exhausted;

  // ---- confirm on the pinned fixture; this replay is outside the shrink budget
  const confirm = await replay(current);
  const repro = reproducibility(current, confirm, files);
  const confirmJudge = judgeCandidate(confirm, assertion);
  repro.reproduced = confirmJudge.kept;
  if (!confirmJudge.kept && !repro.blockedBy.length) repro.blockedBy.push({ code: confirmJudge.code, detail: confirmJudge.reason });

  const originalSummary = summaryOf(scenario, ref, { assertion });
  const minimizedSummary = summaryOf(current, confirm, { assertion, acceptedRecordId: currentRun.record?.id ?? null, acceptedReceiptDigest: currentRun.receipt?.receiptDigest ?? null });
  const record = {
    schema: SHRINK_SCHEMA, schemaVersion: SCHEMA_VERSION,
    invariant: scenario.invariant, fixtureDigest: scenario.fixtureDigest,
    original: originalSummary, minimized: minimizedSummary, removed, attempts, minimal: cleanPass && !exhausted,
  };
  record.id = semanticId('shrk', record, RECORD_ID_FIELDS);
  const check = checkMinimization(scenario, current);
  return {
    status: confirmJudge.kept && check.ok ? 'minimized' : 'not-reproduced',
    code: confirmJudge.kept && check.ok ? null : (check.ok ? 'minimized-not-reproduced' : 'minimization-invalid'),
    reason: confirmJudge.kept && check.ok ? null : (check.ok ? `the minimized scenario did not reproduce on its confirming replay: ${confirmJudge.reason}` : check.errors[0].message),
    minimized: current, original: scenario, minimal: record.minimal, record,
    budget: { ...budget, runsUsed: runs - 1, exhausted },
    reproducibility: repro,
    preserved: { invariant: scenario.invariant, actors: scenario.inputs.actors, fixtureDigest: scenario.fixtureDigest, assertion },
    cost: { runs, requests: ops, elapsedMs: Date.now() - started },
    summary: `${removed.attack.length + removed.control.length + removed.seed.length} unit(s) removed; attack ${opCountOf(scenario.inputs.attack)} -> ${opCountOf(current.inputs.attack)} operation(s)${record.minimal ? ', no single removal left that preserves the verdict' : ', budget reached before a full pass'}; authoritative assertion '${assertion.id}' (${assertion.phase}) preserved`,
  };
}

/**
 * Check a shrink record against the two scenarios it claims to link: digests, ids, the invariant and the structural subset
 * relation. A record whose links do not recompute is rejected. Never throws.
 */
export function verifyShrinkRecord({ record, original, minimized }) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  try {
    if (!isPlainObject(record) || record.schema !== SHRINK_SCHEMA) return { ok: false, errors: [{ code: 'malformed', message: 'not a scenario shrink record' }] };
    if (semanticId('shrk', record, RECORD_ID_FIELDS) !== record.id) fail('record-tampered', 'the record id does not match its content');
    if (record.original?.scenarioDigest !== digestOf(original)) fail('original-link-broken', 'the original scenario does not match the digest the record links');
    if (record.minimized?.scenarioDigest !== digestOf(minimized)) fail('minimized-link-broken', 'the minimized scenario does not match the digest the record links');
    if (record.original?.scenarioId !== original?.id || record.minimized?.scenarioId !== minimized?.id) fail('id-link-broken', 'a scenario id does not match the record');
    if (!same(record.invariant, original?.invariant) || !same(record.invariant, minimized?.invariant)) fail('invariant-changed', 'the record, the original and the minimized scenario must name the same invariant');
    for (const side of ['original', 'minimized']) {
      const r = record[side];
      if (typeof r?.receiptDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(r.receiptDigest) || typeof r.recordId !== 'string' || typeof r.manifestId !== 'string') fail('receipt-missing', `the ${side} side carries no receipt digest, verification record id and replay manifest id`);
    }
    for (const e of checkMinimization(original, minimized).errors) fail(e.code, e.message);
  } catch (e) {
    fail('malformed', `the check could not complete: ${String(e?.message || e).slice(0, 120)}`);
  }
  return { ok: errors.length === 0, errors };
}
