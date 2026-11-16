// The repair coordinator (verified-remediation PRD section 5.2, FR-06, FR-07, FR-17): one state machine for every route (CLI, MCP,
// headless callers, batch), calling the existing canonical services and adding none of its own.
//
//   plan      contract from finding + profile + exact source (contracts.js). No execution.
//   run       baseline validation on the original (quarantine), then bounded rounds: proposals -> scope gate -> development obligations
//             -> counterexample (shrunk) fed to the next round -> central verifier (rescan, footprint, project test delta) -> sealed
//             obligations -> promotion. Every oracle run goes through the oracle runner and the trust boundary (lab.js).
//   apply     only on request, only for a verified-for-contract candidate, only through applyVerifiedFix (signed scan, confinement,
//             material-change approval, concurrent-modification check, transactional write). A source that drifted from the contract
//             is refused before that (T-13).
//
// Trust rules this module enforces:
//   - Promotion needs, for every required oracle obligation, a result produced in THIS process whose receipt the oracle runner issued
//     for exactly the promoted files and the contract's inputs and oracle logic. Persisted records carry receipt digests only; `resume`
//     re-executes every leg and never turns stored JSON back into evidence (AC-17.4, T-16).
//   - Execution is enabled only by the operator (the assurance config the caller passes); a missing backend or a disabled feature is
//     `blocked` with the next prerequisite, never a downgraded pass (AC-04.6, AC-05.6).
//   - Budgets are enforced here, outside candidate code: rounds, strategies per round, attack cases per candidate, the whole-run wall
//     deadline (an AbortSignal that reaches the oracle runner, which ends the process tree), and identical candidates consume an attempt
//     without being re-run (AC-07.6). A budget stop is `partial`, never a proof.
//   - Sealed obligations run only on a candidate that passed everything else; their outcome is recorded but never fed back.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { digestOf } from '../posture/assurance/identity.js';
import { featureStatus } from '../posture/assurance/config.js';
import { getOracle } from '../posture/oracles/registry.js';
import { stateDir } from '../posture/state-dir.js';
import { SCHEMAS, SCHEMA_VERSION, validateContract, validateRepairRecord } from './schemas.js';
import { buildContract, snapshotSource } from './contracts.js';
import { runObligation, judge } from './lab.js';
import { validateAgainstOriginal, counterexampleFrom, shrinkCounterexample } from './counterexamples.js';
import { checkCandidate, makeCandidate } from './candidates.js';

export const PLAN_SCHEMA = 'agentic-security/repair-plan';
export const POLICY_SCHEMA = 'agentic-security/repair-policy';
export const DEFAULT_BUDGETS = Object.freeze({ strategiesPerRound: 3, rounds: 3, attackCasesPerCandidate: 64, wallMs: 15 * 60_000, testCommandMs: 120_000, workers: 1 });
const BUDGET_CEILINGS = Object.freeze({ strategiesPerRound: 3, rounds: 3, attackCasesPerCandidate: 120, wallMs: 60 * 60_000, testCommandMs: 120_000, workers: 2 });
export const EXIT = Object.freeze({ ok: 0, failed: 1, usage: 2, blocked: 3, cancelled: 4 });

export const runsDir = (root) => path.join(stateDir(root), 'repair', 'runs');
const RUN_ID_RE = /^rrun-[0-9a-f]{16}$/;
export const isRunId = (s) => typeof s === 'string' && RUN_ID_RE.test(s);

// ---------------------------------------------------------------- policy and budgets

/** Budgets within their ceilings. An unknown key or an out-of-range value is an error, never clamped silently. */
export function resolveBudgets(requested = {}) {
  const errors = []; const b = { ...DEFAULT_BUDGETS };
  for (const [k, v] of Object.entries(requested || {})) {
    if (!(k in DEFAULT_BUDGETS)) { errors.push(`unknown budget '${k}'`); continue; }
    if (!Number.isInteger(v) || v < 1 || v > BUDGET_CEILINGS[k]) { errors.push(`budget ${k} must be an integer from 1 to ${BUDGET_CEILINGS[k]}`); continue; }
    b[k] = v;
  }
  return { budgets: b, errors };
}

/** A repair policy: budgets and the model setting. It cannot enable execution: only the operator's assurance config can. */
export function validatePolicy(p) {
  const errs = [];
  if (p === undefined || p === null) return { policy: { schema: POLICY_SCHEMA, schemaVersion: '1.0.0', budgets: {}, model: 'none' }, errors: [] };
  if (typeof p !== 'object' || Array.isArray(p)) return { policy: null, errors: ['the policy must be a JSON object'] };
  for (const k of Object.keys(p)) if (!['schema', 'schemaVersion', 'budgets', 'model'].includes(k)) errs.push(`policy: unknown field '${k}'`);
  if (p.schema !== POLICY_SCHEMA) errs.push(`policy.schema must be '${POLICY_SCHEMA}'`);
  if (p.model !== undefined && p.model !== 'none') errs.push("policy.model: only 'none' is supported in this milestone (no model proposer is wired; a local-only policy never becomes a remote call)");
  const { errors } = resolveBudgets(p.budgets);
  return { policy: errs.length || errors.length ? null : { budgets: {}, model: 'none', ...p }, errors: [...errs, ...errors] };
}

// ---------------------------------------------------------------- plan

/**
 * @param {{root:string, finding:object, family:string, profile:object, profileOrigin:string, commit?:string|null}} o
 */
export function planRepair(o) {
  const source = snapshotSource(o.root, o.profile);
  const built = buildContract({ finding: o.finding, profile: o.profile, profileOrigin: o.profileOrigin, source, commit: o.commit ?? null, family: o.family });
  if (!built.contract) return { plan: null, blocked: built.blocked, problems: built.problems };
  const plan = {
    schema: PLAN_SCHEMA, schemaVersion: '1.0.0', contract: built.contract, finding: o.finding,
    blocked: built.blocked, entry: o.profile.application.entry, tests: o.profile.tests || null,
    actors: o.profile.actors.map((a) => ({ id: a.id, headersDigest: digestOf(a.headers || {}) })),
  };
  return { plan, blocked: built.blocked, problems: [] };
}

// ---------------------------------------------------------------- persistence

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function readRun(root, runId) {
  if (!isRunId(runId)) return { error: 'not a repair run id' };
  const dir = path.join(runsDir(root), runId);
  try {
    const record = JSON.parse(fs.readFileSync(path.join(dir, 'record.json'), 'utf8'));
    const plan = JSON.parse(fs.readFileSync(path.join(dir, 'plan.json'), 'utf8'));
    const v = validateRepairRecord(record);
    return { dir, record, plan, valid: v.ok, problems: v.ok ? [] : v.errors.map((e) => `${e.path}: ${e.message}`) };
  } catch (e) { return { error: `the run could not be read: ${String(e.message).slice(0, 160)}` }; }
}

/** Ask a running repair (in any process) to stop. It notices within a fraction of a second and records `cancelled`. */
export function requestCancel(root, runId) {
  if (!isRunId(runId)) return { ok: false, reason: 'not a repair run id' };
  const dir = path.join(runsDir(root), runId);
  try { JSON.parse(fs.readFileSync(path.join(dir, 'record.json'), 'utf8')); } catch { return { ok: false, reason: 'no such run' }; }
  fs.writeFileSync(path.join(dir, 'cancel'), new Date().toISOString());
  return { ok: true };
}

// ---------------------------------------------------------------- run

const actorLookup = (profileActors) => (headers) => {
  const d = digestOf(headers || {});
  return profileActors.find((a) => a.headersDigest === d)?.id ?? null;
};

function baseRecord(runId, plan) {
  const c = plan.contract;
  return {
    schema: SCHEMAS.record, schemaVersion: SCHEMA_VERSION, runId, contractId: c.contractId, contractDigest: c.contractDigest,
    findingRefs: c.findingRefs, sourceDigest: c.sourceDigest,
    disposition: 'proposed', application: 'not-applied', artifact: 'source-only', environment: 'not-checked', completion: 'partial',
    candidates: [], selected: null, rounds: 0, obligationResults: [], counterexamples: [], quarantined: [],
    budget: null, accounting: { oracleRuns: 0, wallMs: 0, modelTokens: null, modelCalls: 0, usd: null }, reasons: [], nextPrerequisite: null,
    scope: `contract ${c.contractId} (${c.family}): ${c.obligations.length} obligations over ${c.editScope.allowed.length} application file(s); source-only, nothing built or deployed`,
    createdAt: new Date().toISOString(),
  };
}

/**
 * @param {{root:string, plan:object, policy?:object, config:object, proposers:object[], signal?:AbortSignal, runId?:string,
 *   apply?:{approval?:object}|null, deps?:{verifyPatch?:Function, applyVerifiedFix?:Function, runOracleDeps?:object, probeEnv?:object},
 *   onEvent?:(e:object)=>void, resumedFrom?:string}} o
 * @returns {Promise<{record:object, exitCode:number, runId:string, dir:string}>}
 */
export async function runRepair(o) {
  const started = Date.now();
  const plan = o.plan;
  const runId = o.runId || `rrun-${crypto.randomBytes(8).toString('hex')}`;
  const dir = path.join(runsDir(o.root), runId);
  const record = baseRecord(runId, plan);
  const emit = (e) => { try { o.onEvent?.(e); } catch { /* observer errors never change the run */ } try { fs.appendFileSync(path.join(dir, 'events.jsonl'), JSON.stringify({ t: Date.now() - started, ...e }) + '\n'); } catch { /* best effort */ } };
  const { policy, errors: policyErrors } = validatePolicy(o.policy);
  if (o.resumedFrom) record.reasons.push(`resumed from ${o.resumedFrom}: every verification leg re-executed in this process`);
  writeJson(path.join(dir, 'plan.json'), plan);
  const finish = (disposition, completion, exitCode, extra = {}) => {
    Object.assign(record, { disposition, completion, ...extra });
    record.accounting.wallMs = Date.now() - started;
    record.policyDigest = digestOf(policy || o.policy || null);
    const v = validateRepairRecord(record);
    if (!v.ok) { record.disposition = 'blocked'; record.completion = 'invalid'; record.reasons.push(`the record failed its own schema: ${v.errors.map((e) => e.message).join('; ').slice(0, 300)}`); exitCode = EXIT.blocked; }
    writeJson(path.join(dir, 'record.json'), record);
    emit({ kind: 'finished', disposition: record.disposition, completion: record.completion });
    return { record, exitCode, runId, dir };
  };
  writeJson(path.join(dir, 'record.json'), record);
  if (policy) writeJson(path.join(dir, 'policy.json'), policy);
  if (!policy) return finish('blocked', 'invalid', EXIT.usage, { reasons: policyErrors });
  const budgets = resolveBudgets(policy.budgets).budgets;
  record.budget = { ...budgets, used: { rounds: 0, proposals: 0, oracleRuns: 0 } };

  // 1. the contract still describes this source, and its oracle logic is still the registered logic
  const cv = validateContract(plan.contract);
  if (!cv.ok) return finish('blocked', 'invalid', EXIT.usage, { reasons: cv.errors.map((e) => `${e.path}: ${e.message}`) });
  for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
    if (getOracle(ob.oracleId)?.logicDigest !== ob.oracleLogicDigest) return finish('blocked', 'invalid', EXIT.blocked, { reasons: [`obligation ${ob.id}: the oracle logic changed since the contract was planned`], nextPrerequisite: 'repair plan (re-plan the contract against the current verifier)' });
  }
  const profileStub = { application: plan.contract.profile.application };
  const now = snapshotSource(o.root, profileStub);
  if (now.sourceDigest !== plan.contract.sourceDigest) return finish('blocked', 'invalid', EXIT.blocked, { reasons: ['the application source changed since the contract was planned; its evidence would not describe this code'], nextPrerequisite: 'repair plan (re-plan against the current source)' });
  if (plan.blocked?.length) return finish('blocked', 'unavailable', EXIT.blocked, { reasons: plan.blocked, nextPrerequisite: 'complete the application profile' });
  const gate = featureStatus(o.config, 'verification-oracles');
  if (gate.status !== 'ok') return finish('blocked', 'unavailable', EXIT.blocked, { reasons: [`execution is not enabled: ${gate.reason}`], nextPrerequisite: 'repair run --allow-execution (the operator enables sandboxed execution; a repository file cannot)' });

  // 2. cancellation and the wall deadline reach the oracle runner through one signal
  const ctl = new AbortController();
  const stop = (why) => { if (!ctl.signal.aborted) { record.reasons.push(why); ctl.abort(); } };
  o.signal?.addEventListener('abort', () => stop('cancelled by the caller'), { once: true });
  const timer = setTimeout(() => stop(`the whole-run wall budget of ${budgets.wallMs} ms ran out`), budgets.wallMs);
  const poll = setInterval(() => { if (fs.existsSync(path.join(dir, 'cancel'))) stop('cancelled by request'); }, 150);
  const cleanup = () => { clearTimeout(timer); clearInterval(poll); };
  const stopped = () => ctl.signal.aborted;
  const stoppedResult = () => { cleanup(); const byBudget = record.reasons.some((r) => r.includes('wall budget')); return finish(byBudget ? 'blocked' : 'cancelled', byBudget ? 'partial' : 'cancelled', EXIT.cancelled, { nextPrerequisite: `repair resume ${runId}` }); };

  const original = now.files;
  const entry = plan.entry;
  const run = async (ob, files, inputs) => {
    record.budget.used.oracleRuns++; record.accounting.oracleRuns++;
    return runObligation(ob, files, { config: o.config, signal: ctl.signal, entry, hypothesisId: `${plan.contract.contractId}:${ob.id}`, inputs, deps: o.deps?.runOracleDeps, probeEnv: o.deps?.probeEnv, runOracle: o.deps?.runOracle });
  };

  try {
    // 3. baseline: every generated check must mean something on the original
    emit({ kind: 'baseline' });
    const base = await validateAgainstOriginal(plan.contract, original, run);
    if (stopped()) return stoppedResult();
    record.quarantined = base.quarantined;
    record.obligationResults.push(...base.baseline.map((b) => ({ ...b, revision: 'original', required: false })));
    const unavailable = base.baseline.filter((b) => ['unavailable', 'invalid'].includes(b.observed));
    if (unavailable.length) { cleanup(); return finish('blocked', 'unavailable', EXIT.blocked, { reasons: unavailable.map((b) => `${b.obligation} on the original: ${b.reason}`), nextPrerequisite: 'a working confinement backend and node:sqlite on this host' }); }
    const attackObs = plan.contract.obligations.filter((x) => x.kind === 'app-attack-blocked');
    const reproduced = base.baseline.filter((b) => b.kind === 'app-attack-blocked' && b.observed === 'confirmed');
    const behaviourOk = base.baseline.filter((b) => b.kind === 'app-behaviour-preserved').every((b) => b.observed === 'refuted' || base.effectiveInputs[b.obligation].requests.length > 0);
    if (!reproduced.length) {
      cleanup();
      const refuted = base.baseline.filter((b) => b.kind === 'app-attack-blocked').every((b) => b.observed === 'refuted');
      if (refuted && behaviourOk) return finish('refuted-finding', 'complete', EXIT.ok, { reasons: ['no declared attack reaches a forbidden effect on the original revision while its legitimate requests work: the finding is not reproduced for this contract, and no patch is proposed'] });
      return finish('needs-review', 'partial', EXIT.blocked, { reasons: base.baseline.filter((b) => b.kind === 'app-attack-blocked').map((b) => `${b.obligation} on the original: ${b.reason}`), nextPrerequisite: 'a profile under which the original revision reproduces the finding and serves its legitimate requests' });
    }
    for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
      const eff = base.effectiveInputs[ob.id];
      const meaningful = ob.kind.startsWith('app-attack') ? eff.requests.some((r) => r.role === 'attack') || (eff.stateChecks || []).length : eff.requests.length;
      if (!meaningful) { cleanup(); return finish('needs-review', 'partial', EXIT.blocked, { reasons: [`required obligation ${ob.id} has no check left that is meaningful on the original revision (all quarantined)`], nextPrerequisite: 'review the quarantined checks and the profile' }); }
    }

    // attack-case budget per candidate
    const capped = {};
    for (const ob of plan.contract.obligations.filter((x) => x.oracleId)) {
      const eff = base.effectiveInputs[ob.id];
      const attacks = eff.requests.filter((r) => r.role === 'attack');
      if (attacks.length > budgets.attackCasesPerCandidate) {
        const keep = new Set(attacks.slice(0, budgets.attackCasesPerCandidate).map((r) => r.id));
        capped[ob.id] = attacks.length - keep.size;
        base.effectiveInputs[ob.id] = { ...eff, requests: eff.requests.filter((r) => r.role !== 'attack' || keep.has(r.id)) };
      }
    }
    if (Object.keys(capped).length) record.reasons.push(`attack cases over the per-candidate budget were omitted: ${Object.entries(capped).map(([k, n]) => `${k} ${n}`).join(', ')}; the verification is partial for those cases`);

    // 4. rounds
    const order = { 'app-behaviour-preserved': 0, 'app-behaviour-after': 1, 'app-attack-blocked': 2 };
    const devObs = plan.contract.obligations.filter((x) => x.oracleId && x.kind !== 'app-attack-sealed').sort((a, b) => order[a.kind] - order[b.kind]);
    const sealedObs = plan.contract.obligations.filter((x) => x.kind === 'app-attack-sealed');
    const seen = new Set();
    let feedback = null; let selected = null; let anyInconclusive = false; let anyProposal = false;
    for (let round = 1; round <= budgets.rounds && !selected; round++) {
      record.rounds = round; record.budget.used.rounds = round;
      const proposals = [];
      for (const p of o.proposers) {
        if (proposals.length >= budgets.strategiesPerRound) break;
        let got;
        try { got = await p.propose({ contract: plan.contract, files: original, round, feedback, max: budgets.strategiesPerRound - proposals.length }); }
        catch (e) { record.reasons.push(`proposer ${p.id} failed: ${String(e?.message || e).slice(0, 160)}`); continue; }
        for (const n of got.notes || []) record.reasons.push(`proposer ${p.id}: ${n}`);
        proposals.push(...(got.proposals || []).slice(0, budgets.strategiesPerRound - proposals.length));
      }
      if (!proposals.length) break;
      anyProposal = true;
      for (const prop of proposals) {
        if (stopped()) return stoppedResult();
        record.budget.used.proposals++;
        const chk = checkCandidate(plan.contract, original, prop.files);
        const summary = { round, generator: prop.generator, generatorIdentity: prop.generatorIdentity, strategy: prop.strategy || null };
        if (!chk.ok) { record.candidates.push({ ...summary, status: 'refused', reasons: chk.reasons, scope: chk.scope.totals }); feedback = { refused: chk.reasons }; emit({ kind: 'candidate-refused', reasons: chk.reasons }); continue; }
        const made = makeCandidate(plan.contract, original, prop, chk);
        if (!made.candidate) { record.candidates.push({ ...summary, status: 'refused', reasons: made.problems }); continue; }
        const cand = made.candidate;
        if (seen.has(cand.patchDigest)) { record.candidates.push({ ...summary, candidateId: cand.candidateId, patchDigest: cand.patchDigest, status: 'duplicate', reasons: ['an identical patch was already judged; it consumes an attempt and is not run again'] }); continue; }
        seen.add(cand.patchDigest);
        writeJson(path.join(dir, 'candidates', `${cand.candidateId.replace(':', '-')}.json`), cand);
        const patched = { ...original };
        for (const [rel, t] of Object.entries(cand.files)) { if (t === null) delete patched[rel]; else patched[rel] = t; }
        const cs = { ...summary, candidateId: cand.candidateId, patchDigest: cand.patchDigest, scope: cand.scope, status: 'pending', results: [] };
        record.candidates.push(cs);
        emit({ kind: 'candidate', candidateId: cand.candidateId, round });
        const t0 = Date.now();
        // Every development obligation runs, so the record attributes every failure (VerificationRun: full failure attribution); the
        // counterexample fed back is the first security failure, else the first behaviour failure.
        let verdict = 'passed'; const failures = [];
        for (const ob of devObs) {
          const inputs = base.effectiveInputs[ob.id];
          const res = await run(ob, patched, inputs);
          if (stopped()) return stoppedResult();
          const status = judge(res.observed, ob.patchedExpectation);
          cs.results.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, status, reason: res.reason, receiptDigest: res.receipt?.receiptDigest ?? null, filesDigest: res.filesDigest, inputsDigest: res.inputsDigest, live: res.receipt });
          if (status === 'failed') failures.push({ ob, inputs, res });
          else if (status !== 'passed' && verdict === 'passed') verdict = status === 'cancelled' ? 'cancelled' : 'inconclusive';
        }
        if (failures.length) {
          verdict = 'failed';
          const { ob, inputs, res } = failures.find((f) => f.ob.kind === 'app-attack-blocked') || failures[0];
          let cx = counterexampleFrom(ob, inputs, res, actorLookup(plan.actors));
          const firstSecret = (res.details?.attackViolations || []).find((v) => v.effect === 'secret-disclosed');
          if (firstSecret && ob.kind === 'app-attack-blocked') {
            const sh = await shrinkCounterexample(ob, inputs, patched, firstSecret.id, run, { maxRounds: 4 });
            if (stopped()) return stoppedResult();
            cx = { ...cx, request: { method: sh.request.method, path: sh.request.path, body: sh.request.body ?? null }, shrunkFrom: { method: sh.original.method, path: sh.original.path, body: sh.original.body ?? null }, shrinkRuns: sh.runs, propertyPreserved: sh.preserved };
          }
          cx.alsoFailed = failures.filter((f) => f.ob.id !== ob.id).map((f) => f.ob.id);
          record.counterexamples.push({ candidateId: cand.candidateId, ...cx });
          feedback = { candidateId: cand.candidateId, counterexample: cx };
        }
        if (verdict === 'passed') {
          const central = await centralVerify(o, plan, cand, budgets);
          cs.results.push(central);
          if (central.status !== 'passed') { verdict = central.status === 'failed' ? 'failed' : 'inconclusive'; if (central.status === 'failed') { record.counterexamples.push({ candidateId: cand.candidateId, obligation: 'central-verifier', property: 'central-verifier', message: central.reason }); feedback = { candidateId: cand.candidateId, counterexample: { obligation: 'central-verifier', message: central.reason } }; } }
        }
        if (verdict === 'passed') {
          for (const ob of sealedObs) {
            const res = await run(ob, patched, base.effectiveInputs[ob.id]);
            if (stopped()) return stoppedResult();
            const status = judge(res.observed, ob.patchedExpectation);
            cs.results.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, status, reason: status === 'failed' ? 'a sealed held-out check failed' : res.reason, receiptDigest: res.receipt?.receiptDigest ?? null, filesDigest: res.filesDigest, inputsDigest: res.inputsDigest, live: res.receipt });
            if (status !== 'passed') { verdict = status === 'failed' ? 'failed' : 'inconclusive'; if (status === 'failed') { record.counterexamples.push({ candidateId: cand.candidateId, obligation: ob.id, sealed: true, message: 'a sealed held-out check failed; its content is not disclosed to candidate generation' }); feedback = { candidateId: cand.candidateId, counterexample: { obligation: ob.id, sealed: true, message: 'a sealed held-out check failed' } }; } break; }
          }
        }
        cs.wallMs = Date.now() - t0;
        if (verdict === 'inconclusive') anyInconclusive = true;
        if (verdict === 'passed' && promotable(plan.contract, cs, patched)) { cs.status = 'verified-for-contract'; selected = { cand, cs }; break; }
        cs.status = verdict === 'passed' ? 'inconclusive' : verdict === 'failed' ? 'rejected' : verdict;
      }
    }
    cleanup();
    for (const c of record.candidates) for (const r of c.results || []) delete r.live;
    if (!anyProposal) return finish('blocked', 'unavailable', EXIT.blocked, { reasons: [...record.reasons, 'no candidate generator produced a proposal'], nextPrerequisite: 'supply candidates (--candidates <file.json>) or a family with a deterministic recipe' });
    if (!selected) {
      const exhausted = record.rounds >= budgets.rounds;
      return finish(anyInconclusive ? 'needs-review' : 'rejected', exhausted ? 'partial' : 'complete', anyInconclusive ? EXIT.blocked : EXIT.failed, { reasons: [...record.reasons, exhausted ? `no candidate satisfied every required obligation within ${budgets.rounds} round(s); this is a budget stop, not a proof that no repair exists` : 'no candidate satisfied every required obligation'] });
    }
    record.selected = selected.cand.candidateId;
    record.patchDigest = selected.cand.patchDigest;
    record.exactPatch = { files: selected.cand.files, beforeDigests: selected.cand.beforeDigests, afterDigests: selected.cand.afterDigests };
    record.obligationResults.push(...selected.cs.results.map((r) => ({ obligation: r.obligation, kind: r.kind, revision: 'patched', required: true, status: r.status, observed: r.observed, receiptDigest: r.receiptDigest ?? null, reason: r.reason })));
    record.legacy = { ok: true, verified: true, fixCompleteness: selected.cs.results.find((r) => r.obligation === 'central-verifier')?.fixCompleteness ?? null, note: 'FULL in the legacy fields means the named contract passed, not universal correctness' };
    // 5. application, only on request and only through the canonical service
    if (o.apply) {
      const drift = snapshotSource(o.root, profileStub);
      if (drift.sourceDigest !== plan.contract.sourceDigest) return finish('verified-for-contract', 'complete', EXIT.blocked, { application: 'concurrent-change-refused', reasons: [...record.reasons, 'the source changed after verification; the verified patch was not applied'] });
      const apply = o.deps?.applyVerifiedFix || (await import('../fix/apply-fix-service.js')).applyVerifiedFix;
      const a = await apply({ scanRoot: o.root, finding: { ...plan.finding, stableId: plan.finding.stableId || plan.contract.findingRefs[0], id: plan.finding.id || plan.contract.findingRefs[0] }, files: selected.cand.files, fixMeta: { approval: o.apply.approval || undefined, repairContract: plan.contract.contractId } });
      if (!a.applied) return finish('verified-for-contract', 'complete', EXIT.blocked, { application: a.reason && /changed on disk/.test(a.reason) ? 'concurrent-change-refused' : 'not-applied', reasons: [...record.reasons, `not applied: ${a.reason}`] });
      return finish('verified-for-contract', 'complete', EXIT.ok, { application: 'applied' });
    }
    return finish('verified-for-contract', 'complete', EXIT.ok);
  } catch (e) {
    cleanup();
    return finish('blocked', 'invalid', EXIT.blocked, { reasons: [...record.reasons, `the coordinator failed: ${String(e?.message || e).slice(0, 200)}`] });
  }
}

/** Every required oracle obligation passed on exactly these files, with a live receipt bound to them. */
function promotable(contract, cs, patched) {
  const fd = digestOf(patched);
  for (const ob of contract.obligations.filter((x) => x.required)) {
    const r = cs.results.find((x) => x.obligation === ob.id);
    if (!r || r.status !== 'passed') return false;
    if (ob.oracleId && (!r.live || r.filesDigest !== fd || r.live.request.filesDigest !== fd)) return false;
  }
  return true;
}

/** The project-tests obligation: the central verifier (verify-patch.js) on the exact candidate. */
async function centralVerify(o, plan, cand, budgets) {
  const verify = o.deps?.verifyPatch || (await import('../fix/verify-patch.js')).verifyPatch;
  const finding = { id: plan.finding.id || plan.contract.findingRefs[0], stableId: plan.finding.stableId || plan.contract.findingRefs[0] };
  try {
    const files = Object.fromEntries(Object.entries(cand.files).filter(([, t]) => t !== null));
    const r = await verify({ scanRoot: o.root, finding, files, route: 'repair', mode: 'verify', testCommand: plan.tests?.command, testTimeoutMs: budgets.testCommandMs, requiredTests: plan.tests?.required || [], flakyTests: plan.tests?.flaky || [] });
    const legs = Object.fromEntries(['securityAfter', 'newFindingDelta', 'behaviorTests', 'behaviorPreservation'].map((k) => [k, r.fixVerification?.[k]?.status ?? null]));
    const ok = r.verdict?.ok === true && r.canonical?.ok === true;
    return { obligation: 'central-verifier', kind: 'project-tests', observed: ok ? 'passed' : 'failed', status: ok ? 'passed' : 'failed', reason: ok ? 'rescan, new-finding delta, footprint and test legs passed or were recorded as not run' : String(r.verdict?.summary || 'a central verification leg failed').slice(0, 400), legs, fixCompleteness: r.fixVerification?.fixCompleteness ?? null };
  } catch (e) {
    return { obligation: 'central-verifier', kind: 'project-tests', observed: 'error', status: 'inconclusive', reason: `the central verifier failed: ${String(e?.message || e).slice(0, 200)}` };
  }
}
