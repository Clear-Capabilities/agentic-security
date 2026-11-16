// Counterexamples (verified-remediation PRD FR-07): validate the generated checks against the original, turn a failed check into a
// minimal, structured counterexample, and keep the sealed set out of the feedback loop.
//
//   validateAgainstOriginal  An attack request that reaches no forbidden effect on the ORIGINAL cannot show that a patch repaired
//                            anything, and a control whose expectation the original does not meet is a wrong expectation: both are
//                            QUARANTINED with the reason and removed from the obligation the candidates are judged by (AC-07.3). The
//                            quarantine is recorded, never silent.
//   counterexampleFrom       A failed development obligation becomes {obligation, request, actor, preconditions, effect}: the request
//                            the verifier saw violate, the actor's identity, and the authoritative assertion it broke. A failed SEALED
//                            obligation yields only "a sealed check failed": no request, value or outcome detail reaches generation
//                            (AC-07.5).
//   shrinkCounterexample     Character-level reduction of the attack value (query parameters and string body fields), batched: every
//                            one-deletion variant is a separate attack request in ONE oracle run, and the shortest variant that still
//                            discloses THE SAME secret (or breaks the same state check) is kept, so the failed property is preserved
//                            (AC-07.4). Bounded by rounds and by the per-run request ceiling.
import { judge, runObligation } from './lab.js';

const REQ_CAP = 120; // the application oracles accept at most 128 requests per run

const idOf = (r) => r.id;

/** The obligation's inputs with quarantined requests and checks removed. Pure. */
export function withoutQuarantined(inputs, quarantined) {
  const q = new Set(quarantined.map((x) => x.id));
  return { ...inputs, requests: inputs.requests.filter((r) => !q.has(r.id)), stateChecks: (inputs.stateChecks || []).filter((c) => !q.has(c.id)) };
}

/**
 * Run each oracle obligation on the original and quarantine the checks that cannot be meaningful.
 * @returns {{baseline: object[], quarantined: object[], effectiveInputs: Record<string, object>}}
 */
export async function validateAgainstOriginal(contract, originalFiles, run) {
  const baseline = []; const quarantined = []; const effectiveInputs = {};
  for (const ob of contract.obligations.filter((x) => x.oracleId)) {
    const res = await run(ob, originalFiles, ob.inputs);
    const d = res.details || {};
    const q = [];
    if (ob.kind === 'app-attack-blocked' || ob.kind === 'app-attack-sealed') {
      const violated = new Set((d.attackViolations || []).map((v) => v.id));
      if (res.observed === 'confirmed' || res.observed === 'refuted') {
        const reqs = ob.inputs.requests;
        for (const r of reqs.filter((x) => x.role === 'attack' && x.forbid?.secrets?.length)) {
          if (!violated.has(r.id)) q.push({ id: r.id, obligation: ob.id, reason: 'this attack discloses no planted secret on the original revision, so it cannot show a repair' });
        }
        // A generated state check names the write attacks it guards: if the original does not break it, the check and those writes go.
        // Profile-declared state checks (no `guards`) are regression guards and stay.
        for (const c of (ob.inputs.stateChecks || []).filter((x) => Array.isArray(x.guards))) {
          if (violated.has(c.id)) continue;
          q.push({ id: c.id, obligation: ob.id, reason: 'the original revision makes no unauthorized change this check can see, so it cannot show a repair' });
          for (const g of c.guards) q.push({ id: g, obligation: ob.id, reason: 'this write attack does not change durable state on the original revision' });
        }
        for (const c of (d.controlFailures || [])) q.push({ id: c.id, obligation: ob.id, reason: `the original revision does not meet this control's expectation (${c.reason}); the expectation is wrong or the application needs setup the profile lacks` });
      }
    } else if (ob.kind === 'app-behaviour-preserved') {
      for (const c of (d.controlFailures || [])) q.push({ id: c.id, obligation: ob.id, reason: `the original revision does not meet this legitimate expectation (${c.reason}); mark it originalMishandles if the repair should fix it` });
    }
    const seen = new Set();
    const uniq = q.filter((x) => (seen.has(x.id) ? false : seen.add(x.id)));
    quarantined.push(...uniq);
    effectiveInputs[ob.id] = withoutQuarantined(ob.inputs, uniq);
    baseline.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, expectation: ob.baselineExpectation, status: ob.baselineExpectation ? judge(res.observed, ob.baselineExpectation) : 'recorded', reason: res.reason });
  }
  return { baseline, quarantined, effectiveInputs };
}

/** Structured feedback for the next proposal from one failed obligation run. */
export function counterexampleFrom(ob, inputs, res, actorsByHeader) {
  if (ob.kind === 'app-attack-sealed') return { obligation: ob.id, sealed: true, message: 'a sealed held-out check failed; its content is not disclosed to candidate generation' };
  const d = res.details || {};
  const byId = Object.fromEntries(inputs.requests.map((r) => [r.id, r]));
  const actorOf = (r) => actorsByHeader?.(r?.headers) ?? null;
  if (ob.kind === 'app-attack-blocked') {
    const v = (d.attackViolations || [])[0];
    if (!v) return { obligation: ob.id, message: res.reason };
    const req = byId[v.id] || null;
    const check = (inputs.stateChecks || []).find((c) => c.id === v.id) || null;
    const writer = check && Array.isArray(check.guards) ? check.guards.map((g) => byId[g]).find(Boolean) || null : null;
    return {
      obligation: ob.id, property: v.effect === 'durable-state' ? 'unauthorized-durable-change' : 'secret-disclosed',
      request: req ? { method: req.method, path: req.path, body: req.body ?? null } : writer ? { method: writer.method, path: writer.path, body: writer.body ?? null } : null,
      actor: actorOf(req || writer), secrets: v.secrets || [], stateCheck: check ? check.sql : null, guardedRequests: check?.guards?.length ?? 0,
      violations: (d.attackViolations || []).length, message: res.reason,
    };
  }
  const f = (d.controlFailures || [])[0];
  const req = f ? byId[f.id] : null;
  return { obligation: ob.id, property: 'legitimate-behaviour', request: req ? { method: req.method, path: req.path, body: req.body ?? null } : null, actor: actorOf(req), expected: req?.expect ?? null, message: f ? f.reason : res.reason };
}

function reductions(req) {
  const out = [];
  const url = new URL(req.path, 'http://x.local');
  for (const [k, v] of url.searchParams) {
    for (let i = 0; i < v.length; i++) {
      const u = new URL(url); u.searchParams.set(k, v.slice(0, i) + v.slice(i + 1));
      out.push({ ...req, path: u.pathname + u.search });
    }
  }
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) if (typeof v === 'string') for (let i = 0; i < v.length; i++) out.push({ ...req, body: { ...req.body, [k]: v.slice(0, i) + v.slice(i + 1) } });
  }
  return out;
}

// Size of the attacker-controlled values, decoded: the URL API re-encodes characters differently from the request builder, so the
// encoded path length would make a shorter value look longer.
const sizeOf = (r) => {
  let n = 0;
  for (const [, v] of new URL(r.path, 'http://x.local').searchParams) n += v.length;
  if (r.body && typeof r.body === 'object') for (const v of Object.values(r.body)) if (typeof v === 'string') n += v.length;
  return n;
};

/**
 * Shrink one violating attack request while it still discloses the same secret(s). `run(ob, files, inputs)` is the lab runner.
 * @returns {Promise<{request:object, original:object, runs:number, preserved:boolean}>}
 */
export async function shrinkCounterexample(ob, inputs, files, violatingId, run, { maxRounds = 6 } = {}) {
  const controls = inputs.requests.filter((r) => r.role === 'control');
  let best = inputs.requests.find((r) => r.id === violatingId);
  const original = best;
  const secrets = new Set(best?.forbid?.secrets || []);
  let runs = 0;
  if (!best || !secrets.size) return { request: best, original, runs, preserved: true };
  for (let round = 0; round < maxRounds; round++) {
    const cands = reductions(best).slice(0, REQ_CAP - controls.length).map((r, i) => ({ ...r, id: `shrink_${round}_${i}` }));
    if (!cands.length) break;
    const res = await run(ob, files, { ...inputs, requests: [...controls, ...cands], stateChecks: [] });
    runs++;
    const hits = new Set((res.details?.attackViolations || []).filter((v) => (v.secrets || []).some((s) => secrets.has(s))).map(idOf));
    const next = cands.filter((c) => hits.has(c.id)).sort((a, b) => sizeOf(a) - sizeOf(b))[0];
    if (!next || sizeOf(next) >= sizeOf(best)) break;
    best = { ...next, id: original.id };
  }
  return { request: best, original, runs, preserved: true };
}

export { runObligation };
