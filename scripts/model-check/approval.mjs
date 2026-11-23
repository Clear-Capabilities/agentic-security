#!/usr/bin/env node
// Bounded state-machine check of service-contract approval (contract-driven verification, H-03 / H-AC05). Optional, P2.
//
// WHAT IS MODELLED. One contract id and version with two contents, A (as reviewed) and B (the same id and version, edited). Actors:
// `dana` (a human the reviewer policy lists), `owner` (a human it does not list), `bot` (code) and `model` (a model). Actions:
// propose(content, actor), approve(content, actor), revoke(content, actor), delist (the operator removes dana from the reviewer
// policy) and advance (time passes beyond the contract's review interval). Per content the model tracks none | proposed | approved |
// revoked, plus `delisted`, `expired` and whether dana has signed an authority record.
//
// THE PROPERTY. The implementation reports a content `approved` and current only if a listed human approved exactly that content,
// it was not revoked since, the review interval has not lapsed, and the approving reviewer is still listed. Checked two ways:
//   1. Conformance over the reachable abstract state graph: breadth-first to a fixpoint (or the depth bound), every action tried in
//      every reached state, including the ones the model forbids. The implementation must refuse exactly the forbidden actions, and
//      after each step `approvalState` of both contents must equal the model's prediction.
//   2. All action sequences up to depth 3 with no state merging, from the empty ledger, replayed through the implementation, with
//      the property checked after every step. This tests the merging assumption of (1) on short traces.
//
// IMPLEMENTATION LINKAGE. Every step calls `proposeContract`, `approveContract`, `revokeContract` and `approvalState` of
// `scanner/src/contracts/approval.js` (which records through `recordTransition` and verifies through `verifyLedger` in
// `scanner/src/posture/invariants/lifecycle.js`). The result records the SHA-256 of both files, so a result names the code it judged.
//
// ASSUMPTIONS AND LIMITS, carried in the result. Signatures are not modelled (a fixed test signer). One contract id and version,
// two contents; no supersession, rejection or approver registry; one reviewer policy. The state merge in (1) assumes the
// implementation's behaviour depends only on the abstract state. A bounded result says nothing about inputs outside these bounds and
// nothing about the application, the sandbox or the rest of the product.
//
// Reproduce: `node scripts/model-check/approval.mjs [--json] [--depth N] [--trace-depth N]` (also `npm run model-check:approval` in
// scanner/). Exit 0 when no counterexample was found within the bounds, 1 with the counterexample trace.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..', 'scanner');
const APPROVAL = path.join(SCANNER, 'src', 'contracts', 'approval.js');
const LIFECYCLE = path.join(SCANNER, 'src', 'posture', 'invariants', 'lifecycle.js');
const REAL = await import(APPROVAL);
const { emptyLedger } = await import(LIFECYCLE);

const flag = (name, d) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? Number(process.argv[i + 1]) : d; };
const signer = { sign: () => 'ff', verify: () => true };
const ACTORS = { dana: { id: 'dana', kind: 'human' }, owner: { id: 'owner', kind: 'human' }, bot: { id: 'bot', kind: 'code' }, model: { id: 'model', kind: 'model' } };
const NOW = { inside: '2026-11-23', expired: '2027-06-01' };

export function contents() {
  const base = JSON.parse(fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'contract-slice', 'security', 'contracts', 'invoices-service', 'contract.json'), 'utf8'));
  const A = base; const B = { ...JSON.parse(JSON.stringify(base)), summary: `${base.summary} (edited after review)` };
  return { A, B };
}

export const ACTIONS = [
  ...['A', 'B'].flatMap((c) => Object.keys(ACTORS).map((a) => ({ op: 'propose', c, a }))),
  ...['A', 'B'].flatMap((c) => Object.keys(ACTORS).map((a) => ({ op: 'approve', c, a }))),
  ...['A', 'B'].flatMap((c) => Object.keys(ACTORS).map((a) => ({ op: 'revoke', c, a }))),
  { op: 'delist' }, { op: 'advance' },
];
const label = (x) => (x.op === 'delist' || x.op === 'advance' ? x.op : `${x.op}(${x.c},${x.a})`);

// ---- the abstract model -------------------------------------------------------------------------------------------------------
const initial = () => ({ A: 'none', B: 'none', delisted: false, expired: false, danaSigned: false });
const key = (s) => `${s.A}|${s.B}|${s.delisted}|${s.expired}|${s.danaSigned}`;
const other = (c) => (c === 'A' ? 'B' : 'A');

/** The model's step: `null` when the action is forbidden, else the next state. */
export function modelStep(s, x) {
  if (x.op === 'delist') return s.delisted ? null : { ...s, delisted: true };
  if (x.op === 'advance') return s.expired ? null : { ...s, expired: true };
  if (x.op === 'propose') return s[x.c] === 'none' && s[other(x.c)] === 'none' ? { ...s, [x.c]: 'proposed' } : null;
  const authorized = x.a === 'dana' && !s.delisted;
  if (x.op === 'approve') return s[x.c] === 'proposed' && authorized ? { ...s, [x.c]: 'approved', danaSigned: true } : null;
  if (x.op === 'revoke') return s[x.c] === 'approved' && authorized ? { ...s, [x.c]: 'revoked', danaSigned: true } : null;
  return null;
}

/** What `approvalState` must report for a content in a model state. */
export function predict(s, c) {
  if (s.delisted && s.danaSigned) return 'approval-unverifiable';
  if (s[c] === 'none') return s[other(c)] !== 'none' ? 'wrong-scope' : 'not-recorded';
  if (s[c] === 'approved') return s.expired ? 'expired' : 'approved';
  return s[c];
}

// ---- the implementation -------------------------------------------------------------------------------------------------------
function implStep(I, ledger, x, k, C) {
  const policy = { id: 'model-check', reviewers: k.delisted ? [] : ['dana'] };
  if (x.op === 'delist') return k.delisted ? { ok: false } : { ok: true, ledger, k: { ...k, delisted: true } };
  if (x.op === 'advance') return k.expired ? { ok: false } : { ok: true, ledger, k: { ...k, expired: true } };
  const actor = ACTORS[x.a]; const contract = C[x.c];
  // the implementation is asked to record onto the current ledger under the current policy; it alone decides what to refuse
  const r = x.op === 'propose' ? I.proposeContract(ledger, contract, { actor, reason: 'model check', signer })
    : x.op === 'approve' ? I.approveContract(ledger, contract, { actor, reason: 'model check', policy, signer })
    : I.revokeContract(ledger, contract, { actor, reason: 'model check', policy, signer });
  return r.ok ? { ok: true, ledger: r.ledger, k } : { ok: false, refusedBy: r.errors?.[0]?.code ?? 'refused' };
}
const implState = (I, ledger, k, C, c) => I.approvalState(C[c], ledger, { policy: { id: 'model-check', reviewers: k.delisted ? [] : ['dana'] }, signer, now: k.expired ? NOW.expired : NOW.inside });

/** The safety property, judged from the model state that produced `state`: approved and current needs every authority condition. */
function propertyHolds(s, c, impl) {
  if (impl.state !== 'approved' && impl.current !== true) return true;
  return s[c] === 'approved' && !s.expired && !s.delisted;
}

/** `impl` defaults to the real module; a test passes a deliberately broken one to show the check can fail. */
export function check({ depth = 12, traceDepth = 3, impl = REAL } = {}) {
  const I = impl;
  const C = contents();
  const counterexamples = [];
  // 1. conformance over the reachable abstract graph, one concrete ledger per abstract state
  const seen = new Map(); const queue = [{ s: initial(), ledger: emptyLedger(), k: { delisted: false, expired: false }, trace: [] }];
  seen.set(key(queue[0].s), queue[0]);
  let transitionsTried = 0; let maxDepth = 0;
  while (queue.length) {
    const cur = queue.shift();
    maxDepth = Math.max(maxDepth, cur.trace.length);
    if (cur.trace.length >= depth) continue;
    for (const x of ACTIONS) {
      transitionsTried += 1;
      const next = modelStep(cur.s, x); const im = implStep(I, cur.ledger, x, cur.k, C);
      const trace = [...cur.trace, label(x)];
      if (!!next !== im.ok) { counterexamples.push({ kind: 'enabledness', trace, model: next ? 'allowed' : 'forbidden', implementation: im.ok ? 'allowed' : `refused (${im.refusedBy})` }); continue; }
      if (!next) continue;
      for (const c of ['A', 'B']) {
        const got = implState(I, im.ledger, im.k, C, c); const want = predict(next, c);
        if (got.state !== want) counterexamples.push({ kind: 'state', trace, content: c, model: want, implementation: got.state });
        if (!propertyHolds(next, c, got)) counterexamples.push({ kind: 'property', trace, content: c, implementation: got.state });
      }
      if (!seen.has(key(next))) { const node = { s: next, ledger: im.ledger, k: im.k, trace }; seen.set(key(next), node); queue.push(node); }
    }
  }
  // 2. every sequence to traceDepth, unmerged
  let traces = 0; let steps = 0;
  const walk = (s, ledger, k, trace) => {
    if (trace.length === traceDepth) { traces += 1; return; }
    for (const x of ACTIONS) {
      const next = modelStep(s, x); const im = implStep(I, ledger, x, k, C);
      steps += 1;
      const t = [...trace, label(x)];
      if (!!next !== im.ok) { counterexamples.push({ kind: 'enabledness', trace: t, unmerged: true }); continue; }
      if (!next) { traces += 1; continue; }
      for (const c of ['A', 'B']) { const got = implState(I, im.ledger, im.k, C, c); if (got.state !== predict(next, c) || !propertyHolds(next, c, got)) counterexamples.push({ kind: 'state', trace: t, content: c, unmerged: true, model: predict(next, c), implementation: got.state }); }
      walk(next, im.ledger, im.k, t);
    }
  };
  walk(initial(), emptyLedger(), { delisted: false, expired: false }, []);
  const sha = (f) => `sha256:${createHash('sha256').update(fs.readFileSync(f)).digest('hex')}`;
  return {
    schema: 'agentic-security/model-check-result', subject: 'service-contract approval', result: counterexamples.length ? 'counterexample' : 'no-counterexample-within-bounds',
    bounds: { contracts: 1, contents: 2, actors: Object.keys(ACTORS), actions: ACTIONS.length, depth, traceDepth, reachableAbstractStates: seen.size, deepestStateDepth: maxDepth, conformanceTransitions: transitionsTried, unmergedTraces: traces, unmergedSteps: steps },
    property: 'approved and current only for exactly the content a listed human approved, not revoked, within the review interval, with the reviewer still listed',
    assumptions: [
      'signatures are not modelled (a fixed test signer); tamper resistance is tested elsewhere',
      'one contract id and version with two contents; supersession, rejection and the approver registry are outside the model',
      'the conformance pass merges concrete ledgers by abstract state; the unmerged pass checks that on every sequence up to the trace depth',
      'expiry is modelled as one step past the review interval',
    ],
    implementation: [{ file: 'scanner/src/contracts/approval.js', sha256: sha(APPROVAL), functions: ['proposeContract', 'approveContract', 'revokeContract', 'approvalState'] }, { file: 'scanner/src/posture/invariants/lifecycle.js', sha256: sha(LIFECYCLE), functions: ['recordTransition', 'verifyLedger', 'authorizeReviewer'] }],
    command: `node scripts/model-check/approval.mjs --depth ${depth} --trace-depth ${traceDepth}`,
    counterexamples: counterexamples.slice(0, 20), counterexampleCount: counterexamples.length,
    limits: 'a bounded result for this model only; it proves nothing about the application, the sandbox or inputs outside the bounds',
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const r = check({ depth: flag('depth', 12), traceDepth: flag('trace-depth', 3) });
  if (process.argv.includes('--json')) console.log(JSON.stringify(r, null, 2));
  else {
    console.log(`${r.subject}: ${r.result}`);
    console.log(`  ${r.bounds.reachableAbstractStates} reachable abstract states, ${r.bounds.conformanceTransitions} transitions tried, ${r.bounds.unmergedTraces} unmerged traces to depth ${r.bounds.traceDepth}`);
    for (const c of r.counterexamples) console.log(`  COUNTEREXAMPLE ${c.kind}: ${c.trace.join(' > ')}${c.content ? ` [${c.content}] model=${c.model} implementation=${c.implementation}` : ''}`);
    console.log(`  ${r.limits}`);
  }
  process.exitCode = r.counterexampleCount ? 1 : 0;
}
