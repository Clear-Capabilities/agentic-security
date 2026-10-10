// Inferred versus approved invariants (X-402).
//
// A contract proposed by a model, or inferred from code by specification mining, is a HYPOTHESIS about what the product
// should do. It enters the ledger as `proposed`, with its source evidence and an uncertainty, and stays advisory: it can be run
// as a scenario and its violations are reported as CANDIDATE violations, but it can never gate and it can never be the ground
// truth that a verdict is measured against. Only a reviewer's approval changes that, and the approval is a record, not a flag:
//
//   - the ledger is append-only and hash-chained (`prev`), and every record carries an HMAC signature under the per-install key
//     (`integrity.js`, the same key handling the scan and attestation signatures use), so editing, reordering or forging a
//     transition is detectable. Tamper-evidence for the operator, NOT third-party non-repudiation (the key is symmetric);
//   - an approval must come from a HUMAN reviewer who is authorized by an explicit local policy (a reviewer list) or by the
//     operator's approver registry (`fix/approver-registry.js`). A model, code or the proposer acting as a model cannot approve,
//     and with no policy and no registry nothing can be approved: the default is closed;
//   - the approval binds to the invariant ID, which is a hash of the contract content, so changing a contract after approval is
//     a different contract that must be reviewed again (a revision supersedes, it does not edit);
//   - the transitions are fixed (propose, approve, reject, supersede) and each is recorded with who, why, from and to.
//
// "Who is the reviewer" is a claim made by the caller, as it is in the approver registry: the policy lists identities the
// operator chose to trust, it does not authenticate anyone. What the signature adds is that the claim cannot be rewritten later
// without the key. Persistence is the caller's (the ledger is plain data), as with the repair-record ledger.
import * as crypto from 'node:crypto';
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isPlainObject } from '../assurance/schema-kit.js';
import { signLastScan } from '../integrity.js';
import { verifyApprover } from '../../fix/approver-registry.js';
import { isIssuedReceipt } from '../oracles/oracle.js';
import { createInvariant, validateInvariant, INVARIANT_CLASSES, BUSINESS_STATE_ORACLE } from './schema.js';

export const LEDGER_SCHEMA = 'agentic-security/invariant-ledger';
const TRANSITION_SCHEMA = 'agentic-security/invariant-transition';
export const ACTIONS = Object.freeze(['propose', 'approve', 'reject', 'supersede']);
const TRANSITION_ID_FIELDS = ['seq', 'invariantId', 'key', 'revision', 'action', 'from', 'to', 'actor', 'reason', 'supersededBy', 'prev'];
const SIGNED_FIELDS = [...TRANSITION_ID_FIELDS, 'id', 'schema', 'schemaVersion', 'policyId', 'origin', 'authorKind', 'uncertainty', 'sourcesDigest'];
const MAX_REASON = 400;

// Which transitions exist: action -> { from states allowed, resulting state }. Anything else is refused.
const MACHINE = Object.freeze({
  propose: { from: [null], to: 'proposed' },
  approve: { from: ['proposed'], to: 'approved' },
  reject: { from: ['proposed'], to: 'rejected' },
  supersede: { from: ['proposed', 'approved'], to: 'superseded' },
});

/** The default signer: the per-install HMAC key. A test or an embedding tool may inject another `{ sign, verify }`. */
const defaultSigner = Object.freeze({
  sign: (body) => signLastScan(body),
  verify: (body, sig) => {
    try {
      const want = Buffer.from(signLastScan(body), 'hex');
      const have = Buffer.from(String(sig), 'hex');
      return want.length === have.length && crypto.timingSafeEqual(want, have);
    } catch { return false; }
  },
});

export function emptyLedger() { return { schema: LEDGER_SCHEMA, schemaVersion: SCHEMA_VERSION, records: [] }; }

const bodyOf = (rec) => { const o = {}; for (const f of SIGNED_FIELDS) o[f] = rec[f] === undefined ? null : rec[f]; return JSON.stringify(sortKeys(o)); };
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

const err = (code, message) => ({ code, message });

/**
 * Who may approve. A reviewer is a HUMAN named by the local policy's reviewer list or verified by the approver registry. Nothing
 * else is an authority: no model, no code, no verifier, and no policy at all means no approval.
 */
export function authorizeReviewer(actor, { policy = null, registry = null } = {}) {
  if (!isPlainObject(actor) || typeof actor.id !== 'string' || !actor.id.trim()) return { ok: false, code: 'anonymous-reviewer', reason: 'an approval names its reviewer' };
  if (actor.kind !== 'human') return { ok: false, code: 'not-a-human-reviewer', reason: `a ${String(actor.kind).slice(0, 20)} cannot approve a contract: model-generated or code-derived contracts do not establish their own ground truth` };
  const listed = isPlainObject(policy) && Array.isArray(policy.reviewers) && policy.reviewers.includes(actor.id);
  const policyConfigured = isPlainObject(policy) && Array.isArray(policy.reviewers) && policy.reviewers.length > 0;
  if (!policyConfigured && !registry) return { ok: false, code: 'no-authorized-policy', reason: 'no local reviewer policy and no approver registry is configured, so nothing can be approved' };
  if (policyConfigured && listed) return { ok: true, authority: `policy:${typeof policy.id === 'string' ? policy.id : 'local'}` };
  if (registry) {
    const v = verifyApprover(registry, actor.id, isPlainObject(policy) && Array.isArray(policy.requiredRoles) ? policy.requiredRoles : []);
    if (v.verified) return { ok: true, authority: 'approver-registry' };
    return { ok: false, code: 'unauthorized-reviewer', reason: v.reason };
  }
  return { ok: false, code: 'unauthorized-reviewer', reason: `'${actor.id.slice(0, 60)}' is not an authorized reviewer under the local policy` };
}

function statesOf(records) {
  const states = new Map();
  const meta = new Map();
  for (const r of records) {
    states.set(r.invariantId, r.to);
    if (r.action === 'propose') meta.set(r.invariantId, { key: r.key, revision: r.revision });
  }
  return { states, meta };
}

/**
 * Append one transition. Never throws; returns a NEW ledger and leaves the input untouched.
 *
 * @param {object} ledger
 * @param {object} req  { action, invariant (propose) | invariantId (others), actor: { id, kind }, reason, supersededBy? }
 * @param {object} [o]  { policy, registry, signer }
 * @returns {{ ok: boolean, ledger: object, record: object|null, errors: Array<{code, message}> }}
 */
export function recordTransition(ledger, req, o = {}) {
  const fail = (...errors) => ({ ok: false, ledger, record: null, errors });
  const signer = o.signer || defaultSigner;
  if (!isPlainObject(ledger) || ledger.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.records)) return fail(err('bad-ledger', 'not an invariant ledger'));
  if (!isPlainObject(req) || !ACTIONS.includes(req.action)) return fail(err('unknown-action', `action must be one of ${ACTIONS.join(', ')}`));
  const actor = isPlainObject(req.actor) && typeof req.actor.id === 'string' && req.actor.id.trim() ? { id: req.actor.id.trim().slice(0, 120), kind: req.actor.kind } : null;
  if (!actor || !['human', 'model', 'code'].includes(actor.kind)) return fail(err('bad-actor', 'the actor needs an id and a kind of human, model or code'));
  const reason = typeof req.reason === 'string' ? req.reason.trim().slice(0, MAX_REASON) : '';
  if (!reason) return fail(err('reason-required', 'every transition records its reason'));

  const { states, meta } = statesOf(ledger.records);
  let invariantId; let key; let revision;
  if (req.action === 'propose') {
    const v = validateInvariant(req.invariant);
    if (!v.ok) return fail(...v.errors.map((e) => err('invalid-invariant', `${e.path}: ${e.message}`)));
    const inv = req.invariant;
    if (inv.review.state !== 'proposed') return fail(err('proposal-must-be-proposed', 'a contract enters the ledger as proposed; approval is a separate recorded transition'));
    if (states.has(inv.id)) return fail(err('already-recorded', `'${inv.id}' is already in the ledger`));
    for (const [id, m] of meta) if (m.key === inv.key && m.revision === inv.revision && id !== inv.id) return fail(err('ambiguous-revision', `'${inv.key}' revision ${inv.revision} already names a different contract (${id})`));
    invariantId = inv.id; key = inv.key; revision = inv.revision;
  } else {
    invariantId = req.invariantId;
    if (typeof invariantId !== 'string' || !states.has(invariantId)) return fail(err('unknown-invariant', 'the invariant is not in the ledger'));
    ({ key, revision } = meta.get(invariantId));
  }
  const from = states.has(invariantId) ? states.get(invariantId) : null;
  const rule = MACHINE[req.action];
  if (!rule.from.includes(from)) return fail(err('illegal-transition', `cannot ${req.action} a contract that is ${from === null ? 'not recorded' : from}`));

  let authority = 'proposer';
  if (req.action === 'approve' || req.action === 'reject' || req.action === 'supersede') {
    const a = authorizeReviewer(actor, { policy: o.policy, registry: o.registry });
    if (!a.ok) return fail(err(a.code, a.reason));
    authority = a.authority;
  }
  let supersededBy = null;
  if (req.action === 'supersede') {
    supersededBy = req.supersededBy;
    const sm = typeof supersededBy === 'string' ? meta.get(supersededBy) : null;
    if (!sm || sm.key !== key || !(sm.revision > revision) || !['proposed', 'approved'].includes(states.get(supersededBy))) {
      return fail(err('bad-supersession', 'a contract is superseded by a later revision of the same key that is itself proposed or approved'));
    }
  }

  const prev = ledger.records.length ? ledger.records[ledger.records.length - 1].id : null;
  const rec = {
    schema: TRANSITION_SCHEMA, schemaVersion: SCHEMA_VERSION, seq: ledger.records.length + 1, invariantId, key, revision,
    action: req.action, from, to: rule.to, actor, reason, supersededBy, prev,
    policyId: authority,
  };
  if (req.action === 'propose') {
    rec.origin = req.invariant.review.origin;
    rec.authorKind = req.invariant.author.kind;
    rec.uncertainty = req.invariant.review.uncertainty ?? null;
    rec.sourcesDigest = digestOf(req.invariant.review.sources ?? []);
  }
  rec.id = semanticId('itrn', rec, TRANSITION_ID_FIELDS);
  rec.signature = signer.sign(bodyOf(rec));
  return { ok: true, ledger: { ...ledger, records: [...ledger.records, rec] }, record: rec, errors: [] };
}

/**
 * Verify a whole ledger: contiguous sequence, unbroken hash chain, every id and signature, every transition legal from the state
 * the earlier records left, and every approval made by a human. Returns the state of each contract that survives verification.
 */
export function verifyLedger(ledger, { signer = defaultSigner } = {}) {
  const errors = [];
  if (!isPlainObject(ledger) || ledger.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.records)) return { ok: false, errors: [err('bad-ledger', 'not an invariant ledger')], states: {} };
  const states = new Map();
  let prev = null;
  ledger.records.forEach((r, i) => {
    const at = `records[${i}]`;
    if (!isPlainObject(r) || r.schema !== TRANSITION_SCHEMA) { errors.push(err('bad-record', `${at}: not a transition record`)); return; }
    if (r.seq !== i + 1) errors.push(err('sequence-broken', `${at}: expected seq ${i + 1}, found ${r.seq}`));
    if (r.prev !== prev) errors.push(err('chain-broken', `${at}: prev does not match the preceding record`));
    if (r.id !== semanticId('itrn', r, TRANSITION_ID_FIELDS)) errors.push(err('id-mismatch', `${at}: the record id does not match its content`));
    if (typeof r.signature !== 'string' || !signer.verify(bodyOf(r), r.signature)) errors.push(err('bad-signature', `${at}: the signature does not verify under the install key`));
    const rule = MACHINE[r.action];
    const from = states.has(r.invariantId) ? states.get(r.invariantId) : null;
    if (!rule || r.from !== from || !rule.from.includes(from) || r.to !== rule.to) errors.push(err('illegal-transition', `${at}: ${String(r.action)} from ${String(r.from)} to ${String(r.to)} is not a legal transition here`));
    if ((r.action === 'approve' || r.action === 'reject' || r.action === 'supersede') && r.actor?.kind !== 'human') errors.push(err('not-a-human-reviewer', `${at}: a ${String(r.actor?.kind)} recorded a reviewer decision`));
    states.set(r.invariantId, r.to);
    prev = r.id;
  });
  return { ok: errors.length === 0, errors, states: Object.fromEntries(states) };
}

/** True only when the ledger verifies AND the contract's latest recorded state is `approved`. A document that merely says approved is not. */
export function isAuthoritative(ledger, invariantId, o = {}) {
  const v = verifyLedger(ledger, o);
  return v.ok && v.states[invariantId] === 'approved';
}

/**
 * Classify what a scenario run says about one invariant. Only an executed, confirmed result with a receipt the oracle runner
 * issued counts as a violation at all; whether it is a violation of an APPROVED contract (eligible to gate) or a CANDIDATE
 * violation (advisory) depends solely on the verified ledger.
 * @returns {{ kind: 'approved-violation'|'candidate-violation'|'no-violation-observed'|'unverified', gating: boolean, reason: string }}
 */
export function classifyViolation({ invariant, ledger, run, signer = defaultSigner }) {
  const id = invariant?.id;
  if (!run || !['confirmed', 'refuted'].includes(run.outcome)) {
    return { kind: 'unverified', gating: false, reason: `the scenario did not settle (${run?.outcome ?? 'not run'}), so it says nothing about the contract` };
  }
  if (!isIssuedReceipt(run.receipt)) return { kind: 'unverified', gating: false, reason: 'no receipt issued by the verifier backs this result' };
  if (run.outcome === 'refuted') return { kind: 'no-violation-observed', gating: false, reason: 'the bounded scenario found no violation; that is not proof the contract holds elsewhere' };
  const verified = verifyLedger(ledger, { signer });
  const state = verified.ok ? verified.states[id] : undefined;
  if (state === 'approved') return { kind: 'approved-violation', gating: true, reason: 'a reviewer-approved contract was violated in an executed scenario' };
  const why = !verified.ok ? 'the approval ledger does not verify' : state ? `the contract is ${state}` : 'the contract is not in the ledger';
  const claimed = invariant?.review?.state === 'approved' ? ' (the document claims approval; only the signed ledger counts)' : '';
  return { kind: 'candidate-violation', gating: false, reason: `${why}, so this is an advisory candidate violation, not a violation of an approved requirement${claimed}` };
}

/** Split classified runs into the two groups a report shows separately. Candidate violations never appear under approved ones. */
export function violationReport(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const pick = (k) => list.filter((e) => e.classification?.kind === k);
  return {
    approvedViolations: pick('approved-violation'), candidateViolations: pick('candidate-violation'),
    noViolationObserved: pick('no-violation-observed'), unverified: pick('unverified'),
    gating: pick('approved-violation').length > 0,
    note: 'only violations of reviewer-approved contracts can gate; candidate violations are advisory and a model-generated contract is never its own ground truth',
  };
}

// ---------------------------------------------------------------- proposals

const TEMPLATES = Object.freeze({
  'tenant-isolation': (a) => ({
    resources: [{ id: 'res-a', kind: 'record', tenant: 'tenant-a', key: 'records/a-1' }, { id: 'res-b', kind: 'record', tenant: 'tenant-b', key: 'records/b-1' }],
    transitions: [{ id: 'own-update', action: a.action, actors: ['user-a'], resource: 'res-a' }],
    forbidden: [{ id: 'no-cross-tenant-write', op: 'cross-tenant-write', prefix: 'records/', bind: BUSINESS_STATE_ORACLE }],
  }),
  'privilege-constraint': (a) => ({
    resources: [{ id: 'res-a', kind: 'setting', tenant: 'tenant-a', key: 'settings/a-1' }],
    transitions: [{ id: 'admin-change', action: a.action, actors: ['admin-a'], resource: 'res-a' }],
    forbidden: [{ id: 'no-unprivileged-change', op: 'unauthorized-role-change', actions: [a.action], allowedRoles: ['admin'], bind: BUSINESS_STATE_ORACLE }],
  }),
  'workflow-order': (a) => ({
    resources: [{ id: 'res-a', kind: 'order', tenant: 'tenant-a', key: 'orders/a-1' }],
    transitions: [{ id: 'advance', action: a.action, actors: ['user-a'], resource: 'res-a' }],
    forbidden: [{ id: 'no-skipped-step', op: 'transition-outside', prefix: 'orders/', field: 'status', allowed: a.allowed || [{ from: 'new', to: 'paid' }, { from: 'paid', to: 'shipped' }], bind: BUSINESS_STATE_ORACLE }],
  }),
});

const ACTORS = Object.freeze({
  'tenant-isolation': [{ id: 'user-a', tenant: 'tenant-a', role: 'member' }, { id: 'user-b', tenant: 'tenant-b', role: 'member' }],
  'privilege-constraint': [{ id: 'admin-a', tenant: 'tenant-a', role: 'admin' }, { id: 'member-a', tenant: 'tenant-a', role: 'member' }],
  'workflow-order': [{ id: 'user-a', tenant: 'tenant-a', role: 'member' }],
});

/**
 * Build an INFERRED invariant proposal from a miner's observation: a skeleton contract with synthetic tenants and actors, the
 * evidence that suggested it, and an explicit uncertainty. The result is `proposed`, authored by a model or by code, and not yet in
 * any ledger. It is a starting point for a reviewer to revise (the application scope, the factory and the exact resources are
 * guesses), never a requirement. `null` for a class this build has no skeleton for.
 *
 * @param {object} p
 * @param {string} p.class        one of INVARIANT_CLASSES (idempotency has no skeleton: a duplicate-effect contract needs an event name only a reviewer knows)
 * @param {string} p.source       'specification-mining' | 'discovery-lens' | 'logic-claim' | 'state-machine'
 * @param {object} p.evidence     what suggested it ({ file, line, ... }); must be present
 * @param {number} p.uncertainty  0..1
 * @param {string} p.action       the application action the contract concerns (an identifier)
 * @param {string} p.application  application slug (defaults to the entry file's stem)
 */
export function inferredInvariant(p) {
  if (!INVARIANT_CLASSES.includes(p?.class) || !TEMPLATES[p.class] || !isPlainObject(p.evidence) || typeof p.evidence.file !== 'string') return null;
  const kind = p.source === 'discovery-lens' || p.source === 'logic-claim' ? 'model' : 'code';
  const action = typeof p.action === 'string' && /^[A-Za-z_$][\w$]{0,63}$/.test(p.action) ? p.action : 'updateRecord';
  const stem = p.evidence.file.split('/').pop().replace(/\.[^.]+$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const application = typeof p.application === 'string' && /^[a-z][a-z0-9-]{1,63}$/.test(p.application) ? p.application : (/^[a-z]/.test(stem) && stem.length > 1 ? stem.slice(0, 60) : `app-${stem || 'unknown'}`);
  const parts = TEMPLATES[p.class]({ action, allowed: p.allowed });
  const tenants = [{ id: 'tenant-a' }, { id: 'tenant-b' }];
  const inv = createInvariant({
    key: `${application}-${p.class}-${action.toLowerCase()}`.slice(0, 63), revision: 1,
    name: `${p.class} for ${action} (inferred from ${p.source})`,
    class: p.class,
    scope: { application, entry: p.evidence.file.replace(/^\/+/, '').slice(0, 120), factory: 'createApp', environment: 'disposable-fixture' },
    actors: ACTORS[p.class], tenants, ...parts,
    oracle: { adapter: BUSINESS_STATE_ORACLE, version: '1' },
    author: { id: `${p.source}:miner`, kind },
    review: { state: 'proposed', origin: 'inferred', sources: [{ source: p.source, ...p.evidence }], uncertainty: Math.min(1, Math.max(0, Number(p.uncertainty) || 0.8)) },
  });
  return validateInvariant(inv).ok ? inv : null;
}
