// Approval of a service contract through the existing invariant ledger (Epic A-02).
//
// There is one approval authority in this codebase: the hash-chained, HMAC-signed ledger of posture/invariants/lifecycle.js, with
// human reviewers named by the operator's policy or approver registry. A service contract is proposed and approved there as a
// `service-contract` subject, so a forged file, a copied ledger head, a model's statement or an `approved` claim in the document
// can satisfy nothing. The approval binds to the contract's content digest and its version: an edited contract has a new digest and
// the old approval does not apply to it (`wrong-scope`), an expired review policy makes the approval `expired` (still visible), a
// revoked approval stays in the ledger as `revoked`.
//
// `now` is always supplied by the caller: this module never reads the clock, so a state is reproducible from its inputs.
import * as fsp from 'node:fs/promises';
import * as pathMod from 'node:path';
import { recordTransition, verifyLedger, emptyLedger, LEDGER_SCHEMA } from '../posture/invariants/lifecycle.js';
import { contractDigest, contractRef, validateContract, CONTRACT_SCHEMA } from './schema.js';

export const APPROVAL_STATES = Object.freeze(['proposed', 'approved', 'rejected', 'superseded', 'revoked', 'expired', 'wrong-scope', 'not-recorded', 'approval-unverifiable']);

/** The ledger subject id of a contract: the same derivation `recordTransition` uses, so callers never guess it. */
export function contractSubjectId(contract) {
  const d = contractDigest(contract);
  return `${CONTRACT_SCHEMA}#${d.slice('sha256:'.length, 'sha256:'.length + 32)}`;
}

function daysBetween(a, b) { return Math.floor((Date.parse(b) - Date.parse(a)) / 86400000); }

/**
 * The approval state of a contract under a ledger, re-verified against the current reviewer policy.
 * @returns {{ state, current: boolean, contractRef, subjectId, transitionId, reviewer, authority, ledgerHead, reasons: string[] }}
 */
export function approvalState(contract, ledger, { policy = null, registry = null, signer, now } = {}) {
  const base = { contractRef: null, subjectId: null, transitionId: null, reviewer: null, authority: null, ledgerHead: null, reasons: [] };
  const v = validateContract(contract);
  if (!v.ok) return { ...base, state: 'approval-unverifiable', current: false, reasons: ['the contract does not validate: ' + v.errors.map((e) => `${e.path}: ${e.message}`).join('; ')] };
  base.contractRef = contractRef(contract);
  base.subjectId = contractSubjectId(contract);
  if (!ledger) return { ...base, state: 'not-recorded', current: false, reasons: ['no approval ledger was supplied'] };
  const verified = verifyLedger(ledger, { signer, policy, registry });
  if (!verified.ok) return { ...base, state: 'approval-unverifiable', current: false, reasons: verified.errors.map((e) => `${e.code}: ${e.message}`) };
  base.ledgerHead = ledger.records.length ? ledger.records[ledger.records.length - 1].id : null;
  const state = verified.states[base.subjectId];
  if (!state) {
    // Is a different content of the same contract id and version approved? That is the classic forged or stale approval: the
    // document changed after the review. Report it as wrong-scope with both digests so the reviewer sees what moved.
    const other = ledger.records.find((r) => r.action === 'propose' && r.subjectKind === 'service-contract' && r.key === contract.id && r.revision === contract.version);
    if (other) return { ...base, state: 'wrong-scope', current: false, reasons: [`the ledger approves ${contract.id}@${contract.version} with digest ${other.subjectDigest}, not this content (${contractDigest(contract)}); the contract changed after review`] };
    return { ...base, state: 'not-recorded', current: false, reasons: ['this contract content has never been proposed in the ledger'] };
  }
  const last = [...ledger.records].reverse().find((r) => r.invariantId === base.subjectId && r.to === state);
  const out = { ...base, transitionId: last?.id ?? null, reviewer: last?.actor?.id ?? null, authority: last?.policyId ?? null };
  if (state !== 'approved') return { ...out, state, current: false, reasons: [`the ledger's latest transition for this content is '${state}'`] };
  if (typeof now === 'string') {
    const exp = contract.expiry?.expiresAt;
    if (exp && Date.parse(now) > Date.parse(exp)) return { ...out, state: 'expired', current: false, reasons: [`the contract expired on ${exp}; the approval is on record but is no longer current authority`] };
    const age = daysBetween(contract.reviewedAt, now);
    if (Number.isFinite(age) && age > contract.expiry.reviewEveryDays) return { ...out, state: 'expired', current: false, reasons: [`reviewed ${age} days ago, more than the ${contract.expiry.reviewEveryDays} the contract allows between reviews`] };
  } else out.reasons.push('no `now` was supplied, so expiry was not evaluated');
  return { ...out, state: 'approved', current: true };
}

/** Propose a contract into a ledger (creates one when none is given). A proposer may be code or a model; approval may not. */
export function proposeContract(ledger, contract, { actor, reason, signer } = {}) {
  return recordTransition(ledger || emptyLedger(), { action: 'propose', contract, actor, reason }, { signer });
}

export function approveContract(ledger, contract, { actor, reason, policy, registry, signer } = {}) {
  return recordTransition(ledger, { action: 'approve', invariantId: contractSubjectId(contract), actor, reason }, { policy, registry, signer });
}

export function revokeContract(ledger, contract, { actor, reason, policy, registry, signer } = {}) {
  return recordTransition(ledger, { action: 'revoke', invariantId: contractSubjectId(contract), actor, reason }, { policy, registry, signer });
}

export { LEDGER_SCHEMA };

// ---- ledger persistence (E-04: the harness under interruption) -----------------------------------------------------------------
// The ledger is plain data the caller persists. These two helpers make that persistence recoverable: a write goes to a sibling temp file
// and is renamed into place (an interrupted write leaves the previous ledger intact and the temp file behind, which a read ignores), a
// link is refused, and a read that does not parse is `corrupt`, never an empty ledger: a corrupted checkpoint can never come back as
// "no approvals yet, start over" and never as approval.

export async function writeLedgerFile(file, ledger) {
  const target = pathMod.resolve(file);
  try { const st = await fsp.lstat(target); if (st.isSymbolicLink()) return { ok: false, reason: 'the ledger path is a link; refused' }; } catch { /* new file */ }
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  await fsp.writeFile(tmp, JSON.stringify(ledger, null, 1) + '\n', { flag: 'wx' });
  await fsp.rename(tmp, target);
  return { ok: true, file: target };
}

export async function readLedgerFile(file) {
  let text;
  try { text = await fsp.readFile(pathMod.resolve(file), 'utf8'); } catch (e) { return { ok: false, state: 'missing', reason: e.code || 'unreadable' }; }
  try {
    const ledger = JSON.parse(text);
    if (!ledger || ledger.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.records)) return { ok: false, state: 'corrupt', reason: 'not an approval ledger' };
    return { ok: true, ledger };
  } catch { return { ok: false, state: 'corrupt', reason: 'the ledger does not parse; it is not treated as empty' }; }
}
