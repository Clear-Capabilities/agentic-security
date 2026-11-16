// The repair lab (verified-remediation PRD FR-05, FR-06): one obligation, one exact file set, executed through the oracle runner and
// therefore through the trust boundary only (network denied, process tree ended, harness digest-checked, verdict formed verifier-side).
//
// This module adds no execution path of its own. It builds the oracle request from the contract's obligation, binds the request to the
// exact tree being judged (the digest of the file set stands in for a commit, so `confirmed`/`refuted` are reachable for an uncommitted
// candidate), and then checks the receipt it got back: issued in this process by the oracle runner (a copied or deserialized receipt is not),
// for these files, these inputs and the oracle logic the contract pinned. A mismatch is `invalid`, never a pass (AC-06.5).
import { runOracle, isIssuedReceipt } from '../posture/oracles/oracle.js';
import { digestOf } from '../posture/assurance/identity.js';

export const OUTCOME_TO_STATUS = Object.freeze({ confirmed: 'confirmed', refuted: 'refuted', inconclusive: 'inconclusive', unsupported: 'unavailable', 'not-run': 'unavailable', error: 'error' });

/** The 64-hex binding of a file set, used where the oracle asks for an exact commit. */
export const treeBinding = (files) => digestOf(files).slice('sha256:'.length);

/**
 * @param {object} obligation  a contract obligation with an oracle (not `project-tests`)
 * @param {Record<string,string>} files  the application files, original or patched
 * @param {{config:object, signal?:AbortSignal, entry:string, hypothesisId:string, inputs?:object, deps?:object, probeEnv?:object, runOracle?:Function}} o  (`runOracle` is a test seam: a stand-in cannot issue a receipt this module accepts)
 * @returns {Promise<{observed:'confirmed'|'refuted'|'inconclusive'|'unavailable'|'error'|'invalid', reason:string, receipt:object|null, details:object|null, filesDigest:string, inputsDigest:string}>}
 */
export async function runObligation(obligation, files, o) {
  const inputs = o.inputs || obligation.inputs;
  const filesDigest = digestOf(files);
  const inputsDigest = digestOf(inputs);
  const res = await (o.runOracle || runOracle)({
    oracleId: obligation.oracleId, hypothesisId: o.hypothesisId, commit: treeBinding(files), files, entry: o.entry, inputs,
  }, { config: o.config, signal: o.signal, ...(o.deps ? { deps: o.deps } : {}), ...(o.probeEnv ? { probeEnv: o.probeEnv } : {}) });
  if (res.status === 'rejected') return { observed: 'invalid', reason: `the oracle refused the request: ${(res.errors || []).join('; ').slice(0, 300)}`, receipt: null, details: null, filesDigest, inputsDigest };
  const base = { filesDigest, inputsDigest, receipt: res.receipt || null };
  if (!res.receipt) return { ...base, observed: res.status === 'cancelled' ? 'cancelled' : (OUTCOME_TO_STATUS[res.outcome] || 'error'), reason: res.reason, details: null };
  const r = res.receipt;
  const bindingProblems = [];
  if (!isIssuedReceipt(r)) bindingProblems.push('the receipt was not issued by the oracle runner in this process');
  if (r.request.filesDigest !== filesDigest) bindingProblems.push('the receipt is for different files');
  if (r.request.inputsDigest !== inputsDigest) bindingProblems.push('the receipt is for different inputs');
  if (r.oracle.logicDigest !== obligation.oracleLogicDigest) bindingProblems.push('the oracle logic differs from the logic the contract pinned (re-plan the contract)');
  if (bindingProblems.length) return { ...base, observed: 'invalid', reason: bindingProblems.join('; '), details: null };
  return { ...base, observed: OUTCOME_TO_STATUS[r.settled.outcome] || 'error', reason: res.reason, details: r.observed || null };
}

/** Did an observed outcome meet the obligation's expectation for this revision? passed | failed | inconclusive | unavailable | invalid | cancelled */
export function judge(observed, expectation) {
  if (['unavailable', 'invalid', 'error', 'cancelled'].includes(observed)) return observed === 'error' ? 'inconclusive' : observed;
  if (observed === 'inconclusive') return 'inconclusive';
  return observed === expectation ? 'passed' : 'failed';
}
