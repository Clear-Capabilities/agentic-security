// Promoting a patch on independent verifier receipts (X-204.AC03).
//
// A patch may be PROMOTED (made eligible to be applied) only after the verifier domain has issued receipts for the exact
// diff it is being asked to promote, at the exact revision it was proposed against:
//
//   original            the original files reproduce the exploit          -> confirmed
//   patched             original files with the proposed diff applied     -> refuted
//   functionalBaseline  the functional expectations on the original files -> refuted (no regression)
//   functional          the same expectations on the patched files        -> refuted (no regression)
//
// Every receipt is checked against the PROPOSAL, not against itself: the digest of the files a receipt covers must equal the
// digest this module recomputes from the proposed diff, and the commit it was issued for must be the proposal's revision. A
// receipt for a different diff, a different revision or a different hypothesis does not promote, and neither does a receipt
// the verifier did not issue (a copy, a hand-built object, a receipt whose content was edited: `isIssuedReceipt` is true only
// for the frozen object `runOracle` itself created).
//
// What this proves and what it does not: the receipts are unsigned objects valid inside the verifier's own process. A receipt
// that crossed a process boundary (JSON) is no longer an issued receipt and cannot promote; carrying promotion across
// processes needs a signing domain, which belongs to the signer, not to this module. Receipts show that the declared scenario
// and the declared functional cases behaved as stated; they do not show the patch is correct beyond them.
import { digestOf } from '../assurance/identity.js';
import { isCommit, isPlainObject } from '../assurance/schema-kit.js';
import { isIssuedReceipt } from '../oracles/oracle.js';

const PROMOTION_ROLES = Object.freeze(['original', 'patched', 'functionalBaseline', 'functional']);
// The oracle class the behaviour-preservation runs must come from. Default `functional-regression`; a proposal may name
// `business-state` (X-406: an authorized-workflow scenario as the declared case). Nothing else is accepted.
const FUNCTIONAL_CLASSES = Object.freeze({ 'functional-regression': 'functional-regression', 'business-state': 'business-state' });

const ISSUED_PROMOTIONS = new WeakSet();

/** True only for a result `promotePatch` itself returned with `ok: true`. A copy or a hand-built object is not. */
export function isIssuedPromotion(p) { return isPlainObject(p) && ISSUED_PROMOTIONS.has(p); }

// What each receipt role must have settled to.
const EXPECTED_OUTCOME = Object.freeze({ original: 'confirmed', patched: 'refuted', functionalBaseline: 'refuted', functional: 'refuted' });

const same = (a, b) => digestOf(a ?? null) === digestOf(b ?? null);

/**
 * @param {object} args
 * @param {object} args.proposal  { hypothesisId, revision, originalFiles, patchFiles, functionalOracle? }
 * @param {object} args.receipts  { original, patched, functionalBaseline, functional }, each issued by runOracle
 * @returns {{ ok: boolean, diffDigest: string|null, revision: string|null, reasons: {code,role,message}[], receiptDigests: object }}
 */
export function promotePatch({ proposal, receipts } = {}) {
  const reasons = [];
  const why = (code, role, message) => reasons.push({ code, role, message });
  const out = (extra = {}) => {
    const result = { ok: reasons.length === 0, diffDigest: null, revision: null, hypothesisId: null, reasons, receiptDigests: {}, ...extra };
    result.ok = reasons.length === 0;
    if (result.ok) ISSUED_PROMOTIONS.add(result);
    return result;
  };

  if (!isPlainObject(proposal) || typeof proposal.hypothesisId !== 'string' || !proposal.hypothesisId
    || !isPlainObject(proposal.originalFiles) || !isPlainObject(proposal.patchFiles) || Object.keys(proposal.patchFiles).length === 0) {
    why('bad-proposal', null, 'a proposal needs a hypothesis id, the original files and a non-empty diff');
    return out();
  }
  if (!isCommit(proposal.revision)) {
    why('revision-unbound', null, 'a promotion is bound to one exact 40 or 64 character commit; none was given');
    return out();
  }
  const functionalClass = proposal.functionalOracle === undefined ? 'functional-regression' : FUNCTIONAL_CLASSES[proposal.functionalOracle];
  if (!functionalClass) {
    why('bad-proposal', null, 'the functional check oracle must be functional-regression or business-state');
    return out();
  }
  const diffDigest = digestOf(proposal.patchFiles);
  const originalDigest = digestOf(proposal.originalFiles);
  const patchedDigest = digestOf({ ...proposal.originalFiles, ...proposal.patchFiles });
  const wantFiles = { original: originalDigest, functionalBaseline: originalDigest, patched: patchedDigest, functional: patchedDigest };
  const base = { diffDigest, revision: proposal.revision, hypothesisId: proposal.hypothesisId };

  const given = isPlainObject(receipts) ? receipts : {};
  const digests = {};
  for (const role of PROMOTION_ROLES) {
    const r = given[role];
    if (!r) { why('receipt-missing', role, `no ${role} receipt was supplied`); continue; }
    if (!isIssuedReceipt(r) || r.issuedBy !== 'verifier' || r.schema !== 'agentic-security/oracle-receipt') {
      why('receipt-not-issued', role, `the ${role} receipt was not issued by the verifier domain (a copy or constructed receipt is not valid)`);
      continue;
    }
    digests[role] = r.receiptDigest;
    if (r.request.hypothesisId !== proposal.hypothesisId) why('receipt-hypothesis', role, `the ${role} receipt is for a different hypothesis`);
    if (r.request.commit !== proposal.revision) why('receipt-revision', role, `the ${role} receipt was issued for a different revision than the proposal`);
    if (r.request.filesDigest !== wantFiles[role]) why('receipt-diff', role, `the ${role} receipt covers different content than the exact proposed diff on the original revision`);
    if (r.settled.outcome !== EXPECTED_OUTCOME[role]) why('receipt-outcome', role, `the ${role} receipt settled '${r.settled.outcome}', not '${EXPECTED_OUTCOME[role]}'`);
    if (role !== 'original' && r.settled.outcome === 'refuted' && r.settled.preconditionsHeld !== true) why('receipt-preconditions', role, `the ${role} receipt did not prove its preconditions`);
  }
  if (reasons.length) return out({ ...base, receiptDigests: digests });

  const { original, patched, functionalBaseline, functional } = given;
  // the exploit oracle is the SAME oracle on the SAME inputs for both revisions
  if (!same(original.oracle, patched.oracle) || original.request.inputsDigest !== patched.request.inputsDigest || original.request.entry !== patched.request.entry) {
    why('oracle-changed', 'patched', 'the patched-negative run did not use the same oracle, entry and inputs as the original-positive run');
  }
  // the functional check is one oracle on one set of inputs for both revisions
  if (!same(functionalBaseline.oracle, functional.oracle) || functionalBaseline.request.inputsDigest !== functional.request.inputsDigest) {
    why('oracle-changed', 'functional', 'the functional check on the patched revision did not use the same oracle and cases as its baseline');
  }
  if (functional.oracle.class !== functionalClass) why('oracle-changed', 'functional', `the functional check is not a ${functionalClass} oracle`);
  if (original.oracle.class === 'functional-regression') why('oracle-changed', 'original', 'the exploit oracle must not be the functional-regression oracle');
  // equivalent disposable environments: one sanitized environment identity across every run
  const envDigest = digestOf(original.environment);
  for (const role of PROMOTION_ROLES) {
    if (digestOf(given[role].environment) !== envDigest) why('environment-mismatch', role, `the ${role} run executed in a different environment than the original run`);
  }
  // four runs are four distinct receipts: one receipt cannot be presented in two roles
  if (new Set(Object.values(digests)).size !== PROMOTION_ROLES.length) why('receipt-reused', null, 'the same receipt was presented in more than one role');
  return out({ ...base, receiptDigests: digests });
}
