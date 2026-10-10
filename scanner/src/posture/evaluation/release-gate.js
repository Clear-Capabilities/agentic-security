// Release evaluation gates, signed by the custodian, with a sealed-population ledger (QA-007).
//
// gates.js decides each gate; this module turns those decisions into a RELEASE verdict that a person can rely on and a tampering
// person cannot quietly improve:
//
//   1. The verdict is an aggregate. The custodian signs `{ overall, gates, population }` and nothing per-case: a development
//      worker iterating on a detector sees the aggregate gate states, never which sealed case failed.
//   2. It is a verdict about ONE detector revision. Every sealed evaluation is appended to a hash-chained ledger together with a
//      digest of the detector source it was run against and the sealed targets it consumed. A detector edit after that evaluation
//      means the sealed population has been seen by the people who made the edit, so a new release accuracy claim needs a FRESH
//      sealed population (`assessReleaseClaim`). The old result stays in the ledger as an evaluation-only artifact: retained,
//      never deleted, never usable for a new claim.
//   3. Insufficient data is `blocked`, never a pass on a smaller sample. gates.js already refuses to pass a short or synthetic
//      population; here a non-pass verdict also blocks the claim, whatever the reason.
//   4. A lower-quality engine, a failed-target spike, a changed denominator, an answer-key leak, a threshold weakened after
//      freezing, and a baseline edited downward each produce a failing or rejected verdict (gates.js plus `verifyLedger`).
//
// Trust: the signature is Ed25519 over the canonical bytes with a custodian key the caller supplies. It is a SELF-ISSUED local
// signature (trustBasis `self-issued-local-key`, `independentlyCertified: false`), tamper evidence for whoever holds the public
// key, not independent certification. Verifying needs only the public key.
//
// Pure apart from `detectorDigestOf` (reads a source tree) and the key handling the caller does. No clock: ordering is the chain.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { canonicalJson } from '../evidence-bundle.js';
import { digestOf } from '../assurance/identity.js';
import { STATE_DIR_NAME } from '../state-dir.js';
import { evaluateGates } from './gates.js';

const GATE_REPORT_SCHEMA = 'agentic-security/evaluation-release-gate';
const LEDGER_SCHEMA = 'agentic-security/sealed-evaluation-ledger';
const TRUST_BASIS = 'self-issued-local-key';

// ---------------------------------------------------------------- detector identity

const DETECTOR_SKIP_DIRS = new Set(['node_modules', '.git', STATE_DIR_NAME, 'vendor', 'dist']);

/**
 * Digest of the detector source: every file under `srcRoot` EXCEPT the evaluation tooling itself (editing the measuring instrument
 * is not editing the detector, and it is covered by the protocol hash). Paths are hashed relative and sorted, so the digest
 * depends on content and layout only.
 */
export function detectorDigestOf(srcRoot, { exclude = ['posture/evaluation'] } = {}) {
  const h = crypto.createHash('sha256');
  const skip = exclude.map((e) => e.replace(/\\/g, '/'));
  const walk = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (skip.includes(r)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!DETECTOR_SKIP_DIRS.has(e.name)) walk(full, r); continue; }
      if (!e.isFile()) continue;
      h.update(`F:${r}\n`); h.update(fs.readFileSync(full));
    }
  };
  walk(srcRoot, '');
  return `sha256:${h.digest('hex')}`;
}

// ---------------------------------------------------------------- the ledger

const entryHashOf = (e) => digestOf({ kind: 'sealed-ledger-entry', e: { ...e, entryHash: undefined } });

export const emptyLedger = () => ({ schema: LEDGER_SCHEMA, entries: [] });

/**
 * Append one sealed evaluation. Returns a NEW ledger; the input is not modified. An entry records the detector digest, the sealed
 * targets consumed and the aggregate outcome, and chains to the previous entry by hash.
 */
export function appendSealedEvaluation(ledger, { protocolHash, detectorDigest, sealedTargetIds, overall, gateStatuses = {}, score = null, label = null }) {
  if (!detectorDigest) throw new Error('a sealed evaluation is recorded against a detector digest');
  const prev = ledger.entries.length ? ledger.entries[ledger.entries.length - 1].entryHash : null;
  const entry = {
    sequence: ledger.entries.length, prev, protocolHash, detectorDigest,
    sealedTargetIds: [...sealedTargetIds].sort(), overall, gateStatuses,
    // The aggregate only: this is what a later no-regression comparison reads. Per-case outcomes are never stored here.
    baseline: score ? { endToEnd: { micro: { f1: score.endToEnd?.micro?.f1 ?? null, precision: score.endToEnd?.micro?.precision ?? null, recall: score.endToEnd?.micro?.recall ?? null }, byLanguage: Object.fromEntries(Object.entries(score.endToEnd?.byLanguage || {}).map(([l, c]) => [l, { f1: c.f1 ?? null }])) } } : null,
    usage: 'evaluation-only', label,
  };
  entry.entryHash = entryHashOf(entry);
  return { ...ledger, entries: [...ledger.entries, entry] };
}

/** The chain must be intact: a recomputed hash that disagrees, a broken link or a gap means an entry (a baseline, say) was edited. */
export function verifyLedger(ledger) {
  const errors = [];
  if (!ledger || ledger.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.entries)) return { ok: false, errors: [{ code: 'BAD_LEDGER', message: 'not a sealed evaluation ledger' }] };
  let prev = null;
  ledger.entries.forEach((e, i) => {
    if (e.sequence !== i) errors.push({ code: 'GAP', index: i, message: `entry ${i} claims sequence ${e.sequence}` });
    if (e.prev !== prev) errors.push({ code: 'BROKEN_CHAIN', index: i, message: `entry ${i} does not chain to the entry before it` });
    if (entryHashOf(e) !== e.entryHash) errors.push({ code: 'ENTRY_EDITED', index: i, message: `entry ${i} no longer matches its recorded hash` });
    prev = e.entryHash;
  });
  return { ok: errors.length === 0, errors };
}

/**
 * May a NEW release accuracy claim be made on this sealed evaluation of this detector?
 *   - the ledger must verify;
 *   - the evaluation must have been run against the CURRENT detector digest (an old result describes an old detector);
 *   - none of the sealed targets it used may have been consumed by an earlier evaluation of a DIFFERENT detector digest: those
 *     targets have been seen, so a claim on them is a claim on a holdout that was tuned against. A fresh sealed population is needed.
 * Historical results stay in `retained`, flagged evaluation-only.
 */
export function assessReleaseClaim({ ledger, detectorDigest, sealedTargetIds, overall }) {
  const v = verifyLedger(ledger);
  if (!v.ok) return { allowed: false, status: 'blocked', reasons: ['ledger-tampered'], errors: v.errors, retained: [] };
  const sealed = new Set(sealedTargetIds);
  const retained = ledger.entries.map((e) => ({ sequence: e.sequence, detectorDigest: e.detectorDigest, overall: e.overall, usage: 'evaluation-only', usableForNewClaim: false }));
  const reasons = [];
  const consumed = new Set();
  const priorOtherDetector = ledger.entries.filter((e) => e.detectorDigest !== detectorDigest);
  for (const e of priorOtherDetector) for (const t of e.sealedTargetIds) if (sealed.has(t)) consumed.add(t);
  if (consumed.size) reasons.push('fresh-sealed-population-required');
  if (!ledger.entries.some((e) => e.detectorDigest === detectorDigest)) reasons.push('no-sealed-evaluation-of-this-detector');
  if (overall !== 'pass') reasons.push(overall === 'insufficient-population' || overall === 'unmeasured' ? `gate-${overall}` : 'gates-not-passing');
  return {
    allowed: reasons.length === 0, status: reasons.length === 0 ? 'claim-allowed' : 'blocked', reasons,
    consumedSealedTargets: [...consumed].sort(), retained,
    note: 'historical sealed results are retained as evaluation-only artifacts; they never support a new claim for a different detector revision',
  };
}

/**
 * The chain alone is not tamper-proof: hashes are unkeyed, so someone who edits a baseline can recompute every later hash. The
 * custodian therefore signs the chain HEAD, and a ledger is trusted only through `verifySignedLedger`.
 */
export function signLedger(ledger, privateKeyPem) {
  const v = verifyLedger(ledger);
  if (!v.ok) throw new Error('refusing to sign a ledger that does not verify');
  const head = ledger.entries.length ? ledger.entries[ledger.entries.length - 1].entryHash : null;
  const body = { ledger, head, length: ledger.entries.length };
  return { ...body, signature: { algorithm: 'ed25519', value: crypto.sign(null, Buffer.from(canonicalJson({ head, length: body.length })), privateKeyPem).toString('base64') } };
}

export function verifySignedLedger(signed, publicKeyPem) {
  if (!signed?.ledger || !signed.signature) return { ok: false, reason: 'not a signed ledger' };
  const v = verifyLedger(signed.ledger);
  if (!v.ok) return { ok: false, reason: 'the chain does not verify', errors: v.errors };
  const entries = signed.ledger.entries;
  const head = entries.length ? entries[entries.length - 1].entryHash : null;
  if (head !== signed.head || entries.length !== signed.length) return { ok: false, reason: 'the ledger head or length differs from the signed one' };
  let good = false;
  try { good = crypto.verify(null, Buffer.from(canonicalJson({ head, length: entries.length })), publicKeyPem, Buffer.from(signed.signature.value, 'base64')); } catch { good = false; }
  return good ? { ok: true, ledger: signed.ledger } : { ok: false, reason: 'the head signature does not verify under the custodian key' };
}

// ---------------------------------------------------------------- the release verdict

/**
 * Evaluate the release gates for one sealed-split run and decide whether a new accuracy claim is allowed.
 * `run` is required: the integrity gates (leaks, denominator) read it, and a verdict that cannot count leaks is not a release verdict.
 */
export function evaluateReleaseGates({ protocol, score, run, defects = [], negatives = [], ledger = emptyLedger(), detectorDigest }) {
  if (!run) return { ok: false, rejected: true, overall: 'rejected', errors: [{ code: 'RUN_REQUIRED', message: 'a release verdict needs the run record: leakage and the denominator are checked against it' }], gates: [] };
  const lv = verifyLedger(ledger);
  if (!lv.ok) return { ok: false, rejected: true, overall: 'rejected', errors: [{ code: 'LEDGER_TAMPERED', message: 'the sealed evaluation ledger does not verify, so no baseline can be trusted', detail: lv.errors }], gates: [] };
  // The baseline is the last PASSING evaluation of any detector in the verified ledger; it cannot be supplied by the caller.
  const lastPass = [...ledger.entries].reverse().find((e) => e.overall === 'pass' && e.baseline);
  const g = evaluateGates({ protocol, score, defects, negatives, run, baseline: lastPass ? lastPass.baseline : null });
  if (g.rejected) return g;
  const sealedIds = protocol.splits.sealed;
  const claim = assessReleaseClaim({ ledger, detectorDigest, sealedTargetIds: sealedIds, overall: g.overall });
  // A first evaluation of this detector has no ledger entry yet; the entry the caller will append is what makes later claims checkable.
  const firstEvaluation = !ledger.entries.some((e) => e.detectorDigest === detectorDigest);
  const verdict = {
    schema: GATE_REPORT_SCHEMA, ok: true, rejected: false,
    protocolHash: protocol.protocolHash, synthetic: !!protocol.synthetic, detectorDigest,
    overall: g.overall,
    gates: g.gates.map((x) => ({ id: x.id, status: x.status, threshold: x.threshold ?? null, measured: x.measured ?? null, ...(x.reason ? { reason: x.reason } : {}) })),
    population: { realSealedPositives: g.population.realSealedPositives, realSealedNegatives: g.population.realSealedNegatives, reason: g.population.reason },
    claim: firstEvaluation && claim.reasons.every((r) => r === 'no-sealed-evaluation-of-this-detector')
      ? { ...claim, reasons: claim.reasons.filter((r) => r !== 'no-sealed-evaluation-of-this-detector'), allowed: g.overall === 'pass', status: g.overall === 'pass' ? 'claim-allowed' : 'blocked' }
      : claim,
    aggregateOnly: 'no per-case sealed outcome appears in this report',
  };
  verdict.reportHash = digestOf({ ...verdict, reportHash: undefined });
  return verdict;
}

// ---------------------------------------------------------------- signing

/** Custodian signature over the aggregate verdict. `privateKeyPem` is the custodian's Ed25519 key. */
export function signGateReport(report, privateKeyPem, { issuerId = 'evaluation-custodian' } = {}) {
  if (!report || report.rejected) throw new Error('only an accepted gate report is signed');
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const fingerprint = crypto.createHash('sha256').update(publicKeyPem).digest('hex');
  const issuance = { issuerId, keyFingerprint: fingerprint, trustBasis: TRUST_BASIS, independentlyCertified: false, statement: 'signed by a local custodian key; tamper evidence, not independent certification' };
  const body = { report, issuance };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(body)), privateKeyPem).toString('base64');
  return { ...body, signature: { algorithm: 'ed25519', value: signature } };
}

/** Verify with only the public key. A report that claims independent certification, or whose fingerprint is not this key, is rejected. */
export function verifyGateReport(signed, publicKeyPem) {
  if (!signed || !signed.report || !signed.signature || !signed.issuance) return { ok: false, reason: 'not a signed gate report' };
  if (signed.signature.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${signed.signature.algorithm}` };
  if (signed.issuance.independentlyCertified !== false || signed.issuance.trustBasis !== TRUST_BASIS) return { ok: false, reason: 'the only verifiable trust basis is a self-issued local key' };
  const fp = crypto.createHash('sha256').update(crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'pem' })).digest('hex');
  if (signed.issuance.keyFingerprint !== fp) return { ok: false, reason: 'the issuer fingerprint is not the verifying key' };
  let good = false;
  try { good = crypto.verify(null, Buffer.from(canonicalJson({ report: signed.report, issuance: signed.issuance })), publicKeyPem, Buffer.from(signed.signature.value, 'base64')); } catch { good = false; }
  if (!good) return { ok: false, reason: 'signature does not match the report' };
  if (digestOf({ ...signed.report, reportHash: undefined }) !== signed.report.reportHash) return { ok: false, reason: 'report content does not match its recorded hash' };
  return { ok: true, overall: signed.report.overall, claimAllowed: !!signed.report.claim?.allowed, trustBasis: TRUST_BASIS };
}
