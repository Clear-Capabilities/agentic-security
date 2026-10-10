// Rollback and compatibility for the assurance features (REL-002.AC02, AC03).
//
// Four things live here, and the line between them is the point:
//
//   1. READER_POLICY: for every record kind, whether a PREVIOUS reader exists, so a rollback that
//      restores old consumers is supported, or does not, in which case the policy says so and
//      a rollback flags the new records instead of pretending the old consumers can read them.
//   2. The one known hard compatibility break. A verifier older than CORE-003 rejects every newly
//      signed evidence bundle, because the new `issuance` block is a top-level key its strict
//      unknown-key rule (which exists to stop unsigned fields being stapled on) does not know.
//      `verifyWithPreCore003Reader` reproduces that reader exactly so the break is tested rather than
//      asserted; `exportLegacyBundle` is the migration path for a consumer that cannot upgrade.
//   3. planRollback / applyRollback: restore the last known-good rollout position and FLAG, never
//      delete or rewrite, the recorded evidence and the assurance claims that rest on it.
//   4. EvidenceStore / guardedFeatureRun: an append-only record, so a feature that fails cannot take
//      earlier evidence down with it.
//
// Nothing here reaches the network or a model. Nothing here edits configuration: a rollback that needs
// a feature off returns the configuration change for the operator to apply.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { canonicalBytes, verifyEvidenceBundle, keyFingerprint } from '../evidence-bundle.js';
import { digestOfBytes } from './identity.js';
import { STAGES } from './rollout.js';

// ---------------------------------------------------------------- reader policy

export const READER_POLICY = Object.freeze({
  verification: { rollbackSupported: true, previousReader: 'toLegacyVerificationView (migrations.js)', note: 'a legacy consumer sees status/verified/reason; verified is true only for confirmed and false only for refuted' },
  evidenceBundle: { rollbackSupported: true, previousReader: 'verifyWithPreCore003Reader', note: 'a pre-CORE-003 verifier can read only bundles re-exported without the issuance block (exportLegacyBundle)' },
  observationBinding: { rollbackSupported: false, previousReader: null, note: 'no previous reader exists: lineage keeps its own observation; the binding is new. Rollback keeps the records and flags them incompatible for any older consumer' },
  capabilityDecision: { rollbackSupported: false, previousReader: null, note: 'the egress decision it adapts has no inverse; a decision is never turned back into a bare allow/deny' },
  routingLabel: { rollbackSupported: false, previousReader: null, note: 'a boolean label has no place for a label source; the inverse would invent one' },
  releaseEvidence: { rollbackSupported: false, previousReader: null, note: 'a legacy check list cannot carry evidence references; the inverse would drop them' },
});

// ---------------------------------------------------------------- the known compatibility break

// Top-level keys a bundle could carry before CORE-003 added `issuance`. Verbatim from the verifier of that time.
export const PRE_CORE_003_BUNDLE_KEYS = Object.freeze(['schema', 'finding', 'evidence', 'engine', 'proves', 'doesNotProve', 'signature']);

/**
 * The bundle verifier as it stood before CORE-003: strict unknown top-level keys, signature over the
 * canonical bytes, nothing about issuers. Kept as a faithful copy so the break is a test, not a belief.
 */
export function verifyWithPreCore003Reader(bundle, publicKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  const unknownKeys = Object.keys(bundle).filter((k) => !PRE_CORE_003_BUNDLE_KEYS.includes(k));
  if (unknownKeys.length) return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  try {
    return crypto.verify(null, canonicalBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64')) ? { ok: true, reason: null } : { ok: false, reason: 'signature does not match the bundle contents' };
  } catch (e) { return { ok: false, reason: `verification error: ${e.message}` }; }
}

/**
 * Migration path for a consumer that cannot upgrade past a pre-CORE-003 verifier: re-sign the SAME content
 * without the issuance block. Three honesty rules:
 *   - the original must verify under the key that matches `privateKeyPem` first. A tampered or foreign
 *     bundle is refused, not laundered into a fresh valid signature;
 *   - the export loses the signed trust-basis statement; a current verifier reports it `none-declared`.
 *     Because an old verifier rejects any extra key, that disclosure cannot ride in the bundle, so it is returned
 *     as a SIDECAR record the operator keeps beside it;
 *   - the export is a new signature by the same local key, so it is still self-issued, still not third-party certification.
 */
export function exportLegacyBundle(bundle, privateKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  let publicKeyPem;
  try { publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }); } catch (e) { return { ok: false, reason: `unusable signing key: ${e.message}` }; }
  const original = verifyEvidenceBundle(bundle, publicKeyPem);
  if (!original.ok) return { ok: false, reason: `the original bundle does not verify under this key (${original.reason}); it is not re-signed` };
  const { issuance, signature, ...content } = bundle;
  void signature;
  const sig = crypto.sign(null, canonicalBytes(content), privateKeyPem);
  const exported = { ...content, signature: { algorithm: 'ed25519', canonicalisation: bundle.signature.canonicalisation, value: sig.toString('base64') } };
  return {
    ok: true, bundle: exported,
    sidecar: {
      kind: 'legacy-bundle-export', from: 'core-003', originalBundleDigest: digestOfBytes(canonicalBytes(bundle)), exportedBundleDigest: digestOfBytes(canonicalBytes(exported)),
      droppedIssuance: issuance ?? null, issuerKeyFingerprint: keyFingerprint(publicKeyPem),
      note: 'Re-signed without the issuance block so a pre-CORE-003 verifier accepts it. The trust basis (self-issued local key, not independent certification) is no longer inside the signed bytes; it is recorded only here. Upgrade the verifier and keep the original bundle.',
    },
  };
}

// ---------------------------------------------------------------- rollback planning

const clone = (x) => JSON.parse(JSON.stringify(x));

/**
 * What a rollback of `feature` would restore and what it would flag. Pure: nothing is changed.
 *   store:  [{ id, kind, digest, producedUnder: { feature, policyVersion } }]
 *   claims: [{ id, evidenceRefs: [store ids] }]
 */
export function planRollback({ ledger, feature, store = [], claims = [] }) {
  const cur = ledger?.features?.[feature];
  if (!cur) return { ok: false, reason: `unknown feature '${feature}'` };
  const here = STAGES.indexOf(cur.stage);
  // The most recent known-good entry at an EARLIER stage; the first stage rolls back to "off".
  let target = null;
  for (let i = cur.history.length - 1; i >= 0 && !target; i--) {
    const h = cur.history[i];
    if (h.knownGood && h.to && STAGES.indexOf(h.to) < here) target = h;
  }
  const restore = target
    ? { stage: target.to, policyVersion: target.policyVersion, source: `history[${target.seq}]` }
    : { stage: cur.stage, policyVersion: cur.history[0].policyVersion, source: 'history[0]' };
  const configChange = target ? null : { feature, enabled: false, why: 'already at the first stage; the only known-good behaviour below it is the feature being off' };

  const annotations = {};
  for (const item of store) {
    if (item?.producedUnder?.feature !== feature) continue;
    const flags = []; const reasons = [];
    if ((item.producedUnder.policyVersion ?? 0) > restore.policyVersion) {
      flags.push('stale'); reasons.push(`produced under policy ${item.producedUnder.policyVersion}, newer than the restored policy ${restore.policyVersion}`);
    }
    const policy = READER_POLICY[item.kind];
    if (!policy) { flags.push('incompatible'); reasons.push(`no reader policy is recorded for kind '${item.kind}'`); }
    else if (!policy.rollbackSupported) { flags.push('incompatible'); reasons.push(`kind '${item.kind}' has no previous reader (${policy.note})`); }
    if (flags.length) annotations[item.id] = { flags, reasons };
  }
  const byId = new Map(store.map((i) => [i.id, i]));
  const claimStatus = {};
  for (const c of claims) {
    const reasons = [];
    for (const ref of c.evidenceRefs || []) {
      if (!byId.has(ref)) reasons.push(`${ref}: not in the evidence store (dangling)`);
      else if (annotations[ref]) reasons.push(`${ref}: ${annotations[ref].flags.join('+')}`);
    }
    claimStatus[c.id] = reasons.length ? { status: 'flagged', reasons } : { status: 'valid', reasons: [] };
  }
  return {
    ok: true, feature, from: { stage: cur.stage, policyVersion: cur.policyVersion }, restore, configChange, annotations, claims: claimStatus,
    // The plan never removes anything: every store id is retained.
    retained: store.map((i) => i.id),
  };
}

/**
 * Apply a plan to the ledger. Returns a NEW ledger with a `rollback` event appended; history is never
 * rewritten. The evidence store and claims are not touched at all: annotations are returned for the caller to
 * keep beside them.
 */
export function applyRollback(ledger, plan, { reason = 'rollback' } = {}) {
  if (!plan?.ok) return { ok: false, ledger, reason: plan?.reason ?? 'no plan' };
  const next = clone(ledger);
  const f = next.features[plan.feature];
  f.history.push({ seq: f.history.length, event: 'rollback', from: f.stage, to: plan.restore.stage, policyVersion: plan.restore.policyVersion, knownGood: true, restoredFrom: plan.restore.source, reason: String(reason), evidence: null });
  f.stage = plan.restore.stage; f.policyVersion = plan.restore.policyVersion;
  return { ok: true, ledger: next, annotations: plan.annotations, claims: plan.claims, configChange: plan.configChange };
}

// ---------------------------------------------------------------- evidence that survives failure

/**
 * Append-only evidence store. An existing id can be re-appended only with the identical digest (idempotent
 * redelivery); the same id with a different digest is refused, because overwriting evidence is erasing it.
 * Optionally backed by a JSONL file written with append-only semantics: a torn last line (a crash mid-write)
 * (or any unreadable line) is counted in `unreadable` and skipped on read, and never costs the other lines.
 */
export class EvidenceStore {
  constructor({ file = null } = {}) {
    this.file = file; this.items = new Map(); this.failures = []; this.unreadable = 0;
    if (file && fs.existsSync(file)) this._load();
  }

  _load() {
    const lines = fs.readFileSync(this.file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      if (!line.trim()) return;
      try {
        const rec = JSON.parse(line);
        if (rec.type === 'item') this.items.set(rec.item.id, rec.item);
        else if (rec.type === 'failure') this.failures.push(rec.failure);
      } catch { this.unreadable += 1; }
    });
  }

  append(item) {
    if (!item || typeof item.id !== 'string' || typeof item.digest !== 'string') return { ok: false, reason: 'an evidence item needs a string id and digest' };
    const have = this.items.get(item.id);
    if (have) return have.digest === item.digest ? { ok: true, duplicate: true } : { ok: false, reason: `evidence '${item.id}' already exists with a different digest; evidence is never overwritten` };
    if (this.file) fs.appendFileSync(this.file, `${JSON.stringify({ type: 'item', item })}\n`);
    this.items.set(item.id, clone(item));
    return { ok: true, duplicate: false };
  }

  recordFailure(failure) {
    this.failures.push(failure);
    if (this.file) fs.appendFileSync(this.file, `${JSON.stringify({ type: 'failure', failure })}\n`);
  }

  all() { return [...this.items.values()].map(clone); }

  /** Digest over every item in id order; changes if any item is removed or altered. */
  digest() { return digestOfBytes(Buffer.from(JSON.stringify([...this.items.keys()].sort().map((k) => this.items.get(k))))); }
}

/**
 * Run a feature body. A throw becomes a typed `blocked` result and a recorded failure event; the store's
 * earlier evidence is untouched, because nothing here has a path that removes an item.
 */
export async function guardedFeatureRun(store, feature, fn) {
  try {
    return { status: 'ok', code: null, feature, value: await fn(store) };
  } catch (e) {
    const failure = { feature, error: String(e?.message ?? e).slice(0, 500) };
    store.recordFailure(failure);
    return { status: 'blocked', code: 'feature-failed', reason: `${feature} failed: ${failure.error}`, feature };
  }
}
