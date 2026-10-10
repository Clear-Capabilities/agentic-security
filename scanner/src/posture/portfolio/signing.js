// Sign and verify bounded assurance claims (X-703).
//
// WHAT IS SIGNED. Not the manifest bytes alone: a small claim that names the manifest id and digest, the portable bundle digest, the
// subject commit, the blocking-finding policy, the coverage counts and the bounded headline, plus the signer identity, key id and the
// assurance policy the signer applied. Verification re-derives every one of those from the bundle on disk, so a signature cannot be
// carried over to different evidence.
//
// WHO MAY SIGN (X-703.AC01). Signing is a SIGNER-domain act (sandbox/trust-domains.js, default deny): a worker, target or verifier
// domain asking to sign is refused before any key is touched. The key lives in its own directory (`assurance-signing/` beside, never
// inside, the scan evidence keys) so the assurance domain has a separate key identity, and the signer refuses a key whose id equals the
// evidence key it is told to stay independent of. The key is read from that directory by the signer; nothing here returns, logs or
// embeds private key material, and `signAssuranceClaim` checks its own output for a PEM block before returning it.
//
// WHAT VERIFICATION DOES (X-703.AC02). Offline, with a trust-root policy the verifier is handed: unknown roots, revoked roots, a trust
// basis this build cannot verify, a tampered claim, a tampered or missing bundle, and a claim that does not match the bundle's manifest
// are each a typed failure. The only basis this build can verify is `self-issued-local-key`; a policy that names any other basis is
// rejected, never displayed as if it were certification.
//
// WHAT IT NEVER CLAIMS (X-703.AC03). `independentlyCertified` is always false and is part of the signed bytes. A valid signature shows
// the manifest and bundle are unmodified since the named key signed them. It is not third-party certification and not a statement that
// no vulnerability exists.

import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { canonicalJson, ensureKeyPair, keyFingerprint, TRUST_BASES } from '../evidence-bundle.js';
import { RESOURCES, mayDo, keyDirectory } from '../../sandbox/trust-domains.js';
import { digestOf } from '../assurance/identity.js';
import { validateManifest, manifestDigest } from './manifest.js';
import { verifyBundle } from './bundle.js';
import { assuranceStatement, HEADLINE } from './wording.js';

const CLAIM_SCHEMA = 'agentic-security/assurance-claim';
const CLAIM_VERSION = '1.0.0';
const TRUST_POLICY_SCHEMA = 'agentic-security/assurance-trust-roots';
const ASSURANCE_POLICY = Object.freeze({
  id: 'bounded-claim-v1',
  statement: `${HEADLINE}, with visible scope and gaps. Not a statement of safety, vulnerability absence or independent certification.`,
});
export const SIGNING_DIR_NAME = 'assurance-signing';

/** The signing key directory for the assurance domain: separate from the scan evidence keys. */
export function assuranceKeyDirectory(env = process.env) { return path.join(keyDirectory(env), SIGNING_DIR_NAME); }

/** Load, or create on first use, the assurance signing key pair. Only the signer domain may call this. */
export function ensureAssuranceKeys({ domain, dir = assuranceKeyDirectory() } = {}) {
  if (!mayDo(domain, RESOURCES.SIGNING_KEY, 'read')) throw signerRefusal(domain);
  const k = ensureKeyPair(dir);
  return { privateKeyPem: k.privateKeyPem, publicKeyPem: k.publicKeyPem, keyId: keyFingerprint(k.publicKeyPem), created: k.created };
}

function signerRefusal(domain) {
  return Object.assign(new Error(`the '${domain}' domain may not sign assurance claims: signing is a signer-domain act and the key is out of its reach`), { code: 'SIGNER_NOT_AUTHORIZED' });
}

/**
 * Sign a bounded claim for a verified bundle. Throws a typed error (`code`) on a refused domain, an invalid manifest, a bundle that does
 * not verify, or a key that is not independent of `independentOfKeyId`.
 *
 * @param {object} a
 * @param {string} a.domain          the calling trust domain (must be 'signer')
 * @param {string} a.bundleDir       an exported portable bundle
 * @param {string} a.privateKeyPem   the signer's Ed25519 key
 * @param {string} a.signerId        stable signer identity, e.g. 'release-signer@org'
 * @param {string} [a.independentOfKeyId]  fingerprint of a key (the scan evidence key) this domain must not share
 */
export function signAssuranceClaim({ domain, bundleDir, privateKeyPem, signerId, independentOfKeyId = null }) {
  if (!mayDo(domain, RESOURCES.SIGNING_KEY, 'read')) throw signerRefusal(domain);
  if (typeof signerId !== 'string' || !signerId.trim()) throw Object.assign(new Error('a signer identity is required'), { code: 'SIGNER_ID_REQUIRED' });
  const vb = verifyBundle(bundleDir);
  if (!vb.ok || !vb.manifest) throw Object.assign(new Error(`refusing to sign: the bundle does not verify (${vb.errors[0]?.code ?? 'no manifest'})`), { code: 'BUNDLE_INVALID', errors: vb.errors });
  const vm = validateManifest(vb.manifest);
  if (!vm.ok) throw Object.assign(new Error('refusing to sign: the manifest is invalid'), { code: 'MANIFEST_INVALID' });
  let publicKeyPem;
  try { publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }); } catch {
    throw Object.assign(new Error('the signing key could not be parsed'), { code: 'BAD_KEY' });
  }
  const keyId = keyFingerprint(publicKeyPem);
  if (independentOfKeyId && keyId === independentOfKeyId) throw Object.assign(new Error('the assurance signing key must be independent of the scan evidence key'), { code: 'KEY_NOT_INDEPENDENT' });

  const m = vb.manifest;
  const body = {
    schema: CLAIM_SCHEMA, schemaVersion: CLAIM_VERSION,
    claim: {
      manifestId: m.id, manifestDigest: manifestDigest(m), bundleDigest: vb.bundleDigest,
      subject: { repository: m.subject.repository, commit: m.subject.commit },
      blockingPolicy: { id: m.policy.id, digest: m.policy.digest, blockingSeverity: m.policy.blockingSeverity },
      blockingFindings: m.findings.blocking, coverage: m.coverage, complete: m.complete,
      headline: assuranceStatement(m).headline,
      ...(m.synthetic === true ? { synthetic: true } : {}),
    },
    signer: { id: signerId, keyId },
    assurancePolicy: { id: ASSURANCE_POLICY.id, digest: digestOf(ASSURANCE_POLICY), statement: ASSURANCE_POLICY.statement },
    issuance: { trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: TRUST_BASES['self-issued-local-key'].statement },
  };
  const value = crypto.sign(null, Buffer.from(canonicalJson(body)), privateKeyPem).toString('base64');
  const envelope = { ...body, signature: { algorithm: 'ed25519', value } };
  if (/PRIVATE KEY/.test(JSON.stringify(envelope))) throw Object.assign(new Error('private key material reached the output; refusing to return it'), { code: 'KEY_LEAK' });
  return envelope;
}

/** A trust-root policy naming the keys a verifier accepts. Only `self-issued-local-key` is a basis this build can verify. */
export function buildTrustPolicy({ roots = [], revoked = [] } = {}) {
  return {
    schema: TRUST_POLICY_SCHEMA, schemaVersion: '1.0.0',
    roots: roots.map((r) => ({ keyId: keyFingerprint(r.publicKeyPem), signerId: r.signerId, basis: r.basis ?? 'self-issued-local-key', publicKeyPem: r.publicKeyPem })),
    revoked: revoked.map((r) => ({ keyId: r.keyId, reason: r.reason ?? 'revoked' })),
  };
}

const fail = (code, reason, extra = {}) => ({ ok: false, code, reason, independentlyCertified: false, ...extra });

/**
 * Verify a signed claim offline against a trust-root policy and the bundle it names. Never throws. Returns `{ ok, ... }`; on failure
 * `code` is one of: NOT_A_CLAIM, UNSUPPORTED_ALGORITHM, NO_TRUST_POLICY, UNKNOWN_TRUST_ROOT, REVOKED_TRUST_ROOT, UNSUPPORTED_BASIS,
 * BAD_TRUST_ROOT, OVER_CLAIM, SIGNATURE_INVALID, BUNDLE_INVALID, EVIDENCE_MISMATCH.
 */
export function verifyAssuranceClaim({ envelope, trustPolicy, bundleDir }) {
  try {
    if (!envelope || envelope.schema !== CLAIM_SCHEMA || !envelope.claim || !envelope.signer || !envelope.signature || !envelope.issuance) return fail('NOT_A_CLAIM', 'not a signed assurance claim');
    if (envelope.signature.algorithm !== 'ed25519') return fail('UNSUPPORTED_ALGORITHM', `unsupported algorithm: ${envelope.signature.algorithm}`);
    if (!trustPolicy || trustPolicy.schema !== TRUST_POLICY_SCHEMA || !Array.isArray(trustPolicy.roots)) return fail('NO_TRUST_POLICY', 'no usable trust-root policy was supplied; a signature is meaningless without one');
    const keyId = envelope.signer.keyId;
    const revoked = (trustPolicy.revoked ?? []).find((r) => r.keyId === keyId);
    if (revoked) return fail('REVOKED_TRUST_ROOT', `key ${String(keyId).slice(0, 12)} is revoked: ${revoked.reason}`);
    const root = trustPolicy.roots.find((r) => r.keyId === keyId);
    if (!root) return fail('UNKNOWN_TRUST_ROOT', `key ${String(keyId).slice(0, 12)} is not a trust root in this policy`);
    if (!TRUST_BASES[root.basis]) return fail('UNSUPPORTED_BASIS', `trust basis '${root.basis}' cannot be verified by this build; it is rejected, not displayed as certification`);
    if (keyFingerprint(root.publicKeyPem) !== root.keyId) return fail('BAD_TRUST_ROOT', 'the trust root public key does not match its key id');
    if (envelope.issuance.independentlyCertified !== false || envelope.issuance.trustBasis !== root.basis) return fail('OVER_CLAIM', 'a self-issued claim may not state independent certification, and its basis must match the trust root');

    const { signature, ...body } = envelope;
    let good = false;
    try { good = crypto.verify(null, Buffer.from(canonicalJson(body)), root.publicKeyPem, Buffer.from(signature.value, 'base64')); } catch { good = false; }
    if (!good) return fail('SIGNATURE_INVALID', 'the signature does not match the claim: it was modified after signing, or signed by another key');

    const vb = verifyBundle(bundleDir);
    if (!vb.ok || !vb.manifest) return fail('BUNDLE_INVALID', `the evidence bundle does not verify: ${vb.errors[0]?.code ?? 'no manifest'}`, { errors: vb.errors });
    const m = vb.manifest;
    const c = envelope.claim;
    const mismatch = [];
    if (c.bundleDigest !== vb.bundleDigest) mismatch.push('bundleDigest');
    if (c.manifestDigest !== manifestDigest(m)) mismatch.push('manifestDigest');
    if (c.manifestId !== m.id) mismatch.push('manifestId');
    if (c.subject?.commit !== m.subject.commit) mismatch.push('subject.commit');
    if (digestOf(c.coverage) !== digestOf(m.coverage)) mismatch.push('coverage');
    if (c.blockingFindings !== m.findings.blocking) mismatch.push('blockingFindings');
    if (c.blockingPolicy?.digest !== m.policy.digest) mismatch.push('blockingPolicy');
    if (mismatch.length) return fail('EVIDENCE_MISMATCH', `the signed claim does not match the evidence: ${mismatch.join(', ')}`, { mismatch });

    const verified = { ok: true, trustBasis: root.basis, independentlyCertified: false, signer: envelope.signer.id, keyId, assurancePolicy: envelope.assurancePolicy?.id ?? null, replay: vb.replay };
    return { ...verified, statement: assuranceStatement(m, { signature: verified }).text, note: TRUST_BASES[root.basis].statement };
  } catch (e) {
    return fail('NOT_A_CLAIM', `verification could not complete: ${String(e?.message ?? e).split('\n')[0]}`);
  }
}
