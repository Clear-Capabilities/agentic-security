// Sign compliance evidence manifests (assurance-hardening PRD FR-505).
//
// "Sign evidence manifests when signing is configured | Signature
// verification detects altered findings, scope, policy, or evidence
// references."
//
// SAME TRUST DOMAIN AS evidence-bundle.js, DELIBERATELY REUSING ITS KEY
// --------------------------------------------------------------------------
// A compliance evidence manifest and a finding evidence bundle make the
// SAME kind of claim: "this artifact is exactly what MY install produced,
// unaltered since." Both are self-attestation by the running install, not
// a claim authored by a third party and distributed for others to verify
// (that is policy-bundle.js's job, and why IT needed a separate key — see
// D-0026). Reusing evidence-bundle.js's `ensureKeyPair()` directly means an
// operator who already generated a key for finding attestations does not
// need a second one for compliance evidence; the two artifact types are
// simply two things the SAME key can honestly attest to.
//
// EA-03 DISCIPLINE, APPLIED FROM THE FIRST WRITE (see D-0026)
// --------------------------------------------------------------------------
// canonicalComplianceEvidenceBytes signs an explicit ALLOWLIST — every key
// emitEvidenceJsonLd() can actually produce, no more, no less — and
// verifyComplianceEvidence REJECTS any top-level key outside
// {that allowlist, signature}. A field stapled on after signing (a status
// silently edited, a control removed, a narrative_evidence line added) must
// fail verification, not verify successfully with the addition unnoticed.
//
// WHY THE FULL DOCUMENT, NOT JUST evidenceDigest (FR-504)
// --------------------------------------------------------------------------
// computeEvidenceDigest (FR-504) binds `controls` down to {id, status} only
// — enough to prove "the CONCLUSION did not change," but not enough to
// catch an edited check reason or narrative evidence bullet without
// touching the top-line status. FR-505's acceptance criterion is broader
// ("altered ... evidence references"), so the signature here covers the
// full per-control shape (checks[], narrative_evidence[]) that
// emitEvidenceJsonLd actually renders, not just the FR-504 digest.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { keyPaths } from './evidence-bundle.js';

export const COMPLIANCE_EVIDENCE_SCHEMA = 'agentic-security/compliance-evidence@1';

/**
 * "Sign evidence manifests WHEN SIGNING IS CONFIGURED" — this is the opt-in
 * check. Unlike `agentic-security attest` (an explicit command an operator
 * runs specifically to sign something, where generating a key on first use
 * is the right default), compliance evidence is emitted automatically on
 * every ordinary scan — auto-generating a signing key as a side effect of a
 * routine scan would be surprising, unrequested behavior. "Configured"
 * therefore means an operator has ALREADY set up the shared key (by running
 * `attest` once, or by any other means) — this function only ever READS,
 * never generates. Read-first-in-try/catch (D-0012) — no
 * existsSync-then-readFileSync.
 *
 * @returns {{privateKeyPem: string, publicKeyPem: string}|null}
 */
export function loadSigningKeyIfConfigured() {
  const p = keyPaths();
  let privateKeyPem, publicKeyPem;
  try { privateKeyPem = fs.readFileSync(p.privateKey, 'utf8'); } catch { return null; }
  try { publicKeyPem = fs.readFileSync(p.publicKey, 'utf8'); } catch { return null; }
  return { privateKeyPem, publicKeyPem };
}

// The complete set of top-level keys a real emitEvidenceJsonLd() output can
// carry, BEFORE signing. Must be kept in sync with that function — the
// signed allowlist and the "known keys" allowlist for unsigned-field
// rejection are the SAME set, exactly as evidence-bundle.js/policy-bundle.js
// both already establish.
const EVIDENCE_FIELDS = [
  '@context', '@type', 'schemaVersion', 'statusSemantics', 'policySource',
  'framework', 'version', 'generatedAt',
  'disclaimer', 'provenance', 'evidenceDigest', 'summary', 'controls',
];
const EVIDENCE_TOP_LEVEL_KEYS = new Set([...EVIDENCE_FIELDS, 'signature']);

// Deterministic JSON, keys sorted at every level — same algorithm as
// evidence-bundle.js's canonicalJson and policy-bundle.js's canonicalJson
// (each duplicated locally rather than imported, per those modules' own
// stated reasoning: a pure, three-line function not worth coupling three
// signing modules' formats together for).
function _canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(_canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${_canonicalJson(value[k])}`).join(',')}}`;
}

export function canonicalComplianceEvidenceBytes(jsonld) {
  const signed = {};
  for (const k of EVIDENCE_FIELDS) signed[k] = jsonld[k] ?? null;
  return Buffer.from(_canonicalJson(signed), 'utf8');
}

/** Sign a compliance evidence document. Returns a new object; the input is not mutated. */
export function signComplianceEvidence(jsonld, privateKeyPem) {
  const sig = crypto.sign(null, canonicalComplianceEvidenceBytes(jsonld), privateKeyPem);
  return {
    ...jsonld,
    signature: { algorithm: 'ed25519', canonicalisation: COMPLIANCE_EVIDENCE_SCHEMA, value: sig.toString('base64') },
  };
}

/**
 * Verify a signed compliance evidence document with a PUBLIC key. Never
 * throws — a malformed or tampered document from an untrusted source (an
 * auditor or GRC tool checking what they were handed) is an expected input.
 *
 * @returns {{ok: boolean, reason: string|null}}
 */
export function verifyComplianceEvidence(jsonld, publicKeyPem) {
  if (!jsonld || typeof jsonld !== 'object') return { ok: false, reason: 'document is not an object' };
  const unknownKeys = Object.keys(jsonld).filter(k => !EVIDENCE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = jsonld.signature;
  if (!sig?.value) return { ok: false, reason: 'document is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, canonicalComplianceEvidenceBytes(jsonld), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return sigOk
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the document contents — it was modified after signing' };
}
