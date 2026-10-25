export const id = 1203;
export const ids = [1203];
export const modules = {

/***/ 21203:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyImageSignature: () => (/* binding */ verifyImageSignature),
/* harmony export */   verifyProvenanceAttestation: () => (/* binding */ verifyProvenanceAttestation)
/* harmony export */ });
/* unused harmony export SIGNATURE_STATES */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
// PRD 5 P0 §5 — Signature Verification. States are exactly the PRD's own
// four, deliberately different from `sca/sigstore-verify.js`'s own vocabulary
// (`verified/unverified/tampered/unknown`) so the two are never confused by
// shared words — see docs/implementation-status/source-to-artifact-provenance.md's
// naming-discipline section:
//
//   verified    — a real cryptographic check ran and the signature matches.
//   invalid     — a real cryptographic check ran and the signature does NOT match.
//   missing     — no signature/attestation material was supplied at all.
//   unavailable — material was supplied but could not be cryptographically
//                 checked (no public key given, or the check itself could
//                 not run) — the PRD's "never treat missing tooling as
//                 verified" clause means this state, not `verified`, is what
//                 an incomplete check must report.
//
// Two real, independent mechanisms are implemented:
//   1. A plain detached signature over the image digest string, verified
//      with an operator-supplied public key. This is this tool's OWN local
//      convention, not cosign's "simple signing" JSON format — disclosed in
//      the implementation-status doc, not silently passed off as cosign-
//      compatible.
//   2. Real DSSE (Dead Simple Signing Envelope) verification for in-toto/SLSA
//      provenance attestations — the actual encoding cosign/Sigstore use for
//      attestations, so a real cosign-keyed attestation bundle DOES verify
//      here given the matching public key. `dssePae` is the exact PAE
//      (Pre-Authentication Encoding) from the DSSE spec.
//
// Keyless/Rekor-transparency-log verification is NOT implemented — disclosed
// as a gap, never faked. `sca/sigstore-verify.js`'s Rekor-query pattern is
// the template a future increment could extend this module with.


const SIGNATURE_STATES = Object.freeze(['verified', 'invalid', 'missing', 'unavailable']);

function verifyRaw(payload, signature, publicKeyPem) {
  let publicKey;
  try {
    publicKey = node_crypto__WEBPACK_IMPORTED_MODULE_0__.createPublicKey(publicKeyPem);
  } catch (err) {
    return { ok: false, error: `public key is not parseable: ${err.message}` };
  }
  const keyType = publicKey.asymmetricKeyType;
  const algorithm = (keyType === 'ed25519' || keyType === 'ed448') ? null : 'sha256';
  try {
    const ok = node_crypto__WEBPACK_IMPORTED_MODULE_0__.verify(algorithm, payload, publicKey, signature);
    return { ok, keyType };
  } catch (err) {
    return { ok: false, error: `signature verification failed to run: ${err.message}` };
  }
}

/**
 * Verifies a detached signature over an image's digest string.
 * `signature`/`publicKeyPem` are Buffer/PEM-string; either missing means
 * `missing` (nothing was supplied to check).
 */
function verifyImageSignature({ digest, signature, publicKeyPem }) {
  if (typeof digest !== 'string' || !digest.startsWith('sha256:')) {
    return { state: 'unavailable', reason: 'no image digest available to verify a signature against' };
  }
  if (!signature || !publicKeyPem) {
    return { state: 'missing', reason: 'no detached signature and public key were supplied for this image' };
  }
  const { ok, error, keyType } = verifyRaw(Buffer.from(digest, 'utf8'), signature, publicKeyPem);
  if (error) return { state: 'invalid', reason: error };
  return ok
    ? { state: 'verified', keyType }
    : { state: 'invalid', reason: 'signature does not match the image digest under the supplied public key' };
}

// DSSE Pre-Authentication Encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
function dssePae(payloadType, payloadBytes) {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from('DSSEv1 ', 'ascii'),
    Buffer.from(String(typeBytes.length), 'ascii'),
    Buffer.from(' ', 'ascii'),
    typeBytes,
    Buffer.from(' ', 'ascii'),
    Buffer.from(String(payloadBytes.length), 'ascii'),
    Buffer.from(' ', 'ascii'),
    payloadBytes,
  ]);
}

const SLSA_PREDICATE_PREFIX = 'https://slsa.dev/provenance/';
const INTOTO_STATEMENT_TYPES = new Set(['https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1']);

/**
 * Verifies an in-toto/SLSA provenance attestation for an image.
 * `envelope` is a DSSE envelope: `{ payloadType, payload (base64 in-toto
 * Statement JSON), signatures: [{ sig (base64) }] }` — the real shape
 * cosign/Sigstore attestations use. `publicKeyPem` verifies one of
 * `signatures` against `dssePae(payloadType, payload)`.
 *
 * The subject-digest match is checked FIRST and independently of signature
 * verification, so a mismatched subject is always `invalid` (never
 * "unavailable", which would understate a real, checkable problem).
 */
function verifyProvenanceAttestation({ digest, envelope, publicKeyPem }) {
  if (!envelope) return { state: 'missing', reason: 'no in-toto/SLSA provenance attestation was supplied for this image' };

  let env;
  try {
    env = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
  } catch (err) {
    return { state: 'invalid', reason: `attestation envelope is not valid JSON: ${err.message}` };
  }
  if (typeof env.payload !== 'string' || typeof env.payloadType !== 'string' || !Array.isArray(env.signatures)) {
    return { state: 'invalid', reason: 'not a recognized DSSE envelope (missing payload, payloadType, or signatures)' };
  }

  let payloadBytes;
  let stmt;
  try {
    payloadBytes = Buffer.from(env.payload, 'base64');
    stmt = JSON.parse(payloadBytes.toString('utf8'));
  } catch (err) {
    return { state: 'invalid', reason: `attestation payload is not a valid base64-encoded JSON statement: ${err.message}` };
  }
  if (!INTOTO_STATEMENT_TYPES.has(stmt._type)) {
    return { state: 'invalid', reason: 'statement is missing a recognized in-toto "_type"' };
  }

  const digestHex = typeof digest === 'string' && digest.startsWith('sha256:') ? digest.slice('sha256:'.length) : digest;
  const subjects = Array.isArray(stmt.subject) ? stmt.subject : [];
  const subjectMatches = subjects.some((s) => s && s.digest && s.digest.sha256 === digestHex);
  if (!subjectMatches) {
    return { state: 'invalid', reason: 'attestation subject digest does not match this image', predicateType: stmt.predicateType || null };
  }

  const predicateType = stmt.predicateType || null;
  const isSlsa = typeof predicateType === 'string' && predicateType.startsWith(SLSA_PREDICATE_PREFIX);

  if (!publicKeyPem || env.signatures.length === 0) {
    return {
      state: 'unavailable',
      reason: 'attestation subject matches this image, but no public key was supplied to verify its signature',
      predicateType, isSlsa,
    };
  }

  const pae = dssePae(env.payloadType, payloadBytes);
  for (const sigEntry of env.signatures) {
    if (!sigEntry || typeof sigEntry.sig !== 'string') continue;
    let sigBytes;
    try {
      sigBytes = Buffer.from(sigEntry.sig, 'base64');
    } catch {
      continue;
    }
    const { ok } = verifyRaw(pae, sigBytes, publicKeyPem);
    if (ok) return { state: 'verified', predicateType, isSlsa };
  }
  return { state: 'invalid', reason: 'no signature in the attestation envelope verifies under the supplied public key', predicateType, isSlsa };
}


/***/ })

};
