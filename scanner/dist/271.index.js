export const id = 271;
export const ids = [271];
export const modules = {

/***/ 2271:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildProvenanceEvidenceBundle: () => (/* binding */ buildProvenanceEvidenceBundle),
/* harmony export */   ensureKeyPair: () => (/* reexport safe */ _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__.ensureKeyPair),
/* harmony export */   signProvenanceEvidenceBundle: () => (/* binding */ signProvenanceEvidenceBundle)
/* harmony export */ });
/* unused harmony exports PROVENANCE_BUNDLE_SCHEMA, verifyProvenanceEvidenceBundle */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(7598);
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(8317);
// Signed provenance evidence bundles (Finding Provenance PRD, M4 §4.1).
//
// Sibling to posture/evidence-bundle.js, not a generalization of it — that
// module's bundle shape (proofTier, taintPath, exploitability...) answers
// "is this finding real"; this one answers "who/when introduced it, how
// sure are we." Forcing one shape to cover both would leave half of every
// bundle null. Same four-function pattern (build/sign/verify + a schema
// string + a top-level-key allowlist), same Ed25519 key material — reused,
// not reimplemented.
//
// The allowlisted fields mirror provenance/coordinator.js's own
// computeDigest() material EXACTLY (stableId, findingOrigin.commit,
// branchIntroduction.commit, evidenceAttribution role:path:line:commit
// strings, method, confidence.reasons, limitations) plus repo/HEAD identity
// (not in computeDigest's material, since that digest never leaves the repo
// it was computed in, but a bundle does). Everything here is copied from
// what findingProvenance already computed. Nothing is inferred.
//
// canonicalJson vs canonicalBytes — resolved before writing this file
// -------------------------------------------------------------------
// evidence-bundle.js exports TWO canonicalisation helpers, not one, and they
// are not interchangeable. `canonicalJson(value)` is a pure, shape-agnostic
// deterministic serialiser (sorted keys at every level, order-preserving
// arrays) — safe to reuse for any bundle shape. `canonicalBytes(bundle)`
// is NOT generic: it hardcodes evidence-bundle.js's own six top-level keys
// (`schema, finding, evidence, engine, proves, doesNotProve`) when building
// the object it signs. Reusing `canonicalBytes` here would silently sign a
// filtered object missing this module's `repo` and `provenance` fields
// (and would read `bundle.evidence`, which a provenance bundle never has) —
// exactly the EA-03 failure mode the allowlist check below exists to catch,
// just introduced from the signing side instead of the verifying side. So
// this module imports the generic `canonicalJson` (as the brief's Step 1
// sketch already did) and signs `canonicalJson(bundle)` directly, since
// `buildProvenanceEvidenceBundle` never puts anything on the unsigned
// object beyond this module's own allowlisted fields.




const PROVENANCE_BUNDLE_SCHEMA = 'agentic-security/provenance-evidence@1';

const PROVES = 'This bundle\'s contents are exactly what was signed at attestation time.';
const DOES_NOT_PROVE = 'This bundle does NOT prove the origin commit is correctly identified — read confidence.level and limitations for that. It proves the RECORD is unmodified, not that the record is right.';

/**
 * Build an unsigned provenance bundle from one finding's findingProvenance.
 * Returns null for a finding with no findingProvenance at all (nothing to
 * attest) — this is a caller error (attest a scan before its provenance
 * pass ran), not a case to paper over with an empty bundle.
 */
function buildProvenanceEvidenceBundle(finding, { engineVersion, repoIdentity, head } = {}) {
  if (!finding || typeof finding !== 'object') return null;
  const fp = finding.findingProvenance;
  if (!fp || typeof fp !== 'object') return null;
  return {
    schema: PROVENANCE_BUNDLE_SCHEMA,
    finding: {
      id: finding.id ?? null,
      stableId: finding.stableId ?? null,
    },
    repo: {
      identity: repoIdentity ?? null,
      head: head ?? fp.analysisBasis?.head ?? null,
    },
    provenance: {
      status: fp.status ?? null,
      findingOrigin: fp.findingOrigin
        ? {
            commit: fp.findingOrigin.commit ?? null,
            authorName: fp.findingOrigin.authorName ?? null,
            authorDate: fp.findingOrigin.authorDate ?? null,
            summary: fp.findingOrigin.summary ?? null,
          }
        : null,
      branchIntroduction: fp.branchIntroduction
        ? { commit: fp.branchIntroduction.commit ?? null, branch: fp.branchIntroduction.branch ?? null }
        : null,
      evidenceAttribution: (fp.evidenceAttribution || []).map((n) => ({
        role: n.role ?? null, path: n.path ?? null, line: n.line ?? null, commit: n.commit ?? null,
      })),
      method: fp.method ?? null,
      confidence: fp.confidence
        ? { level: fp.confidence.level ?? null, score: fp.confidence.score ?? null, reasons: fp.confidence.reasons || [] }
        : null,
      limitations: fp.limitations || [],
    },
    engine: { engineVersion: engineVersion ?? null },
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  };
}

function signProvenanceEvidenceBundle(bundle, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_0__.sign(null, Buffer.from((0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__/* .canonicalJson */ .dj)(bundle), 'utf8'), privateKeyPem);
  return {
    ...bundle,
    signature: { algorithm: 'ed25519', canonicalisation: PROVENANCE_BUNDLE_SCHEMA, value: sig.toString('base64') },
  };
}

const PROVENANCE_BUNDLE_TOP_LEVEL_KEYS = new Set([
  'schema', 'finding', 'repo', 'provenance', 'engine', 'proves', 'doesNotProve', 'signature',
]);

/**
 * Verify with a PUBLIC key only. Rejects any top-level key outside the
 * allowlist BEFORE checking the signature — same EA-03 fix evidence-bundle.js
 * carries: a signature only covers the bytes it was computed over, so an
 * unknown key stapled on after signing would otherwise verify as authentic.
 */
function verifyProvenanceEvidenceBundle(bundle, publicKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== PROVENANCE_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  const unknownKeys = Object.keys(bundle).filter((k) => !PROVENANCE_BUNDLE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  const { signature, ...unsigned } = bundle;
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(canonicalJson(unsigned), 'utf8'), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return ok
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
}




/***/ })

};
