export const id = 262;
export const ids = [262];
export const modules = {

/***/ 70262:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ARTIFACT_BUNDLE_SCHEMA: () => (/* binding */ ARTIFACT_BUNDLE_SCHEMA),
/* harmony export */   buildArtifactEvidenceBundle: () => (/* binding */ buildArtifactEvidenceBundle),
/* harmony export */   ensureKeyPair: () => (/* reexport safe */ _posture_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__.ensureKeyPair),
/* harmony export */   signArtifactEvidenceBundle: () => (/* binding */ signArtifactEvidenceBundle),
/* harmony export */   verifyArtifactEvidenceBundle: () => (/* binding */ verifyArtifactEvidenceBundle)
/* harmony export */ });
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _posture_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(32876);
// A signed, portable evidence bundle for one image scan (PRD 5; the sibling-bundle pattern of provenance-evidence-bundle.js).
// Ed25519, verifiable with only the public key, same key material and the same defence as its siblings: an ALLOWLIST of top-level
// keys is signed, and a bundle with any other key is refused, because a signature covers only the bytes it was computed over.
//
// What it carries is what the scan found, and nothing that is secret: secret findings are reported by layer, path and kind, never by
// value. What it proves is that the record is unmodified since signing. It does not prove the scan was complete or the image safe;
// the truncation flags and the signature state travel inside it so a reader can see how much was and was not checked.



const ARTIFACT_BUNDLE_SCHEMA = 'agentic-security/artifact-evidence@1';
const PROVES = 'This bundle\'s contents are exactly what was signed at attestation time.';
const DOES_NOT_PROVE = 'This bundle does NOT prove the image is free of vulnerabilities or secrets: read `scan.truncated` and `scan.vulnerabilityLookup` for how much was checked, and `signature` for whether the image\'s own signature was verified. It proves the RECORD is unmodified, not that the conclusions are complete.';
const MAX_ITEMS = 500;

function buildArtifactEvidenceBundle(record, { engineVersion = null, source = null, signatureResult = null } = {}) {
  if (!record?.inventory?.digest) return null;
  const inv = record.inventory;
  const vulns = (record.vulnerabilities || []).filter((v) => v?.type === 'vulnerable_dep');
  return {
    schema: ARTIFACT_BUNDLE_SCHEMA,
    artifact: {
      digest: inv.digest, digestKind: inv.digestKind ?? null, format: inv.format ?? null, os: inv.os ?? null, architecture: inv.architecture ?? null,
      labels: inv.buildLabels ?? inv.labels ?? null, source: source ? { kind: source.kind ?? null, registry: source.registry ?? null, repository: source.repository ?? null, reference: source.reference ?? null, runtime: source.runtime ?? null } : null,
    },
    scan: {
      scannedAt: record.scannedAt ?? null,
      packages: { os: inv.osPackages?.length ?? 0, app: inv.appPackages?.length ?? 0 },
      vulnerabilities: vulns.slice(0, MAX_ITEMS).map((v) => ({ id: v.id ?? v.vulnId ?? null, package: v.package ?? v.name ?? null, version: v.version ?? null, severity: v.severity ?? null, cve: v.cve ?? null, kev: v.kev ?? null })),
      secrets: (record.secrets?.deletedButRecoverable || []).slice(0, MAX_ITEMS).map((s) => ({ layer: s.layerIndex ?? s.addedInLayer ?? null, path: s.path ?? null, kind: s.kind ?? s.type ?? s.vuln ?? null })),
      truncated: { materialization: !!inv.materializationTruncated, vulnerabilitiesListed: Math.min(vulns.length, MAX_ITEMS), vulnerabilitiesTotal: vulns.length, secretsListed: Math.min(record.secrets?.deletedButRecoverable?.length ?? 0, MAX_ITEMS), secretsTotal: record.secrets?.deletedButRecoverable?.length ?? 0 },
      vulnerabilityLookup: record.vulnerabilityLookup ?? 'osv (cached or live; see scannedAt)',
    },
    signature: signatureResult ? { state: signatureResult.state ?? null, via: signatureResult.via ?? null, reason: signatureResult.reason ?? null } : { state: 'not-checked', via: null, reason: 'no signature verification was requested for this bundle' },
    engine: { engineVersion },
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  };
}

function signArtifactEvidenceBundle(bundle, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_0__.sign(null, Buffer.from((0,_posture_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__/* .canonicalJson */ .dj)(bundle), 'utf8'), privateKeyPem);
  return { ...bundle, attestation: { algorithm: 'ed25519', canonicalisation: ARTIFACT_BUNDLE_SCHEMA, value: sig.toString('base64') } };
}

const TOP_LEVEL = new Set(['schema', 'artifact', 'scan', 'signature', 'engine', 'proves', 'doesNotProve', 'attestation']);

function verifyArtifactEvidenceBundle(bundle, publicKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== ARTIFACT_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  const unknown = Object.keys(bundle).filter((k) => !TOP_LEVEL.has(k));
  if (unknown.length) return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknown.join(', ')}` };
  const att = bundle.attestation;
  if (!att?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (att.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${att.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  const { attestation, ...unsigned } = bundle;
  let ok = false;
  try { ok = node_crypto__WEBPACK_IMPORTED_MODULE_0__.verify(null, Buffer.from((0,_posture_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_1__/* .canonicalJson */ .dj)(unsigned), 'utf8'), publicKeyPem, Buffer.from(att.value, 'base64')); } catch (e) { return { ok: false, reason: `verification error: ${e.message}` }; }
  return ok ? { ok: true, reason: null } : { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
}




/***/ })

};
