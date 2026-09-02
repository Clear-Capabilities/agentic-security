export const id = 3736;
export const ids = [3736];
export const modules = {

/***/ 3736:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildPolicyBundle: () => (/* binding */ buildPolicyBundle),
/* harmony export */   ensurePolicyKeyPair: () => (/* binding */ ensurePolicyKeyPair),
/* harmony export */   loadPolicyBundles: () => (/* binding */ loadPolicyBundles),
/* harmony export */   loadPolicyPublicKey: () => (/* binding */ loadPolicyPublicKey),
/* harmony export */   resolveEffectivePolicy: () => (/* binding */ resolveEffectivePolicy),
/* harmony export */   signPolicyBundle: () => (/* binding */ signPolicyBundle)
/* harmony export */ });
/* unused harmony exports POLICY_BUNDLE_SCHEMA, SCOPES, canonicalPolicyBytes, verifyPolicyBundle, computePolicyDrift */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(8161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(7598);
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(8317);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(1174);
// Signed, portable policy bundles (assurance-hardening PRD FR-1001).
//
// "Support signed portable policy bundles with organization, repository, and
// environment inheritance" | "Tampered or expired policy is rejected;
// effective policy is explainable."
//
// WHY REUSE evidence-bundle.js's Ed25519 SCHEME, NOT integrity.js's HMAC
// -------------------------------------------------------------------------
// A policy bundle is authored by one party (typically a central security
// team, "the organization") and distributed to many repositories that never
// had the signing key. integrity.js's per-install symmetric HMAC is
// tamper-evidence for the SAME install that wrote it — a different install
// verifying a bundle it didn't sign is exactly the case that scheme cannot
// serve. evidence-bundle.js already solved this for findings: Ed25519,
// verify with only the public key. This module reuses that primitive
// directly (canonicalisation shape, allowlist-signed-fields discipline,
// exclusive-create key generation) rather than inventing a third signing
// mechanism, per this session's own established "survey before building a
// parallel primitive" practice (see D-0023/D-0025 for the same discipline
// applied to identity and exception mechanisms respectively).
//
// EA-03 LESSON, APPLIED HERE FROM THE START
// -------------------------------------------------------------------------
// evidence-bundle.js's own history (see its EA-03 comment) is the reason
// `canonicalPolicyBytes` signs an explicit ALLOWLIST and `verifyPolicyBundle`
// REJECTS any top-level key outside it: a bundle with a field stapled on
// after signing must fail verification, not silently pass with the addition
// unverified. Getting this right on the first pass — rather than discovering
// the gap the way evidence-bundle.js did — is the entire point of writing it
// down here.
//
// SCOPE — WHAT THIS MODULE DOES NOT DO
// -------------------------------------------------------------------------
// It does not invent a policy SCHEMA — `policy` is an opaque object; whatever
// keys a bundle carries (egress rules, severity floors, approved providers,
// anything else this repo already treats as policy) are merged the same way.
// It does not implement deep/recursive merging — inheritance is shallow,
// top-level-key override (organization -> repository -> environment, most
// specific wins per key), matching how every other flat policy config file
// in this repo (egress-policy.yml, compliance-severity-policy.json, …) is
// already shaped. A future consumer needing nested-key inheritance is new,
// separate scope, not assumed here.








const POLICY_BUNDLE_SCHEMA = 'agentic-security/policy-bundle@1';

const SCOPES = ['organization', 'repository', 'environment'];
// Inheritance order — later entries override earlier ones, per top-level key.
const INHERITANCE_ORDER = ['organization', 'repository', 'environment'];

function keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME || node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.config');
  return node_path__WEBPACK_IMPORTED_MODULE_2__.join(xdg, 'agentic-security', 'policy-bundles');
}

/** A SEPARATE Ed25519 keypair from evidence-bundle.js's finding-attestation
 * key — signing "this policy is authentic" and "this finding really came
 * from a scan run by me" are different trust domains and must not share a
 * key. Reuses evidence-bundle.js's hardened, race-safe generation logic
 * directly (its exclusive-create collision handling is the kind of code
 * worth NOT re-implementing) rather than duplicating it — the separation
 * that matters is the DIRECTORY (`policy-bundles/`, isolated from
 * evidence-bundle.js's own key dir), not the leaf filenames, which are
 * `attest-key.pem`/`attest-key.pub.pem` regardless of caller (a
 * evidence-bundle.js internal, not overridable here) — a readability wart,
 * not a security one, since the directory is what prevents key reuse. */
function ensurePolicyKeyPair(dir = keyDir()) {
  return (0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__.ensureKeyPair)(dir);
}

/**
 * Deterministic JSON, keys sorted at every level — identical algorithm to
 * evidence-bundle.js's canonicalJson (duplicated rather than imported: it is
 * a pure, three-line function, and importing it would couple this module's
 * signature format to evidence-bundle.js's internals for no real benefit).
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

// The complete set of fields a legitimately-built bundle carries, BEFORE
// signing. This is the signed allowlist AND (in verifyPolicyBundle) the
// complete set of keys a signed bundle is permitted to have alongside
// `signature` — see the EA-03 note above for why both matter.
const BUNDLE_FIELDS = ['schema', 'scope', 'policy', 'issuedAt', 'expiresAt'];
const BUNDLE_TOP_LEVEL_KEYS = new Set([...BUNDLE_FIELDS, 'signature']);

function canonicalPolicyBytes(bundle) {
  const signed = {};
  for (const k of BUNDLE_FIELDS) signed[k] = bundle[k] ?? null;
  return Buffer.from(canonicalJson(signed), 'utf8');
}

/**
 * Build an unsigned bundle. `policy` is caller-supplied and opaque — this
 * module does not validate its shape, only its provenance and freshness.
 */
function buildPolicyBundle(scope, policy, { issuedAt, expiresAt } = {}) {
  if (!SCOPES.includes(scope)) return null;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return null;
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    scope,
    policy,
    issuedAt: issuedAt ?? new Date().toISOString(),
    expiresAt: expiresAt ?? null,
  };
}

/** Sign a bundle. Returns a new object; the input is not mutated. */
function signPolicyBundle(bundle, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_3__.sign(null, canonicalPolicyBytes(bundle), privateKeyPem);
  return {
    ...bundle,
    signature: { algorithm: 'ed25519', canonicalisation: POLICY_BUNDLE_SCHEMA, value: sig.toString('base64') },
  };
}

/**
 * Verify a bundle: signature authenticity AND freshness. Never throws — a
 * malformed or tampered bundle from an untrusted source (a repo checking out
 * whatever an org distributed) is an expected input, not exceptional.
 *
 * @returns {{ok: boolean, reason: string|null}}
 */
function verifyPolicyBundle(bundle, publicKeyPem, { now = Date.now() } = {}) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== POLICY_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  if (!SCOPES.includes(bundle.scope)) return { ok: false, reason: `unrecognised scope: ${bundle.scope}` };
  const unknownKeys = Object.keys(bundle).filter(k => !BUNDLE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let sigOk = false;
  try {
    sigOk = node_crypto__WEBPACK_IMPORTED_MODULE_3__.verify(null, canonicalPolicyBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  if (!sigOk) return { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
  if (bundle.expiresAt) {
    const exp = Date.parse(bundle.expiresAt);
    if (!Number.isFinite(exp)) return { ok: false, reason: `expiresAt is not a valid date: ${bundle.expiresAt}` };
    if (exp < now) return { ok: false, reason: `policy expired on ${bundle.expiresAt}` };
  }
  return { ok: true, reason: null };
}

/**
 * Merge verified bundles into one effective policy, in inheritance order
 * (organization -> repository -> environment; most specific wins per key).
 * A tampered or expired bundle is EXCLUDED from the merge (rejected, not
 * silently dropped — its scope and reason are reported so a rejection is
 * visible, not just absent). `provenance[key]` names which scope's bundle
 * last set that key — the "effective policy is explainable" half of the
 * acceptance criterion.
 *
 * @param {Array<{scope: string, bundle: object}>} entries
 * @param {string} publicKeyPem
 * @returns {{effective: object, provenance: Record<string,string>,
 *   accepted: string[], rejected: Array<{scope:string, reason:string}>}}
 */
function resolveEffectivePolicy(entries, publicKeyPem, { now = Date.now() } = {}) {
  const byScope = new Map();
  for (const e of entries || []) {
    if (e && SCOPES.includes(e.scope)) byScope.set(e.scope, e.bundle);
  }
  const effective = {};
  const provenance = {};
  const accepted = [];
  const rejected = [];
  for (const scope of INHERITANCE_ORDER) {
    const bundle = byScope.get(scope);
    if (!bundle) continue;
    const v = verifyPolicyBundle(bundle, publicKeyPem, { now });
    if (!v.ok) { rejected.push({ scope, reason: v.reason }); continue; }
    accepted.push(scope);
    for (const [k, val] of Object.entries(bundle.policy)) {
      effective[k] = val;
      provenance[k] = scope;
    }
  }
  return { effective, provenance, accepted, rejected };
}

/**
 * Load whichever policy bundle files exist under
 * `.agentic-security/policy-bundles/{organization,repository,environment}.json`.
 * Degrades gracefully — a missing directory or missing/malformed individual
 * file is simply absent from the result, never thrown. Read-first-in-try/
 * catch throughout (no existsSync-then-readFileSync — D-0012/D-0022).
 */
function loadPolicyBundles(scanRoot) {
  if (!scanRoot) return [];
  const entries = [];
  for (const scope of SCOPES) {
    let fp;
    try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__/* .statePath */ .BQ)(scanRoot, 'policy-bundles', `${scope}.json`); } catch { continue; }
    let raw;
    try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { continue; }
    try {
      const bundle = JSON.parse(raw);
      if (bundle && typeof bundle === 'object') entries.push({ scope, bundle });
    } catch { /* malformed — skip, do not throw */ }
  }
  return entries;
}

/**
 * Read the operator-supplied public key an org distributes alongside its
 * bundles, from `.agentic-security/policy-bundle-public-key.pem`. Returns
 * null (not a throw) if absent or unreadable — resolution then rejects
 * every bundle for lack of a key, same as any other "no public key
 * supplied" case in verifyPolicyBundle.
 */
function loadPolicyPublicKey(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__/* .statePath */ .BQ)(scanRoot, 'policy-bundle-public-key.pem'); } catch { return null; }
  try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return null; }
}

/**
 * FR-1006 ("policy drift"): does this repository's LOCALLY resolved effective
 * policy diverge from what the organization-scope bundle alone specifies —
 * and is anything the repo is relying on actually being rejected (tampered
 * or expired) rather than enforced? Both are GOVERNANCE gaps, distinct from
 * risk findings, which is the exact distinction FR-1006's acceptance
 * criterion asks fleet output to make.
 *
 * No bundles configured at all is a no-op (`null`), matching this session's
 * established convention: drift can only be reported relative to a
 * baseline, and a repo with no organization bundle has no baseline to drift
 * from.
 *
 * @returns {{accepted: string[], rejected: Array<{scope,reason}>,
 *   overrides: Array<{key, organizationValue, effectiveValue, overriddenBy}>}
 *   | null}
 */
function computePolicyDrift(scanRoot) {
  const entries = loadPolicyBundles(scanRoot);
  if (!entries.length) return null;
  const publicKeyPem = loadPolicyPublicKey(scanRoot);
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(entries, publicKeyPem);

  const overrides = [];
  const orgEntry = entries.find(e => e.scope === 'organization');
  if (orgEntry && accepted.includes('organization')) {
    for (const [key, organizationValue] of Object.entries(orgEntry.bundle.policy || {})) {
      const overriddenBy = provenance[key];
      if (overriddenBy && overriddenBy !== 'organization' && !_deepEqual(effective[key], organizationValue)) {
        overrides.push({ key, organizationValue, effectiveValue: effective[key], overriddenBy });
      }
    }
  }
  return { accepted, rejected, overrides };
}

function _deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}


/***/ })

};
