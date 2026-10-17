export const id = 3917;
export const ids = [3917];
export const modules = {

/***/ 93917:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyReleasePackage: () => (/* binding */ verifyReleasePackage)
/* harmony export */ });
/* unused harmony export MINIMUM_KINDS */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
// The verifier for a signed release assurance package (E7-03). Used by `scripts/verify-release-package.mjs` (a command-line wrapper) and by `release-view`.
//
// This file imports nothing but Node built-ins. It does not use the producer's code, so a defect in the producer cannot make it agree with itself. What it
// checks, each reported under its own code:
//   FORMAT      known schema, supported major version, no unknown top-level keys
//   SIGNATURE   Ed25519 over the domain label plus the canonical JSON of everything but the signature, verified with the key the CALLER supplies; the key the
//               package names must be the same key (a package cannot vouch for itself, and a signature lifted from another package does not verify)
//   SNAPSHOT    the snapshot digest matches its fields
//   EVIDENCE    every record matches the digest in its reference; every reference matches its own digest; every reference is bound to this snapshot
//   LINEAGE     every dependency is present, there is no cycle, and the stated order is the dependency order
//   MANDATORY   every kind in the verifier's own minimum, in the caller's --require list, and in the package's own list is present
//   COMPLETE    the package may not claim a complete scan over a scan health that is not complete
//   FINDINGS    each finding's proof tier and exploitability flag equal what the finding itself says
//   ASSERTIONS  every cited record is in the package, and a "supported" statement cites at least one


const MINIMUM_KINDS = Object.freeze(['scan-health', 'finding']);
const SCHEMA = 'agentic-security/release-package';
const DOMAIN = `${SCHEMA}@1\n`;
const TOP_KEYS = new Set(['schema', 'schemaVersion', 'snapshot', 'evidence', 'lineageOrder', 'requiredKinds', 'findings', 'completeness', 'policy', 'assertions', 'proves', 'doesNotProve', 'issuance', 'signature']);
const ROLES = new Set(['finding', 'completeness', 'context', 'control', 'inventory']);

const canon = (v) => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
};
const digest = (v) => `sha256:${node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(canon(v)).digest('hex')}`;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function verifyReleasePackage(pkg, publicKeyPem, { require: extraRequired = [] } = {}) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  if (!isObj(pkg)) return { ok: false, errors: [{ code: 'FORMAT', message: 'the package is not an object' }] };
  if (pkg.schema !== SCHEMA) fail('FORMAT', `unrecognised schema ${JSON.stringify(pkg.schema)}`);
  const major = Number(String(pkg.schemaVersion).split('.')[0]);
  if (major !== 1) fail('FORMAT', `unsupported version ${JSON.stringify(pkg.schemaVersion)}`);
  for (const k of Object.keys(pkg)) if (!TOP_KEYS.has(k)) fail('FORMAT', `unrecognised top-level key "${k}", which the signature does not vouch for`);
  if (errors.length) return { ok: false, errors };

  // ---- SIGNATURE
  const sig = pkg.signature;
  let publicKey = null;
  if (!publicKeyPem) fail('SIGNATURE', 'no public key was supplied');
  else { try { publicKey = node_crypto__WEBPACK_IMPORTED_MODULE_0__.createPublicKey(publicKeyPem); } catch (e) { fail('SIGNATURE', `the public key is unusable: ${e.message}`); } }
  if (!isObj(sig) || sig.algorithm !== 'ed25519' || typeof sig.value !== 'string') fail('SIGNATURE', 'the package is unsigned or uses an unsupported algorithm');
  else if (publicKey) {
    const { signature, ...rest } = pkg;
    let ok = false;
    try { ok = node_crypto__WEBPACK_IMPORTED_MODULE_0__.verify(null, Buffer.from(DOMAIN + canon(rest), 'utf8'), publicKey, Buffer.from(sig.value, 'base64')); } catch (e) { fail('SIGNATURE', `verification error: ${e.message}`); }
    if (!ok && !errors.some((e) => e.code === 'SIGNATURE')) fail('SIGNATURE', 'the signature does not match the package contents: something changed after signing, or it was signed by another key');
    const fp = node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const named = pkg.issuance && pkg.issuance.issuer && pkg.issuance.issuer.keyFingerprint;
    if (named !== fp) fail('SIGNATURE', 'the key the package names is not the key supplied for verification');
    if (!pkg.issuance || pkg.issuance.independentlyCertified !== false) fail('SIGNATURE', 'a self-issued package may not claim independent certification');
  }

  // ---- SNAPSHOT
  const snap = pkg.snapshot;
  if (!isObj(snap)) fail('SNAPSHOT', 'there is no snapshot');
  else {
    const { digest: d, immutable, ...body } = snap;
    if (d !== digest(body)) fail('SNAPSHOT', 'the snapshot does not match its digest');
    if (immutable !== (!!body.commit && body.dirty === false)) fail('SNAPSHOT', 'the snapshot\'s immutability flag is not what its fields imply');
  }

  // ---- EVIDENCE
  const entries = Array.isArray(pkg.evidence) ? pkg.evidence : [];
  if (!Array.isArray(pkg.evidence)) fail('EVIDENCE', 'evidence is not a list');
  const byDigest = new Map();
  for (const [i, e] of entries.entries()) {
    if (!isObj(e) || !isObj(e.ref) || !('payload' in e)) { fail('EVIDENCE', `entry ${i} is malformed`); continue; }
    if (!ROLES.has(e.role)) fail('EVIDENCE', `entry ${i} has an unknown role ${JSON.stringify(e.role)}`);
    const { digest: rd, findingProvenanceDigest, otherProvenanceDigest, ...rb } = e.ref;
    if (rd !== digest(rb)) fail('EVIDENCE', `the reference of entry ${i} (${e.ref.kind}) does not match its own digest`);
    if (e.ref.payloadDigest !== digest(e.payload)) fail('EVIDENCE', `the ${e.ref.kind} record in entry ${i} does not match the digest in its reference`);
    if (isObj(snap) && e.ref.snapshotDigest !== snap.digest) fail('EVIDENCE', `the ${e.ref.kind} record in entry ${i} describes a different snapshot`);
    if (byDigest.has(e.ref.digest)) fail('EVIDENCE', `entry ${i} duplicates another reference`);
    byDigest.set(e.ref.digest, e);
  }

  // ---- LINEAGE
  for (const e of byDigest.values()) for (const dep of e.ref.restsOn || []) if (!byDigest.has(dep)) fail('LINEAGE', `${e.ref.kind} rests on a record that is not in the package (${String(dep).slice(0, 19)}...)`);
  const state = new Map(); const order = [];
  const visit = (d, trail) => {
    if (state.get(d) === 2) return; if (state.get(d) === 1) { fail('LINEAGE', `cycle through ${trail.concat(d).map((x) => x.slice(7, 15)).join(' -> ')}`); return; }
    state.set(d, 1);
    for (const dep of (byDigest.get(d) || { ref: {} }).ref.restsOn || []) if (byDigest.has(dep)) visit(dep, trail.concat(d));
    state.set(d, 2); order.push(d);
  };
  for (const d of [...byDigest.keys()].sort()) visit(d, []);
  if (JSON.stringify(order) !== JSON.stringify(pkg.lineageOrder)) fail('LINEAGE', 'the stated order is not the dependency order');
  if (JSON.stringify(entries.map((e) => e && e.ref && e.ref.digest)) !== JSON.stringify(pkg.lineageOrder)) fail('LINEAGE', 'the evidence list is not in the stated order');

  // ---- MANDATORY
  const kinds = new Set([...byDigest.values()].map((e) => e.ref.kind));
  const needed = new Set([...MINIMUM_KINDS, ...extraRequired, ...(Array.isArray(pkg.requiredKinds) ? pkg.requiredKinds : [])]);
  for (const k of MINIMUM_KINDS) if (!(Array.isArray(pkg.requiredKinds) && pkg.requiredKinds.includes(k))) fail('MANDATORY', `the package does not declare "${k}" as required`);
  for (const k of [...needed].sort()) if (!kinds.has(k)) fail('MANDATORY', `required evidence is missing: ${k}`);

  // ---- COMPLETE
  const healthEntry = [...byDigest.values()].find((e) => e.ref.kind === 'scan-health');
  const c = pkg.completeness;
  if (!isObj(c)) fail('COMPLETE', 'there is no completeness statement');
  else if (healthEntry) {
    const hs = healthEntry.payload && healthEntry.payload.status;
    if (c.scanStatus !== hs) fail('COMPLETE', `the package states scan status ${JSON.stringify(c.scanStatus)} but the scan health says ${JSON.stringify(hs)}`);
    if (c.verdict === 'complete' && hs !== 'complete') fail('COMPLETE', 'the package claims a complete scan over a scan health that is not complete');
    if (c.verdict !== 'complete' && hs === 'complete') fail('COMPLETE', 'the package calls an unfinished scan complete or the reverse: the verdict disagrees with the scan health');
    if (JSON.stringify(c.conditions) !== JSON.stringify(Array.isArray(healthEntry.payload.conditions) ? healthEntry.payload.conditions : [])) fail('COMPLETE', 'the stated conditions differ from the scan health\'s own');
    if (c.source !== healthEntry.ref.digest) fail('COMPLETE', 'the completeness statement cites a different scan health');
  }

  // ---- FINDINGS
  const findingEntries = [...byDigest.values()].filter((e) => e.ref.kind === 'finding');
  const listed = new Map((Array.isArray(pkg.findings) ? pkg.findings : []).map((f) => [f.findingRef, f]));
  if (listed.size !== findingEntries.length) fail('FINDINGS', `the package lists ${listed.size} findings but contains ${findingEntries.length}`);
  for (const e of findingEntries) {
    const f = listed.get(e.ref.digest);
    if (!f) { fail('FINDINGS', `finding ${e.ref.payloadId} is in the package but not in its findings summary`); continue; }
    const tier = e.payload && typeof e.payload.proofTier === 'string' ? e.payload.proofTier : 'unproven';
    if (f.proofTier !== tier) fail('FINDINGS', `finding ${e.ref.payloadId}: the summary says proof tier ${JSON.stringify(f.proofTier)} but the finding says ${JSON.stringify(tier)}`);
    if (f.exploitabilityProven !== (tier === 'execution-proven')) fail('FINDINGS', `finding ${e.ref.payloadId}: exploitability is stated as proven without an execution proof`);
    if (f.integrity !== 'unmodified-since-signing') fail('FINDINGS', `finding ${e.ref.payloadId}: unexpected integrity statement`);
  }

  // ---- ASSERTIONS
  for (const a of Array.isArray(pkg.assertions) ? pkg.assertions : []) {
    for (const d of a.evidence || []) if (!byDigest.has(d)) fail('ASSERTIONS', `assertion ${a.id} cites a record that is not in the package`);
    if (a.status === 'supported' && !(a.evidence || []).length) fail('ASSERTIONS', `assertion ${a.id} is "supported" but cites nothing`);
    if (!['supported', 'unsupported', 'unknown'].includes(a.status)) fail('ASSERTIONS', `assertion ${a.id} has an unknown status`);
  }
  return { ok: errors.length === 0, errors, issuer: pkg.issuance && pkg.issuance.issuer, completeness: isObj(c) ? c.verdict : null };
}



/***/ })

};
