export const id = 7798;
export const ids = [7798,2530];
export const modules = {

/***/ 17798:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdReleasePackage: () => (/* binding */ cmdReleasePackage)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(69259);
// EXTERNAL MODULE: ./src/posture/integrity.js
var integrity = __webpack_require__(37455);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(91026);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(99666);
;// CONCATENATED MODULE: ./src/posture/assurance/evidence-registry.js
// The evidence contract inventory (E7-01): every kind of evidence the product emits, how each names its schema and identity, and one uniform way to
// bind any of them to an immutable snapshot.
//
// WHY. The evidence a release rests on comes from a dozen producers written at different times. They name their schema three different ways
// (`x/y@1`, `x/y` plus a `schemaVersion` of 1.0.0, `thing/1`), identify records by a field called `id`, `stableId`, `findingId` or nothing, and refer to the code
// they describe by a commit, a tree hash, an engine version or not at all. A reader (an auditor, a verifier, a signed release package) cannot tell what a
// record is about or whether two records are about the same code. This module does not change any producer. It
//   1. records, for each kind, how to read its schema, version and id (`describeEvidence`), so they are comparable;
//   2. wraps any record in an EvidenceRef: its kind, schema, version, id, a digest of its canonical content, the digest of the snapshot it describes, and
//      the digests of the evidence it rests on (`buildEvidenceRef`), checked by `verifyEvidenceRef`;
//   3. checks a set of refs as a lineage (`checkLineage`): no ref points at a digest that is not in the set, no cycle, no ref bound to a different snapshot
//      than the evidence it rests on;
//   4. refuses an unknown kind, a future major version and a record that does not carry what its kind promises (`inspectEvidence`).
//
// A SNAPSHOT is a description of the code and the tool that produced a result: commit, tree digest, whether the working tree was dirty, engine version,
// bundle digest, configuration digest. Its digest covers all of those. A snapshot with a dirty tree or no commit is `immutable: false`, and a ref bound to
// it says so: evidence about code nobody can recover is evidence, but it is not evidence a release can be signed on.
//
// PROVENANCE. The git origin of a finding is `findingProvenance`. A bare `provenance` property on a finding belongs to other features and means something
// else. This module reads only the first, never merges the two, and the ref for a finding carries each under its own name.



const EVIDENCE_REF_SCHEMA = 'agentic-security/evidence-ref';
const EVIDENCE_REF_VERSION = '1.0.0';
const SNAPSHOT_SCHEMA = 'agentic-security/snapshot-ref';

/** How a kind spells its schema: `at` is `x/y@N`, `semver` is `{schema, schemaVersion}`, `slash` is `thing/N`, `none` is unversioned. */
const read = {
  at: (p, c) => { const v = String(c.field || 'schema').split('.').reduce((a, k) => (a === null || a === undefined ? undefined : a[k]), p); const m = typeof v === 'string' ? /^(.*)@(\d+)$/.exec(v) : null; return m ? { schema: m[1], version: `${m[2]}.0.0` } : null; },
  semver: (p, c) => (typeof p.schema === 'string' && typeof p.schemaVersion === 'string' ? { schema: p.schema, version: p.schemaVersion } : null),
  semverNumber: (p, c) => (typeof p.schema === 'string' && Number.isInteger(p.schemaVersion) ? { schema: p.schema, version: `${p.schemaVersion}.0.0` } : null),
  slash: (p, c) => { const m = typeof p[c.field] === 'string' ? /^(.*)\/(\d+)$/.exec(p[c.field]) : null; return m ? { schema: m[1], version: `${m[2]}.0.0` } : null; },
  none: () => null,
};

const at = (field = 'schema') => ({ style: 'at', field });
const SNAP = Object.freeze({ commit: 'commit', tree: 'tree', engine: 'engine', digest: 'digest', none: 'none' });

/**
 * The inventory. `producer` is the module that creates the record (a test checks it exists); `id` names the identity field; `snapshot` says how the record
 * refers to the code it describes today (`none` is a gap the EvidenceRef closes); `signed` says what protects it in transit.
 */
const EVIDENCE_KINDS = Object.freeze({
  finding: { title: 'scanner finding', producer: 'scanner/src/engine.js', schemaRead: { style: 'none' }, id: ['stableId', 'id'], snapshot: SNAP.none, signed: 'none', provenanceField: 'findingProvenance' },
  'scan-health': { title: 'scan health', producer: 'scanner/src/pipeline/scan-health.js', schemaRead: { style: 'versionOnly', field: 'schemaVersion' }, id: [], snapshot: SNAP.none, signed: 'hmac-with-last-scan' },
  'finding-evidence': { title: 'per-finding evidence bundle', producer: 'scanner/src/posture/evidence-bundle.js', schemaRead: at(), id: ['finding.stableId', 'finding.id'], snapshot: SNAP.commit, signed: 'ed25519' },
  'provenance-evidence': { title: 'finding provenance bundle', producer: 'scanner/src/posture/provenance-evidence-bundle.js', schemaRead: at(), id: ['finding.stableId', 'finding.id'], snapshot: SNAP.commit, signed: 'ed25519', provenanceField: 'provenance' },
  'compliance-evidence': { title: 'compliance evidence', producer: 'scanner/src/posture/compliance-evidence-signing.js', schemaRead: { style: 'at', field: 'signature.canonicalisation' }, id: [], snapshot: SNAP.none, signed: 'ed25519', note: 'the schema is declared only inside the signature block' },
  'obligation-evidence-pack': { title: 'regulatory obligation evidence pack', producer: 'scanner/src/posture/obligation-evidence-pack.js', schemaRead: at(), id: [], snapshot: SNAP.engine, signed: 'ed25519' },
  'fix-verification': { title: 'patch verification record', producer: 'scanner/src/fix/verification-record.js', schemaRead: { style: 'semver' }, id: ['id'], snapshot: SNAP.commit, signed: 'none' },
  verification: { title: 'hypothesis verification record', producer: 'scanner/src/posture/assurance/verification-record.js', schemaRead: { style: 'semver' }, id: ['id'], snapshot: SNAP.commit, signed: 'none' },
  'release-evidence': { title: 'release evidence', producer: 'scanner/src/posture/assurance/contracts.js', schemaRead: { style: 'semver' }, id: ['id'], snapshot: SNAP.commit, signed: 'none' },
  'dci-invariants': { title: 'context-intelligence invariants', producer: 'scanner/src/context-intelligence/invariants.js', schemaRead: { style: 'semver' }, id: [], snapshot: SNAP.none, signed: 'none' },
  'runtime-explanation': { title: 'static/runtime explanation', producer: 'scanner/src/posture/runtime-explanation.js', schemaRead: at(), id: ['findingStableId', 'findingId'], snapshot: SNAP.commit, signed: 'none' },
  'exploitability-evidence': { title: 'multi-level exploitability evidence', producer: 'scanner/src/posture/exploitability-evidence.js', schemaRead: at(), id: [], snapshot: SNAP.none, signed: 'none' },
  'semantic-graph': { title: 'semantic graph', producer: 'scanner/src/ir/semantic-graph.js', schemaRead: { style: 'semver' }, id: [], snapshot: SNAP.none, signed: 'none' },
  scorecard: { title: 'accuracy scorecard', producer: 'scanner/src/posture/accuracy-scorecard.js', schemaRead: at(), id: [], snapshot: SNAP.commit, signed: 'none' },
  sbom: { title: 'software bill of materials', producer: 'scanner/src/posture/sbom.js', schemaRead: { style: 'cyclonedx' }, id: [], snapshot: SNAP.none, signed: 'none', note: 'serialNumber is a fresh UUID on every run, so it does not identify the content' },
  'ai-bom': { title: 'AI bill of materials', producer: 'scanner/src/posture/aibom.js', schemaRead: { style: 'cyclonedx' }, id: [], snapshot: SNAP.none, signed: 'none', note: 'serialNumber is a fresh UUID on every run, so it does not identify the content' },
});

const EVIDENCE_KIND_NAMES = Object.freeze(Object.keys(EVIDENCE_KINDS));

const get = (o, path) => path.split('.').reduce((a, k) => (a === null || a === undefined ? undefined : a[k]), o);

/** Read schema, version and identity out of a record of `kind`, whatever convention the producer used. Never throws. */
function describeEvidence(kind, payload) {
  const k = EVIDENCE_KINDS[kind];
  if (!k) return { ok: false, reason: `unknown evidence kind "${kind}"` };
  if (!(0,schema_kit/* isPlainObject */.Qd)(payload)) return { ok: false, reason: 'the record is not an object' };
  const style = k.schemaRead.style;
  let sv = null;
  if (style === 'at' || style === 'slash') sv = read[style](payload, k.schemaRead);
  else if (style === 'semver') sv = typeof payload.schemaVersion === 'number' ? read.semverNumber(payload) : read.semver(payload);
  else if (style === 'versionOnly') sv = payload[k.schemaRead.field] !== undefined ? { schema: `agentic-security/${kind}`, version: Number.isInteger(payload[k.schemaRead.field]) ? `${payload[k.schemaRead.field]}.0.0` : String(payload[k.schemaRead.field]) } : null;
  else if (style === 'cyclonedx') sv = payload.bomFormat === 'CycloneDX' && payload.specVersion ? { schema: 'cyclonedx', version: String(payload.specVersion) } : null;
  let id = null;
  for (const f of k.id) { const v = get(payload, f); if (typeof v === 'string' && v) { id = v; break; } }
  return { ok: true, kind, schema: sv ? sv.schema : null, version: sv ? sv.version : null, id };
}

/**
 * What a record of this kind should carry, checked against the record itself.
 * @returns {{ok:boolean, gaps:string[], errors:string[]}} `gaps` are known weaknesses of the producer's format (informational); `errors` make the record unusable.
 */
function inspectEvidence(kind, payload) {
  const d = describeEvidence(kind, payload);
  if (!d.ok) return { ok: false, gaps: [], errors: [d.reason] };
  const k = EVIDENCE_KINDS[kind]; const gaps = []; const errors = [];
  if (k.schemaRead.style !== 'none' && !d.schema) errors.push('the record does not carry the schema declaration this kind promises');
  if (k.schemaRead.style === 'none') gaps.push('the format declares no schema or version');
  if (d.version) { const major = Number(d.version.split('.')[0]); if (Number.isFinite(major) && major > SUPPORTED_MAJOR && kind !== 'sbom' && kind !== 'ai-bom') errors.push(`major version ${major} is newer than this build supports (${SUPPORTED_MAJOR})`); }
  if (k.id.length && !d.id) errors.push(`the record carries none of its identity fields (${k.id.join(', ')})`);
  if (!k.id.length) gaps.push(k.note && /serialNumber/.test(k.note) ? 'the only identifier is random per run: the record is identified by the digest of its content' : 'the format has no identity field: it is identified by the digest of its content');
  if (k.note && !/serialNumber/.test(k.note)) gaps.push(k.note);
  if (k.snapshot === SNAP.none) gaps.push('the format does not say which code it describes');
  if (k.signed === 'none') gaps.push('the format is not signed on its own');
  return { ok: errors.length === 0, gaps, errors };
}

/**
 * How a record actually refers to the code it describes: the strongest of a commit, a tree hash, an engine version or a digest field that it carries WITH
 * A VALUE. This is read from the record, so the registry's declared `snapshot` can be checked against what a producer emits.
 */
function observeSnapshotBinding(payload) {
  const found = new Set();
  const walk = (v, depth) => {
    if (depth > 4 || !v || typeof v !== 'object') return;
    for (const [key, val] of Object.entries(v)) {
      if (typeof val === 'string' && val) {
        if (/^(commit|preCommit|head)$/.test(key) && /^[0-9a-f]{40,64}$/.test(val)) found.add('commit');
        else if (/^(preTreeHash|treeHash|treeDigest|postTreeHash)$/.test(key)) found.add('tree');
        else if (key === 'engineVersion') found.add('engine');
        else if (/^(sourceDigest|snapshotDigest|graphDigest|controlsDigest)$/.test(key)) found.add('digest');
      } else if (val && typeof val === 'object') walk(val, depth + 1);
    }
  };
  walk(payload, 0);
  for (const b of ['commit', 'tree', 'engine', 'digest']) if (found.has(b)) return b;
  return 'none';
}

// ---- snapshots -----------------------------------------------------------------------------------------------------------------

/** A description of the code and tool a result is about, with a digest over all of it. */
function buildSnapshotRef({ commit = null, treeDigest = null, dirty = false, engineVersion = null, bundleSha = null, configDigest = null } = {}) {
  const body = { schema: SNAPSHOT_SCHEMA, commit: commit || null, treeDigest: treeDigest || null, dirty: dirty === true, engineVersion: engineVersion || null, bundleSha: bundleSha || null, configDigest: configDigest || null };
  const immutable = !!body.commit && body.dirty === false;
  return { ...body, immutable, digest: (0,identity/* digestOf */.ol)(body) };
}

function verifySnapshotRef(s) {
  if (!(0,schema_kit/* isPlainObject */.Qd)(s) || s.schema !== SNAPSHOT_SCHEMA) return false;
  const { digest, immutable, ...body } = s;
  return digest === (0,identity/* digestOf */.ol)(body) && immutable === (!!body.commit && body.dirty === false);
}

// ---- evidence refs -------------------------------------------------------------------------------------------------------------

/**
 * @param {string} kind
 * @param {object} payload the evidence record, unmodified
 * @param {object} snapshot from buildSnapshotRef
 * @param {{rests_on?:string[]}} opts digests of the evidence this record rests on
 */
function buildEvidenceRef(kind, payload, snapshot, { restsOn = [] } = {}) {
  const d = describeEvidence(kind, payload);
  if (!d.ok) throw new Error(d.reason);
  if (!verifySnapshotRef(snapshot)) throw new Error('the snapshot is not a valid snapshot reference');
  for (const r of restsOn) if (!(0,schema_kit/* isDigest */.Bc)(r)) throw new Error(`restsOn holds a value that is not a digest: ${JSON.stringify(r)}`);
  const body = {
    schema: EVIDENCE_REF_SCHEMA, schemaVersion: EVIDENCE_REF_VERSION, kind,
    payloadSchema: d.schema, payloadVersion: d.version, payloadId: d.id,
    payloadDigest: (0,identity/* digestOf */.ol)(payload),
    snapshotDigest: snapshot.digest, snapshotImmutable: snapshot.immutable,
    restsOn: [...new Set(restsOn)].sort(),
  };
  const out = { ...body, digest: (0,identity/* digestOf */.ol)(body) };
  // the git origin of a finding is findingProvenance and nothing else; a bare `provenance` is another feature's field and is carried only as its own label
  if (kind === 'finding') {
    out.findingProvenanceDigest = (0,schema_kit/* isPlainObject */.Qd)(payload.findingProvenance) ? (0,identity/* digestOf */.ol)(payload.findingProvenance) : null;
    out.otherProvenanceDigest = payload.provenance !== undefined ? (0,identity/* digestOf */.ol)(payload.provenance) : null;
  }
  return out;
}

/** Re-derive a ref from the payload and snapshot it claims to describe. @returns {{ok:boolean, errors:string[]}} */
function verifyEvidenceRef(ref, payload, snapshot) {
  const errors = [];
  if (!isPlainObject(ref) || ref.schema !== EVIDENCE_REF_SCHEMA) return { ok: false, errors: ['not an evidence reference'] };
  if (Number(String(ref.schemaVersion).split('.')[0]) !== SUPPORTED_MAJOR) return { ok: false, errors: [`unsupported evidence reference version ${ref.schemaVersion}`] };
  const { digest, findingProvenanceDigest, otherProvenanceDigest, ...body } = ref;
  if (digestOf(body) !== digest) errors.push('the reference was altered after it was built (its digest does not match its fields)');
  if (!EVIDENCE_KINDS[ref.kind]) errors.push(`unknown evidence kind "${ref.kind}"`);
  else {
    if (digestOf(payload) !== ref.payloadDigest) errors.push('the evidence record does not match the digest in its reference');
    if (!snapshot || snapshot.digest !== ref.snapshotDigest || !verifySnapshotRef(snapshot)) errors.push('the snapshot does not match the reference');
    const d = describeEvidence(ref.kind, payload);
    if (d.ok && (d.schema !== ref.payloadSchema || d.version !== ref.payloadVersion || d.id !== ref.payloadId)) errors.push('the record\'s schema, version or id differs from what the reference states');
    if (ref.kind === 'finding' && isPlainObject(payload)) {
      const fp = isPlainObject(payload.findingProvenance) ? digestOf(payload.findingProvenance) : null;
      if ((findingProvenanceDigest ?? null) !== fp) errors.push('findingProvenance differs from what the reference states');
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * A set of refs is a lineage when every `restsOn` digest names a ref in the set, nothing rests on itself through a cycle, and evidence rests only on
 * evidence about the SAME snapshot. @returns {{ok:boolean, errors:string[], order:string[]}} order is a dependency-first ordering of ref digests
 */
function checkLineage(refs) {
  const errors = [];
  const by = new Map();
  for (const r of refs) { if (by.has(r.digest)) errors.push(`duplicate reference ${r.digest}`); by.set(r.digest, r); }
  for (const r of refs) {
    for (const dep of r.restsOn || []) {
      const t = by.get(dep);
      if (!t) errors.push(`${r.kind} ${r.payloadId ?? r.digest.slice(0, 19)} rests on ${dep.slice(0, 19)}..., which is not in the set (dangling)`);
      else if (t.snapshotDigest !== r.snapshotDigest) errors.push(`${r.kind} rests on ${t.kind} that describes a different snapshot`);
    }
  }
  const order = []; const state = new Map();
  const visit = (d, trail) => {
    if (state.get(d) === 2) return; if (state.get(d) === 1) { errors.push(`cycle through ${trail.concat(d).map((x) => x.slice(7, 15)).join(' -> ')}`); return; }
    state.set(d, 1);
    for (const dep of (by.get(d) || {}).restsOn || []) if (by.has(dep)) visit(dep, trail.concat(d));
    state.set(d, 2); order.push(d);
  };
  for (const d of [...by.keys()].sort()) visit(d, []);
  return { ok: errors.length === 0, errors, order };
}



// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./src/posture/evidence-bundle.js
var evidence_bundle = __webpack_require__(32876);
;// CONCATENATED MODULE: ./src/posture/assurance/release-package.js
// The signed release assurance package (E7-03): everything a reviewer needs to judge one release, in one portable file that can be checked offline.
//
// WHAT IT HOLDS. A snapshot (the code and tool the evidence is about), the evidence itself (each record with its EvidenceRef), the lineage that ties them
// together, the declared scan completeness taken from the scan's own `scanHealth`, the policy decisions applied, and a list of statements (`assertions`)
// each citing the evidence it rests on. It is signed with Ed25519. The signing key is the one the evidence bundles use (`attest` creates it); the verifier
// needs only the public key.
//
// TWO CLAIMS THAT MUST NOT BE CONFUSED.
//   INTEGRITY    The signature proves that nothing in the package changed since the key holder signed it: not a field, not the order of the evidence, not which
//                evidence is present. That is all it proves.
//   EXPLOITABILITY  Whether a finding is real, and whether it is exploitable, is a separate claim, carried per finding as `proofTier` and
//                `exploitabilityProven` (true only for `execution-proven`). A signed finding with `unproven` is still unproven. The verifier recomputes both from
//                the finding in the package, so the summary cannot say more than the finding does.
//
// WHAT A VALID SIGNATURE DOES NOT MAKE TRUE. A package can be perfectly signed and still say the scan was incomplete. `completeness` is derived from
// `scanHealth` and the verifier refuses a package that claims `complete` over a scan health that is not. Required evidence is checked twice: against the list
// the package declares and against a minimum the VERIFIER holds, so a package cannot weaken its own requirements by leaving something out and not saying so.
//
// ISSUER. Locally generated keys are self-issued, exactly as for evidence bundles: the package says so inside the signed bytes.




const RELEASE_PACKAGE_SCHEMA = 'agentic-security/release-package';
const RELEASE_PACKAGE_VERSION = '1.0.0';
const MANDATORY_KINDS = Object.freeze(['scan-health', 'finding']);

/** Which side of the evidence a kind sits on. */
const EVIDENCE_ROLES = Object.freeze({
  finding: 'finding', 'finding-evidence': 'finding', 'provenance-evidence': 'finding', 'fix-verification': 'finding', verification: 'finding',
  'runtime-explanation': 'finding', 'exploitability-evidence': 'finding',
  'scan-health': 'completeness', 'semantic-graph': 'context', scorecard: 'context', 'dci-invariants': 'context',
  'compliance-evidence': 'control', 'obligation-evidence-pack': 'control', sbom: 'inventory', 'ai-bom': 'inventory', 'release-evidence': 'control',
});

const PROVES = 'Nothing in this package changed after the key holder signed it: no field, no record, no ordering, no omission of the records it lists.';
const DOES_NOT_PROVE = 'That any finding is real or exploitable (read each finding\'s proofTier), that the scan covered everything (read completeness), or that the key holder is independently certified (read issuance).';

const SIGNING_DOMAIN = `${RELEASE_PACKAGE_SCHEMA}@${RELEASE_PACKAGE_VERSION.split('.')[0]}\n`;

const proofTierOf = (payload) => (payload && typeof payload === 'object' && typeof payload.proofTier === 'string' ? payload.proofTier : 'unproven');

/**
 * @param {object} o
 * @param {object} o.snapshot from buildSnapshotRef
 * @param {{kind:string, payload:object, restsOn?:number[]}[]} o.evidence `restsOn` are INDEXES into this array of the records this one rests on
 * @param {object[]} [o.policyDecisions] decisions already taken (id, outcome, reason, policyVersion); recorded as given, never evaluated here
 * @param {string[]} [o.requiredKinds] kinds this package declares it must contain (added to the minimum the verifier holds)
 * @param {{id:string, text:string, evidence:number[], status:'supported'|'unsupported'|'unknown', reason?:string}[]} [o.assertions] indexes into `evidence`
 */
function buildReleasePackage({ snapshot, evidence, policyDecisions = [], requiredKinds = [], assertions = [] } = {}) {
  if (!verifySnapshotRef(snapshot)) throw new Error('a valid snapshot reference is required');
  if (!Array.isArray(evidence) || evidence.length === 0) throw new Error('at least one evidence record is required');
  // refs are built in dependency order so each one can name the digests of the records it rests on
  const built = new Array(evidence.length);
  const state = new Array(evidence.length).fill(0);
  const make = (i, trail) => {
    if (built[i]) return built[i];
    if (state[i] === 1) throw new Error(`evidence ${trail.concat(i).join(' -> ')} rests on itself`);
    state[i] = 1;
    const e = evidence[i];
    const deps = (e.restsOn || []).map((j) => { if (!Number.isInteger(j) || j < 0 || j >= evidence.length) throw new Error(`evidence ${i} rests on ${j}, which does not exist`); return make(j, trail.concat(i)).ref.digest; });
    built[i] = { ref: buildEvidenceRef(e.kind, e.payload, snapshot, { restsOn: deps }), payload: e.payload, role: EVIDENCE_ROLES[e.kind] || 'context' };
    state[i] = 2;
    return built[i];
  };
  for (let i = 0; i < evidence.length; i++) make(i, []);
  const lineage = checkLineage(built.map((b) => b.ref));
  if (!lineage.ok) throw new Error(`lineage is not valid: ${lineage.errors.join('; ')}`);
  const byDigest = new Map(built.map((b) => [b.ref.digest, b]));
  const ordered = lineage.order.map((d) => byDigest.get(d));

  const health = built.find((b) => b.ref.kind === 'scan-health');
  const healthPayload = health ? health.payload : null;
  const findings = built.filter((b) => b.ref.kind === 'finding').map((b) => {
    const tier = proofTierOf(b.payload);
    return {
      findingRef: b.ref.digest, findingId: b.ref.payloadId,
      integrity: 'unmodified-since-signing',
      proofTier: tier, exploitabilityProven: tier === 'execution-proven',
    };
  });
  const body = {
    schema: RELEASE_PACKAGE_SCHEMA, schemaVersion: RELEASE_PACKAGE_VERSION,
    snapshot,
    evidence: ordered.map((b) => ({ role: b.role, ref: b.ref, payload: b.payload })),
    lineageOrder: lineage.order,
    requiredKinds: [...new Set([...MANDATORY_KINDS, ...requiredKinds])].sort(),
    findings: findings.sort((a, b) => (a.findingRef < b.findingRef ? -1 : 1)),
    completeness: {
      scanStatus: healthPayload && typeof healthPayload.status === 'string' ? healthPayload.status : 'unknown',
      conditions: healthPayload && Array.isArray(healthPayload.conditions) ? [...healthPayload.conditions] : [],
      verdict: healthPayload && healthPayload.status === 'complete' ? 'complete' : 'incomplete',
      source: health ? health.ref.digest : null,
    },
    policy: { decisions: policyDecisions.map((d) => ({ ...d })) },
    assertions: assertions.map((a) => ({ id: a.id, text: a.text, status: a.status, reason: a.reason ?? null, evidence: [...new Set(a.evidence || [])].map((i) => { if (!built[i]) throw new Error(`assertion ${a.id} cites evidence ${i}, which does not exist`); return built[i].ref.digest; }).sort() })),
    proves: PROVES, doesNotProve: DOES_NOT_PROVE,
  };
  return body;
}

/** The exact bytes that are signed: a domain label, then the canonical JSON of everything except the signature. */
function signedBytes(pkg) {
  const { signature, ...rest } = pkg;
  return Buffer.from(SIGNING_DOMAIN + (0,evidence_bundle/* canonicalJson */.dj)(rest), 'utf8');
}

function signReleasePackage(pkg, privateKeyPem) {
  const publicKeyPem = external_node_crypto_.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const issuance = {
    trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: evidence_bundle/* TRUST_BASES */.oR['self-issued-local-key'].statement,
    issuer: { keyFingerprint: (0,evidence_bundle/* keyFingerprint */.yy)(publicKeyPem) },
  };
  const withIssuance = { ...pkg, issuance };
  const sig = external_node_crypto_.sign(null, signedBytes(withIssuance), privateKeyPem);
  return { ...withIssuance, signature: { algorithm: 'ed25519', domain: SIGNING_DOMAIN.trim(), value: sig.toString('base64') } };
}

// EXTERNAL MODULE: ./src/posture/assurance/release-verdict.js
var release_verdict = __webpack_require__(86067);
// EXTERNAL MODULE: ./src/posture/assurance/release-package-verify.js
var release_package_verify = __webpack_require__(92530);
;// CONCATENATED MODULE: ./src/posture/assurance/release-package-cli.js
// `agentic-security release-package build|verify`: assembles a signed release assurance package from the last scan and checks one offline.
//
//   release-package build [path] --private-key <pem> [--output <file>] [--fix-records <file>] [--public-key-out <file>]
//   release-package verify <package.json> --public-key <pem> [--require kind,kind]
//
// `io.git(root, ...args)` answers a read-only git query (or null); the caller supplies it so this layer never spawns a process itself.
// Exit codes: 0 built or verified; 1 the scan state failed its integrity check, or a package was rejected; 2 a usage problem or unreadable input.
//
// What goes in: the scan's health record and one record per finding (and, with --fix-records, one verification record per fix claimed). The proof tier of a
// finding is whatever the scan recorded; a finding that recorded none is `taint-proven` when the taint engine found its path and `unproven` otherwise. An
// executed counterexample is never inferred here. The verdict is computed from the package's own contents and recorded as a policy decision, so the stated
// verdict can always be recomputed by anyone holding the package.









const USAGE = 'Usage: agentic-security release-package build [path] --private-key <pem> [--output <file>] [--fix-records <file>] [--public-key-out <file>]\n       agentic-security release-package verify <package.json> --public-key <pem> [--require kind,kind]';
const DEFAULT_OUT = 'release-package.json';


function release_package_cli_proofTierOf(f) {
  if (typeof f.proofTier === 'string') return f.proofTier;
  return f.parser === 'IR-TAINT' ? 'taint-proven' : 'unproven';
}

function findingPayload(f) {
  return {
    id: f.id, stableId: f.stableId ?? null, severity: f.severity, vuln: f.vuln, file: f.file, line: f.line ?? null,
    parser: f.parser, family: f.family, cwe: f.cwe ?? null, proofTier: release_package_cli_proofTierOf(f),
    ...(f.triage ? { triage: f.triage } : {}),
  };
}

async function build(args, say, git) {
  const root = external_node_path_.resolve(args._[2] || '.');
  const keyFile = args.flags['private-key'];
  if (!keyFile) { say.err(USAGE); return 2; }
  let privateKey;
  try { privateKey = external_node_fs_.readFileSync(external_node_path_.resolve(String(keyFile)), 'utf8'); } catch { say.err(`Could not read the private key at ${keyFile}.`); return 2; }

  const file = (0,state_dir.statePath)(root, 'last-scan.json');
  let body;
  try { body = external_node_fs_.readFileSync(file, 'utf8'); } catch { say.err(`No scan found at ${file}. Run a scan first.`); return 2; }
  const sig = (0,integrity/* verifyLastScan */.Ef)(body, file + '.sig');
  if (sig !== true) { say.err(sig === null ? 'The last scan has no signature, so it is not used as evidence. Run a scan again.' : 'The last scan failed its integrity check, so it is not used as evidence.'); return 1; }
  let scan;
  try { scan = JSON.parse(body); } catch { say.err('The last scan is not valid JSON.'); return 1; }
  if (!scan.scanHealth || typeof scan.scanHealth !== 'object') { say.err('The last scan carries no scan health record, which a release package requires.'); return 1; }

  let fixes = [];
  if (args.flags['fix-records']) {
    try { fixes = JSON.parse(external_node_fs_.readFileSync(external_node_path_.resolve(String(args.flags['fix-records'])), 'utf8')); } catch (e) { say.err(`Could not read the fix records: ${e.message}`); return 2; }
    if (!Array.isArray(fixes)) { say.err('The fix records file must hold a list.'); return 2; }
  }

  const findings = (scan.findings || []).filter(f => f && typeof f === 'object');
  const evidence = [{ kind: 'scan-health', payload: scan.scanHealth }];
  for (const f of findings) evidence.push({ kind: 'finding', payload: findingPayload(f) });
  for (const rec of fixes) {
    const at = findings.findIndex(f => f.id === rec.findingId || (rec.findingStableId && f.stableId === rec.findingStableId));
    evidence.push({ kind: 'fix-verification', payload: rec, ...(at >= 0 ? { restsOn: [at + 1] } : {}) });
  }

  const commit = git(root, 'rev-parse', 'HEAD');
  const dirty = commit ? (git(root, 'status', '--porcelain') || '').length > 0 : false;
  const snapshot = buildSnapshotRef({ commit, dirty, engineVersion: scan.engineVersion || null });
  let pkg;
  try {
    const draft = buildReleasePackage({ snapshot, evidence });
    const v = (0,release_verdict/* releaseVerdict */.D)(draft);
    pkg = signReleasePackage(buildReleasePackage({ snapshot, evidence, policyDecisions: [{ id: 'release-verdict', outcome: v.verdict, reason: v.statement, policyVersion: '1' }] }), privateKey);
  } catch (e) { say.err(`Could not build the package: ${e.message}`); return 1; }

  const out = external_node_path_.resolve(String(args.flags.output || external_node_path_.join(root, DEFAULT_OUT)));
  external_node_fs_.writeFileSync(out, JSON.stringify(pkg, null, 2) + '\n');
  if (args.flags['public-key-out']) {
    const { createPublicKey } = await Promise.resolve(/* import() */).then(__webpack_require__.t.bind(__webpack_require__, 77598, 19));
    external_node_fs_.writeFileSync(external_node_path_.resolve(String(args.flags['public-key-out'])), createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }));
  }
  const v = (0,release_verdict/* releaseVerdict */.D)(pkg);
  say.out(`release package written to ${out}: ${pkg.evidence.length} evidence records, ${pkg.findings.length} findings, scan ${pkg.completeness.scanStatus}`);
  say.out(`verdict: ${v.verdict}. ${v.statement}`);
  if (!snapshot.immutable) say.out('The snapshot is not immutable: the working tree has uncommitted changes or there is no commit, and the package says so.');
  return 0;
}

async function verify(args, say) {
  const file = args._[2];
  const keyFile = args.flags['public-key'];
  if (!file || !keyFile) { say.err(USAGE); return 2; }
  let pkg; let key;
  try { pkg = JSON.parse(external_node_fs_.readFileSync(external_node_path_.resolve(file), 'utf8')); key = external_node_fs_.readFileSync(external_node_path_.resolve(String(keyFile)), 'utf8'); } catch (e) { say.err(`Could not read the input: ${e.message}`); return 2; }
  const r = (0,release_package_verify.verifyReleasePackage)(pkg, key, { require: String(args.flags.require || '').split(',').filter(Boolean) });
  const stated = r.ok ? (0,release_verdict/* verifyStatedVerdict */.s)(pkg) : null;
  if (r.ok && stated && stated.ok) { say.out(`release package verified: scan ${r.completeness}, ${pkg.evidence.length} records, ${pkg.findings.length} findings`); return 0; }
  for (const e of (r.errors || [])) say.err(`${e.code}: ${e.message}`);
  if (r.ok && stated && stated.ok === false) say.err(`verdict-mismatch: ${stated.message}`);
  say.err('release package REJECTED');
  return 1;
}

async function cmdReleasePackage(args, io = {}) {
  const say = { out: io.out || ((s) => console.log(s)), err: io.err || ((s) => console.error(s)) };
  const sub = args._[1];
  if (sub === 'build') return build(args, say, io.git || (() => null));
  if (sub === 'verify') return verify(args, say);
  say.err(USAGE);
  return 2;
}


/***/ }),

/***/ 92530:
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



/***/ }),

/***/ 86067:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   D: () => (/* binding */ releaseVerdict),
/* harmony export */   s: () => (/* binding */ verifyStatedVerdict)
/* harmony export */ });
// The release verdict (E7-08): a deterministic function from a release package to one of three answers, with every reason in plain words.
//
//   not_deployable   a condition the policy treats as blocking is present: an unfinished scan, files that were not scanned, an analyzer that timed out or failed,
//                    a fix that was claimed and not verified, an open finding that is proven exploitable, an open high or critical finding
//   needs_review     nothing blocks, but something is unknown and a person has to decide: a signal the context analysis could not settle, runtime evidence that
//                    came from a different build, a finding of unproven exploitability that is high or critical
//   deployable       none of the above. This is NOT a statement that the release is safe; it says no blocking or unknown condition was found in the evidence the package holds
//
// The word "safe" is never produced. The verdict is a function of the package alone (no clock, no environment), so the same package gives the same verdict and the same
// reasons in the same order, and a stated verdict that differs from the one recomputed here is refused (`verifyStatedVerdict`).
//
// WHAT COUNTS AS A BLOCKER is the policy below, not a judgement made per release. Waived findings (a waiver the package lists as honoured) do not block but are listed.
const SEV_BLOCK = new Set(['critical', 'high']);

const asArray = (v) => (Array.isArray(v) ? v : []);
const by = (pkg, kind) => asArray(pkg && pkg.evidence).filter((e) => e && e.ref && e.ref.kind === kind);

/**
 * @param {object} pkg a release package
 * @param {{waivedIds?:string[]}} [opts] finding ids covered by an honoured waiver
 * @returns {{verdict:'not_deployable'|'needs_review'|'deployable', blockers:{code:string, message:string, evidence:string[]}[], unknowns:{code:string, message:string, evidence:string[]}[], waived:string[], statement:string}}
 */
function releaseVerdict(pkg, { waivedIds = [] } = {}) {
  const blockers = []; const unknowns = [];
  const block = (code, message, evidence = []) => blockers.push({ code, message, evidence });
  const unk = (code, message, evidence = []) => unknowns.push({ code, message, evidence });
  const waived = new Set(waivedIds);

  // ---- the scan itself
  const health = by(pkg, 'scan-health')[0];
  if (!health) block('NO_SCAN_HEALTH', 'the package holds no scan health, so nothing says the scan finished');
  else {
    const h = health.payload || {}; const ev = [health.ref.digest];
    if (h.status !== 'complete') block('SCAN_INCOMPLETE', `the scan did not finish cleanly (status ${JSON.stringify(h.status ?? 'unknown')}): ${asArray(h.conditions).join('; ') || 'no reason was recorded'}`, ev);
    const f = h.files || {};
    if (Number.isFinite(f.expected) && Number.isFinite(f.scanned) && f.scanned < f.expected) block('FILES_NOT_SCANNED', `${f.expected - f.scanned} of ${f.expected} files were not scanned`, ev);
    else if (Number.isFinite(f.unanalysed) ? f.unanalysed > 0 : (Number.isFinite(f.skipped) && f.skipped > 0)) block('FILES_SKIPPED', `${Number.isFinite(f.unanalysed) ? f.unanalysed : f.skipped} file(s) were skipped (too large or too dense to analyse)`, ev);
    if (Number.isFinite(f.timedOut) && f.timedOut > 0) block('FILES_TIMED_OUT', `${f.timedOut} file(s) exceeded the per-file analysis time`, ev);
    const a = h.analyzers || {};
    if (Number.isFinite(a.timedOut) && a.timedOut > 0) block('ANALYZER_TIMED_OUT', `${a.timedOut} analyzer(s) timed out, so what they would have found is not in this result`, ev);
    if (Number.isFinite(a.failed) && a.failed > 0 && !(Number.isFinite(a.timedOut) && a.failed === a.timedOut)) block('ANALYZER_FAILED', `${a.failed} analyzer(s) failed, so what they would have found is not in this result`, ev);
    if (h.deepAnalysis && Array.isArray(h.deepAnalysis.incomplete) && h.deepAnalysis.incomplete.length) unk('DEEP_ANALYSIS_INCOMPLETE', `deep analysis stopped short: ${h.deepAnalysis.incomplete.map((x) => `${x.reason} x${x.count}`).join(', ')}`, ev);
  }

  // ---- findings and fixes
  const fixes = by(pkg, 'fix-verification');
  const fixFor = (id) => fixes.filter((x) => x.payload && (x.payload.findingStableId === id || x.payload.findingId === id));
  for (const e of by(pkg, 'finding')) {
    const f = e.payload || {}; const id = e.ref.payloadId || f.stableId || f.id; const ev = [e.ref.digest];
    const triage = f.triage && f.triage.state;
    const falsePositive = triage === 'false_positive' || f.falsePositive === true;
    const myFixes = fixFor(id); const fixed = myFixes.find((x) => x.payload.verifiedFull === true);
    if (waived.has(id)) continue;
    if (falsePositive) {
      if (!(f.triage && f.triage.by && f.triage.reason)) unk('FALSE_POSITIVE_UNJUSTIFIED', `finding ${id} is marked a false positive without a named person and a reason`, ev);
      continue;
    }
    for (const x of myFixes) if (x.payload.verifiedFull !== true) block('FIX_NOT_VERIFIED', `a fix for ${id} is claimed but was not fully verified (${asArray(x.payload.degradedLegs).map((d) => (typeof d === 'string' ? d : d && d.leg)).filter(Boolean).join(', ') || 'checks did not all pass'})`, [...ev, x.ref.digest]);
    if (fixed) continue;
    const sev = String(f.severity || 'info'); const tier = typeof f.proofTier === 'string' ? f.proofTier : 'unproven';
    const ci = f.contextIntelligence && (f.contextIntelligence.counterexample && f.contextIntelligence.counterexample.state || f.contextIntelligence.state);
    if (tier === 'execution-proven') block('PROVEN_OPEN_FINDING', `finding ${id} (${sev}) is proven exploitable and is open`, ev);
    else if (SEV_BLOCK.has(sev)) {
      if (ci === 'unresolved' || ci === 'plausible') unk('CONTEXT_SIGNAL_UNSETTLED', `finding ${id} (${sev}) rests on a context signal the analysis could not settle (${ci}); a person has to decide whether it is real`, ev);
      else block('OPEN_HIGH_FINDING', `finding ${id} is open at severity ${sev}`, ev);
    } else if (ci === 'unresolved' || ci === 'plausible') unk('CONTEXT_SIGNAL_UNSETTLED', `finding ${id} rests on a context signal the analysis could not settle (${ci})`, ev);
  }

  // ---- runtime evidence from another build
  for (const e of by(pkg, 'runtime-explanation')) {
    const edges = asArray(e.payload && e.payload.runtime && e.payload.runtime.edges); const bad = edges.filter((x) => Number(x.mismatchedRecords) > 0);
    if (bad.length) unk('RUNTIME_BUILD_MISMATCH', `runtime records for ${bad.length} edge(s) of ${e.ref.payloadId || 'a finding'} came from a different build than the one released, so they say nothing about this release and are not counted as corroboration`, [e.ref.digest]);
    const miss = asArray(e.payload && e.payload.runtime && e.payload.runtime.missingObservations);
    if (!bad.length && miss.length && e.payload.compare && e.payload.compare.state !== 'corroborated') unk('RUNTIME_NOT_CORROBORATED', `runtime evidence for ${e.ref.payloadId || 'a finding'} does not corroborate the path: ${miss[0]}`, [e.ref.digest]);
  }

  blockers.sort((a, b) => (a.code + a.message < b.code + b.message ? -1 : 1)); unknowns.sort((a, b) => (a.code + a.message < b.code + b.message ? -1 : 1));
  const verdict = blockers.length ? 'not_deployable' : unknowns.length ? 'needs_review' : 'deployable';
  const statement = verdict === 'deployable'
    ? 'No blocking or unknown condition was found in the evidence this package holds. That is not a statement that the release is safe.'
    : verdict === 'needs_review' ? `Nothing blocks the release, but ${unknowns.length} thing(s) are unknown and a person has to decide.` : `${blockers.length} condition(s) block the release.`;
  return { verdict, blockers, unknowns, waived: [...waived].sort(), statement };
}

/** Is the verdict a package states the one its own contents give? @returns {{ok:boolean, stated:string|null, computed:string, message:string|null}} */
function verifyStatedVerdict(pkg, opts) {
  const computed = releaseVerdict(pkg, opts).verdict;
  const decisions = asArray(pkg && pkg.policy && pkg.policy.decisions);
  const d = decisions.find((x) => x && x.id === 'release-verdict');
  const stated = d ? d.outcome : null;
  if (stated === null) return { ok: false, stated, computed, message: 'the package states no release verdict' };
  if (stated !== computed) return { ok: false, stated, computed, message: `the package states "${stated}" but its own contents give "${computed}"` };
  return { ok: true, stated, computed, message: null };
}


/***/ })

};
