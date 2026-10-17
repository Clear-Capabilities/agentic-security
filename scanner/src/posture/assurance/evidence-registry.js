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
import { digestOf, canonicalize } from './identity.js';
import { SUPPORTED_MAJOR, isDigest, isPlainObject } from './schema-kit.js';

export const EVIDENCE_REF_SCHEMA = 'agentic-security/evidence-ref';
export const EVIDENCE_REF_VERSION = '1.0.0';
export const SNAPSHOT_SCHEMA = 'agentic-security/snapshot-ref';

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
export const EVIDENCE_KINDS = Object.freeze({
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

export const EVIDENCE_KIND_NAMES = Object.freeze(Object.keys(EVIDENCE_KINDS));

const get = (o, path) => path.split('.').reduce((a, k) => (a === null || a === undefined ? undefined : a[k]), o);

/** Read schema, version and identity out of a record of `kind`, whatever convention the producer used. Never throws. */
export function describeEvidence(kind, payload) {
  const k = EVIDENCE_KINDS[kind];
  if (!k) return { ok: false, reason: `unknown evidence kind "${kind}"` };
  if (!isPlainObject(payload)) return { ok: false, reason: 'the record is not an object' };
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
export function inspectEvidence(kind, payload) {
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
export function observeSnapshotBinding(payload) {
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
export function buildSnapshotRef({ commit = null, treeDigest = null, dirty = false, engineVersion = null, bundleSha = null, configDigest = null } = {}) {
  const body = { schema: SNAPSHOT_SCHEMA, commit: commit || null, treeDigest: treeDigest || null, dirty: dirty === true, engineVersion: engineVersion || null, bundleSha: bundleSha || null, configDigest: configDigest || null };
  const immutable = !!body.commit && body.dirty === false;
  return { ...body, immutable, digest: digestOf(body) };
}

export function verifySnapshotRef(s) {
  if (!isPlainObject(s) || s.schema !== SNAPSHOT_SCHEMA) return false;
  const { digest, immutable, ...body } = s;
  return digest === digestOf(body) && immutable === (!!body.commit && body.dirty === false);
}

// ---- evidence refs -------------------------------------------------------------------------------------------------------------

/**
 * @param {string} kind
 * @param {object} payload the evidence record, unmodified
 * @param {object} snapshot from buildSnapshotRef
 * @param {{rests_on?:string[]}} opts digests of the evidence this record rests on
 */
export function buildEvidenceRef(kind, payload, snapshot, { restsOn = [] } = {}) {
  const d = describeEvidence(kind, payload);
  if (!d.ok) throw new Error(d.reason);
  if (!verifySnapshotRef(snapshot)) throw new Error('the snapshot is not a valid snapshot reference');
  for (const r of restsOn) if (!isDigest(r)) throw new Error(`restsOn holds a value that is not a digest: ${JSON.stringify(r)}`);
  const body = {
    schema: EVIDENCE_REF_SCHEMA, schemaVersion: EVIDENCE_REF_VERSION, kind,
    payloadSchema: d.schema, payloadVersion: d.version, payloadId: d.id,
    payloadDigest: digestOf(payload),
    snapshotDigest: snapshot.digest, snapshotImmutable: snapshot.immutable,
    restsOn: [...new Set(restsOn)].sort(),
  };
  const out = { ...body, digest: digestOf(body) };
  // the git origin of a finding is findingProvenance and nothing else; a bare `provenance` is another feature's field and is carried only as its own label
  if (kind === 'finding') {
    out.findingProvenanceDigest = isPlainObject(payload.findingProvenance) ? digestOf(payload.findingProvenance) : null;
    out.otherProvenanceDigest = payload.provenance !== undefined ? digestOf(payload.provenance) : null;
  }
  return out;
}

/** Re-derive a ref from the payload and snapshot it claims to describe. @returns {{ok:boolean, errors:string[]}} */
export function verifyEvidenceRef(ref, payload, snapshot) {
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
export function checkLineage(refs) {
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

export { canonicalize };
