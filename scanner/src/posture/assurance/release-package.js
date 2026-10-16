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
import * as crypto from 'node:crypto';
import { buildEvidenceRef, buildSnapshotRef, checkLineage, verifySnapshotRef } from './evidence-registry.js';
import { canonicalJson, keyFingerprint, TRUST_BASES } from '../evidence-bundle.js';

const RELEASE_PACKAGE_SCHEMA = 'agentic-security/release-package';
const RELEASE_PACKAGE_VERSION = '1.0.0';
export const MANDATORY_KINDS = Object.freeze(['scan-health', 'finding']);

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
export function buildReleasePackage({ snapshot, evidence, policyDecisions = [], requiredKinds = [], assertions = [] } = {}) {
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
export function signedBytes(pkg) {
  const { signature, ...rest } = pkg;
  return Buffer.from(SIGNING_DOMAIN + canonicalJson(rest), 'utf8');
}

export function signReleasePackage(pkg, privateKeyPem) {
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const issuance = {
    trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: TRUST_BASES['self-issued-local-key'].statement,
    issuer: { keyFingerprint: keyFingerprint(publicKeyPem) },
  };
  const withIssuance = { ...pkg, issuance };
  const sig = crypto.sign(null, signedBytes(withIssuance), privateKeyPem);
  return { ...withIssuance, signature: { algorithm: 'ed25519', domain: SIGNING_DOMAIN.trim(), value: sig.toString('base64') } };
}
