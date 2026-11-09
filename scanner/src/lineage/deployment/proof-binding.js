// Scope-bound proof for deployed paths (threat-model PRD FR-04.1, FR-04.2; TM-05).
//
// A verification record proves a COMPONENT behaviour at one commit. Before this, a record for revision A promoted both the exposure
// and the impact paths of a revision B graph to exploitable. Now:
//
//   component proof   the record is applicable (validated, trusted runtime proof, the class's oracle) AND its commit is the graph's
//                     revision. A record for another revision is kept as historical evidence with the mismatch, never applied.
//   path promotion    additionally needs a proof-binding envelope, version 1, for that record and that exact path: the artifact and
//                     policy (graph) digests, environment, tenant, actor, route and action, the path id and its kind (exposure or
//                     impact), the oracle version and the effect the oracle observed, issued and signed by an issuer the operator
//                     trusts (an Ed25519 public key in the trust root). A matching digest or a caller's label is not authority.
//
// Every refusal has its own code, so a reviewer can tell a malformed envelope from a tampered, an expired or a replayed one. An exact
// duplicate envelope adds nothing.
import crypto from 'node:crypto';

export const PROOF_BINDING_SCHEMA = 'agentic-security/proof-binding';
export const PROOF_BINDING_VERSION = 1;
const FIELDS = ['schema', 'version', 'recordId', 'commit', 'artifactDigest', 'policyDigest', 'environment', 'tenant', 'actor', 'route', 'action', 'pathId', 'claim', 'oracleVersion', 'effect', 'issuer', 'issuedAt', 'expires'];
const REQUIRED = ['recordId', 'commit', 'artifactDigest', 'policyDigest', 'environment', 'actor', 'pathId', 'claim', 'oracleVersion', 'effect', 'issuer', 'issuedAt', 'expires'];
const CLAIMS = new Set(['exposure', 'impact']);

const canonical = (e) => JSON.stringify(FIELDS.map((k) => [k, e[k] ?? null]));
export const bindingDigest = (e) => crypto.createHash('sha256').update(canonical(e)).digest('hex');

/** Sign an envelope with an issuer's Ed25519 private key (used by an issuer and by tests). */
export function signProofBinding(envelope, privateKeyPem) {
  const body = { schema: PROOF_BINDING_SCHEMA, version: PROOF_BINDING_VERSION, ...envelope };
  return { ...body, signature: crypto.sign(null, Buffer.from(canonical(body)), privateKeyPem).toString('base64') };
}

/** Structural and authority check of one envelope. Returns { ok, code, reason }. */
export function verifyProofBinding(e, { trustRoot = {}, now = Date.now() } = {}) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, code: 'malformed', reason: 'the binding is not an object' };
  if (e.schema !== PROOF_BINDING_SCHEMA || e.version !== PROOF_BINDING_VERSION) return { ok: false, code: 'unsupported-version', reason: 'the binding schema or version is not supported' };
  for (const k of Object.keys(e)) if (!FIELDS.includes(k) && k !== 'signature') return { ok: false, code: 'malformed', reason: `unknown binding field ${k}` };
  for (const k of REQUIRED) if (e[k] === undefined || e[k] === null || e[k] === '') return { ok: false, code: 'missing-binding', reason: `the binding has no ${k}` };
  if (!CLAIMS.has(e.claim)) return { ok: false, code: 'malformed', reason: 'claim must be exposure or impact' };
  const key = trustRoot[e.issuer];
  if (!key) return { ok: false, code: 'untrusted-issuer', reason: `issuer ${String(e.issuer).slice(0, 60)} is not in the operator's trust root` };
  let good = false;
  try { good = typeof e.signature === 'string' && crypto.verify(null, Buffer.from(canonical(e)), key, Buffer.from(e.signature, 'base64')); } catch { good = false; }
  if (!good) return { ok: false, code: 'tampered', reason: 'the signature does not verify against the issuer\'s key' };
  if (!(Date.parse(e.expires) > now)) return { ok: false, code: 'expired', reason: 'the binding has expired' };
  return { ok: true, code: 'verified', reason: null };
}

/**
 * Decide whether a path may be promoted by a component proof, given the bindings supplied for it.
 * @param {{path:object, kind:'exposure'|'impact', graph:object, record:object, bindings:object[], trustRoot:object, now:number,
 *          expect:{artifactDigest?:string, environment?:string, tenant?:string|null, actor?:string, route?:string, action?:string}}} a
 * @returns {{promote:boolean, code:string, reason:string, bindingId:string|null, diagnostics:object[]}}
 */
export function judgePathPromotion({ path, kind, graph, record, bindings = [], trustRoot = {}, now = Date.now(), expect = {} }) {
  const diagnostics = [];
  const seen = new Set();
  const forRecord = bindings.filter((b) => b && b.recordId === record.id);
  if (!forRecord.length) return { promote: false, code: 'component-only', reason: 'the proof covers the component; no issued binding ties it to this deployed path', bindingId: null, diagnostics };
  for (const b of forRecord) {
    const id = bindingDigest(b);
    if (seen.has(id)) continue; // an exact duplicate adds no authority
    seen.add(id);
    const v = verifyProofBinding(b, { trustRoot, now });
    if (!v.ok) { diagnostics.push({ bindingId: id.slice(0, 16), code: v.code, reason: v.reason }); continue; }
    const mismatch = [];
    if (b.commit !== record.commit) mismatch.push('commit');
    if (graph.revision && b.commit !== graph.revision) mismatch.push('revision');
    if (b.policyDigest !== graph.digest) mismatch.push('policy');
    if (b.pathId !== path.id) mismatch.push('path');
    if (b.claim !== kind) mismatch.push('claim');
    if (record.oracle && b.oracleVersion !== String(record.oracle.version ?? '')) mismatch.push('oracle');
    if (!(path.environments || []).includes(b.environment)) mismatch.push('environment');
    if ((path.tenants || []).length && !(path.tenants || []).includes(b.tenant)) mismatch.push('tenant');
    for (const k of ['artifactDigest', 'environment', 'tenant', 'actor', 'route', 'action']) if (expect[k] !== undefined && expect[k] !== null && b[k] !== expect[k]) mismatch.push(k);
    if (mismatch.length) { diagnostics.push({ bindingId: id.slice(0, 16), code: 'context-mismatch', reason: `the binding was issued for another ${[...new Set(mismatch)].join(', ')}` }); continue; }
    return { promote: true, code: 'bound', reason: `issued binding ${id.slice(0, 16)} by ${b.issuer} ties the proof to this ${kind} path`, bindingId: id.slice(0, 16), diagnostics };
  }
  return { promote: false, code: diagnostics.length ? diagnostics[0].code : 'component-only', reason: diagnostics.length ? diagnostics.map((d) => d.reason).join('; ') : 'no binding applies', bindingId: null, diagnostics };
}
