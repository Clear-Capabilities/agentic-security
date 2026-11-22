// The service security contract (Epic A of the contract-driven verification programme).
//
// A CONTRACT is the operator's statement of what a service must guarantee: its invariants in plain language, the attacker each one
// assumes, the repositories at exact revisions and the environment it speaks about, the compensating controls the operator declares,
// and the bindings that connect every invariant to the producers that can check it (a deterministic context-intelligence rule, an
// executable scenario invariant, a runtime predicate, a preservation test). It is data, never code: every field is closed-world,
// identifiers are slugs, revisions are commits, and a string that reads like a command, a credential or an absolute host path is
// refused, because an approved contract must not be able to authorise anything on its own.
//
// Identity. `contractDigest` covers the semantic content (everything but the readable companion's text, whose digest IS covered when
// the companion is declared, since a pack that influences model input is material). `contractRef` is `<id>@<version>#<digest16>`; it
// is carried unchanged across the hunt, the qualification decision, the proof attempt, the repair verification, the regression
// artifact and the evaluation record. A contract whose content changes has a new ref, and an approval bound to the old one does not
// follow it.
//
// Authority. `review` in the document is a claim. Approval is decided only by the signed ledger (`approval.js` over
// posture/invariants/lifecycle.js); a document that says approved is not approved. A model-drafted contract (`review.origin:
// 'inferred'`) is proposed and stays proposed until a human records the transition.
import { digestOf } from '../posture/assurance/identity.js';
import { SCHEMA_VERSION, checkHeader, checkFields, checkEnum, checkCommit, guardObject, isPlainObject, isNonEmptyString, result } from '../posture/assurance/schema-kit.js';

export const CONTRACT_SCHEMA = 'agentic-security/service-contract';
export const CONTRACT_SCHEMA_VERSION = SCHEMA_VERSION;

export const REVIEW_PRIORITIES = Object.freeze(['low', 'normal', 'high', 'critical']);
export const ENVIRONMENTS = Object.freeze(['disposable-fixture', 'isolated-test', 'staging', 'production']);
export const CONTROL_KINDS = Object.freeze(['authentication', 'authorization-role', 'ownership', 'tenant-scope', 'network', 'rate-limit', 'input-validation', 'other']);
export const CONTROL_SOURCES = Object.freeze(['declared', 'observed', 'executed']);
export const BINDING_KINDS = Object.freeze(['static', 'scenario', 'runtime', 'preservation']);
export const REVIEW_STATES = Object.freeze(['proposed', 'approved', 'rejected', 'superseded']);
export const REVIEW_ORIGINS = Object.freeze(['authored', 'inferred']);
export const EVIDENCE_KINDS = Object.freeze(['authorized-control', 'cross-tenant-attempt', 'forbidden-request', 'durable-effect', 'runtime-observation', 'preservation-run']);

const TOP_ALLOWED = ['schema', 'schemaVersion', 'id', 'version', 'owner', 'summary', 'reviewPriority', 'reviewedAt', 'expiry', 'scope', 'invariants', 'controls', 'review', 'threatPack', 'approvalLedgerRef', 'createdAt'];
const TOP_REQUIRED = ['schema', 'schemaVersion', 'id', 'version', 'owner', 'summary', 'reviewPriority', 'reviewedAt', 'expiry', 'scope', 'invariants', 'review'];
const DIGEST_FIELDS = ['id', 'version', 'owner', 'summary', 'reviewPriority', 'reviewedAt', 'expiry', 'scope', 'invariants', 'controls', 'threatPack'];
const INV_ALLOWED = ['id', 'statement', 'attacker', 'scope', 'boundaries', 'dciInvariantRefs', 'scenarioInvariantRefs', 'runtimePredicateRefs', 'preservationRefs', 'requiredEvidence', 'controlRefs'];
const INV_REQUIRED = ['id', 'statement', 'attacker', 'requiredEvidence'];
const CONTROL_ALLOWED = ['id', 'kind', 'statement', 'source', 'provenance', 'scope', 'evidenceRefs', 'expiresAt'];
const CONTROL_REQUIRED = ['id', 'kind', 'statement', 'source', 'scope'];

export const LIMITS = Object.freeze({ invariants: 64, controls: 64, repositories: 16, services: 32, routes: 64, refs: 32, statement: 1000, summary: 2000 });

const SLUG = /^[a-z][a-z0-9-]{1,63}$/;
const INVARIANT_ID = /^[A-Z][A-Z0-9-]{2,63}$/;
const SEMVER = /^\d+\.\d+\.\d+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const PLACEHOLDER = /\b(?:REPLACE[_-]WITH|TODO|FIXME|CHANGEME|xxxxxxxx|0000000000000000)/i;
// A string that could act, or that must never sit in an approved document: shell substitution, a pipeline into a shell, a key or
// token shape, a password assignment, a host-absolute or home path.
const DANGEROUS = /\$\(|`|\|\s*(?:sh|bash|zsh)\b|\b(?:AKIA[0-9A-Z]{12,}|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[abp]-)|\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S|(?:^|[\s"'(])(?:\/(?:Users|home|root|etc|var|tmp|opt)\/|[A-Za-z]:\\)/i;

function pushErr(ctx, code, path, message) { ctx.err(code, path, message); }

function checkText(ctx, path, value, max) {
  if (!isNonEmptyString(value)) { pushErr(ctx, 'BAD_TYPE', path, 'must be a non-empty string'); return false; }
  if (value.length > max) { pushErr(ctx, 'RULE_VIOLATION', path, `longer than ${max} characters`); return false; }
  if (PLACEHOLDER.test(value)) { pushErr(ctx, 'RULE_VIOLATION', path, 'carries a placeholder; a contract names real values or omits the field'); return false; }
  if (DANGEROUS.test(value)) { pushErr(ctx, 'RULE_VIOLATION', path, 'reads like a command, a credential or a host path; a contract cannot carry executable or secret content'); return false; }
  return true;
}

function checkStringList(ctx, path, value, { max = LIMITS.refs, pattern = null, required = false } = {}) {
  if (value === undefined) { if (required) pushErr(ctx, 'MISSING_FIELD', path, 'required'); return []; }
  if (!Array.isArray(value)) { pushErr(ctx, 'BAD_TYPE', path, 'must be an array of strings'); return []; }
  if (value.length > max) pushErr(ctx, 'RULE_VIOLATION', path, `more than ${max} entries`);
  value.forEach((v, i) => {
    if (!checkText(ctx, `${path}[${i}]`, v, 400)) return;
    if (pattern && !pattern.test(v)) pushErr(ctx, 'RULE_VIOLATION', `${path}[${i}]`, `does not match ${pattern}`);
  });
  const seen = new Set();
  for (const v of value) { if (seen.has(v)) pushErr(ctx, 'DUPLICATE_ID', path, `'${String(v).slice(0, 60)}' is listed twice`); seen.add(v); }
  return value;
}

function checkScope(ctx, scope) {
  if (!isPlainObject(scope)) { pushErr(ctx, 'BAD_TYPE', 'scope', 'must be an object'); return; }
  for (const k of Object.keys(scope)) if (!['environment', 'repositories', 'services'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `scope.${k}`, 'not part of this schema');
  checkEnum(ctx, 'scope.environment', scope.environment, ENVIRONMENTS);
  if (!Array.isArray(scope.repositories) || !scope.repositories.length) { pushErr(ctx, 'MISSING_FIELD', 'scope.repositories', 'at least one repository at an exact revision'); return; }
  if (scope.repositories.length > LIMITS.repositories) pushErr(ctx, 'RULE_VIOLATION', 'scope.repositories', `more than ${LIMITS.repositories}`);
  const ids = new Set();
  scope.repositories.forEach((r, i) => {
    const p = `scope.repositories[${i}]`;
    if (!isPlainObject(r)) { pushErr(ctx, 'BAD_TYPE', p, 'must be an object'); return; }
    for (const k of Object.keys(r)) if (!['id', 'revision', 'url'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.${k}`, 'not part of this schema (roots and credentials belong to operator configuration)');
    if (!isNonEmptyString(r.id) || !SLUG.test(r.id)) pushErr(ctx, 'BAD_ID', `${p}.id`, 'a repository id is a slug');
    if (ids.has(r.id)) pushErr(ctx, 'DUPLICATE_ID', `${p}.id`, 'repository listed twice'); ids.add(r.id);
    if (typeof r.revision === 'string' && PLACEHOLDER.test(r.revision)) pushErr(ctx, 'RULE_VIOLATION', `${p}.revision`, 'a placeholder revision is refused; name the exact commit');
    else checkCommit(ctx, `${p}.revision`, r.revision, { nullable: false });
    if (r.url !== undefined) checkText(ctx, `${p}.url`, r.url, 400);
  });
  if (scope.services !== undefined) {
    if (!Array.isArray(scope.services)) { pushErr(ctx, 'BAD_TYPE', 'scope.services', 'must be an array'); return; }
    if (scope.services.length > LIMITS.services) pushErr(ctx, 'RULE_VIOLATION', 'scope.services', `more than ${LIMITS.services}`);
    const sids = new Set();
    scope.services.forEach((s, i) => {
      const p = `scope.services[${i}]`;
      if (!isPlainObject(s)) { pushErr(ctx, 'BAD_TYPE', p, 'must be an object'); return; }
      for (const k of Object.keys(s)) if (!['id', 'repository'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.${k}`, 'not part of this schema');
      if (!isNonEmptyString(s.id) || !SLUG.test(s.id)) pushErr(ctx, 'BAD_ID', `${p}.id`, 'a service id is a slug');
      if (sids.has(s.id)) pushErr(ctx, 'DUPLICATE_ID', `${p}.id`, 'service listed twice'); sids.add(s.id);
      if (!ids.has(s.repository)) pushErr(ctx, 'DANGLING_REF', `${p}.repository`, 'names a repository the scope does not list');
    });
  }
}

function checkInvariant(ctx, inv, i, controlIds) {
  const p = `invariants[${i}]`;
  if (!isPlainObject(inv)) { pushErr(ctx, 'BAD_TYPE', p, 'must be an object'); return; }
  for (const k of Object.keys(inv)) if (!INV_ALLOWED.includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.${k}`, 'not part of this schema');
  for (const k of INV_REQUIRED) if (inv[k] === undefined) pushErr(ctx, 'MISSING_FIELD', `${p}.${k}`, 'required');
  if (!isNonEmptyString(inv.id) || !INVARIANT_ID.test(inv.id)) pushErr(ctx, 'BAD_ID', `${p}.id`, 'an invariant id is upper case letters, digits and dashes, 3 to 64 characters');
  checkText(ctx, `${p}.statement`, inv.statement, LIMITS.statement);
  if (isPlainObject(inv.attacker)) {
    for (const k of Object.keys(inv.attacker)) if (!['assumptions', 'entryPoints', 'principal'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.attacker.${k}`, 'not part of this schema');
    checkStringList(ctx, `${p}.attacker.assumptions`, inv.attacker.assumptions, { required: true });
    checkStringList(ctx, `${p}.attacker.entryPoints`, inv.attacker.entryPoints, { max: LIMITS.routes });
    if (inv.attacker.principal !== undefined) checkEnum(ctx, `${p}.attacker.principal`, inv.attacker.principal, ['anonymous', 'authenticated', 'tenant-member', 'tenant-admin', 'operator']);
  } else if (inv.attacker !== undefined) pushErr(ctx, 'BAD_TYPE', `${p}.attacker`, 'must be an object');
  if (inv.scope !== undefined) {
    if (!isPlainObject(inv.scope)) pushErr(ctx, 'BAD_TYPE', `${p}.scope`, 'must be an object');
    else {
      for (const k of Object.keys(inv.scope)) if (!['routes', 'services'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.scope.${k}`, 'not part of this schema');
      checkStringList(ctx, `${p}.scope.routes`, inv.scope.routes, { max: LIMITS.routes });
      checkStringList(ctx, `${p}.scope.services`, inv.scope.services, { pattern: SLUG });
    }
  }
  checkStringList(ctx, `${p}.boundaries`, inv.boundaries);
  checkStringList(ctx, `${p}.dciInvariantRefs`, inv.dciInvariantRefs, { pattern: INVARIANT_ID });
  checkStringList(ctx, `${p}.scenarioInvariantRefs`, inv.scenarioInvariantRefs, { pattern: /^[a-z][a-z0-9-]{1,63}(?:@\d+)?$|^inv:[0-9a-f]{16}$/ });
  checkStringList(ctx, `${p}.runtimePredicateRefs`, inv.runtimePredicateRefs);
  checkStringList(ctx, `${p}.preservationRefs`, inv.preservationRefs);
  const ev = checkStringList(ctx, `${p}.requiredEvidence`, inv.requiredEvidence, { required: true });
  ev.forEach((e, j) => { if (typeof e === 'string' && !EVIDENCE_KINDS.includes(e)) pushErr(ctx, 'UNKNOWN_ENUM', `${p}.requiredEvidence[${j}]`, `${JSON.stringify(e)} is not one of: ${EVIDENCE_KINDS.join(', ')}`); });
  const refs = checkStringList(ctx, `${p}.controlRefs`, inv.controlRefs, { pattern: SLUG });
  refs.forEach((r, j) => { if (!controlIds.has(r)) pushErr(ctx, 'DANGLING_REF', `${p}.controlRefs[${j}]`, 'names a control the contract does not declare'); });
}

function checkControl(ctx, c, i) {
  const p = `controls[${i}]`;
  if (!isPlainObject(c)) { pushErr(ctx, 'BAD_TYPE', p, 'must be an object'); return; }
  for (const k of Object.keys(c)) if (!CONTROL_ALLOWED.includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.${k}`, 'not part of this schema');
  for (const k of CONTROL_REQUIRED) if (c[k] === undefined) pushErr(ctx, 'MISSING_FIELD', `${p}.${k}`, 'required');
  if (!isNonEmptyString(c.id) || !SLUG.test(c.id)) pushErr(ctx, 'BAD_ID', `${p}.id`, 'a control id is a slug');
  checkEnum(ctx, `${p}.kind`, c.kind, CONTROL_KINDS);
  checkText(ctx, `${p}.statement`, c.statement, LIMITS.statement);
  checkEnum(ctx, `${p}.source`, c.source, CONTROL_SOURCES);
  if (c.provenance !== undefined) {
    if (!isPlainObject(c.provenance)) pushErr(ctx, 'BAD_TYPE', `${p}.provenance`, 'must be an object');
    else {
      for (const k of Object.keys(c.provenance)) if (!['repository', 'file', 'line', 'symbol'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.provenance.${k}`, 'not part of this schema');
      if (c.provenance.file !== undefined) {
        if (/^(?:\/|[A-Za-z]:\\|\.\.)/.test(String(c.provenance.file))) pushErr(ctx, 'RULE_VIOLATION', `${p}.provenance.file`, 'a repository-relative path, never absolute or parent-relative');
        else checkText(ctx, `${p}.provenance.file`, c.provenance.file, 400);
      }
      if (c.provenance.line !== undefined && !(Number.isInteger(c.provenance.line) && c.provenance.line >= 1)) pushErr(ctx, 'BAD_TYPE', `${p}.provenance.line`, 'a positive line number');
    }
  }
  if (!isPlainObject(c.scope)) { if (c.scope !== undefined) pushErr(ctx, 'BAD_TYPE', `${p}.scope`, 'must be an object'); }
  else {
    for (const k of Object.keys(c.scope)) if (!['environment', 'routes', 'services'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `${p}.scope.${k}`, 'not part of this schema');
    checkEnum(ctx, `${p}.scope.environment`, c.scope.environment, ENVIRONMENTS);
    checkStringList(ctx, `${p}.scope.routes`, c.scope.routes, { max: LIMITS.routes });
    checkStringList(ctx, `${p}.scope.services`, c.scope.services, { pattern: SLUG });
  }
  checkStringList(ctx, `${p}.evidenceRefs`, c.evidenceRefs);
  if (c.expiresAt !== undefined && !(typeof c.expiresAt === 'string' && DATE.test(c.expiresAt))) pushErr(ctx, 'BAD_TYPE', `${p}.expiresAt`, 'YYYY-MM-DD');
  // A declared control is a claim; the document may not promote it. `observed` and `executed` need evidence references.
  if ((c.source === 'observed' || c.source === 'executed') && !(Array.isArray(c.evidenceRefs) && c.evidenceRefs.length)) pushErr(ctx, 'RULE_VIOLATION', `${p}.evidenceRefs`, `a control recorded as ${c.source} names the evidence that observed or executed it`);
}

/** Validate a contract document. Pure; never throws. Returns { ok, errors: [{code, path, message}] }. */
export function validateContract(rec) {
  const g = guardObject(rec);
  if (!g.ok) return result(g.ctx);
  const ctx = g.ctx;
  if (!checkHeader(ctx, rec, CONTRACT_SCHEMA)) return result(ctx);
  checkFields(ctx, rec, TOP_ALLOWED, TOP_REQUIRED);
  if (!isNonEmptyString(rec.id) || !SLUG.test(rec.id)) pushErr(ctx, 'BAD_ID', 'id', 'a contract id is a slug (service id)');
  if (!(typeof rec.version === 'string' && SEMVER.test(rec.version))) pushErr(ctx, 'BAD_TYPE', 'version', 'a semantic version');
  checkText(ctx, 'owner', rec.owner, 200);
  checkText(ctx, 'summary', rec.summary, LIMITS.summary);
  checkEnum(ctx, 'reviewPriority', rec.reviewPriority, REVIEW_PRIORITIES);
  if (!(typeof rec.reviewedAt === 'string' && DATE.test(rec.reviewedAt))) pushErr(ctx, 'BAD_TYPE', 'reviewedAt', 'YYYY-MM-DD');
  if (!isPlainObject(rec.expiry)) pushErr(ctx, 'BAD_TYPE', 'expiry', 'must be an object { reviewEveryDays, expiresAt? }');
  else {
    for (const k of Object.keys(rec.expiry)) if (!['reviewEveryDays', 'expiresAt'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `expiry.${k}`, 'not part of this schema');
    if (!(Number.isInteger(rec.expiry.reviewEveryDays) && rec.expiry.reviewEveryDays >= 1 && rec.expiry.reviewEveryDays <= 730)) pushErr(ctx, 'BAD_TYPE', 'expiry.reviewEveryDays', 'an integer number of days between 1 and 730');
    if (rec.expiry.expiresAt !== undefined && !(typeof rec.expiry.expiresAt === 'string' && DATE.test(rec.expiry.expiresAt))) pushErr(ctx, 'BAD_TYPE', 'expiry.expiresAt', 'YYYY-MM-DD');
  }
  checkScope(ctx, rec.scope);
  const controlIds = new Set();
  if (rec.controls !== undefined) {
    if (!Array.isArray(rec.controls)) pushErr(ctx, 'BAD_TYPE', 'controls', 'must be an array');
    else {
      if (rec.controls.length > LIMITS.controls) pushErr(ctx, 'RULE_VIOLATION', 'controls', `more than ${LIMITS.controls}`);
      rec.controls.forEach((c, i) => { checkControl(ctx, c, i); if (isPlainObject(c) && typeof c.id === 'string') { if (controlIds.has(c.id)) pushErr(ctx, 'DUPLICATE_ID', `controls[${i}].id`, 'control listed twice'); controlIds.add(c.id); } });
    }
  }
  if (!Array.isArray(rec.invariants) || !rec.invariants.length) pushErr(ctx, 'MISSING_FIELD', 'invariants', 'at least one invariant');
  else {
    if (rec.invariants.length > LIMITS.invariants) pushErr(ctx, 'RULE_VIOLATION', 'invariants', `more than ${LIMITS.invariants}`);
    const seen = new Set();
    rec.invariants.forEach((inv, i) => { checkInvariant(ctx, inv, i, controlIds); if (isPlainObject(inv) && typeof inv.id === 'string') { if (seen.has(inv.id)) pushErr(ctx, 'DUPLICATE_ID', `invariants[${i}].id`, 'invariant listed twice'); seen.add(inv.id); } });
  }
  if (!isPlainObject(rec.review)) pushErr(ctx, 'BAD_TYPE', 'review', 'must be an object { state, origin }');
  else {
    for (const k of Object.keys(rec.review)) if (!['state', 'origin', 'note'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `review.${k}`, 'not part of this schema');
    checkEnum(ctx, 'review.state', rec.review.state, REVIEW_STATES);
    checkEnum(ctx, 'review.origin', rec.review.origin, REVIEW_ORIGINS);
    if (rec.review.note !== undefined) checkText(ctx, 'review.note', rec.review.note, 400);
  }
  if (rec.threatPack !== undefined) {
    if (!isPlainObject(rec.threatPack)) pushErr(ctx, 'BAD_TYPE', 'threatPack', 'must be an object { path, digest }');
    else {
      for (const k of Object.keys(rec.threatPack)) if (!['path', 'digest'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `threatPack.${k}`, 'not part of this schema');
      if (!isNonEmptyString(rec.threatPack.path) || /^(?:\/|[A-Za-z]:\\|\.\.)/.test(rec.threatPack.path) || !/\.md$/.test(rec.threatPack.path)) pushErr(ctx, 'RULE_VIOLATION', 'threatPack.path', 'a relative markdown path beside the contract');
      if (!/^sha256:[0-9a-f]{64}$/.test(String(rec.threatPack.digest))) pushErr(ctx, 'BAD_DIGEST', 'threatPack.digest', "'sha256:' and 64 hex characters");
    }
  }
  if (rec.approvalLedgerRef !== undefined) {
    if (!isPlainObject(rec.approvalLedgerRef)) pushErr(ctx, 'BAD_TYPE', 'approvalLedgerRef', 'must be an object { path?, head? }');
    else {
      for (const k of Object.keys(rec.approvalLedgerRef)) if (!['path', 'head'].includes(k)) pushErr(ctx, 'UNKNOWN_FIELD', `approvalLedgerRef.${k}`, 'not part of this schema');
      if (rec.approvalLedgerRef.path !== undefined && (!isNonEmptyString(rec.approvalLedgerRef.path) || /^(?:\/|[A-Za-z]:\\|\.\.)/.test(rec.approvalLedgerRef.path))) pushErr(ctx, 'RULE_VIOLATION', 'approvalLedgerRef.path', 'a relative path');
      if (rec.approvalLedgerRef.head !== undefined && !/^itrn:[0-9a-f]{16}$/.test(String(rec.approvalLedgerRef.head))) pushErr(ctx, 'BAD_ID', 'approvalLedgerRef.head', 'a transition id (itrn:…)');
    }
  }
  return result(ctx);
}

/** Digest over the semantic content: a change to any of it is a new contract. The review claim and the created-at stamp are not content. */
export function contractDigest(contract) {
  const material = {};
  for (const f of DIGEST_FIELDS) material[f] = contract?.[f] === undefined ? null : contract[f];
  return digestOf({ kind: CONTRACT_SCHEMA, material });
}

/** `<id>@<version>#<digest16>`: the identity carried across every stage. */
export function contractRef(contract) {
  const d = contractDigest(contract);
  return `${contract.id}@${contract.version}#${d.slice('sha256:'.length, 'sha256:'.length + 16)}`;
}

/** `<contractRef>/<invariantId>`. */
export function invariantRef(contract, invariantId) { return `${contractRef(contract)}/${invariantId}`; }

export function parseContractRef(ref) {
  const m = /^([a-z][a-z0-9-]{1,63})@(\d+\.\d+\.\d+)#([0-9a-f]{16})(?:\/([A-Z][A-Z0-9-]{2,63}))?$/.exec(String(ref || ''));
  return m ? { id: m[1], version: m[2], digest16: m[3], invariantId: m[4] || null } : null;
}

/**
 * Which producers can check each invariant, by the bindings the contract declares. A missing binding kind is a visible gap, never a
 * satisfied check. `available` says which binding kinds this build of the scanner can execute at all; the rest are `unsupported`.
 */
export function bindingView(contract, { available = ['static', 'scenario'] } = {}) {
  const out = [];
  for (const inv of contract?.invariants || []) {
    const has = {
      static: Array.isArray(inv.dciInvariantRefs) && inv.dciInvariantRefs.length > 0,
      scenario: Array.isArray(inv.scenarioInvariantRefs) && inv.scenarioInvariantRefs.length > 0,
      runtime: Array.isArray(inv.runtimePredicateRefs) && inv.runtimePredicateRefs.length > 0,
      preservation: Array.isArray(inv.preservationRefs) && inv.preservationRefs.length > 0,
    };
    const bindings = {};
    for (const k of BINDING_KINDS) bindings[k] = !has[k] ? 'missing' : available.includes(k) ? 'declared' : 'unsupported';
    const gaps = BINDING_KINDS.filter((k) => bindings[k] !== 'declared');
    out.push({ invariantId: inv.id, bindings, gaps, checkable: gaps.length < BINDING_KINDS.length });
  }
  return out;
}

/** Build a contract document from its parts: fills the header and a proposed review claim. Does not validate. */
export function createContract(parts) {
  return { schema: CONTRACT_SCHEMA, schemaVersion: CONTRACT_SCHEMA_VERSION, review: { state: 'proposed', origin: 'authored' }, ...parts };
}
