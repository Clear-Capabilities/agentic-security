// Approvals, waivers and tenant isolation (E7-05).
//
// A WAIVER is a decision by named people to leave a finding (or a class of them) open for a stated time, for a stated reason, under a stated policy. Three
// things make it safe to honour and all three are enforced here, not left to convention:
//   1. It can never suppress silently. A waiver that is honoured puts the finding in `waived` with the waiver attached; one that is not honoured (expired, for
//      another tenant or environment, signed under a superseded policy, short of approvers, badly signed) is listed in `refused` with the reason, and the finding
//      stays open. `summary` counts both, so a gate can fail on an expired waiver instead of a person finding out later.
//   2. It is bound: to a tenant, an environment, a scope, an expiry and a policy version. None of those can be widened by editing another field.
//   3. It identifies people by opaque id only. An id that looks like an e-mail address is refused, justification text is scanned for secrets and personal data,
//      and the audit log records ids and reason codes, never free text.
//
// The AUDIT LOG is append-only and hash-chained: each entry commits to the one before it, so removing or editing an entry is detected. Erasure of a tenant's
// evidence leaves a tombstone entry (who asked, when, which tenant), never the content, and is refused while a legal hold covers the tenant.
//
// TENANT ISOLATION. Evidence lives under one directory per tenant. A request names the tenant it acts for and the tenant whose evidence it wants; they must be
// the same, the names are validated so neither can walk out of the store, symlinks are refused, and every denial is written to the audit log.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { canonicalJson, keyFingerprint } from '../evidence-bundle.js';
import { secretCanaryHit, canaryHit } from '../runtime-trace-ingest.js';
import { isUnderHold } from '../legal-hold.js';
import { digestOf } from './identity.js';
import { SCHEMA_VERSION, checkFields, checkHeader, checkString, guardObject, isPlainObject, makeCtx, result } from './schema-kit.js';

const WAIVER_SCHEMA = 'agentic-security/waiver';
const SCOPE_KINDS = Object.freeze(['finding', 'rule', 'path']);
const ALLOWED = ['schema', 'schemaVersion', 'id', 'tenant', 'environment', 'scope', 'actor', 'approvals', 'justification', 'compensatingControl', 'createdAt', 'expiresAt', 'policyVersion', 'signature'];
const REQUIRED = ['schema', 'schemaVersion', 'id', 'tenant', 'environment', 'scope', 'actor', 'approvals', 'justification', 'createdAt', 'expiresAt', 'policyVersion'];
const ID = /^[a-z0-9][a-z0-9._:-]{1,62}$/i;
const ACTOR_ID = /^[a-z0-9][a-z0-9._:-]{2,63}$/i;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
export const DEFAULT_POLICY = Object.freeze({ version: 1, minPolicyVersion: 1, maxLifetimeDays: 90, requiredApprovals: 1, requireSignature: false, minJustificationChars: 20, requireCompensatingControl: true });

export const waiverId = (w) => `wvr:${digestOf({ tenant: w.tenant, environment: w.environment, scope: w.scope, actor: w.actor && w.actor.id, createdAt: w.createdAt, expiresAt: w.expiresAt, policyVersion: w.policyVersion }).slice(7, 7 + 16)}`;

function actorOk(ctx, p, a) {
  if (!isPlainObject(a)) { ctx.err('BAD_TYPE', p, 'must be an object {id, role}'); return; }
  for (const k of Object.keys(a)) if (!['id', 'role'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, 'only an opaque id and a role are recorded for a person; no name or contact detail');
  if (typeof a.id !== 'string' || !ACTOR_ID.test(a.id)) ctx.err('BAD_ID', `${p}.id`, 'must be an opaque identifier (letters, digits, . _ : -), 3 to 64 characters');
  else if (a.id.includes('@')) ctx.err('BAD_ID', `${p}.id`, 'an e-mail address is personal data and is not accepted as an identifier; use an opaque id');
  checkString(ctx, `${p}.role`, a.role);
}

/** Closed-world validation of one waiver. Never throws. */
export function validateWaiver(w, policy = DEFAULT_POLICY) {
  const g = guardObject(w); const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, w, WAIVER_SCHEMA)) return result(ctx);
  checkFields(ctx, w, ALLOWED, REQUIRED);
  for (const k of ['tenant', 'environment']) if (typeof w[k] !== 'string' || !ID.test(w[k])) ctx.err('BAD_ID', k, 'must be a plain identifier (letters, digits, . _ : -)');
  if (!isPlainObject(w.scope) || !SCOPE_KINDS.includes(w.scope.kind) || typeof w.scope.value !== 'string' || !w.scope.value) ctx.err('BAD_TYPE', 'scope', `must be {kind: ${SCOPE_KINDS.join('|')}, value}`);
  else if (w.scope.kind === 'path' && (w.scope.value === '**' || w.scope.value === '*')) ctx.err('RULE_VIOLATION', 'scope.value', 'a waiver for every path is not a scoped waiver');
  actorOk(ctx, 'actor', w.actor);
  if (!Array.isArray(w.approvals)) ctx.err('BAD_TYPE', 'approvals', 'must be a list');
  else {
    const seen = new Set();
    w.approvals.forEach((a, i) => { actorOk(ctx, `approvals[${i}]`, a); if (a && a.id) { if (a.id === (w.actor && w.actor.id)) ctx.err('RULE_VIOLATION', `approvals[${i}]`, 'a person cannot approve their own waiver'); if (seen.has(a.id)) ctx.err('DUPLICATE_ID', `approvals[${i}]`, 'the same approver twice counts once'); seen.add(a.id); } });
    if (seen.size < policy.requiredApprovals) ctx.err('RULE_VIOLATION', 'approvals', `${policy.requiredApprovals} distinct approver(s) required, ${seen.size} given`);
  }
  if (typeof w.justification !== 'string' || w.justification.trim().length < policy.minJustificationChars) ctx.err('RULE_VIOLATION', 'justification', `a justification of at least ${policy.minJustificationChars} characters is required`);
  else { const hit = secretCanaryHit(w.justification) || canaryHit(w.justification); if (hit) ctx.err('RULE_VIOLATION', 'justification', `the justification contains something that looks like ${hit.replace(/-/g, ' ')}; waivers are stored and shown, so it is refused`); }
  if (policy.requireCompensatingControl && (typeof w.compensatingControl !== 'string' || w.compensatingControl.trim().length < 10)) ctx.err('RULE_VIOLATION', 'compensatingControl', 'a compensating control is required: a reason to wait is not one');
  for (const k of ['createdAt', 'expiresAt']) if (typeof w[k] !== 'string' || !ISO.test(w[k]) || !Number.isFinite(Date.parse(w[k]))) ctx.err('BAD_TYPE', k, 'must be a UTC ISO timestamp');
  if (ISO.test(w.createdAt || '') && ISO.test(w.expiresAt || '')) {
    const life = (Date.parse(w.expiresAt) - Date.parse(w.createdAt)) / 86400000;
    if (life <= 0) ctx.err('RULE_VIOLATION', 'expiresAt', 'must be after createdAt');
    if (life > policy.maxLifetimeDays) ctx.err('RULE_VIOLATION', 'expiresAt', `a waiver may last at most ${policy.maxLifetimeDays} days`);
  }
  if (!Number.isInteger(w.policyVersion) || w.policyVersion < 1) ctx.err('BAD_TYPE', 'policyVersion', 'must be a positive integer');
  if (w.id && w.id !== waiverId(w)) ctx.err('ID_MISMATCH', 'id', 'the id does not match the waiver it names');
  return result(ctx);
}

export function buildWaiver(f) {
  const w = { schema: WAIVER_SCHEMA, schemaVersion: SCHEMA_VERSION, tenant: f.tenant, environment: f.environment, scope: f.scope, actor: f.actor, approvals: f.approvals || [], justification: f.justification, ...(f.compensatingControl ? { compensatingControl: f.compensatingControl } : {}), createdAt: f.createdAt, expiresAt: f.expiresAt, policyVersion: f.policyVersion };
  w.id = waiverId(w);
  return w;
}

const bytesOf = (w) => Buffer.from(canonicalJson((({ signature, ...rest }) => rest)(w)), 'utf8');
export function signWaiver(w, privateKeyPem) {
  const pub = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  return { ...w, signature: { algorithm: 'ed25519', keyFingerprint: keyFingerprint(pub), value: crypto.sign(null, bytesOf(w), privateKeyPem).toString('base64') } };
}
function signatureState(w, trustedKeys) {
  if (!w.signature) return 'unsigned';
  const pem = trustedKeys && trustedKeys[w.signature.keyFingerprint];
  if (!pem) return 'untrusted-key';
  try { return crypto.verify(null, bytesOf(w), pem, Buffer.from(w.signature.value, 'base64')) ? 'valid' : 'invalid'; } catch { return 'invalid'; }
}

// ---- evaluation ----------------------------------------------------------------------------------------------------------------

/**
 * Can this waiver be honoured here and now?
 * @param {{now:number, tenant:string, environment:string, policy?:object, trustedKeys?:Object<string,string>}} ctx
 * @returns {{honoured:boolean, reasons:string[]}} `reasons` are stable codes: invalid, expired, tenant-mismatch, environment-mismatch, policy-version-superseded, unsigned, untrusted-key, bad-signature
 */
export function evaluateWaiver(w, ctx) {
  const policy = { ...DEFAULT_POLICY, ...(ctx.policy || {}) };
  const reasons = [];
  // judged against the policy in force NOW: a waiver made under looser rules (a longer lifetime, fewer approvers) stops being honoured when the rules tighten
  const v = validateWaiver(w, policy);
  if (!v.ok) return { honoured: false, reasons: ['invalid'], errors: v.errors.map((e) => `${e.path}: ${e.message}`) };
  if (Date.parse(w.expiresAt) <= ctx.now) reasons.push('expired');
  if (Date.parse(w.createdAt) > ctx.now) reasons.push('not-yet-valid');
  if (w.tenant !== ctx.tenant) reasons.push('tenant-mismatch');
  if (w.environment !== ctx.environment) reasons.push('environment-mismatch');
  if (w.policyVersion < policy.minPolicyVersion) reasons.push('policy-version-superseded');
  const sig = signatureState(w, ctx.trustedKeys);
  if (sig === 'invalid') reasons.push('bad-signature'); else if (sig === 'untrusted-key') reasons.push('untrusted-key'); else if (sig === 'unsigned' && policy.requireSignature) reasons.push('unsigned');
  return { honoured: reasons.length === 0, reasons };
}

const globToRe = (g) => new RegExp('^' + g.split('**').map((p) => p.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')).join('.*') + '$');
function matches(w, f) {
  if (w.scope.kind === 'finding') return w.scope.value === f.stableId || w.scope.value === f.id;
  if (w.scope.kind === 'rule') return w.scope.value === f.vuln || w.scope.value === f.family || w.scope.value === f.cwe || w.scope.value === f.id;
  return typeof f.file === 'string' && globToRe(w.scope.value).test(f.file);
}

/**
 * Apply waivers to findings. A finding is removed from `open` only by a waiver that is honoured; everything else is reported.
 * @returns {{open:object[], waived:{finding:object, waiverId:string}[], refused:{waiverId:string, findingId:string, reasons:string[]}[], summary:object}}
 */
export function applyWaivers(findings, waivers, ctx, auditLog = null) {
  const open = []; const waived = []; const refused = [];
  const evals = new Map((waivers || []).map((w) => [w.id, evaluateWaiver(w, ctx)]));
  for (const f of findings || []) {
    const cand = (waivers || []).filter((w) => isPlainObject(w) && isPlainObject(w.scope) && typeof w.scope.value === 'string' && matches(w, f));
    const ok = cand.find((w) => evals.get(w.id).honoured);
    if (ok) { waived.push({ finding: f, waiverId: ok.id }); if (auditLog) auditLog.append({ event: 'waiver.applied', tenant: ctx.tenant, waiver: ok.id, finding: f.stableId || f.id }); continue; }
    open.push(f);
    for (const w of cand) { const e = evals.get(w.id); refused.push({ waiverId: w.id, findingId: f.stableId || f.id, reasons: e.reasons }); if (auditLog) auditLog.append({ event: 'waiver.refused', tenant: ctx.tenant, waiver: w.id, finding: f.stableId || f.id, reasons: e.reasons }); }
  }
  const expired = [...new Set(refused.filter((r) => r.reasons.includes('expired')).map((r) => r.waiverId))];
  const unusedExpired = (waivers || []).filter((w) => evals.get(w.id) && evals.get(w.id).reasons.includes('expired') && !expired.includes(w.id)).map((w) => w.id);
  return { open, waived, refused, summary: { findings: (findings || []).length, open: open.length, waived: waived.length, refusedMatches: refused.length, expiredWaivers: [...expired, ...unusedExpired].length, reopenedByExpiry: refused.filter((r) => r.reasons.includes('expired')).length } };
}

// ---- audit log -----------------------------------------------------------------------------------------------------------------

const AUDIT_FIELDS = new Set(['event', 'tenant', 'actor', 'waiver', 'finding', 'reasons', 'target', 'name', 'code']);
export function createAuditLog({ file = null, now = () => Date.now() } = {}) {
  const entries = []; let prev = 'sha256:' + '0'.repeat(64);
  const log = {
    entries,
    append(e) {
      const body = {};
      for (const [k, v] of Object.entries(e)) {
        if (!AUDIT_FIELDS.has(k)) throw new Error(`the audit log does not record "${k}": ids and reason codes only`);
        if (typeof v === 'string' && (canaryHit(v) || secretCanaryHit(v))) throw new Error(`the audit log refuses a value that looks like personal data or a secret (${k})`);
        body[k] = v;
      }
      const entry = { seq: entries.length + 1, at: new Date(now()).toISOString(), ...body, prev };
      entry.hash = digestOf(entry); prev = entry.hash; entries.push(entry);
      if (file) fs.appendFileSync(file, JSON.stringify(entry) + '\n');
      return entry;
    },
  };
  return log;
}

/** Re-derive the chain. A removed, edited or reordered entry breaks it. @returns {{ok:boolean, brokenAt:number|null}} */
export function verifyAuditLog(entries) {
  let prev = 'sha256:' + '0'.repeat(64);
  for (const [i, e] of (entries || []).entries()) {
    const { hash, ...rest } = e;
    if (e.seq !== i + 1 || e.prev !== prev || hash !== digestOf(rest)) return { ok: false, brokenAt: i + 1 };
    prev = hash;
  }
  return { ok: true, brokenAt: null };
}

// ---- tenant-isolated evidence store -------------------------------------------------------------------------------------------

export class AccessDenied extends Error { constructor(m) { super(m); this.code = 'ACCESS_DENIED'; } }
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function createTenantStore(root, { auditLog, holds = () => [], now = () => Date.now() } = {}) {
  const dirOf = (tenant) => { if (typeof tenant !== 'string' || !ID.test(tenant)) throw new AccessDenied('invalid tenant identifier'); return path.join(root, 'tenants', tenant); };
  const deny = (requester, target, why) => { if (auditLog) auditLog.append({ event: 'access.denied', tenant: typeof requester === 'string' ? requester.slice(0, 64) : 'invalid', target: typeof target === 'string' ? target.slice(0, 64) : 'invalid', code: why }); throw new AccessDenied(`access denied: ${why}`); };
  const guard = (requester, tenant) => { if (typeof requester !== 'string' || !ID.test(requester)) deny(requester, tenant, 'invalid-requester'); if (requester !== tenant) deny(requester, tenant, 'other-tenant'); };
  const fileOf = (tenant, name, requester) => { if (typeof name !== 'string' || !NAME.test(name) || name.includes('..')) deny(requester, tenant, 'invalid-name'); return path.join(dirOf(tenant), name); };
  return {
    put(requester, tenant, name, bytes) { guard(requester, tenant); const f = fileOf(tenant, name, requester); fs.mkdirSync(dirOf(tenant), { recursive: true }); try { if (fs.lstatSync(f).isSymbolicLink()) deny(requester, tenant, 'symlink'); } catch (e) { if (e instanceof AccessDenied) throw e; } fs.writeFileSync(f, bytes); if (auditLog) auditLog.append({ event: 'evidence.put', tenant, name }); },
    get(requester, tenant, name) { guard(requester, tenant); const f = fileOf(tenant, name, requester); let st; try { st = fs.lstatSync(f); } catch { return null; } if (st.isSymbolicLink()) deny(requester, tenant, 'symlink'); if (auditLog) auditLog.append({ event: 'evidence.get', tenant, name }); return fs.readFileSync(f); },
    list(requester, tenant) { guard(requester, tenant); try { return fs.readdirSync(dirOf(tenant)).sort(); } catch { return []; } },
    /** Erase a tenant's evidence on request. Refused while a legal hold covers the tenant. Leaves a tombstone, not the content. */
    erase(requester, tenant, { reason } = {}) {
      guard(requester, tenant);
      if (isUnderHold(`tenant:${tenant}`, holds(), now())) { if (auditLog) auditLog.append({ event: 'erasure.refused', tenant, code: 'legal-hold' }); return { erased: false, reason: 'legal-hold' }; }
      let n = 0; try { n = fs.readdirSync(dirOf(tenant)).length; } catch { /* nothing stored */ }
      fs.rmSync(dirOf(tenant), { recursive: true, force: true });
      if (auditLog) auditLog.append({ event: 'erasure.done', tenant, code: typeof reason === 'string' && /^[a-z-]{3,32}$/.test(reason) ? reason : 'requested' });
      return { erased: true, files: n };
    },
  };
}
