// Explicit policy recovery (X-506).
//
// A denied task does not talk its way out of a denial and does not retry until
// something gives. The only way a denial turns into a permission is a policy
// change that
//
//   is OPERATOR-ONLY   the grant is an Ed25519 signature over the exact change;
//                      the signing key lives in the signer domain, which a worker
//                      cannot read (sandbox/trust-domains.js, the protected key
//                      directory), so a worker cannot mint one and a forged
//                      signature fails verification
//   is BOUND           the signature covers the digest of the manifest it
//                      changes AND the digest of the manifest it produces, the
//                      task and both policy versions, so it is not a blank
//                      cheque and cannot be replayed on another task or version
//   is BOUNDED         a short validity window, a single use (nonce), and a
//                      finite number of changes per task
//   is RECORDED        every applied change is an entry in a hash-chained ledger
//   creates a NEW VERSION  the policy version rises by one. Every earlier binding
//                      is then stale (`binding-mismatch`) and every receipt for
//                      the earlier digest is superseded (receipts.js)
//
// A denial itself returns `blocked`, the missing capability and a proposed
// manifest change for a human to review (`proposeChange`). The proposal is data:
// applying it needs the operator grant above. Repeated denials of one action hit
// a finite limit and stay blocked (`createDenialGuard`); no path in this module
// turns a denial into an allow, falls back to unrestricted execution or loops.
import crypto from 'node:crypto';
import { canonicalJson, keyFingerprint, TRUST_BASES } from '../posture/evidence-bundle.js';
import { mayDo, RESOURCES } from '../sandbox/trust-domains.js';
import { digestOf } from '../posture/assurance/identity.js';
import { bindManifest, validateManifest } from './manifest.js';
import { decide } from './decide.js';
import { detectSecretShapes } from './secrets.js';
import { normalizeHost, classifyAddress } from './address.js';
import { reasonText, sanitizeSubject } from './reasons.js';
import { requiredControlsFor, unmetControls, probeCapabilityControls } from './probes.js';
import { toolCapabilityFor } from './tool-registry.js';

export const GRANT_SCHEMA = 'agentic-security/policy-grant';
export const LEDGER_SCHEMA = 'agentic-security/policy-ledger';
export const DEFAULT_RETRY_LIMIT = 3;
export const MAX_RETRY_LIMIT = 10;
export const DEFAULT_TASK_DENIAL_BUDGET = 20;
export const MAX_TASK_DENIAL_BUDGET = 100;
export const MAX_GRANT_TTL_MS = 60 * 60 * 1000;
export const DEFAULT_MAX_CHANGES = 5;
const MAX_TRACKED = 1000;
const GENESIS = '0'.repeat(64);

const sha = (v) => crypto.createHash('sha256').update(typeof v === 'string' ? v : canonicalJson(v)).digest('hex');
const clean = (s) => typeof s === 'string' && !/[\u0000-\u001f\u007f]/.test(s) && !detectSecretShapes(s);

// ---------------------------------------------------------------- proposals

// Codes that name a structural refusal. A proposal for any of these would be an
// invitation to widen the boundary around keys, labels, links and secrets.
const NOT_PROPOSABLE = new Set([
  'binding-mismatch', 'unknown-action', 'invalid-manifest', 'scope-expansion', 'path-invalid', 'path-traversal',
  'symlink-escape', 'protected-path', 'executable-not-absolute', 'executable-unresolvable', 'executable-in-writable-root',
  'args-invalid', 'secret-in-argument', 'host-invalid', 'port-invalid', 'dns-private-address', 'dns-changed',
  'payload-too-large', 'payload-uninspectable', 'resource-limit-exceeded', 'retry-limit', 'task-halted', 'identity-spoofed',
  'identity-missing', 'tool-unclassified', 'allowed', 'delegation-depth',
]);

function unproposable(decision, why) {
  return Object.freeze({
    proposable: false, why, missing: Object.freeze({ capability: decision.kind, code: decision.code, detail: decision.subject }),
    selfGrantable: false, requiresOperatorGrant: true, change: null,
  });
}

/**
 * The missing capability and a reviewable manifest change for one denial. The
 * change is the NARROWEST addition that would allow exactly this action (an exact
 * path, an exact argument array, one host and port). It is a proposal: a worker
 * can read it and cannot apply it.
 */
export function proposeChange(bound, action, decision) {
  const base = { kind: decision?.kind ?? 'unknown', code: decision?.code ?? 'unknown-action', subject: decision?.subject ?? '' };
  if (!decision || decision.decision === 'allow') return unproposable({ ...base, code: 'allowed' }, 'the action was allowed; there is nothing to propose');
  if (NOT_PROPOSABLE.has(decision.code)) return unproposable(decision, `${reasonText(decision.code)}; no manifest change is proposed for this refusal`);
  let add = null; let risk = 'scope-addition';
  const a = action || {};
  switch (a.kind) {
    case 'filesystem-read':
    case 'filesystem-write':
      if (typeof a.path === 'string' && clean(a.path)) add = { filesystem: { [a.kind === 'filesystem-write' ? 'write' : 'read']: [a.path] } };
      break;
    case 'command':
      if (typeof a.executable === 'string' && clean(a.executable) && (a.args ?? []).every((x) => typeof x === 'string' && clean(x))) {
        const entry = { executable: a.executable, args: { mode: 'exact', values: [...(a.args ?? [])] } };
        if (decision.code === 'interpreter-blocked' || decision.code === 'interpreter-args-unpinned') { entry.interpreter = 'scoped'; risk = 'interpreter'; }
        add = { commands: [entry] };
      }
      break;
    case 'network':
      // A literal loopback, private, link-local or metadata address is never offered as a destination.
      if (typeof a.host === 'string' && clean(a.host) && Number.isInteger(a.port) && (() => {
        const h = normalizeHost(a.host);
        return h.ok && (h.kind === 'name' || classifyAddress(h.host) === 'public');
      })()) {
        add = { network: [{ host: a.host, port: a.port, schemes: [a.scheme === 'http' ? 'http' : 'https'] }] };
      }
      break;
    case 'tool':
      // Only a tool this build knows can be proposed; an unknown name is not a capability.
      if (typeof a.tool === 'string' && toolCapabilityFor(a.tool)) add = { tools: [a.tool] };
      break;
    case 'delegation':
      if (decision.code === 'delegation-not-allowed') add = { delegation: { allow: true, maxDepth: 1 } };
      break;
    default: break;
  }
  if (!add) return unproposable(decision, 'the request cannot be turned into a safe manifest addition');
  const change = Object.freeze({ add });
  return Object.freeze({
    proposable: true, why: null, risk,
    missing: Object.freeze({ capability: decision.kind, code: decision.code, detail: decision.subject }),
    selfGrantable: false, requiresOperatorGrant: true,
    nextPolicyVersion: bound.binding.policyVersion + 1,
    change, changeDigest: digestOf(change),
    review: `Add to task ${sanitizeSubject(bound.binding.taskId, 80)} at policy version ${bound.binding.policyVersion + 1}: ${sanitizeSubject(JSON.stringify(add), 300)}`,
  });
}

// ---------------------------------------------------------------- denial guard

function actionKey(binding, action) {
  const a = action && typeof action === 'object' ? action : {};
  const material = { kind: a.kind ?? null, path: a.path ?? null, executable: a.executable ?? null, args: Array.isArray(a.args) ? a.args : null, host: a.host ?? null, port: a.port ?? null, scheme: a.scheme ?? null, tool: a.tool ?? null };
  return sha({ taskId: binding?.taskId ?? null, policyVersion: binding?.policyVersion ?? null, material });
}

/**
 * Bounded denial handling. `admit` is asked BEFORE the policy is evaluated; once
 * an action has been denied `retryLimit` times in one policy version, or the task
 * has been denied `taskBudget` times in all, the answer is a fixed refusal and the
 * action is not even evaluated again. A new policy version starts a new count (the
 * operator changed something, so a retry is no longer the same request).
 */
export function createDenialGuard({ retryLimit = DEFAULT_RETRY_LIMIT, taskBudget = DEFAULT_TASK_DENIAL_BUDGET } = {}) {
  const rl = Number.isInteger(retryLimit) && retryLimit >= 1 ? Math.min(retryLimit, MAX_RETRY_LIMIT) : DEFAULT_RETRY_LIMIT;
  const tb = Number.isInteger(taskBudget) && taskBudget >= 1 ? Math.min(taskBudget, MAX_TASK_DENIAL_BUDGET) : DEFAULT_TASK_DENIAL_BUDGET;
  const perAction = new Map();
  const perTask = new Map();
  const taskKey = (b) => `${b?.taskId ?? 'unbound'}@${b?.policyVersion ?? 0}`;
  return Object.freeze({
    retryLimit: rl, taskBudget: tb,
    admit(binding, action) {
      const t = perTask.get(taskKey(binding)) ?? 0;
      if (t >= tb || perAction.size >= MAX_TRACKED) return { admit: false, code: 'task-halted' };
      if ((perAction.get(actionKey(binding, action)) ?? 0) >= rl) return { admit: false, code: 'retry-limit' };
      return { admit: true, code: null };
    },
    record(binding, action) {
      const k = actionKey(binding, action);
      const n = (perAction.get(k) ?? 0) + 1;
      perAction.set(k, n);
      perTask.set(taskKey(binding), (perTask.get(taskKey(binding)) ?? 0) + 1);
      return { attempts: n, remaining: Math.max(0, rl - n), exhausted: n >= rl };
    },
    stats(binding) { return { taskDenials: perTask.get(taskKey(binding)) ?? 0, trackedActions: perAction.size }; },
  });
}

/**
 * One mediated decision with recovery semantics. The result is either the policy
 * allowing the action, or `blocked`; there is no third outcome, no retry inside
 * this function and no fallback.
 */
export function mediate(bound, action, ctx, { guard } = {}) {
  const binding = ctx?.binding;
  if (guard) {
    const adm = guard.admit(binding, action);
    if (!adm.admit) {
      const decision = Object.freeze({
        decision: 'deny', code: adm.code, reason: reasonText(adm.code), kind: typeof action?.kind === 'string' ? sanitizeSubject(action.kind, 40) : 'unknown',
        subject: '(action not re-evaluated)', taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
      });
      return Object.freeze({ status: 'blocked', blocked: true, decision, ...proposalFields(unproposable(decision, reasonText(adm.code))), attemptsRemaining: 0, exhausted: true });
    }
  }
  const decision = decide(bound, action, ctx);
  if (decision.decision === 'allow') return Object.freeze({ status: 'ok', blocked: false, decision, proposal: null, missing: null, attemptsRemaining: null, exhausted: false });
  const counted = guard ? guard.record(binding, action) : null;
  const proposal = counted?.exhausted ? unproposable(decision, `${reasonText('retry-limit')}`) : proposeChange(bound, action, decision);
  return Object.freeze({
    status: 'blocked', blocked: true, decision, ...proposalFields(proposal),
    attemptsRemaining: counted ? counted.remaining : null, exhausted: counted ? counted.exhausted : false,
  });
}

function proposalFields(p) { return { proposal: p, missing: p.missing }; }

// ---------------------------------------------------------------- operator grants

function assertSigner(domain) {
  if (!mayDo(domain, RESOURCES.SIGNING_KEY, 'read')) {
    throw Object.assign(new Error(`the ${String(domain)} domain may not sign a policy grant`), { code: 'domain-denied' });
  }
}

const ADD_KEYS = ['filesystem', 'commands', 'network', 'tools', 'delegation'];

/** Apply an add-only change to a normalized manifest; the result is validated and bound at the next policy version. */
export function applyChangeToManifest(manifest, change) {
  if (!change || typeof change !== 'object' || Array.isArray(change) || Object.keys(change).some((k) => k !== 'add')) return { ok: false, code: 'change-invalid', bound: null };
  const add = change.add;
  if (!add || typeof add !== 'object' || Array.isArray(add) || Object.keys(add).length === 0 || Object.keys(add).some((k) => !ADD_KEYS.includes(k))) return { ok: false, code: 'change-invalid', bound: null };
  const next = JSON.parse(JSON.stringify(manifest));
  next.policyVersion = manifest.policyVersion + 1;
  if (add.filesystem) {
    if (typeof add.filesystem !== 'object' || Object.keys(add.filesystem).some((k) => !['read', 'write'].includes(k))) return { ok: false, code: 'change-invalid', bound: null };
    next.filesystem.read = [...next.filesystem.read, ...(add.filesystem.read ?? [])];
    next.filesystem.write = [...next.filesystem.write, ...(add.filesystem.write ?? [])];
  }
  if (add.commands) next.commands = [...next.commands, ...add.commands];
  if (add.network) next.network = [...next.network, ...add.network];
  if (add.tools) next.tools = [...next.tools, ...add.tools];
  if (add.delegation) next.delegation = add.delegation;
  const b = bindManifest(next);
  return b.ok ? { ok: true, code: null, bound: b.bound } : { ok: false, code: 'change-invalid', bound: null, errors: b.errors };
}

/**
 * Operator side. Signs a grant for ONE change to ONE manifest. Refuses unless the
 * caller declares the signer domain; a worker or target cannot sign (and in any
 * case does not hold the key).
 */
export function signPolicyGrant({ domain, privateKeyPem, bound, change, operator, reason, now = new Date(), ttlMs = 15 * 60 * 1000, nonce }) {
  assertSigner(domain);
  const applied = applyChangeToManifest(bound.manifest, change);
  if (!applied.ok) throw Object.assign(new Error('the change is not a valid add-only manifest change'), { code: applied.code });
  const ttl = Math.min(Math.max(1, ttlMs), MAX_GRANT_TTL_MS);
  const payload = {
    schema: GRANT_SCHEMA, taskId: bound.binding.taskId,
    fromPolicyVersion: bound.binding.policyVersion, fromDigest: bound.binding.digest,
    toPolicyVersion: applied.bound.binding.policyVersion, toDigest: applied.bound.binding.digest,
    operator: sanitizeSubject(operator, 80), reason: sanitizeSubject(reason, 200),
    issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + ttl).toISOString(),
    nonce: nonce ?? crypto.randomBytes(12).toString('hex'),
  };
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const issuance = {
    issuer: { id: `local-install:${keyFingerprint(publicKeyPem).slice(0, 16)}`, kind: 'local-install', keyFingerprint: keyFingerprint(publicKeyPem) },
    trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: TRUST_BASES['self-issued-local-key'].statement,
  };
  const sig = crypto.sign(null, Buffer.from(canonicalJson({ payload, issuance }), 'utf8'), privateKeyPem);
  return Object.freeze({ payload, issuance, signature: { algorithm: 'ed25519', value: sig.toString('base64') } });
}

function verifyGrant(grant, publicKeyPem) {
  if (!grant || typeof grant !== 'object' || !grant.payload || !grant.signature || grant.payload.schema !== GRANT_SCHEMA) return { ok: false, code: 'grant-invalid' };
  if (Object.keys(grant).some((k) => !['payload', 'issuance', 'signature'].includes(k))) return { ok: false, code: 'grant-invalid' };
  if (grant.signature.algorithm !== 'ed25519' || typeof grant.signature.value !== 'string') return { ok: false, code: 'grant-invalid' };
  if (!publicKeyPem) return { ok: false, code: 'grant-unsigned' };
  let ok = false;
  try { ok = crypto.verify(null, Buffer.from(canonicalJson({ payload: grant.payload, issuance: grant.issuance }), 'utf8'), publicKeyPem, Buffer.from(grant.signature.value, 'base64')); } catch { ok = false; }
  if (!ok) return { ok: false, code: 'grant-signature-invalid' };
  const iss = grant.issuance;
  if (!iss || !TRUST_BASES[iss.trustBasis] || iss.independentlyCertified !== false || iss.issuer?.keyFingerprint !== keyFingerprint(publicKeyPem)) return { ok: false, code: 'grant-issuer-invalid' };
  return { ok: true, code: null };
}

// ---------------------------------------------------------------- ledger

/** A hash-chained record of every applied policy change. Held by the controller, never by a worker. */
export function createPolicyLedger({ maxChanges = DEFAULT_MAX_CHANGES } = {}) {
  const max = Number.isInteger(maxChanges) && maxChanges >= 1 ? Math.min(maxChanges, 50) : DEFAULT_MAX_CHANGES;
  const entries = [];
  const nonces = new Set();
  const current = new Map(); // taskId -> {policyVersion, digest}
  const head = () => (entries.length ? entries[entries.length - 1].hash : GENESIS);
  return {
    maxChanges: max,
    entries: () => entries.map((e) => ({ ...e })),
    changesFor: (taskId) => entries.filter((e) => e.taskId === taskId).length,
    nonceUsed: (n) => nonces.has(n),
    /** Seed the current policy of a task (the first bound manifest). */
    register(bound) { if (!current.has(bound.binding.taskId)) current.set(bound.binding.taskId, { policyVersion: bound.binding.policyVersion, digest: bound.binding.digest }); },
    current: (taskId) => current.get(taskId) ?? null,
    isCurrent: (binding) => { const c = current.get(binding?.taskId); return !!c && c.policyVersion === binding.policyVersion && c.digest === binding.digest; },
    append(entry) {
      const body = { seq: entries.length, prev: head(), ...entry };
      const full = { ...body, hash: sha(body) };
      entries.push(Object.freeze(full));
      nonces.add(entry.nonce);
      current.set(entry.taskId, { policyVersion: entry.toPolicyVersion, digest: entry.toDigest });
      return full;
    },
    verify() { return verifyLedgerEntries(entries); },
  };
}

export function verifyLedgerEntries(list) {
  let prev = GENESIS;
  for (let i = 0; i < list.length; i++) {
    const { hash, ...body } = list[i];
    if (body.seq !== i || body.prev !== prev || sha(body) !== hash) return { ok: false, breakAt: i };
    prev = hash;
  }
  return { ok: true, breakAt: null, head: prev };
}

// ---------------------------------------------------------------- applying a grant

/**
 * Apply an operator grant to a task's policy. Returns the NEW bound manifest (a
 * new policy version), the ledger entry and the re-run preflight. On any refusal
 * `ok` is false, `bound` is null and the old policy is untouched.
 *
 * @param {object} o
 * @param {{manifest:object,binding:object}} o.bound   the current policy
 * @param {object} o.change                            the proposed `{add}`
 * @param {object} o.grant                             from `signPolicyGrant`
 * @param {string} o.publicKeyPem                      the operator's public key
 * @param {object} o.ledger                            from `createPolicyLedger`
 * @param {Date}   [o.now]
 * @param {object} [o.deniedAction]                    re-decided under the new policy
 * @param {object} [o.probeReport]                     injected probe report (default: probe this host)
 */
export async function applyPolicyChange({ bound, change, grant, publicKeyPem, ledger, now = new Date(), deniedAction, probeReport, ctxExtra = {} }) {
  const refuse = (code) => ({ ok: false, code, reason: `policy change refused: ${code}`, bound: null, entry: null, preflight: null });
  if (!bound?.manifest || !bound?.binding || !ledger) return refuse('invalid-input');
  const v = verifyGrant(grant, publicKeyPem);
  if (!v.ok) return refuse(v.code);
  const p = grant.payload;
  const issued = Date.parse(p.issuedAt); const expires = Date.parse(p.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires - issued > MAX_GRANT_TTL_MS || expires <= issued) return refuse('grant-window-invalid');
  if (now.getTime() < issued) return refuse('grant-not-yet-valid');
  if (now.getTime() >= expires) return refuse('grant-expired');
  const b = bound.binding;
  if (p.taskId !== b.taskId) return refuse('grant-wrong-task');
  if (p.fromPolicyVersion !== b.policyVersion || p.fromDigest !== b.digest) return refuse('grant-stale');
  ledger.register(bound);
  if (!ledger.isCurrent(b)) return refuse('grant-stale');
  if (ledger.nonceUsed(p.nonce)) return refuse('grant-replayed');
  if (ledger.changesFor(b.taskId) >= ledger.maxChanges) return refuse('change-limit');
  const applied = applyChangeToManifest(bound.manifest, change);
  if (!applied.ok) return refuse(applied.code);
  if (applied.bound.binding.digest !== p.toDigest || applied.bound.binding.policyVersion !== p.toPolicyVersion) return refuse('grant-change-mismatch');

  const entry = ledger.append({
    taskId: b.taskId, operator: p.operator, reason: p.reason, nonce: p.nonce,
    fromPolicyVersion: b.policyVersion, fromDigest: b.digest, toPolicyVersion: p.toPolicyVersion, toDigest: p.toDigest,
    changeDigest: digestOf(change), at: now.toISOString(),
  });

  // Rerun what the change can affect: the manifest itself, the controls the new
  // manifest depends on, and the action that was denied.
  const nb = applied.bound;
  const pr = probeReport || await probeCapabilityControls({});
  const required = requiredControlsFor(nb.manifest);
  const unmet = unmetControls(pr, required);
  const valid = validateManifest(nb.manifest).ok;
  const redecision = deniedAction ? decide(nb, deniedAction, { binding: nb.binding, ...ctxExtra }) : null;
  const preflight = {
    manifestValid: valid, requiredControls: required, unmet,
    redecision: redecision ? { decision: redecision.decision, code: redecision.code } : null,
    ready: valid && unmet.length === 0 && (!redecision || redecision.decision === 'allow'),
  };
  return {
    ok: true, code: null, reason: 'policy changed; a new policy version was created', bound: nb, entry, preflight,
    supersedes: { policyVersion: b.policyVersion, digest: b.digest },
  };
}
