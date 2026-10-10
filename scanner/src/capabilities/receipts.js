// Tamper-evident capability receipts (X-507).
//
// A receipt chain is the audit trail of ONE task run under ONE policy version:
//
//   start       the task identity, the manifest digest and policy version, the
//               backend the runner used, the level it reached and the controls
//               the runner OBSERVED (the active-probe states and probe digest),
//               plus the requested/checked/enforced report built from them
//   decision    one per capability decision, carrying the CORE-002
//               `capability-decision` record (decision, action, mediation,
//               enforced flag, backend)
//   outcome     what happened to the action (exited, timeout, denied, not-run ...)
//   end         the seal: how many receipts came before it and the ids of every
//               decision receipt, so removing one is visible even to a verifier
//               who only has the envelope
//
// Each receipt carries the hash of the one before it (`prev`) and its own hash, so
// a missing, reordered or edited receipt breaks the chain at a named position.
// The sealed chain is then signed (Ed25519) in the SIGNER domain with the same
// self-issued trust label the evidence bundles carry. Three roles, three domains
// (sandbox/trust-domains.js):
//
//   recorder   verifier domain: writes authoritative evidence. A worker or target
//              cannot create a recorder.
//   signer     signer domain: the only one that may read the signing key.
//   workers    neither. A worker cannot write a receipt file (the receipt
//              directory is outside every write root and read-denied by the
//              runner), cannot alter one (the signature), and cannot supply the
//              key.
//
// What a receipt PROVES: that the verifier-side recorder observed these decisions
// and outcomes under this manifest and backend, and that nothing was changed
// afterwards. It does NOT prove independent certification (the issuer is the local
// install), and `fullyEnforced` is a label the verifier computes: it is true only
// for a complete, intact, current chain whose runner reached `enforced` with every
// control proved. A host-proved run (macOS) is never labelled enforced.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson, keyFingerprint, TRUST_BASES } from '../posture/evidence-bundle.js';
import { mayDo, RESOURCES } from '../sandbox/trust-domains.js';
import { sanitizeSubject } from './reasons.js';
import { toCapabilityDecisionRecord } from './records.js';
import { canonicalPath, overlaps } from './paths.js';
import { platformStatements } from './probes.js';

export const RECEIPT_SCHEMA = 'agentic-security/capability-receipt';
export const RECEIPT_CHAIN_SCHEMA = 'agentic-security/capability-receipt-chain';
export const RECEIPT_ENVELOPE_SCHEMA = 'agentic-security/capability-receipt-envelope';
export const RECEIPT_KINDS = Object.freeze(['start', 'decision', 'outcome', 'policy-change', 'end']);
export const MAX_RECEIPTS = 2000;
export const MAX_ENVELOPE_BYTES = 4 * 1024 * 1024;
const GENESIS = '0'.repeat(64);

const sha = (v) => crypto.createHash('sha256').update(canonicalJson(v)).digest('hex');

function assertDomain(domain, resource, action, role) {
  if (!mayDo(domain, resource, action)) {
    throw Object.assign(new Error(`the ${String(domain)} domain may not act as the receipt ${role}`), { code: 'domain-denied' });
  }
}

// ---------------------------------------------------------------- recording

/**
 * @param {object} o
 * @param {string} o.domain   must be a domain that may write authoritative evidence (the verifier)
 * @param {{manifest:object,binding:object}} o.bound
 * @param {object|null} o.observed  what the runner observed: `{backend, level, enforced, probeDigest, controls, report}`; null when the run never reached a backend
 */
export function createReceiptRecorder({ domain, bound, observed, now = () => new Date().toISOString() }) {
  assertDomain(domain, RESOURCES.AUTHORITATIVE_EVIDENCE, 'write', 'recorder');
  const b = bound.binding;
  const m = bound.manifest;
  const receipts = [];
  let sealed = false;

  function push(kind, body) {
    if (sealed) throw Object.assign(new Error('the receipt chain is sealed'), { code: 'sealed' });
    if (receipts.length >= MAX_RECEIPTS) throw Object.assign(new Error('receipt limit reached'), { code: 'receipt-limit' });
    const core = {
      schema: RECEIPT_SCHEMA, seq: receipts.length, kind, taskId: b.taskId, policyVersion: b.policyVersion,
      manifestDigest: b.digest, prev: receipts.length ? receipts[receipts.length - 1].hash : GENESIS, at: now(), body,
    };
    const receipt = Object.freeze({ ...core, hash: sha(core) });
    receipts.push(receipt);
    return receipt;
  }

  push('start', {
    revision: b.revision,
    requested: {
      filesystemRead: m.filesystem.read.length, filesystemWrite: m.filesystem.write.length, commands: m.commands.length,
      network: m.network.length, tools: m.tools.length, delegation: m.delegation.allow,
    },
    observed: observed ? {
      backend: observed.backend ?? null, level: observed.level ?? 'none', enforced: observed.enforced === true,
      probeDigest: observed.probeDigest ?? null, controls: observed.controls ?? {},
    } : null,
    report: observed?.report ?? null,
  });

  return {
    decision(record) {
      if (!record || record.schema !== 'agentic-security/capability-decision') throw Object.assign(new Error('a capability-decision record is required'), { code: 'bad-record' });
      return push('decision', { record });
    },
    outcome(o) {
      return push('outcome', {
        action: sanitizeSubject(o.action ?? '', 200), outcome: sanitizeSubject(o.outcome ?? '', 60),
        status: o.status ?? null, code: o.code ?? null, exitCode: Number.isInteger(o.exitCode) ? o.exitCode : null,
        cleanupComplete: o.cleanupComplete === undefined ? null : o.cleanupComplete === true,
      });
    },
    policyChange(entry) { return push('policy-change', { entry }); },
    seal() {
      const decisionIds = receipts.filter((r) => r.kind === 'decision').map((r) => r.body.record.id);
      push('end', { count: receipts.length, decisionIds });
      sealed = true;
      const head = receipts[receipts.length - 1].hash;
      return Object.freeze({
        schema: RECEIPT_CHAIN_SCHEMA,
        binding: Object.freeze({ taskId: b.taskId, revision: b.revision, policyVersion: b.policyVersion, manifestDigest: b.digest }),
        receipts: Object.freeze(receipts.slice()), count: receipts.length, head,
      });
    },
  };
}

/**
 * Build a sealed chain from a `runCapabilityTask` result. Every decision the run
 * produced becomes a receipt; a run that never reached a backend still produces a
 * chain (start, its denial, an outcome of `not-run`, end), so a refusal is as
 * auditable as a run, and its `observed` is null so it can never read as enforced.
 */
export function receiptsFromRun({ domain, bound, result, now }) {
  const r = result || {};
  const observed = r.report ? {
    backend: r.report.backend ?? r.backend ?? null, level: r.report.level ?? r.level ?? 'none', enforced: r.enforced === true,
    probeDigest: r.report.probeDigest ?? null,
    controls: Object.fromEntries(Object.entries(r.report.controls || {}).map(([k, v]) => [k, v.state])),
    report: r.report,
  } : null;
  const rec = createReceiptRecorder({ domain, bound, observed, now });
  let records = Array.isArray(r.capabilityDecisions) ? r.capabilityDecisions : [];
  if (!records.length && Array.isArray(r.decisions)) {
    records = r.decisions
      .map((d) => toCapabilityDecisionRecord(d, { mediation: 'runner', enforced: false, backend: r.backend ?? null }))
      .filter((x) => x.ok).map((x) => x.record);
  }
  for (const record of records) rec.decision(record);
  rec.outcome({
    action: 'task', outcome: r.outcome ?? 'not-run', status: r.status ?? null, code: r.code ?? r.policyCode ?? null,
    exitCode: r.exitCode, cleanupComplete: r.cleanup ? r.cleanup.complete : undefined,
  });
  return rec.seal();
}

// ---------------------------------------------------------------- integrity

/** Recompute the chain: hashes, linkage, sequence and consistent task/policy binding. Pure; needs no key. */
export function verifyChainIntegrity(chain) {
  const fail = (breakAt, reason) => ({ ok: false, breakAt, reason });
  if (!chain || typeof chain !== 'object' || chain.schema !== RECEIPT_CHAIN_SCHEMA || !Array.isArray(chain.receipts) || !chain.binding) return fail(null, 'not a receipt chain');
  if (chain.receipts.length > MAX_RECEIPTS) return fail(null, 'too many receipts');
  let prev = GENESIS;
  for (let i = 0; i < chain.receipts.length; i++) {
    const r = chain.receipts[i];
    if (!r || typeof r !== 'object' || r.schema !== RECEIPT_SCHEMA || !RECEIPT_KINDS.includes(r.kind)) return fail(i, 'malformed receipt');
    const { hash, ...core } = r;
    if (r.seq !== i) return fail(i, 'receipt out of sequence (missing or reordered)');
    if (r.prev !== prev) return fail(i, 'chain link broken (a receipt was removed, reordered or replaced)');
    if (sha(core) !== hash) return fail(i, 'receipt content does not match its hash (modified)');
    if (r.taskId !== chain.binding.taskId || r.manifestDigest !== chain.binding.manifestDigest || r.policyVersion !== chain.binding.policyVersion) return fail(i, 'receipt is bound to a different task or policy');
    prev = hash;
  }
  if (chain.count !== chain.receipts.length) return fail(null, 'receipt count does not match the chain');
  if (chain.head !== prev) return fail(null, 'chain head does not match the last receipt');
  return { ok: true, breakAt: null, reason: null };
}

/** Whether a chain that is intact is also COMPLETE: start first, seal last, every decision named by the seal present. */
export function assessCompleteness(chain, { requiredDecisionIds = [] } = {}) {
  const reasons = [];
  const rs = chain?.receipts || [];
  if (!rs.length || rs[0].kind !== 'start') reasons.push('missing-start');
  const last = rs[rs.length - 1];
  if (!last || last.kind !== 'end') reasons.push('missing-seal');
  const decisions = rs.filter((r) => r.kind === 'decision');
  const have = new Set(decisions.map((r) => r.body?.record?.id));
  if (last?.kind === 'end') {
    if (last.body.count !== rs.length - 1) reasons.push('seal-count-mismatch');
    const sealed = new Set(last.body.decisionIds || []);
    for (const id of sealed) if (!have.has(id)) reasons.push('sealed-decision-missing');
    for (const id of have) if (!sealed.has(id)) reasons.push('decision-not-sealed');
  }
  for (const id of requiredDecisionIds) if (!have.has(id)) reasons.push('required-decision-missing');
  // A run that reached a backend must account for each kind of access it was
  // granted. A refusal that never started has only the denial to account for.
  const req = rs[0]?.body?.requested;
  const obs = rs[0]?.body?.observed;
  const kinds = new Set(decisions.map((r) => r.body.record.capability));
  if (req && obs && obs.level !== 'none') {
    if (req.commands > 0 && !kinds.has('command')) reasons.push('command-decision-missing');
    if (req.filesystemRead > 0 && !kinds.has('filesystem-read')) reasons.push('filesystem-read-decision-missing');
    if (req.filesystemWrite > 0 && !kinds.has('filesystem-write')) reasons.push('filesystem-write-decision-missing');
  }
  if (!rs.some((r) => r.kind === 'outcome')) reasons.push('missing-outcome');
  return { complete: reasons.length === 0, reasons: [...new Set(reasons)] };
}

// ---------------------------------------------------------------- signing

function issuanceFor(publicKeyPem) {
  const fp = keyFingerprint(publicKeyPem);
  return {
    issuer: { id: `local-install:${fp.slice(0, 16)}`, kind: 'local-install', keyFingerprint: fp },
    trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: TRUST_BASES['self-issued-local-key'].statement,
  };
}

/** Sign a sealed chain. Only the signer domain may read the signing key; any other domain is refused. */
export function signReceiptChain(chain, { domain, privateKeyPem }) {
  assertDomain(domain, RESOURCES.SIGNING_KEY, 'read', 'signer');
  const intact = verifyChainIntegrity(chain);
  if (!intact.ok) throw Object.assign(new Error(`refusing to sign a chain that is not intact: ${intact.reason}`), { code: 'chain-not-intact' });
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const body = { schema: RECEIPT_ENVELOPE_SCHEMA, chain, issuance: issuanceFor(publicKeyPem) };
  const sig = crypto.sign(null, Buffer.from(canonicalJson(body), 'utf8'), privateKeyPem);
  return { ...body, signature: { algorithm: 'ed25519', canonicalisation: RECEIPT_ENVELOPE_SCHEMA, value: sig.toString('base64') } };
}

const ENVELOPE_KEYS = new Set(['schema', 'chain', 'issuance', 'signature']);
const ENFORCEABLE = ['filesystem-read', 'filesystem-write', 'command', 'network'];

/**
 * Verify an envelope with the PUBLIC key alone.
 *
 * @param {object} envelope
 * @param {string} publicKeyPem
 * @param {object} [expected]
 * @param {{taskId:string, policyVersion:number, digest:string}} [expected.binding]  the CURRENT policy; a chain for any other digest or version is `superseded`
 * @param {string[]} [expected.requiredDecisionIds]  decision ids the run is known to have produced
 * @returns `ok` means the signature and chain are intact; `fullyEnforced` is the stricter label.
 */
export function verifyReceiptEnvelope(envelope, publicKeyPem, expected = {}) {
  const base = {
    ok: false, signatureValid: false, chainIntact: false, complete: false, current: null, fullyEnforced: false,
    label: 'invalid', reasons: [], breakAt: null, trustBasis: null, independentlyCertified: false, report: null,
  };
  const out = (patch) => Object.freeze({ ...base, ...patch });
  if (!envelope || typeof envelope !== 'object' || envelope.schema !== RECEIPT_ENVELOPE_SCHEMA) return out({ reasons: ['not-an-envelope'] });
  const extra = Object.keys(envelope).filter((k) => !ENVELOPE_KEYS.has(k));
  if (extra.length) return out({ label: 'tampered', reasons: [`unsigned-fields:${extra.join(',')}`] });
  if (!envelope.signature?.value || envelope.signature.algorithm !== 'ed25519') return out({ reasons: ['unsigned'] });
  if (!publicKeyPem) return out({ reasons: ['no-public-key'] });
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, Buffer.from(canonicalJson({ schema: envelope.schema, chain: envelope.chain, issuance: envelope.issuance }), 'utf8'), publicKeyPem, Buffer.from(envelope.signature.value, 'base64'));
  } catch { sigOk = false; }
  if (!sigOk) return out({ label: 'tampered', reasons: ['signature-mismatch'] });
  const iss = envelope.issuance;
  if (!iss || !TRUST_BASES[iss.trustBasis] || iss.independentlyCertified !== false || iss.issuer?.keyFingerprint !== keyFingerprint(publicKeyPem)) {
    return out({ signatureValid: true, label: 'invalid', reasons: ['issuer-invalid'] });
  }
  const intact = verifyChainIntegrity(envelope.chain);
  if (!intact.ok) return out({ signatureValid: true, label: 'tampered', reasons: [intact.reason], breakAt: intact.breakAt, trustBasis: iss.trustBasis });

  const chain = envelope.chain;
  const comp = assessCompleteness(chain, { requiredDecisionIds: expected.requiredDecisionIds || [] });
  let current = null;
  const reasons = [...comp.reasons];
  if (expected.binding) {
    const eb = expected.binding;
    current = eb.taskId === chain.binding.taskId && eb.policyVersion === chain.binding.policyVersion && eb.digest === chain.binding.manifestDigest;
    if (!current) reasons.push('superseded-policy');
  }
  const start = chain.receipts[0];
  const observed = start?.body?.observed ?? null;
  const report = start?.body?.report ?? null;
  const caps = (report?.capabilities || []).filter((c) => ENFORCEABLE.includes(c.kind));
  const decisionsEnforced = chain.receipts.filter((r) => r.kind === 'decision' && ['runner', 'proxy'].includes(r.body.record.mediation)).every((r) => r.body.record.enforced === true);
  const fullyEnforcedAll = comp.complete && current !== false && !!observed && observed.level === 'enforced' && observed.enforced === true
    && caps.length === ENFORCEABLE.length && caps.every((c) => c.enforced === true) && decisionsEnforced;

  let label;
  if (!comp.complete) label = 'incomplete-audit-trail';
  else if (current === false) label = 'superseded-policy';
  else if (!observed) label = 'not-run';
  else if (fullyEnforcedAll) label = 'fully-enforced';
  else if (observed.level === 'host-proved') label = 'host-proved-not-enforced';
  else label = 'not-enforced';

  return out({
    ok: true, signatureValid: true, chainIntact: true, complete: comp.complete, current, fullyEnforced: label === 'fully-enforced',
    label, reasons, trustBasis: iss.trustBasis, independentlyCertified: false, issuer: iss.issuer.id,
    report: receiptReport(chain),
  });
}

// ---------------------------------------------------------------- reporting

/**
 * requested / checked / enforced for each capability, read from the SIGNED start
 * receipt (what the runner observed), with the platform and network-boundary
 * limitations that apply. Nothing here is recomputed from the current host.
 */
export function receiptReport(chain) {
  const start = chain?.receipts?.[0];
  const rep = start?.body?.report ?? null;
  const observed = start?.body?.observed ?? null;
  return Object.freeze({
    level: observed?.level ?? 'none', backend: observed?.backend ?? null, probeDigest: observed?.probeDigest ?? null,
    requested: start?.body?.requested ?? null,
    capabilities: (rep?.capabilities || []).map((c) => ({
      kind: c.kind, requested: c.requested, checked: c.checked, enforcedBy: c.enforcedBy, enforced: c.enforced === true,
      ...(c.payloadFiltering ? { payloadFiltering: c.payloadFiltering } : {}),
    })),
    resources: rep?.resources ?? null,
    platforms: rep?.platforms ?? platformStatements(),
    networkBoundary: rep ? (rep.capabilities || []).find((c) => c.kind === 'network')?.enforcedBy ?? null : null,
    limitations: rep?.limitations ?? [],
  });
}

// ---------------------------------------------------------------- storage

/** Is a directory safe to hold receipts for this task: it must overlap none of the task's declared roots. */
export function receiptDirectoryConflict(bound, dir) {
  const real = canonicalPath(dir) ?? dir;
  for (const r of [...bound.manifest.filesystem.read, ...bound.manifest.filesystem.write]) {
    if (overlaps(real, canonicalPath(r) ?? r)) return r;
  }
  return null;
}

/**
 * Write a signed envelope into a verifier-owned directory. Exclusive create: an
 * existing receipt is never overwritten, so replacing one means deleting it, which
 * is itself visible to anyone holding the previous head.
 */
export function writeReceiptEnvelope(dir, envelope, { domain } = {}) {
  assertDomain(domain, RESOURCES.AUTHORITATIVE_EVIDENCE, 'write', 'writer');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const c = envelope.chain;
  const safe = String(c.binding.taskId).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 60);
  const file = path.join(dir, `${safe}.v${c.binding.policyVersion}.${c.head.slice(0, 12)}.receipt.json`);
  fs.writeFileSync(file, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  return file;
}

export function readReceiptEnvelope(file) {
  const st = fs.statSync(file);
  if (!st.isFile() || st.size > MAX_ENVELOPE_BYTES) throw Object.assign(new Error('receipt file is not a regular file within the size limit'), { code: 'bad-receipt-file' });
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
