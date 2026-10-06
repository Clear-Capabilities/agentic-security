// Evidence envelopes: written ONLY by the verifier, HMAC-signed, bound to the
// requirement's own acceptance hash, the PRD hash, the verifier's own source
// hash and the digest of the files the requirement depends on. Anything that
// stops matching makes the evidence stale and removes it from the numerator.
import { createHmac } from 'node:crypto';
import { readFileSync, readdirSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson, sha256, atomicWriteJson, readJson, fileExists } from './util.mjs';
import { acceptanceCore } from './manifest.mjs';
import { validate } from './schema.mjs';
import { loadSchema } from './manifest.mjs';

export const VERIFIER_VERSION = '1.0.0';
const VERIFIER_FILES = ['verifier.mjs', 'evidence.mjs', 'tap.mjs', 'tree.mjs', 'proc.mjs', 'procscan.mjs', 'oplease.mjs', 'manifest.mjs', 'prd-import.mjs', 'remote.mjs'];
let _vh = null;
export function verifierHash() {
  if (_vh) return _vh;
  const parts = VERIFIER_FILES.map((f) => sha256(readFileSync(new URL(`./${f}`, import.meta.url))));
  _vh = sha256(VERIFIER_VERSION + parts.join(''));
  return _vh;
}

export const requirementHash = (req) => sha256(canonicalJson(acceptanceCore(req)));

export function sign(envelope, key) {
  const { signature, ...rest } = envelope;
  void signature;
  return createHmac('sha256', key).update(canonicalJson(rest)).digest('hex');
}

export function evidenceDir(L, reqId) { return join(L.evidenceDir, reqId); }

export function nextSeq(L, reqId) {
  try {
    const nums = readdirSync(evidenceDir(L, reqId)).map((f) => /^(\d{6})\.json$/.exec(f)).filter(Boolean).map((m) => +m[1]);
    return (nums.length ? Math.max(...nums) : 0) + 1;
  } catch { return 1; }
}

export function writeEvidence(L, reqId, envelope, key) {
  mkdirSync(evidenceDir(L, reqId), { recursive: true, mode: 0o700 });
  const seq = nextSeq(L, reqId);
  const id = `${reqId}-${String(seq).padStart(6, '0')}`;
  const full = { ...envelope, evidenceId: id };
  full.signature = sign(full, key);
  const file = join(evidenceDir(L, reqId), `${String(seq).padStart(6, '0')}.json`);
  atomicWriteJson(file, full);
  return { file, seq, evidence: full };
}

export function listEvidence(L, reqId) {
  let names = [];
  try { names = readdirSync(evidenceDir(L, reqId)).filter((f) => /^\d{6}\.json$/.test(f)).sort(); } catch { return []; }
  return names.map((n) => ({ file: join(evidenceDir(L, reqId), n), seq: parseInt(n, 10), ev: readJson(join(evidenceDir(L, reqId), n), null) })).filter((e) => e.ev);
}

export function checkEnvelope(ev, key, { checkLogs = false } = {}) {
  const reasons = [];
  const errs = validate(loadSchema('evidence.schema.json'), ev);
  if (errs.length) reasons.push(`schema: ${errs[0]}`);
  if (typeof ev.signature !== 'string' || sign(ev, key) !== ev.signature) reasons.push('bad signature (forged or edited evidence)');
  if (checkLogs && ev.logs) {
    for (const l of Object.values(ev.logs)) {
      if (!l || !l.path) continue;
      if (!fileExists(l.path)) { reasons.push(`log missing: ${l.path}`); continue; }
      if (sha256(readFileSync(l.path)) !== l.sha256) reasons.push(`log hash mismatch: ${l.path}`);
    }
  }
  return { valid: reasons.length === 0, reasons };
}

// Union of this requirement's watch globs and those of everything it
// transitively depends on.
export function effectiveWatch(manifest, req) {
  const byId = new Map(manifest.requirements.map((r) => [r.id, r]));
  const globs = new Set();
  const seen = new Set();
  const walk = (r) => {
    if (!r || seen.has(r.id)) return;
    seen.add(r.id);
    r.watch.forEach((g) => globs.add(g));
    r.dependencies.forEach((d) => walk(byId.get(d)));
  };
  walk(req);
  return [...globs].sort();
}

export function assessOne(ev, { key, manifest, req, tree, checkLogs = false }) {
  const c = checkEnvelope(ev, key, { checkLogs });
  const staleReasons = [];
  if (ev.requirement !== req.id) c.reasons.push('evidence is for a different requirement');
  if (ev.manifest?.requirementHash !== requirementHash(req)) staleReasons.push('acceptance definition changed');
  if (ev.prdSha256 !== manifest.prd.sha256) staleReasons.push('PRD changed');
  if (ev.verifier?.hash !== verifierHash()) staleReasons.push('verifier changed');
  const cur = tree.digestFor(effectiveWatch(manifest, req)).digest;
  if (ev.treeDigest !== cur) staleReasons.push('relevant source/test files changed');
  const valid = c.valid && !c.reasons.length;
  const fresh = valid && staleReasons.length === 0;
  const passed = (ev.criteria || []).filter((x) => x.state === 'pass').length;
  return {
    valid, fresh, invalidReasons: c.reasons, staleReasons,
    verified: fresh && ev.result === 'pass' && (ev.criteria || []).length === req.criteria.length && passed === req.criteria.length,
    passedCriteria: passed, totalCriteria: req.criteria.length,
  };
}

// Newest VALID evidence wins; invalid (forged) files are ignored, not trusted.
export function assessRequirement(L, req, ctx) {
  const list = listEvidence(L, req.id).reverse();
  let latest = null;
  const rejected = [];
  for (const e of list) {
    const a = assessOne(e.ev, { ...ctx, req });
    if (a.valid) { latest = { ...e, assessment: a }; break; }
    rejected.push({ file: e.file, reasons: a.invalidReasons });
  }
  if (!latest) return { latest: null, verified: false, fresh: false, stale: false, passedCriteria: 0, totalCriteria: req.criteria.length, rejected };
  const a = latest.assessment;
  return {
    latest, verified: a.verified, fresh: a.fresh,
    stale: !a.fresh && latest.ev.result === 'pass',
    staleReasons: a.staleReasons, passedCriteria: a.passedCriteria, totalCriteria: a.totalCriteria, rejected,
  };
}
