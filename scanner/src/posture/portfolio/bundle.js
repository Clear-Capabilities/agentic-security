// Portable, content-addressed evidence bundle and its OFFLINE verifier (X-702).
//
// A bundle is a directory:
//
//     bundle.json        the index: schema, manifest digest, every entry (role, logical name, digest, size), replay prerequisites
//     blobs/<sha256 hex> one file per entry, named by the digest of its canonical bytes
//
// Everything a reviewer needs to check a release claim is in it (X-702.AC01): the assurance manifest, the SANITIZED findings, finding
// provenance, replay manifests, the dependency and toolchain identities, and the verification receipts the manifest cites. Nothing in it
// refers to the agent conversation that produced the work.
//
// The verifier (X-702.AC02) uses node:fs and node:crypto only. It never opens a socket and never executes anything from the bundle:
// it re-hashes every blob against the index, validates the manifest through manifest.js, checks that every receipt the manifest cites
// is present as a blob, and then DISCLOSES what a runtime replay would need (`replay.prerequisites`) without attempting one. A verified
// bundle therefore proves its contents are unmodified; it does not prove a replay would still reproduce today.
//
// Export and import enforce limits (X-702.AC03): entry count, per-blob and total bytes, logical-name shape (no absolute path, no `..`,
// no unusual characters), no symlinks, and a secret filter. The filter first REDACTS known secret shapes in findings and provenance, then
// refuses to write a blob in which any secret shape survives; the importer refuses a bundle that carries one. A missing blob, a modified
// blob or a modified index fails integrity validation; none is ever repaired or skipped silently.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { canonicalJson } from '../evidence-bundle.js';
import { digestOf, digestOfBytes } from '../assurance/identity.js';
import { redactSecrets } from '../../llm-validator/redact.js';
import { validateManifest, manifestDigest } from './manifest.js';

export const BUNDLE_SCHEMA = 'agentic-security/portable-evidence-bundle';
const BUNDLE_VERSION = '1.0.0';
export const INDEX_FILE = 'bundle.json';
export const BLOB_DIR = 'blobs';
export const ROLES = Object.freeze(['manifest', 'findings', 'provenance', 'replay-manifest', 'toolchain', 'receipt']);
const REQUIRED_ROLES = Object.freeze(['manifest', 'findings', 'provenance', 'toolchain']);

export const BUNDLE_LIMITS = Object.freeze({ maxEntries: 4096, maxBlobBytes: 4 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024, maxIndexBytes: 8 * 1024 * 1024, maxNameLength: 200, maxDepth: 24, maxString: 8192 });

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

// ---------------------------------------------------------------- secret filter

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']?[^\s"',;]{8,}/i,
];
const PLACEHOLDER = '[REDACTED-SECRET]';

/** The first secret shape found in a text, or null. */
export function findSecret(text) {
  if (typeof text !== 'string') return null;
  for (const re of SECRET_PATTERNS) { const m = re.exec(text); if (m && !m[0].includes(PLACEHOLDER)) return m[0].slice(0, 12) + '...'; }
  return null;
}

/** Replace every known secret shape with a placeholder. */
function redactText(text) {
  let out = String(text);
  for (const re of SECRET_PATTERNS) out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'), PLACEHOLDER);
  return redactSecrets(out).text;
}

function sanitizeValue(v, depth = 0) {
  if (depth > BUNDLE_LIMITS.maxDepth) throw new Error('evidence is nested deeper than the limit');
  if (typeof v === 'string') return redactText(v.length > BUNDLE_LIMITS.maxString ? v.slice(0, BUNDLE_LIMITS.maxString) : v);
  if (Array.isArray(v)) return v.map((x) => sanitizeValue(x, depth + 1));
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sanitizeValue(v[k], depth + 1)]));
  return v;
}

// A finding leaves the machine as a closed set of fields. Source snippets, taint traces and raw evidence stay behind.
const FINDING_FIELDS = ['id', 'stableId', 'severity', 'file', 'line', 'vuln', 'cwe', 'family', 'parser', 'confidence', 'confidenceTier', 'description', 'remediation', 'unreachable', 'findingProvenance'];

function sanitizeFindings(findings) {
  return (Array.isArray(findings) ? findings : []).map((f) => {
    const out = {};
    for (const k of FINDING_FIELDS) if (f && f[k] !== undefined) out[k] = sanitizeValue(f[k]);
    return out;
  });
}

// ---------------------------------------------------------------- names and paths

export function checkLogicalName(name) {
  if (typeof name !== 'string' || !name) return 'empty name';
  if (name.length > BUNDLE_LIMITS.maxNameLength) return `name longer than ${BUNDLE_LIMITS.maxNameLength}`;
  if (name.includes('\0') || name.includes('\\')) return 'name contains a NUL or backslash';
  if (path.isAbsolute(name) || name.startsWith('/')) return 'absolute path';
  if (name.split('/').some((s) => s === '..' || s === '.')) return 'path traversal';
  if (!NAME_RE.test(name)) return 'name has characters outside the allowed set';
  return null;
}

function blobFile(dir, digest) { return path.join(dir, BLOB_DIR, digest.slice('sha256:'.length)); }

function writeAtomic(file, bytes) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, bytes, { flag: 'wx', mode: 0o644 });
  fs.renameSync(tmp, file);
}

// ---------------------------------------------------------------- replay prerequisites

const BASE_PREREQUISITES = Object.freeze([
  { code: 'source-at-commit', statement: 'the exact source revision named by the manifest subject must be checked out' },
  { code: 'toolchain-identities', statement: 'the toolchain identities recorded in the bundle must be installed at the recorded versions' },
  { code: 'confinement-backend', statement: 'a runtime replay needs a confinement backend; isolation-required replays are only advertised on Linux and enforcement there is unverified in this build' },
]);

function replayPrerequisites(replayManifests) {
  const seen = new Set(BASE_PREREQUISITES.map((p) => p.code));
  const out = BASE_PREREQUISITES.map((p) => ({ ...p }));
  for (const rm of replayManifests) {
    for (const p of Array.isArray(rm?.prerequisites) ? rm.prerequisites : []) {
      const code = typeof p === 'string' ? p : p?.code;
      if (typeof code !== 'string' || seen.has(code)) continue;
      seen.add(code);
      out.push({ code, statement: typeof p === 'object' && typeof p.statement === 'string' ? p.statement : code, source: rm.id ?? null });
    }
  }
  return out;
}

// ---------------------------------------------------------------- export

/**
 * Write a bundle to `outDir` (must not exist or must be empty). Throws on a limit, name, manifest or secret violation, and writes the
 * index LAST so a half-written directory has no index and never verifies.
 *
 * @param {object} a
 * @param {object} a.manifest        a valid release assurance manifest
 * @param {object[]} a.findings      raw findings; sanitized here
 * @param {object} a.provenance      finding provenance and dependency identities
 * @param {object[]} [a.replayManifests]  `{ id, prerequisites?, ... }`
 * @param {object} a.toolchain       toolchain identities
 * @param {Array<{id:string, content:*}>} [a.receipts]  the verification receipt contents; each digest must equal the manifest's
 */
export function exportBundle({ outDir, manifest, findings = [], provenance = {}, replayManifests = [], toolchain = {}, receipts = [] }) {
  const v = validateManifest(manifest);
  if (!v.ok) throw new Error(`refusing to export: the manifest is invalid (${v.errors[0].code} ${v.errors[0].path})`);
  if (fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0) throw new Error('refusing to export into a non-empty directory');

  const items = [];
  const add = (role, name, value, sanitize = true) => {
    const bad = checkLogicalName(name);
    if (bad) throw new Error(`refusing to export '${name}': ${bad}`);
    const body = sanitize ? sanitizeValue(value) : value;
    const bytes = Buffer.from(canonicalJson(body));
    if (bytes.length > BUNDLE_LIMITS.maxBlobBytes) throw new Error(`refusing to export '${name}': ${bytes.length} bytes exceeds the ${BUNDLE_LIMITS.maxBlobBytes} byte limit`);
    const hit = findSecret(bytes.toString('utf8'));
    if (hit) throw new Error(`refusing to export '${name}': a secret shape survived redaction (${hit})`);
    items.push({ role, name, digest: digestOfBytes(bytes), size: bytes.length, bytes });
  };
  add('manifest', 'manifest.json', manifest, false);
  add('findings', 'findings.json', sanitizeFindings(findings), false);
  add('provenance', 'provenance.json', provenance);
  add('toolchain', 'toolchain.json', toolchain);
  replayManifests.forEach((rm, i) => add('replay-manifest', `replay/${String(rm?.id ?? i).replace(/[^A-Za-z0-9._-]/g, '_')}.json`, rm));
  const byId = new Map(receipts.map((r) => [r.id, r]));
  for (const r of manifest.verificationReceipts) {
    const given = byId.get(r.id);
    if (!given) throw new Error(`refusing to export: receipt '${r.id}' cited by the manifest was not supplied`);
    if (digestOf(given.content) !== r.digest) throw new Error(`refusing to export: receipt '${r.id}' content does not match the digest the manifest binds`);
    add('receipt', `receipts/${r.id.replace(/[^A-Za-z0-9._-]/g, '_')}.json`, given.content);
  }
  if (items.length > BUNDLE_LIMITS.maxEntries) throw new Error('refusing to export: too many entries');
  const total = items.reduce((n, i) => n + i.size, 0);
  if (total > BUNDLE_LIMITS.maxTotalBytes) throw new Error('refusing to export: total size exceeds the limit');
  const names = new Set();
  for (const i of items) { if (names.has(i.name)) throw new Error(`refusing to export: duplicate name '${i.name}'`); names.add(i.name); }

  fs.mkdirSync(path.join(outDir, BLOB_DIR), { recursive: true });
  for (const i of items) {
    const f = blobFile(outDir, i.digest);
    if (!fs.existsSync(f)) writeAtomic(f, i.bytes);
  }
  const entries = items.map(({ role, name, digest, size }) => ({ role, name, digest, size })).sort((a, b) => (a.name < b.name ? -1 : 1));
  const index = indexFor(entries, manifest, replayManifests);
  writeAtomic(path.join(outDir, INDEX_FILE), Buffer.from(JSON.stringify(index, null, 2)));
  return { bundleDigest: index.bundleDigest, manifestDigest: index.manifestDigest, entries: entries.length, totalBytes: total };
}

function indexFor(entries, manifest, replayManifests) {
  const body = {
    schema: BUNDLE_SCHEMA, schemaVersion: BUNDLE_VERSION,
    ...(manifest.synthetic === true ? { synthetic: true } : {}),
    manifestId: manifest.id, manifestDigest: manifestDigest(manifest), entries,
    replay: { attempted: false, prerequisites: replayPrerequisites(replayManifests) },
    limits: BUNDLE_LIMITS,
  };
  return { ...body, bundleDigest: bundleDigestOf(body) };
}

/** The identity of a bundle: the manifest digest plus every entry's digest, independent of file order. */
export function bundleDigestOf(index) {
  return digestOf({ manifestDigest: index.manifestDigest, entries: index.entries.map((e) => [e.role, e.name, e.digest, e.size]) });
}

// ---------------------------------------------------------------- verify (offline)

function readBounded(file, max) {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile()) throw Object.assign(new Error('not a regular file'), { code: 'NOT_REGULAR' });
  if (st.size > max) throw Object.assign(new Error(`${st.size} bytes exceeds ${max}`), { code: 'TOO_LARGE' });
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(Math.min(st.size, max) + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    if (n > max) throw Object.assign(new Error('grew past the limit while reading'), { code: 'TOO_LARGE' });
    return buf.subarray(0, n);
  } finally { fs.closeSync(fd); }
}

/**
 * Verify a bundle directory using only the local filesystem. Returns `{ ok, errors, manifest, entries, replay, network:false }`.
 * `errors` carry a stable `code`: BAD_INDEX, BAD_ENTRY, MISSING_BLOB, DIGEST_MISMATCH, SIZE_MISMATCH, TOO_LARGE, NOT_REGULAR,
 * BUNDLE_DIGEST_MISMATCH, MANIFEST_INVALID, MANIFEST_MISMATCH, MISSING_EVIDENCE, MISSING_ROLE, SECRET_IN_BLOB, LIMIT.
 */
export function verifyBundle(dir) {
  const errors = [];
  const err = (code, message, extra = {}) => errors.push({ code, message, ...extra });
  const out = (extra = {}) => ({ ok: errors.length === 0, errors, network: false, manifest: null, entries: [], replay: { attempted: false, prerequisites: [], statement: 'replay was not attempted: this verifier is offline and executes nothing from the bundle' }, ...extra });

  let index;
  try { index = JSON.parse(readBounded(path.join(dir, INDEX_FILE), BUNDLE_LIMITS.maxIndexBytes).toString('utf8')); } catch (e) {
    err('BAD_INDEX', `cannot read ${INDEX_FILE}: ${e.code || e.message}`); return out();
  }
  if (!index || index.schema !== BUNDLE_SCHEMA || !Array.isArray(index.entries) || typeof index.bundleDigest !== 'string') { err('BAD_INDEX', 'not a portable evidence bundle index'); return out(); }
  if (index.entries.length > BUNDLE_LIMITS.maxEntries) { err('LIMIT', 'too many entries'); return out(); }

  const names = new Set();
  let total = 0;
  const loaded = new Map();
  for (const e of index.entries) {
    if (!e || !ROLES.includes(e.role) || !DIGEST_RE.test(e.digest ?? '') || !Number.isInteger(e.size) || e.size < 0) { err('BAD_ENTRY', 'malformed entry', { entry: e?.name ?? null }); continue; }
    const bad = checkLogicalName(e.name);
    if (bad) { err('BAD_ENTRY', `entry name rejected: ${bad}`, { entry: String(e.name).slice(0, 60) }); continue; }
    if (names.has(e.name)) { err('BAD_ENTRY', 'duplicate entry name', { entry: e.name }); continue; }
    names.add(e.name);
    if (e.size > BUNDLE_LIMITS.maxBlobBytes) { err('TOO_LARGE', `entry exceeds the per-blob limit`, { entry: e.name }); continue; }
    total += e.size;
    let bytes;
    try { bytes = readBounded(blobFile(dir, e.digest), BUNDLE_LIMITS.maxBlobBytes); } catch (x) {
      err(x.code === 'ENOENT' ? 'MISSING_BLOB' : (x.code || 'MISSING_BLOB'), `blob for '${e.name}' is unavailable: ${x.code || x.message}`, { entry: e.name }); continue;
    }
    if (bytes.length !== e.size) { err('SIZE_MISMATCH', `blob size differs from the index`, { entry: e.name }); continue; }
    if (digestOfBytes(bytes) !== e.digest) { err('DIGEST_MISMATCH', `blob for '${e.name}' was modified after export`, { entry: e.name }); continue; }
    const hit = findSecret(bytes.toString('utf8'));
    if (hit) err('SECRET_IN_BLOB', `'${e.name}' carries a secret shape`, { entry: e.name });
    loaded.set(e.name, { e, bytes });
  }
  if (total > BUNDLE_LIMITS.maxTotalBytes) err('LIMIT', 'total size exceeds the limit');
  for (const role of REQUIRED_ROLES) if (!index.entries.some((e) => e?.role === role)) err('MISSING_ROLE', `required role '${role}' is absent`);
  if (index.entries.every((e) => e && DIGEST_RE.test(e.digest ?? '')) && bundleDigestOf(index) !== index.bundleDigest) err('BUNDLE_DIGEST_MISMATCH', 'the index does not match its recorded bundle digest');

  // manifest
  let manifest = null;
  const mEntry = index.entries.find((e) => e?.role === 'manifest');
  if (mEntry && loaded.has(mEntry.name)) {
    try { manifest = JSON.parse(loaded.get(mEntry.name).bytes.toString('utf8')); } catch { err('MANIFEST_INVALID', 'manifest is not JSON'); }
    if (manifest) {
      const v = validateManifest(manifest);
      if (!v.ok) err('MANIFEST_INVALID', `manifest fails validation: ${v.errors[0].code} ${v.errors[0].path}`, { detail: v.errors.slice(0, 5) });
      else {
        if (manifestDigest(manifest) !== index.manifestDigest) err('MANIFEST_MISMATCH', 'the manifest is not the one the index was built for');
        const have = new Set(index.entries.filter((e) => e?.role === 'receipt').map((e) => e.digest));
        for (const r of manifest.verificationReceipts) if (!have.has(r.digest)) err('MISSING_EVIDENCE', `receipt '${r.id}' cited by the manifest is not in the bundle`, { receipt: r.id });
      }
    }
  }
  const replayManifests = [];
  for (const [, { e, bytes }] of loaded) if (e.role === 'replay-manifest') { try { replayManifests.push(JSON.parse(bytes.toString('utf8'))); } catch { /* integrity already checked; unparsable replay manifest adds no prerequisites */ } }
  return out({
    manifest: errors.length === 0 ? manifest : null,
    entries: [...loaded.values()].map(({ e }) => ({ role: e.role, name: e.name, digest: e.digest })),
    bundleDigest: index.bundleDigest,
    replay: { attempted: false, prerequisites: replayPrerequisites(replayManifests), statement: 'replay was not attempted: this verifier is offline and executes nothing from the bundle' },
  });
}

// ---------------------------------------------------------------- import

/**
 * Verify `from`, then materialize its entries under `to` using their logical names. Verification failure writes nothing. Every
 * destination is resolved and confined to `to`; an existing destination is never overwritten.
 */
export function importBundle({ from, to }) {
  const v = verifyBundle(from);
  if (!v.ok) return { ok: false, errors: v.errors, written: [] };
  const index = JSON.parse(fs.readFileSync(path.join(from, INDEX_FILE), 'utf8'));
  const root = path.resolve(to);
  const plan = [];
  for (const e of index.entries) {
    const dest = path.resolve(root, e.name);
    if (dest !== root && !dest.startsWith(root + path.sep)) return { ok: false, errors: [{ code: 'BAD_ENTRY', message: `entry '${e.name}' escapes the destination` }], written: [] };
    if (fs.existsSync(dest)) return { ok: false, errors: [{ code: 'DESTINATION_EXISTS', message: `'${e.name}' already exists at the destination` }], written: [] };
    plan.push({ e, dest });
  }
  fs.mkdirSync(root, { recursive: true });
  const written = [];
  for (const { e, dest } of plan) {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    writeAtomic(dest, readBounded(blobFile(from, e.digest), BUNDLE_LIMITS.maxBlobBytes));
    written.push(e.name);
  }
  return { ok: true, errors: [], written, bundleDigest: v.bundleDigest, replay: v.replay };
}
