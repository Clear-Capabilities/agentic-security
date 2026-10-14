//
// Governed persistence for DCI artifacts, under `<project>/.agentic-security/context-intelligence/`.
//
// Layout (all content-addressed where it can be):
//   bundles/<contextHash>/manifest.json, context-<n>.txt   one directory per bundle set
//   index.json                                             entry point -> current bundle, plus the build identity
//   reviews/<jobKey>.json                                  one verified review result per job
//   queues/<runId>.json                                    durable job-queue state (resume / cancel)
//   batches/<batchId>/                                     offline batch request and result files
//
// Every write is a temp file + rename, opened O_EXCL | O_NOFOLLOW, so a symlink or hard link planted at the target is
// REPLACED, never written through. Directories are created 0700 and files 0600. The state root must resolve inside
// the project root. Reads re-verify: a stored text file whose hash no longer matches its manifest is an ERROR.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath, STATE_DIR_NAME, stateWritesEnabled, isSafeStateDir } from '../posture/state-dir.js';
import { loadLegalHolds, isUnderHold } from '../posture/legal-hold.js';
import { validateManifest } from './manifest.js';
import { sha256 } from './canonical.js';

export const STORE_DIR = 'context-intelligence';
export const ARTIFACT_NAME = STORE_DIR;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_JSON_BYTES = 32 * 1024 * 1024;

export function storeRoot(root) { return statePath(root, STORE_DIR); }

function refuse(code, reason) { return { ok: false, code, reason }; }

function segments(rel) {
  const segs = String(rel).split('/');
  if (!segs.length || segs.some(s => !SAFE_SEGMENT.test(s) || s === '.' || s === '..')) return null;
  return segs;
}

/** Create the directory chain below the store root, refusing links and anything resolving outside the project. */
function ensureDirs(root, segs) {
  const base = storeRoot(root);
  const projectReal = fs.realpathSync(path.resolve(root));
  const stateRoot = path.join(projectReal, STATE_DIR_NAME);
  if (!isSafeStateDir(stateRoot)) return refuse('unsafe-state-dir', 'no project marker beside the state directory');
  fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  let cur = path.join(stateRoot, STORE_DIR);
  void base;
  for (const seg of [null, ...segs]) {
    if (seg !== null) cur = path.join(cur, seg);
    try {
      const st = fs.lstatSync(cur);
      if (st.isSymbolicLink()) return refuse('symlink', `${path.relative(projectReal, cur)} is a symbolic link`);
      if (!st.isDirectory()) return refuse('not-a-directory', path.relative(projectReal, cur));
    } catch (e) {
      if (e && e.code !== 'ENOENT') return refuse('stat-failed', String(e.code || e));
      fs.mkdirSync(cur, { mode: 0o700 });
    }
  }
  const real = fs.realpathSync(cur);
  if (real !== stateRoot && !real.startsWith(stateRoot + path.sep)) return refuse('escapes-state-root', 'the store resolves outside the project');
  return { ok: true, dir: real };
}

/** Atomic, link-safe write of one file below the store root. `rel` is like `bundles/<hash>/manifest.json`. */
export function writeStoreFile(root, rel, body) {
  try {
    if (!stateWritesEnabled()) return refuse('state-writes-disabled', 'state writes are switched off for this process');
    if (typeof body !== 'string' && !Buffer.isBuffer(body)) return refuse('bad-body', 'body must be a string or Buffer');
    if (Buffer.byteLength(body) > MAX_JSON_BYTES) return refuse('too-large', 'artifact exceeds the size ceiling');
    const segs = segments(rel);
    if (!segs) return refuse('bad-path', 'store paths are safe relative names');
    const name = segs.pop();
    const d = ensureDirs(root, segs);
    if (!d.ok) return d;
    const target = path.join(d.dir, name);
    try { if (fs.lstatSync(target).isSymbolicLink()) { fs.rmSync(target, { force: true }); } } catch { /* absent */ }
    const tmp = path.join(d.dir, `.${name}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    let fd = null;
    try {
      fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
      fs.closeSync(fd); fd = null;
      fs.renameSync(tmp, target);
    } catch (e) {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      try { fs.rmSync(tmp, { force: true }); } catch { /* best effort */ }
      return refuse('write-failed', String((e && e.message) || e).slice(0, 160));
    }
    return { ok: true, path: target };
  } catch (e) {
    return refuse('write-failed', String((e && e.message) || e).slice(0, 160));
  }
}

export function writeStoreJson(root, rel, value) { return writeStoreFile(root, rel, JSON.stringify(value, null, 2) + '\n'); }

/** Read one store file. Never follows a link. Returns { ok, text } or { ok:false, code }. */
export function readStoreFile(root, rel) {
  const segs = segments(rel);
  if (!segs) return refuse('bad-path', 'store paths are safe relative names');
  const file = path.join(storeRoot(root), ...segs);
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) return refuse('not-a-regular-file', rel);
    if (st.size > MAX_JSON_BYTES) return refuse('too-large', rel);
    return { ok: true, text: fs.readFileSync(file, 'utf8') };
  } catch (e) {
    return refuse(e && e.code === 'ENOENT' ? 'missing' : 'unreadable', rel);
  }
}

export function readStoreJson(root, rel) {
  const r = readStoreFile(root, rel);
  if (!r.ok) return r;
  try { return { ok: true, value: JSON.parse(r.text) }; } catch { return refuse('corrupt-json', rel); }
}

/** Persist one built bundle set: manifest + every package text. */
export function writeBundle(root, bundle) {
  const { manifest, pack } = bundle;
  const dir = `bundles/${manifest.contextHash}`;
  const written = [];
  for (const p of pack.packages) {
    const r = writeStoreFile(root, `${dir}/context-${p.index}.txt`, p.text);
    if (!r.ok) return r;
    written.push(r.path);
  }
  const m = writeStoreJson(root, `${dir}/manifest.json`, manifest);
  if (!m.ok) return m;
  written.push(m.path);
  return { ok: true, paths: written, contextHash: manifest.contextHash };
}

export function readManifest(root, contextHash) {
  if (!/^[0-9a-f]{64}$/.test(String(contextHash))) return refuse('bad-hash', 'a context hash is 64 hex characters');
  return readStoreJson(root, `bundles/${contextHash}/manifest.json`);
}

/** Read a package's stored text and prove it still matches the hash in its manifest. */
export function readPackageText(root, manifest, index = 1) {
  const pk = manifest.context.packages.find(p => p.index === index);
  if (!pk) return refuse('no-such-package', String(index));
  const r = readStoreFile(root, `bundles/${manifest.contextHash}/context-${index}.txt`);
  if (!r.ok) return r;
  if (sha256(r.text) !== pk.sha256) return refuse('hash-mismatch', `context-${index}.txt does not match the manifest`);
  return { ok: true, text: r.text, package: pk };
}

/**
 * Verify a stored bundle: manifest contract, every package text against its hash, and (with fileContents) every span
 * against the current source. Any mismatch is an error; nothing is skipped quietly.
 */
export function verifyStoredBundle(root, contextHash, { fileContents = null } = {}) {
  const m = readManifest(root, contextHash);
  if (!m.ok) return { ok: false, problems: [`manifest-${m.code}`] };
  const problems = [...validateManifest(m.value, { fileContents })];
  if (m.value.contextHash !== contextHash) problems.push('context-hash-differs-from-directory');
  for (const pk of m.value.context.packages) {
    const t = readPackageText(root, m.value, pk.index);
    if (!t.ok) problems.push(`package-${pk.index}-${t.code}`);
  }
  return { ok: problems.length === 0, problems, manifest: m.value };
}

export function listStoredBundles(root) {
  const dir = path.join(storeRoot(root), 'bundles');
  try {
    return fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory() && /^[0-9a-f]{64}$/.test(e.name)).map(e => e.name).sort();
  } catch { return []; }
}

/**
 * Remove stored bundles that the current index does not reference and that are older than `olderThanDays`.
 * A legal hold on the `context-intelligence` artifact blocks every deletion. `dryRun` reports without removing.
 */
export function cleanupStore(root, { olderThanDays = 30, now = Date.now(), dryRun = false } = {}) {
  const holds = loadLegalHolds(root);
  const hold = isUnderHold(ARTIFACT_NAME, holds, now);
  if (hold) return { ok: true, removed: [], kept: listStoredBundles(root), blockedByLegalHold: { owner: hold.owner, reason: hold.reason } };
  const idx = readStoreJson(root, 'index.json');
  const referenced = new Set(idx.ok ? (idx.value.entrypoints || []).map(e => e.contextHash).filter(Boolean) : []);
  const removed = [];
  const kept = [];
  for (const h of listStoredBundles(root)) {
    const dir = path.join(storeRoot(root), 'bundles', h);
    let age;
    try { age = (now - fs.statSync(dir).mtimeMs) / 86400000; } catch { kept.push(h); continue; }
    if (referenced.has(h) || age <= olderThanDays) { kept.push(h); continue; }
    if (!dryRun) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { kept.push(h); continue; } }
    removed.push(h);
  }
  return { ok: true, removed, kept, blockedByLegalHold: null, dryRun };
}

/**
 * Secure export: a single self-describing JSON document with the manifest and the package texts (never the source
 * tree), refused for a bundle that fails verification. Honours legal hold trivially (it only reads).
 */
export function exportBundle(root, contextHash) {
  const v = verifyStoredBundle(root, contextHash);
  if (!v.ok) return { ok: false, problems: v.problems };
  const texts = v.manifest.context.packages.map(p => readPackageText(root, v.manifest, p.index).text);
  return { ok: true, export: { schemaVersion: 'context-export/1', manifest: v.manifest, packages: texts } };
}
