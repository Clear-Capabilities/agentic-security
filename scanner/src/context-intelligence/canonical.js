//
// Canonical serialization, hashing and path/snapshot safety for Deterministic Context Intelligence.
//
// Everything DCI stores or compares goes through this module so that "same checkout + same config => same bytes" is
// a property of one place. No clock, no randomness, no host path ever enters a hashed value.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Bump when the canonical encoding below changes; it is mixed into every hash. */
export const HASH_ALGORITHM = 'sha256/canon-1';

export function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Code-unit order, independent of the host locale. `localeCompare` orders by the process locale, so the same checkout
 * could be sorted differently on two machines; every ordering that reaches a hashed value goes through this instead.
 */
export function cmpCodeUnit(a, b) {
  const x = String(a); const y = String(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

// Control characters (C0, DEL, C1), the bidirectional override/isolate marks and the line/paragraph separators. A
// repository controls the text of its own route strings and file names, so anything printed to a terminal or placed
// in a prompt outside the untrusted fence must not be able to carry an escape sequence or reorder what a reader sees.
const UNSAFE_DISPLAY = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** Make text safe to print: unsafe characters become '?'. Newline and tab are kept; use `safeLabel` for one-line values. */
export function cleanForTerminal(text) {
  return String(text).replace(UNSAFE_DISPLAY, '?');
}

/** A one-line, bounded, printable form of a name taken from source (a route path, a file name). */
export function safeLabel(text, max = 120) {
  const t = String(text).replace(/[\n\r\t]+/g, ' ').replace(UNSAFE_DISPLAY, '?').replace(/ {2,}/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 3)}...` : t;
}

/** CRLF/CR -> LF so a Windows checkout and a Unix one produce the same spans and hashes. */
export function normalizeText(text) {
  return String(text).replace(/\r\n?/g, '\n');
}

/**
 * JSON with object keys sorted at every depth. Arrays keep their order (callers sort them where order is not
 * meaningful). `undefined` members are dropped, exactly as JSON.stringify does, so a missing and an undefined field hash alike.
 */
export function canonicalJson(value) {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (v[k] !== undefined) out[k] = sortKeys(v[k]);
    }
    return out;
  }
  return v;
}

export function hashOf(value) {
  return sha256(`${HASH_ALGORITHM}\n${canonicalJson(value)}`);
}

/**
 * A repository-relative path in canonical form, or null. Rejects absolute paths, drive letters, NUL, backslash
 * tricks and any `..` segment: a manifest can never name a file outside the repository.
 */
export function safeRelPath(p) {
  if (typeof p !== 'string' || p === '' || p.includes('\0')) return null;
  const n = p.replace(/\\/g, '/');
  if (n.startsWith('/') || /^[A-Za-z]:/.test(n)) return null;
  const parts = n.split('/');
  const out = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') return null;
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

/**
 * Read one repository file for analysis. Refuses a symlink and anything whose real path leaves the repository root,
 * and refuses non-regular files. Returns { ok, text } or { ok:false, reason }; never throws.
 */
export function readRepoFile(rootReal, rel, { maxBytes = 2 * 1024 * 1024 } = {}) {
  const safe = safeRelPath(rel);
  if (!safe) return { ok: false, reason: 'unsafe-path' };
  const abs = path.join(rootReal, safe);
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) return { ok: false, reason: 'symlink' };
    if (!st.isFile()) return { ok: false, reason: 'not-a-regular-file' };
    if (st.size > maxBytes) return { ok: false, reason: 'too-large' };
    const real = fs.realpathSync(abs);
    if (real !== rootReal && !real.startsWith(rootReal + path.sep)) return { ok: false, reason: 'escapes-root' };
    return { ok: true, text: normalizeText(fs.readFileSync(abs, 'utf8')) };
  } catch (err) {
    return { ok: false, reason: err && err.code ? String(err.code) : 'unreadable' };
  }
}

/** Hash of the analysed file set: sorted [path, content hash] pairs. Order of discovery never matters. */
export function snapshotHashOf(fileContents) {
  const rows = Object.keys(fileContents).sort().map(f => [f, sha256(fileContents[f])]);
  return hashOf(rows);
}

/** 1-based inclusive line slice of already-normalised text. */
export function sliceLines(text, startLine, endLine) {
  const lines = text.split('\n');
  return lines.slice(Math.max(0, startLine - 1), Math.max(0, endLine)).join('\n');
}
