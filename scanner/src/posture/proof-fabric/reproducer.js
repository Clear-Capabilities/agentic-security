// Serialized reproducer: the ONLY thing an independent verifier receives (besides revision, finding id and oracle).
// It carries no reasoning, no model output and no prior results. Everything per-run (nonce, secrets, canary paths,
// callback URL) is a placeholder substituted fresh by the trusted runner, so a replay can never reuse a stale value
// and a target cannot learn the values in advance.
import { createHash } from 'node:crypto';
import { ORACLE_TYPES } from './oracles.js';
import { validateAttackFacts } from '../dnr/attack-facts.js';

const REPRODUCER_SCHEMA = 'agentic-security/reproducer';
const REPRODUCER_VERSION = 1;
export const LANGUAGES = Object.freeze(['javascript', 'typescript', 'python', 'java', 'c', 'cpp', 'csharp']);
export const MAX_FILES = 64;
export const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024;
const PLACEHOLDER_RE = /\{\{([A-Z_]+)(?::([a-z0-9_-]{1,32}))?\}\}/g;
const ALLOWED_PLACEHOLDERS = new Set(['NONCE', 'SECRET', 'CANARY', 'CALLBACK_URL', 'CALLBACK_PORT', 'ROOT', 'NODE', 'PYTHON', 'JAVA', 'JAVAC', 'CC']);

export function isSafeRelPath(rel) {
  if (typeof rel !== 'string' || !rel || rel.length > 200) return false;
  if (rel.startsWith('/') || rel.includes('\0') || rel.includes('\\')) return false;
  if (['canary', 'tmp'].includes(rel.split('/')[0])) return false;
  return rel.split('/').every((seg) => seg && seg !== '.' && seg !== '..' && !seg.startsWith('__oracle_'));
}

/** Canonical JSON (sorted keys) so identical reproducers hash identically regardless of key order. */
export function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const reproducerDigest = (r) => sha256(canonicalize(r));

export function validateReproducer(r) {
  const errs = [];
  if (!r || typeof r !== 'object' || Array.isArray(r)) return ['reproducer must be an object'];
  if (r.schema !== REPRODUCER_SCHEMA) errs.push('unknown schema');
  if (r.version !== REPRODUCER_VERSION) errs.push('unsupported reproducer version');
  if (typeof r.findingId !== 'string' || !r.findingId || r.findingId.length > 200) errs.push('findingId required');
  if (!LANGUAGES.includes(r.lang)) errs.push(`unsupported language: ${String(r.lang)}`);
  if (!r.oracle || !ORACLE_TYPES.includes(r.oracle.type)) errs.push(`unknown oracle: ${String(r.oracle?.type)}`);
  const files = r.files ?? {};
  if (typeof files !== 'object' || Array.isArray(files)) errs.push('files must be an object');
  else {
    const names = Object.keys(files);
    if (names.length > MAX_FILES) errs.push(`file count must be at most ${MAX_FILES}`);
    let total = 0;
    for (const n of names) {
      if (!isSafeRelPath(n)) { errs.push(`unsafe file path: ${n}`); continue; }
      if (typeof files[n] !== 'string') { errs.push(`file ${n} must be a string`); continue; }
      const b = Buffer.byteLength(files[n]);
      total += b;
      if (b > MAX_FILE_BYTES) errs.push(`file ${n} exceeds ${MAX_FILE_BYTES} bytes`);
    }
    if (total > MAX_TOTAL_BYTES) errs.push('reproducer exceeds total size limit');
  }
  const sourceNames = r.sources && typeof r.sources === 'object' && !Array.isArray(r.sources) ? Object.keys(r.sources) : [];
  if (Object.keys(files).length + sourceNames.length === 0) errs.push('reproducer must declare at least one file or source');
  for (const key of ['build', 'run']) {
    const a = r[key];
    if (a == null && key === 'build') continue;
    if (!Array.isArray(a) || !a.length || !a.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'))) errs.push(`${key} must be a non-empty argv array of strings (no shell string)`);
  }
  for (const text of [...Object.values(files || {}), ...(r.build || []), ...(r.run || [])]) {
    if (typeof text !== 'string') continue;
    for (const m of text.matchAll(PLACEHOLDER_RE)) if (!ALLOWED_PLACEHOLDERS.has(m[1])) errs.push(`unknown placeholder {{${m[1]}}}`);
  }
  if (r.watch != null) {
    if (typeof r.watch !== 'object' || Array.isArray(r.watch)) errs.push('watch must be an object');
    else for (const [k, v] of Object.entries(r.watch)) if (!/^[a-z0-9_-]{1,32}$/.test(k) || !isSafeRelPath(v)) errs.push(`bad watch entry: ${k}`);
  }
  if (r.env != null) {
    if (typeof r.env !== 'object' || Array.isArray(r.env)) errs.push('env must be an object');
    else for (const [k, v] of Object.entries(r.env)) {
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(k)) errs.push(`bad env var name: ${k}`);
      if (typeof v !== 'string' || v.length > 4096) errs.push(`env value for ${k} must be a short string`);
    }
  }
  if (r.sources != null) {
    if (typeof r.sources !== 'object' || Array.isArray(r.sources)) errs.push('sources must be an object');
    else for (const [dest, src] of Object.entries(r.sources)) if (!isSafeRelPath(dest) || !isSafeRelPath(src)) errs.push(`bad sources entry: ${dest}`);
  }
  if (r.network != null && !['none', 'callback'].includes(r.network)) errs.push('network must be none or callback');
  // Optional request-level facts for the detection-and-response loop. The runner never reads them.
  errs.push(...validateAttackFacts(r.attack));
  return errs;
}

/** The view handed to an independent verifier: exactly the reproducer, plus identifiers. Nothing else. */
export function verifierView({ revision, reproducer, findingId, oracle }) {
  return Object.freeze({ revision: revision ?? null, findingId, oracle, reproducer: structuredClone(reproducer) });
}

export function substitute(text, ctx) {
  return text.replace(PLACEHOLDER_RE, (whole, name, arg) => {
    switch (name) {
      case 'NONCE': return ctx.nonce;
      case 'SECRET': return ctx.secret(arg || 'default');
      case 'CANARY': return ctx.canary(arg || 'default');
      case 'CALLBACK_URL': return ctx.callbackUrl ?? whole;
      case 'CALLBACK_PORT': return String(ctx.callbackPort ?? '');
      case 'ROOT': return ctx.root;
      case 'NODE': return ctx.tools.node;
      case 'PYTHON': return ctx.tools.python ?? whole;
      case 'JAVA': return ctx.tools.java ?? whole;
      case 'JAVAC': return ctx.tools.javac ?? whole;
      case 'CC': return ctx.tools.cc ?? whole;
      default: return whole;
    }
  });
}
