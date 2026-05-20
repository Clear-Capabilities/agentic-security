// Type-stub integration (v0.70 #7).
//
// Today the engine treats `req.body` as opaque-tainted. With type stubs,
// we can refine: `req.body: any` but `req.body.email: string` after
// destructuring; `string.length: number`; `string.match(): RegExpMatchArray`.
// This eliminates a class of FPs where "everything reachable from a
// tainted root" was conservatively tainted.
//
// v1 supports:
//   - TypeScript `.d.ts` declarations in `node_modules/@types/**`
//   - Python `.pyi` stubs at the project root (best-effort)
//   - Java JAR `MANIFEST.MF` class signatures (best-effort; v2 will use
//     proper class-file parsing)
//
// Public API:
//   loadProjectStubs(root)             → { signatures: Map<qid, {paramTypes, returnType}>,
//                                          types: Map<typeName, FieldMap>,
//                                          frameworks: Set<string> }
//   signatureFor(stubs, qidOrName)     → { paramTypes, returnType } | null
//   typeOf(stubs, typeName)            → FieldMap | null
//
// Cache lives at $XDG_CONFIG_HOME/agentic-security/stub-cache/<projectHash>.json
// keyed by package-lock.json content hash so the parse runs once per project
// snapshot.
//
// Budget: parsing is capped at AGENTIC_SECURITY_TYPE_STUBS_BUDGET_MS
// (default 10_000). When the budget blows, parsed stubs are still
// returned — incomplete is honest.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as os from 'node:os';

const CACHE_DIR_REL = 'agentic-security/stub-cache';

function _cacheBase() {
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg) return path.join(xdg, CACHE_DIR_REL);
  return path.join(os.homedir(), '.config', CACHE_DIR_REL);
}

function _projectFingerprint(root) {
  // Hash inputs that uniquely identify the stub state.
  const inputs = [];
  for (const p of ['package-lock.json', 'package.json', 'requirements.txt', 'poetry.lock', 'pom.xml']) {
    const fp = path.join(root, p);
    try { inputs.push(p + ':' + fs.statSync(fp).mtimeMs); } catch {}
  }
  return crypto.createHash('sha256').update(inputs.join('|') || root).digest('hex').slice(0, 16);
}

function _readCache(root) {
  const dir = _cacheBase();
  const fp = path.join(dir, _projectFingerprint(root) + '.json');
  try {
    if (!fs.existsSync(fp)) return null;
    const obj = JSON.parse(fs.readFileSync(fp, 'utf8'));
    // Reconstitute Maps / Sets that JSON dropped.
    return {
      signatures: new Map(obj.signatures || []),
      types: new Map((obj.types || []).map(([k, v]) => [k, new Map(v)])),
      frameworks: new Set(obj.frameworks || []),
      fingerprint: obj.fingerprint,
    };
  } catch { return null; }
}

function _writeCache(root, stubs) {
  const dir = _cacheBase();
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const fp = path.join(dir, _projectFingerprint(root) + '.json');
  const obj = {
    fingerprint: stubs.fingerprint,
    signatures: [...stubs.signatures],
    types: [...stubs.types].map(([k, m]) => [k, [...m]]),
    frameworks: [...stubs.frameworks],
  };
  try { fs.writeFileSync(fp, JSON.stringify(obj)); } catch {}
}

// ─── .d.ts parser (regex; intentionally narrow) ──────────────────────────

// `function NAME(args): RET` or `NAME(args): RET` inside interface { }
const FN_DECL_RE =
  /(?:^|\s)(?:export\s+)?(?:declare\s+)?function\s+([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*:\s*([^;{]+);?/g;

// `interface NAME { fields }` or `class NAME { fields }`
const TYPE_DECL_RE =
  /(?:^|\s)(?:export\s+)?(?:declare\s+)?(?:interface|class|type)\s+([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*(?:extends\s+[^{=]+)?(?:[={])/g;

// Inside a type block: `name: Type;` or `name(args): Type;`
const FIELD_RE =
  /([A-Za-z_$][\w$]*)\s*(?:\(([^)]*)\))?\s*\??\s*:\s*([^;,\n}]+)/g;

function _parseDtsFile(text) {
  // Returns { signatures: Map, types: Map<name, FieldMap> } for this file.
  const signatures = new Map();
  const types = new Map();
  let m;
  // Top-level function declarations.
  FN_DECL_RE.lastIndex = 0;
  while ((m = FN_DECL_RE.exec(text)) !== null) {
    const name = m[1];
    const paramTypes = _parseParams(m[2]);
    const returnType = m[3].trim();
    signatures.set(name, { paramTypes, returnType });
  }
  // Type / interface bodies — find the brace span and parse fields.
  TYPE_DECL_RE.lastIndex = 0;
  while ((m = TYPE_DECL_RE.exec(text)) !== null) {
    const name = m[1];
    const openBraceIdx = text.indexOf('{', m.index);
    if (openBraceIdx < 0) continue;
    const body = _balancedSection(text, openBraceIdx);
    if (!body) continue;
    const fields = new Map();
    let fm;
    FIELD_RE.lastIndex = 0;
    while ((fm = FIELD_RE.exec(body)) !== null) {
      const fname = fm[1];
      const fparams = fm[2] !== undefined ? _parseParams(fm[2]) : null;
      const ftype = fm[3].trim();
      fields.set(fname, fparams !== null ? { paramTypes: fparams, returnType: ftype } : ftype);
    }
    if (fields.size > 0) types.set(name, fields);
  }
  return { signatures, types };
}

function _parseParams(s) {
  if (!s || !s.trim()) return [];
  return s.split(',').map(p => {
    const t = p.trim();
    if (!t) return { name: '?', type: 'any' };
    const colon = t.indexOf(':');
    if (colon < 0) return { name: t.replace(/[?=].*$/, '').trim(), type: 'any' };
    return {
      name: t.slice(0, colon).replace(/[?=].*$/, '').trim(),
      type: t.slice(colon + 1).trim(),
    };
  });
}

function _balancedSection(text, openIdx) {
  if (text[openIdx] !== '{') return null;
  let depth = 1;
  let i = openIdx + 1;
  while (i < text.length && depth > 0) {
    const c = text[i];
    if (c === '{') depth++;
    else if (c === '}') depth--;
    if (depth === 0) return text.slice(openIdx + 1, i);
    i++;
  }
  return null;
}

// ─── .pyi parser (very narrow — function signatures only) ────────────────

const PYI_FN_RE =
  /^def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*->\s*([^:\n]+):/gm;

function _parsePyiFile(text) {
  const signatures = new Map();
  let m;
  PYI_FN_RE.lastIndex = 0;
  while ((m = PYI_FN_RE.exec(text)) !== null) {
    const name = m[1];
    const paramTypes = m[2].split(',').map(p => {
      const t = p.trim();
      const colon = t.indexOf(':');
      return colon < 0 ? { name: t, type: 'Any' } : { name: t.slice(0, colon).trim(), type: t.slice(colon + 1).trim() };
    });
    const returnType = m[3].trim();
    signatures.set(name, { paramTypes, returnType });
  }
  return { signatures, types: new Map() };
}

// ─── Project walker ──────────────────────────────────────────────────────

function _findStubFiles(root, budgetDeadline) {
  const stubs = [];
  const exclude = new Set(['.git', '.venv', 'dist', 'build', 'target', '__pycache__']);
  function walk(dir, depth) {
    if (Date.now() > budgetDeadline) return;
    if (depth > 8) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (exclude.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        // Only descend into @types/* inside node_modules; otherwise we walk too deep.
        if (e.name === 'node_modules') {
          const tdir = path.join(full, '@types');
          if (fs.existsSync(tdir)) walk(tdir, depth + 1);
          continue;
        }
        walk(full, depth + 1);
      } else if (e.isFile()) {
        if (e.name.endsWith('.d.ts')) stubs.push({ lang: 'ts', path: full });
        else if (e.name.endsWith('.pyi')) stubs.push({ lang: 'py', path: full });
      }
    }
  }
  walk(root, 0);
  return stubs;
}

// Heuristic framework recognition — which packages installed.
function _detectFrameworks(root) {
  const fw = new Set();
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const all = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if ('express' in all) fw.add('express');
    if ('koa' in all) fw.add('koa');
    if ('fastify' in all) fw.add('fastify');
    if ('@nestjs/core' in all) fw.add('nestjs');
    if ('next' in all) fw.add('next');
    if ('react' in all) fw.add('react');
  } catch {}
  return fw;
}

/**
 * Load all type stubs reachable from `root`. Returns a unified signatures
 * map + types map. Cache-hits on the project fingerprint.
 */
export function loadProjectStubs(root) {
  if (!root) return _emptyStubs();
  const fingerprint = _projectFingerprint(root);
  const cached = _readCache(root);
  if (cached && cached.fingerprint === fingerprint) return cached;
  const budgetMs = Number(process.env.AGENTIC_SECURITY_TYPE_STUBS_BUDGET_MS) || 10_000;
  const deadline = Date.now() + budgetMs;
  const files = _findStubFiles(root, deadline);
  const signatures = new Map();
  const types = new Map();
  for (const f of files) {
    if (Date.now() > deadline) break;
    let body;
    try { body = fs.readFileSync(f.path, 'utf8'); } catch { continue; }
    if (body.length > 500_000) continue;   // skip huge stub files
    const parsed = f.lang === 'ts' ? _parseDtsFile(body) : _parsePyiFile(body);
    for (const [k, v] of parsed.signatures) {
      if (!signatures.has(k)) signatures.set(k, v);
    }
    for (const [k, v] of parsed.types) {
      if (!types.has(k)) types.set(k, v);
    }
  }
  const frameworks = _detectFrameworks(root);
  const stubs = { signatures, types, frameworks, fingerprint };
  _writeCache(root, stubs);
  return stubs;
}

function _emptyStubs() {
  return { signatures: new Map(), types: new Map(), frameworks: new Set(), fingerprint: null };
}

/**
 * Look up a function signature by qid OR by name. Returns null if absent.
 */
export function signatureFor(stubs, qidOrName) {
  if (!stubs || !stubs.signatures) return null;
  // Try the full qid first, then strip after `::` to get the name.
  if (stubs.signatures.has(qidOrName)) return stubs.signatures.get(qidOrName);
  const idx = String(qidOrName).indexOf('::');
  if (idx > 0) {
    const tail = qidOrName.slice(idx + 2).split('@')[0];
    if (stubs.signatures.has(tail)) return stubs.signatures.get(tail);
  }
  return null;
}

/**
 * Look up a type / interface / class definition by name.
 */
export function typeOf(stubs, typeName) {
  if (!stubs || !stubs.types) return null;
  return stubs.types.get(typeName) || null;
}

export const _internal = { _parseDtsFile, _parsePyiFile, _projectFingerprint, _cacheBase };
