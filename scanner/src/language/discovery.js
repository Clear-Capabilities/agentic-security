// Shared discovery registry for Haskell and Nix inputs (CORE-002).
//
// One place answers "is this path a Haskell/Nix source, a manifest, an explicit
// export, or build output to stay out of?", so the scan walker (runScan.js), the
// per-file filter (engine.js shouldScan), the watch filter (posture/watch-mode.js)
// and the incremental-invalidation key all agree. Before this module the answer
// was copied into each of those and would have drifted.
//
// Everything here is static: nothing is executed and nothing is read outside the
// scan root. Paths are '/'-separated and relative to the root.
//
// Three deliberate rules:
//
//   * Build output is out of ordinary traversal. `dist-newstyle/`, `.stack-work/`,
//     `.direnv/` and anything under `nix/store/` hold generated sources, caches
//     and a store closure that is neither the project's code nor bounded in size.
//   * An EXPLICIT export inside such a directory is the one exception, and it is
//     read by exact path (`readExplicitExports`), never by recursing into the
//     directory. A tool-written plan file is evidence; the directory around it is
//     not.
//   * Every graph walk is bounded (nodes, depth, imports per file) and every
//     resolved path must stay inside the scan root. A bound hit is reported as
//     `truncated`, never silently dropped.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const SOURCE_RE = /\.(lhs-boot|hs-boot|lhs|hs|hsig|hsc|nix)$/i;
const NIX_RE = /\.nix$/i;

const MANIFEST_NAMES = new Set([
  'cabal.project', 'cabal.project.freeze', 'cabal.project.local', 'cabal.config',
  'stack.yaml', 'stack.yaml.lock', 'package.yaml', 'hie.yaml',
  'flake.nix', 'flake.lock', 'default.nix', 'shell.nix',
]);

// Directory names that hold build output or a store closure. Matched per path
// segment, plus the two-segment `nix/store`.
const EXCLUDED_DIRS = new Set(['dist-newstyle', '.stack-work', '.cabal-sandbox', '.direnv']);

// Exact project-relative paths a user or tool writes on purpose. Resolved per
// project directory, never by walking the excluded directory that holds them.
export const EXPLICIT_EXPORTS = Object.freeze([
  'dist-newstyle/cache/plan.json',
  '.stack-work/dependencies.json',
  '.direnv/nix-export.json',
  'nix-export.json',
]);

export const DEFAULT_BUDGETS = Object.freeze({
  maxNodes: 5000,
  maxDepth: 32,
  maxImportsPerFile: 256,
  maxExportBytes: 10_000_000,
  maxProjectDirs: 256,
});

const norm = (p) => String(p || '').replace(/\\/g, '/');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function isLanguageSource(rel) {
  return SOURCE_RE.test(norm(rel));
}

export function isLanguageManifest(rel) {
  const base = norm(rel).split('/').pop() || '';
  return MANIFEST_NAMES.has(base) || /\.cabal$/i.test(base);
}

export function languageOf(rel) {
  const p = norm(rel);
  if (NIX_RE.test(p)) return 'nix';
  if (SOURCE_RE.test(p)) return 'haskell';
  const base = p.split('/').pop() || '';
  if (/\.cabal$/i.test(base) || /^(?:cabal\.|stack\.yaml|package\.yaml|hie\.yaml)/.test(base)) return 'haskell';
  if (base === 'flake.lock') return 'nix';
  return null;
}

export function isLanguageExcludedPath(rel) {
  const p = norm(rel);
  const segs = p.split('/');
  for (let i = 0; i < segs.length; i++) {
    if (EXCLUDED_DIRS.has(segs[i])) return true;
    if (segs[i] === 'nix' && segs[i + 1] === 'store') return true;
  }
  return false;
}

export function isExplicitExport(rel) {
  const p = norm(rel);
  return EXPLICIT_EXPORTS.some((e) => p === e || p.endsWith('/' + e));
}

// Glob patterns for the walker's ignore list. Pruning only; correctness comes
// from the per-file predicates above.
export const WALK_IGNORE_GLOBS = Object.freeze([
  '**/dist-newstyle/**', '**/.stack-work/**', '**/.cabal-sandbox/**', '**/.direnv/**', '**/nix/store/**',
]);

function within(root, abs) {
  const r = path.resolve(root);
  const a = path.resolve(abs);
  return a === r || a.startsWith(r + path.sep);
}

/**
 * Read the explicit exports for every project directory (root plus the
 * directory of each manifest in `manifestRels`). Exact-path reads only: lstat
 * rejects symlinks, realpath must stay inside `root`, and the size is capped.
 * Returns { contents: {rel: text}, skipped: [{path, reason}] }.
 */
export function readExplicitExports(root, manifestRels = [], budgets = {}) {
  const b = { ...DEFAULT_BUDGETS, ...budgets };
  const contents = {};
  const skipped = [];
  let realRoot;
  try { realRoot = fs.realpathSync(root); } catch { return { contents, skipped }; }
  const dirs = new Set(['']);
  for (const m of manifestRels) {
    if (dirs.size >= b.maxProjectDirs) { skipped.push({ path: m, reason: 'project-dir-budget' }); break; }
    const d = path.posix.dirname(norm(m));
    if (!isLanguageExcludedPath(d)) dirs.add(d === '.' ? '' : d);
  }
  for (const d of [...dirs].sort()) {
    for (const e of EXPLICIT_EXPORTS) {
      const rel = d ? `${d}/${e}` : e;
      const abs = path.join(root, rel);
      let st;
      try { st = fs.lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) { skipped.push({ path: rel, reason: 'symlink' }); continue; }
      if (!st.isFile()) continue;
      if (st.size > b.maxExportBytes) { skipped.push({ path: rel, reason: 'too-large' }); continue; }
      let real;
      try { real = fs.realpathSync(abs); } catch { continue; }
      if (!within(realRoot, real)) { skipped.push({ path: rel, reason: 'escapes-root' }); continue; }
      try { contents[rel] = fs.readFileSync(abs, 'utf8'); } catch { /* unreadable */ }
    }
  }
  return { contents, skipped };
}

/**
 * Describe a source file's declared scope and keep its source locations.
 * `code` has exactly the same number of lines as `content` and every code
 * character stays at its original column, so a position found in `code` is the
 * same position in the file on disk.
 *   .lhs / .lhs-boot  bird-track ("> ") and \begin{code} blocks are code
 *   .hs-boot          scope 'boot-interface'
 *   .hsig             scope 'signature'
 *   .hsc              '#' preprocessor lines are blanked, scope 'preprocessed'
 */
export function describeSource(rel, content) {
  const p = norm(rel);
  const lang = languageOf(p);
  const text = String(content ?? '');
  const lower = p.toLowerCase();
  let kind = 'plain';
  let scope = lang === 'nix' ? 'nix-expression' : 'module';
  if (/\.lhs-boot$/.test(lower)) { kind = 'literate-boot'; scope = 'boot-interface'; }
  else if (/\.hs-boot$/.test(lower)) { kind = 'boot'; scope = 'boot-interface'; }
  else if (/\.lhs$/.test(lower)) kind = 'literate';
  else if (/\.hsig$/.test(lower)) { kind = 'signature'; scope = 'signature'; }
  else if (/\.hsc$/.test(lower)) { kind = 'hsc'; scope = 'preprocessed'; }

  const lines = text.split('\n');
  let outLines = lines;
  if (kind === 'literate' || kind === 'literate-boot') {
    let inBlock = false;
    outLines = lines.map((l) => {
      if (/^\s*\\begin\{code\}/.test(l)) { inBlock = true; return ''; }
      if (/^\s*\\end\{code\}/.test(l)) { inBlock = false; return ''; }
      if (inBlock) return l;
      if (l.startsWith('>')) return ' ' + l.slice(1);
      return '';
    });
  } else if (kind === 'hsc') {
    outLines = lines.map((l) => (/^\s*#/.test(l) ? '' : l));
  }
  const code = outLines.join('\n');
  const m = lang === 'haskell' ? /^\s*(?:module|signature)\s+([A-Z][\w.']*)/m.exec(code) : null;
  return {
    language: lang, kind, scope,
    declaredModule: m ? m[1] : null,
    code,
    lineCount: lines.length,
  };
}

const HS_IMPORT_RE = /^\s*import\s+(?:\{-#\s*SOURCE\s*#-\}\s+)?(?:safe\s+)?(?:qualified\s+)?(?:"[^"]*"\s+)?([A-Z][\w.']*)/gm;
const NIX_PATH_RE = /(?<![\w.\/~-])(\.{1,2}\/[\w.\/+@-]+)/g;

// Map module name -> file keys, from the paths themselves. `src/Foo/Bar.hs`
// registers `Foo.Bar` and `Bar`; lower-case directories end the module path.
function haskellModuleIndex(keys) {
  const idx = new Map();
  for (const k of keys) {
    if (!/\.(?:lhs-boot|hs-boot|lhs|hs|hsig|hsc)$/i.test(k)) continue;
    const segs = k.replace(/\.(?:lhs-boot|hs-boot|lhs|hs|hsig|hsc)$/i, '').split('/');
    const parts = [];
    for (let i = segs.length - 1; i >= 0 && /^[A-Z]/.test(segs[i]); i--) {
      parts.unshift(segs[i]);
      const name = parts.join('.');
      if (!idx.has(name)) idx.set(name, []);
      idx.get(name).push(k);
    }
  }
  return idx;
}

function commonPrefixLen(a, b) {
  const x = a.split('/'); const y = b.split('/');
  let n = 0;
  while (n < x.length - 1 && n < y.length - 1 && x[n] === y[n]) n++;
  return n;
}

/**
 * Local import edges within `fileContents` (the already root-confined scan
 * set). Returns { graph: Map<rel, string[]>, escaped: [{file, spec}] } where
 * `escaped` lists Nix path literals that resolve outside the root. Unresolved
 * imports (packages, store paths) add no edge.
 */
export function buildImportGraph(fileContents, budgets = {}) {
  const b = { ...DEFAULT_BUDGETS, ...budgets };
  const keys = Object.keys(fileContents).map(norm).filter(isLanguageSource).sort();
  const keySet = new Set(keys);
  const modIdx = haskellModuleIndex(keys);
  const graph = new Map();
  const escaped = [];
  for (const k of keys) {
    const deps = new Set();
    const text = String(fileContents[k] ?? '');
    if (languageOf(k) === 'haskell') {
      const code = describeSource(k, text).code;
      let n = 0; let m;
      HS_IMPORT_RE.lastIndex = 0;
      while ((m = HS_IMPORT_RE.exec(code)) && n++ < b.maxImportsPerFile) {
        const cands = (modIdx.get(m[1]) || []).filter((c) => c !== k);
        if (!cands.length) continue;
        cands.sort((x, y) => commonPrefixLen(k, y) - commonPrefixLen(k, x) || (x < y ? -1 : 1));
        deps.add(cands[0]);
      }
    } else {
      let n = 0; let m;
      NIX_PATH_RE.lastIndex = 0;
      while ((m = NIX_PATH_RE.exec(text)) && n++ < b.maxImportsPerFile) {
        const spec = m[1].replace(/[.,;]+$/, '');
        const joined = path.posix.normalize(path.posix.join(path.posix.dirname(k), spec));
        if (joined.startsWith('../') || joined === '..' || path.posix.isAbsolute(joined)) { escaped.push({ file: k, spec }); continue; }
        for (const c of [joined, `${joined}.nix`, `${joined}/default.nix`]) {
          if (keySet.has(c) && c !== k) { deps.add(c); break; }
        }
      }
    }
    graph.set(k, [...deps].sort());
  }
  return { graph, escaped };
}

/** Transitive closure of `start` over `graph`, cycle-safe and bounded. */
export function importClosure(graph, start, budgets = {}) {
  const b = { ...DEFAULT_BUDGETS, ...budgets };
  const seen = new Set([start]);
  let frontier = [start];
  let truncated = false;
  for (let depth = 0; frontier.length; depth++) {
    if (depth >= b.maxDepth) { truncated = true; break; }
    const next = [];
    for (const f of frontier) {
      for (const d of graph.get(f) || []) {
        if (seen.has(d)) continue;
        if (seen.size >= b.maxNodes) { truncated = true; break; }
        seen.add(d); next.push(d);
      }
    }
    frontier = next;
  }
  seen.delete(start);
  return { files: [...seen].sort(), truncated };
}

/**
 * Per-file invalidation digests. A file's digest covers its own content, the
 * content of every module it transitively imports, every language manifest
 * (lockfile, project flags, target/configuration), every explicit export, and
 * the library-model inputs. Change any of them and every file whose digest
 * depended on it changes.
 */
export function computeLanguageDigests(fileContents, { manifests = {}, models = {}, budgets = {} } = {}) {
  const { graph, escaped } = buildImportGraph(fileContents, budgets);
  const project = crypto.createHash('sha256');
  for (const [label, map] of [['m', manifests], ['l', models]]) {
    for (const k of Object.keys(map).sort()) {
      project.update(label + k + '\0' + sha(String(map[k] ?? '')) + '\n');
    }
  }
  const projectDigest = project.digest('hex');
  const digests = new Map();
  let truncated = false;
  for (const k of graph.keys()) {
    const cl = importClosure(graph, k, budgets);
    if (cl.truncated) truncated = true;
    const h = crypto.createHash('sha256');
    h.update(projectDigest + '\n' + k + '\0' + sha(String(fileContents[k] ?? '')) + '\n');
    for (const d of cl.files) h.update(d + '\0' + sha(String(fileContents[d] ?? '')) + '\n');
    digests.set(k, h.digest('hex'));
  }
  return { digests, graph, escaped, truncated, projectDigest };
}

function collectManifests(fileContents, depFileContents) {
  const out = {};
  for (const map of [fileContents, depFileContents]) {
    for (const k of Object.keys(map || {})) {
      if (isLanguageManifest(k) || isExplicitExport(k)) out[norm(k)] = map[k];
    }
  }
  return out;
}

/**
 * A copy of `fileContents` whose Haskell/Nix sources carry their import-closure
 * digest, for use as the checkpoint's per-file hash input. Other entries keep
 * their exact value, and with no Haskell/Nix source the SAME object is returned,
 * so scans of other languages are untouched.
 */
export function withLanguageClosure(fileContents, depFileContents = {}, opts = {}) {
  const hasLang = Object.keys(fileContents || {}).some(isLanguageSource);
  if (!hasLang) return fileContents;
  const { digests } = computeLanguageDigests(fileContents, { manifests: collectManifests(fileContents, depFileContents), models: opts.models || {}, budgets: opts.budgets });
  const out = { ...fileContents };
  for (const [k, d] of digests) out[k] = `${fileContents[k]}\n\0closure:${d}`;
  return out;
}

/**
 * Files whose cached results are stale after a change: the changed files, every
 * file that transitively imports one, and (for a manifest, export or model
 * change) every Haskell/Nix source.
 */
export function impactedFiles(fileContents, depFileContents, changedRels, opts = {}) {
  const changed = new Set([...changedRels].map(norm));
  const { graph } = buildImportGraph(fileContents, opts.budgets);
  const all = [...graph.keys()];
  const broad = [...changed].some((c) => isLanguageManifest(c) || isExplicitExport(c) || (opts.modelRels || []).includes(c));
  if (broad) return all;
  const out = new Set([...changed].filter((c) => graph.has(c)));
  const rev = new Map();
  for (const [k, ds] of graph) for (const d of ds) { if (!rev.has(d)) rev.set(d, []); rev.get(d).push(k); }
  let frontier = [...out];
  while (frontier.length) {
    const next = [];
    for (const f of frontier) for (const r of rev.get(f) || []) if (!out.has(r)) { out.add(r); next.push(r); }
    frontier = next;
  }
  return [...out].sort();
}
