// bundle-frontend.mjs — Milestone 4, sub-project Self-contained HTML
// report. A minimal, hand-rolled ES-module bundler, deliberately NOT a
// general one — see this sub-project's own scoping doc for why a real
// bundler dependency (esbuild etc.) was considered and NOT chosen:
// frontend/src/'s real module graph (confirmed by a full-tree grep before
// this file was written) uses ONLY named imports/exports, no default
// exports, no `export *`, no namespace or side-effect-only imports. This
// bundler supports exactly that subset and throws a clear error on
// anything else, rather than silently mishandling an unsupported form.
//
// Algorithm: parse each file's own import specifiers + exported top-level
// names via regex (safe here because the supported subset's syntax is
// simple and unambiguous — a full parser is not needed for this bounded,
// fully-enumerated 21-file input); topologically order every reachable
// module; wrap EVERY NON-ENTRY module in its own IIFE (this is what
// prevents two dependency files' same-named PRIVATE top-level bindings
// from colliding when concatenated — a real risk with naive flat
// concatenation, proven by this file's own test suite); each module's
// IIFE destructures its own imports from its dependencies' already-
// evaluated namespace objects (`const { a, b } = __NS_shared;`) and
// returns its own exports as a plain object.
//
// The ENTRY module is deliberately NOT wrapped in an IIFE: its body is
// emitted directly at the top level of the output (after its own
// destructured imports), so its top-level declarations — functions the
// caller needs to invoke directly, e.g. `bootstrap()` in a `<script>`
// tag, or (as this file's own tests require) a bare exported name called
// straight off the bundled output — become real top-level bindings
// rather than being trapped inside a closure whose return value is
// discarded. Wrapping the entry in an IIFE too (as an earlier draft of
// this algorithm did) type-checks and looks symmetrical, but it is a
// correctness bug: it makes every exported name of the entry module
// unreachable from outside the bundle, which is never what a bundle's
// caller wants. Only the entry is unwrapped — every other module is
// still fully IIFE-isolated, so the collision guarantee above is
// unaffected (there is exactly one unwrapped scope per bundle, by
// construction, since the entry is the unique DFS root and cannot be
// re-entered — a cycle back to it is rejected below as a circular
// import).

import * as fs from 'node:fs';
import * as path from 'node:path';

const IMPORT_RE = /import\s*\{([\s\S]*?)\}\s*from\s*['"](\.[^'"]+)['"];?/g;
const UNSUPPORTED_IMPORT_RE = /^import\s+(?!\{)/m;
const EXPORT_STAR_RE = /^export\s*\*/m;
const EXPORT_DEFAULT_RE = /^export\s+default\b/m;
const EXPORT_NAMED_RE = /^export\s+(?:function\*?|class|const|let|var)\s+([A-Za-z0-9_$]+)/gm;

function _nsName(absPath, seen) {
  // A stable, collision-free JS identifier per module, derived from its
  // path. seen is a Map<absPath, name> shared across the whole bundle run.
  if (seen.has(absPath)) return seen.get(absPath);
  const base = absPath.replace(/[^A-Za-z0-9_$]/g, '_');
  const name = `__NS_${base}`;
  seen.set(absPath, name);
  return name;
}

function _parseModule(absPath) {
  const src = fs.readFileSync(absPath, 'utf8');
  if (UNSUPPORTED_IMPORT_RE.test(src) || EXPORT_STAR_RE.test(src) || EXPORT_DEFAULT_RE.test(src)) {
    throw new Error(`bundleFrontendModules: unsupported import/export form in ${absPath} — only named imports/exports are supported`);
  }
  const imports = [];
  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(src))) {
    const names = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    const resolved = path.resolve(path.dirname(absPath), m[2]);
    imports.push({ names, resolved });
  }
  const exportNames = [];
  EXPORT_NAMED_RE.lastIndex = 0;
  while ((m = EXPORT_NAMED_RE.exec(src))) exportNames.push(m[1]);
  // Strip import lines entirely; strip the leading `export ` keyword from
  // each exported declaration (the declaration itself — function/const/
  // class — is kept verbatim, so the body is otherwise untouched).
  const body = src
    .replace(IMPORT_RE, '')
    .replace(/^export\s+(?=(?:function\*?|class|const|let|var)\s)/gm, '');
  return { absPath, body, imports, exportNames };
}

export function bundleFrontendModules(entryAbsPath) {
  const nsNames = new Map();
  const parsed = new Map(); // absPath -> parsed module
  const order = []; // topological, dependency-first
  const visiting = new Set();

  function visit(absPath) {
    if (parsed.has(absPath)) return;
    if (visiting.has(absPath)) {
      throw new Error(`bundleFrontendModules: circular import detected at ${absPath} — this bundler does not support cycles`);
    }
    visiting.add(absPath);
    const mod = _parseModule(absPath);
    parsed.set(absPath, mod);
    for (const imp of mod.imports) visit(imp.resolved);
    visiting.delete(absPath);
    order.push(absPath);
  }
  visit(entryAbsPath);

  const chunks = [];
  for (const absPath of order) {
    const mod = parsed.get(absPath);
    const destructures = mod.imports
      .map((imp) => `  const { ${imp.names.join(', ')} } = ${_nsName(imp.resolved, nsNames)};`)
      .join('\n');

    if (absPath === entryAbsPath) {
      // Entry: emit unwrapped at top level so its declarations become
      // real top-level bindings the caller can invoke — see the header
      // comment for why this must not be an IIFE like every other module.
      chunks.push(`${destructures}\n${mod.body}`);
      continue;
    }

    const ns = _nsName(absPath, nsNames);
    const returnObj = mod.exportNames.length ? `  return { ${mod.exportNames.join(', ')} };` : '  return {};';
    chunks.push(`const ${ns} = (function() {\n${destructures}\n${mod.body}\n${returnObj}\n})();`);
  }
  return chunks.join('\n\n');
}
