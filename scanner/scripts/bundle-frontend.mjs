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
// Three more real, unsupported forms — added after the final whole-branch
// review found each builds with NO error (`EXPORT_NAMED_RE` below requires
// `function`/`class`/`const`/`let`/`var` immediately after `export `, so
// `export async function` matches none of these guards OR the named-export
// extractor, and is silently dropped as neither a caught error nor a real
// export) and only fails later as a page-load SyntaxError, blanking the
// whole page with no visible error — `export async function` already
// exists in the real tree today (frontend/src/lib/api-client.js), outside
// today's bundled entry point's own reachable graph only by luck.
const EXPORT_ASYNC_RE = /^export\s+async\s+function/m;
const EXPORT_LIST_RE = /^export\s*\{/m;
const IMPORT_RENAME_RE = /\bas\b/;
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
  if (UNSUPPORTED_IMPORT_RE.test(src) || EXPORT_STAR_RE.test(src) || EXPORT_DEFAULT_RE.test(src) || EXPORT_ASYNC_RE.test(src) || EXPORT_LIST_RE.test(src)) {
    throw new Error(`bundleFrontendModules: unsupported import/export form in ${absPath} — only named imports/exports are supported (no default/namespace/side-effect imports, no export */export default/export {}-list/export async function)`);
  }
  const imports = [];
  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(src))) {
    if (IMPORT_RENAME_RE.test(m[1])) {
      throw new Error(`bundleFrontendModules: unsupported \`import { x as y }\` rename in ${absPath} — only bare named imports are supported`);
    }
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
    // `visiting` (currently-on-the-DFS-stack) must be checked BEFORE
    // `parsed` (fully-resolved, safe to skip) — found by this task's own
    // review: the original ordering set `parsed` before recursing into a
    // module's own imports, so a cycle back to an ancestor hit the
    // `parsed.has()` check first and returned silently, making the
    // `visiting`-based throw below unreachable for ANY cycle. Reproduced
    // live: a real entry<->b.js cycle built successfully at bundle time
    // and only failed later, as a confusing `ReferenceError` (TDZ) when
    // the broken output was executed, instead of this function's own
    // clear build-time error.
    if (visiting.has(absPath)) {
      throw new Error(`bundleFrontendModules: circular import detected at ${absPath} — this bundler does not support cycles`);
    }
    if (parsed.has(absPath)) return;
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
  const bundled = chunks.join('\n\n');

  // Real gap found by the final whole-branch review, live-reproduced: the
  // UNSUPPORTED_IMPORT_RE/EXPORT_STAR_RE/EXPORT_DEFAULT_RE guards above
  // only cover THREE specific unsupported forms — real ES syntax this
  // bundler doesn't handle (`export async function`, `export { g };`
  // re-export lists, `import { h as hh }` renames) builds with NO error
  // and only fails later, as a page-load-time SyntaxError that silently
  // blanks the whole page (export-entry.js's own showError() never runs,
  // since the entire inline <script> fails to parse before any of its
  // code executes) — directly contradicting this file's own documented
  // "throws a clear error on anything else" promise. `export async
  // function` already exists in the real tree today
  // (frontend/src/lib/api-client.js) — outside today's bundled entry
  // point's own reachable graph only by luck. Rather than enumerating
  // every unsupported form by name (the exact approach that missed these
  // three), validate the FINAL bundle is syntactically valid JS before
  // returning it — this converts any parse failure, including forms not
  // yet imagined, into a clear build-time error. `new Function` compiles
  // without executing (measured ~1ms on the real ~131KB bundle — cheap).
  try {
    // eslint-disable-next-line no-new-func
    new Function(bundled);
  } catch (e) {
    throw new Error(`bundleFrontendModules: the assembled bundle is not valid JavaScript (${e.message}) — one of the ${order.length} modules likely uses an ES form this bundler doesn't support (only named imports/exports, no async/generator export shorthand ambiguity, no \`export { x };\` lists, no \`import { x as y }\` renames)`);
  }
  return bundled;
}
