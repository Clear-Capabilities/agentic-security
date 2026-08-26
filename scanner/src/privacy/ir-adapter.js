// Privacy IR adapter (assurance-hardening PRD, Milestone 2, FR-401).
//
// dataflow/privacy-taint.js's annotatePrivacyTaint() expects a per-file map
// of `{ _content, decls: [{name, line, type}], calls: [{line, fullPath|callee,
// args: [{text}]}] }` — a FLAT, per-file shape. The real Layer-1 IR
// (ir/index.js#buildProjectIR) does not produce that shape at all: it is
// per-FUNCTION (`functions: [{params, cfg: {nodes: {...}}}]`), and CFG node
// arguments are structured expression trees (`{kind:'ident', name}`,
// `{kind:'member', object, prop}`, ...), not `{text: string}` objects. This
// was the actual reason privacy analysis was wired with hardcoded
// `decls:[], calls:[]` (A-06) — there was no adapter reconciling the two
// shapes, not a missing capability in the underlying IR/taint engine (see
// docs/implementation/assurance-hardening-decisions.md D-0003's pattern:
// verify before assuming something is unbuilt).
//
// This module is that adapter. It does NOT reimplement privacy analysis —
// it only reshapes the real IR into exactly what annotatePrivacyTaint()
// already knows how to consume.
//
// Declarations: sourced from every function's `params` (a parameter is a
// declaration) and every `assign`-kind CFG node's `target` (an assignment
// declares/rebinds a name). Both are what a real codebase would call PII
// "at the point it enters a function or gets bound to a local".
//
// Calls: sourced from every `call`-kind CFG node, AND from `assign`-kind
// nodes whose `source` is itself a call expression (`const x = fetch(...)`)
// — privacy-taint.js only walks a flat `ir.calls` list, so a call used as
// an assignment's right-hand side needs to be surfaced there too or it's
// invisible to the sink-matching pass entirely.
//
// Argument "text": privacy-taint.js's sink-matching does a literal
// \b<name>\b regex test against the joined text of a call's argument
// expressions — it does not need faithful re-rendered source code, only
// text that CONTAINS every identifier name referenced (directly or nested)
// in that argument, so a tainted variable's name is found wherever it
// appears. `_identifiersIn` recursively collects identifier names (and
// literal values, for completeness) rather than attempting full expression
// pretty-printing, which is simpler and sufficient for this consumer's
// actual matching logic.
//
// Storage: this codebase already has a separate stored-taint subsystem
// (engine.js's STORED_TAINT_FIELD_PATTERNS / buildStoredTaintRegistry) that
// tracks which ORM/model fields are written with unsanitized request input,
// for its own cross-file write-then-render correlation (crossStoredTaint).
// `_storageForFile` reindexes that ALREADY-COMPUTED, whole-project registry
// down to one file's writes rather than recomputing anything — the engine
// builds it once per scan regardless of whether privacy analysis runs at all.
//
// Types: the underlying Layer-1 IR (ir/index.js#buildProjectIR) tracks no
// type-annotation/inference data for any language — genuine cross-language
// type inference would mean extending every language parser, a separate,
// substantially larger project deliberately out of scope here. What IS in
// scope, and implemented below, is a narrow, honest, TypeScript-only sliver:
// `_extractTsTypes` does a SEPARATE, read-only `@babel/core` `parseSync` pass
// over `.ts`/`.tsx` source (never touching ir/parser-js.js's own transform
// pipeline or its shared, heavily-relied-on visitor plugin) and walks the
// resulting AST for `TSTypeAnnotation` nodes on function parameters and
// `let`/`const`/`var` declarators. Babel's `parseSync` only PARSES — it never
// runs `@babel/preset-typescript`'s stripping transform, so a `.ts` file's
// type annotations are fully intact on the AST it returns, no plugin-ordering
// trick required. Matching this SEPARATE parse's declarations back to the
// real IR's decls is done by `(line, name)` — the same real source line and
// identifier name a given parameter or declarator sits on in both parses,
// since both parse the identical source text. A `.js` file, a type Babel
// cannot express as a plain name (destructured/computed types, deeply
// generic types past a small recursion depth), or any parse/traverse failure
// all degrade to `type: null` — never a guess, matching every other
// optional field in this module.

import { parseSync as babelParseSync, traverse as babelTraverse } from '@babel/core';
import presetTypescript from '@babel/preset-typescript';

const MAX_EXPR_DEPTH = 40;
const MAX_TS_TYPE_DEPTH = 6;

function _calleeToString(callee, depth = 0) {
  if (typeof callee === 'string') return callee;
  if (!callee || typeof callee !== 'object' || depth > MAX_EXPR_DEPTH) return '';
  switch (callee.kind) {
    case 'ident': return callee.name || '';
    case 'member': {
      const obj = _calleeToString(callee.object, depth + 1);
      return obj ? `${obj}.${callee.prop || ''}` : String(callee.prop || '');
    }
    case 'call': return _calleeToString(callee.callee, depth + 1);
    default: return '';
  }
}

function _identifiersIn(expr, out, depth = 0) {
  if (!expr || typeof expr !== 'object' || depth > MAX_EXPR_DEPTH) return;
  switch (expr.kind) {
    case 'ident':
      if (expr.name) out.push(expr.name);
      return;
    case 'literal':
      if (expr.value != null) out.push(String(expr.value));
      return;
    case 'member':
      _identifiersIn(expr.object, out, depth + 1);
      if (expr.prop) out.push(String(expr.prop));
      return;
    case 'binary':
    case 'logical':
      _identifiersIn(expr.left, out, depth + 1);
      _identifiersIn(expr.right, out, depth + 1);
      return;
    case 'tpl':
      for (const p of expr.parts || []) _identifiersIn(p, out, depth + 1);
      return;
    case 'call':
      _identifiersIn(expr.callee, out, depth + 1);
      for (const a of expr.args || []) _identifiersIn(a, out, depth + 1);
      return;
    case 'array':
      for (const e of expr.elements || []) _identifiersIn(e, out, depth + 1);
      return;
    case 'object':
      for (const p of expr.props || []) _identifiersIn(p.value, out, depth + 1);
      return;
    case 'union':
      for (const b of expr.branches || []) _identifiersIn(b, out, depth + 1);
      return;
    default:
      return;
  }
}

function _argsToTextArgs(args) {
  return (args || []).map(a => {
    const names = [];
    _identifiersIn(a, names);
    return { text: names.join(' ') };
  });
}

// A TSQualifiedName is `A.B.C` (e.g. `Foo.Bar`) — dot-join it the same way
// _calleeToString dot-joins a member expression above.
function _qualifiedTypeName(node, depth = 0) {
  if (!node || depth > MAX_TS_TYPE_DEPTH) return null;
  if (node.type === 'Identifier') return node.name || null;
  if (node.type === 'TSQualifiedName') {
    const left = _qualifiedTypeName(node.left, depth + 1);
    const right = node.right?.name || null;
    if (!left || !right) return left || right;
    return `${left}.${right}`;
  }
  return null;
}

/**
 * Renders a TSType AST node to a short, human-readable string — never a
 * best-effort re-render of the whole type, just enough to be a real,
 * non-fabricated signal. Anything not recognized (mapped types, conditional
 * types, indexed access, deeply nested generics past the depth guard) is
 * `null`, exactly like every other "don't know" in this module — no type
 * string is ever invented for a shape this doesn't genuinely understand.
 */
function _tsTypeToString(node, depth = 0) {
  if (!node || depth > MAX_TS_TYPE_DEPTH) return null;
  switch (node.type) {
    case 'TSStringKeyword': return 'string';
    case 'TSNumberKeyword': return 'number';
    case 'TSBooleanKeyword': return 'boolean';
    case 'TSAnyKeyword': return 'any';
    case 'TSUnknownKeyword': return 'unknown';
    case 'TSVoidKeyword': return 'void';
    case 'TSNullKeyword': return 'null';
    case 'TSUndefinedKeyword': return 'undefined';
    case 'TSNeverKeyword': return 'never';
    case 'TSObjectKeyword': return 'object';
    case 'TSBigIntKeyword': return 'bigint';
    case 'TSSymbolKeyword': return 'symbol';
    case 'TSTypeReference': {
      const name = node.typeName?.type === 'Identifier'
        ? node.typeName.name
        : _qualifiedTypeName(node.typeName, depth + 1);
      if (!name) return null;
      // Babel's current AST names this `typeArguments`; `typeParameters` was
      // the property on older @babel/parser versions for the same node —
      // checking both means this doesn't silently go generic-blind on a
      // dependency bump either direction.
      const paramNodes = (node.typeArguments || node.typeParameters)?.params || [];
      const args = paramNodes.map(p => _tsTypeToString(p, depth + 1)).filter(Boolean);
      return (args.length && args.length === paramNodes.length) ? `${name}<${args.join(', ')}>` : name;
    }
    case 'TSArrayType': {
      const el = _tsTypeToString(node.elementType, depth + 1);
      return el ? `${el}[]` : null;
    }
    case 'TSUnionType': {
      const parts = (node.types || []).map(t => _tsTypeToString(t, depth + 1)).filter(Boolean);
      return parts.length === (node.types || []).length ? parts.join(' | ') : null;
    }
    case 'TSLiteralType': {
      const lit = node.literal;
      if (lit?.type === 'StringLiteral') return JSON.stringify(lit.value);
      if (lit?.type === 'NumericLiteral') return String(lit.value);
      if (lit?.type === 'BooleanLiteral') return String(lit.value);
      return null;
    }
    default: return null;
  }
}

/**
 * FR-401's "types" element, TypeScript-only. A separate, read-only parse of
 * the real source — never the transformed AST ir/parser-js.js builds its IR
 * from, and never a mutation of anything that module owns. `parseSync` only
 * parses; `@babel/preset-typescript`'s stripping transform never runs, so
 * `.ts`/`.tsx` type annotations are fully intact on the returned AST.
 *
 * Keyed by the real source line a parameter or declarator's IDENTIFIER sits
 * on (matching how ir/parser-js.js's own IR already records a parameter's
 * line as its enclosing function's start line, and an assignment's line as
 * its own CFG node's line) so `_adaptFile` can look a type up by the exact
 * (line, name) pair it already has, without needing any cross-parse node
 * identity.
 *
 * @returns {Map<number, Map<string,string>>} line -> (name -> type string)
 */
function _extractTsTypes(file, content) {
  const out = new Map();
  if (!/\.tsx?$/i.test(file) || typeof content !== 'string' || content.length > 500_000) return out;
  const record = (name, line, typeAnnotationNode) => {
    if (!name || !line || !typeAnnotationNode) return;
    const t = _tsTypeToString(typeAnnotationNode.typeAnnotation);
    if (!t) return;
    if (!out.has(line)) out.set(line, new Map());
    out.get(line).set(name, t);
  };
  let ast;
  try {
    ast = babelParseSync(content, {
      filename: file,
      presets: [[presetTypescript, { ignoreExtensions: true }]],
      // Mirrors ir/parser-js.js's own parserOpts exactly — accepting the same
      // decorator syntax it accepts, so this separate parse does not reject
      // (and silently lose types from) a file the real IR parser accepts.
      parserOpts: { plugins: ['decorators-legacy', 'decoratorAutoAccessors'] },
      babelrc: false, configFile: false, ast: true, code: false,
    });
  } catch { return out; }
  if (!ast) return out;
  try {
    babelTraverse(ast, {
      Function(path) {
        for (const p of path.node.params || []) {
          const resolved = p.type === 'AssignmentPattern' ? p.left : p;
          if (resolved?.type === 'Identifier' && resolved.typeAnnotation) {
            record(resolved.name, path.node.loc?.start?.line, resolved.typeAnnotation);
          }
        }
      },
      VariableDeclarator(path) {
        const id = path.node.id;
        if (id?.type === 'Identifier' && id.typeAnnotation) {
          record(id.name, path.node.loc?.start?.line, id.typeAnnotation);
        }
      },
    });
  } catch { /* degrade to whatever was recorded before the failure */ }
  return out;
}

/**
 * FR-401's "storage" element. Reindexes the whole-project, field-name-keyed
 * stored-taint registry (engine.js#buildStoredTaintRegistry — already
 * computed once per scan for crossStoredTaint's own cross-file correlation,
 * not recomputed here) down to just the writes that happened in THIS file.
 * `storedRegistry` is `{ [fieldName]: [{file, line, snippet, named}, ...] }`;
 * this returns the flattened, per-file subset as
 * `[{field, line, snippet, named}, ...]`.
 */
function _storageForFile(file, storedRegistry) {
  const out = [];
  if (!storedRegistry || typeof storedRegistry !== 'object') return out;
  for (const [field, writes] of Object.entries(storedRegistry)) {
    for (const w of writes || []) {
      if (w && w.file === file) out.push({ field, line: w.line ?? 0, snippet: w.snippet || '', named: !!w.named });
    }
  }
  return out;
}

/**
 * @param {object} fileIR - one entry from ir/index.js#buildProjectIR's `perFile` map: {file, functions, topLevel}
 * @param {Map<number, Map<string,string>>|null} [tsTypes] - `_extractTsTypes`'s
 *   output for this same file. Optional: omitted (or no match at a given
 *   (line, name)) leaves `type: null`, exactly as before this existed.
 * @returns {{decls: Array, calls: Array}}
 */
function _adaptFile(fileIR, tsTypes) {
  const decls = [];
  const calls = [];
  const returns = [];
  const typeAt = (line, name) => tsTypes?.get(line)?.get(name) ?? null;
  for (const fn of fileIR?.functions || []) {
    for (const paramName of fn.params || []) {
      if (typeof paramName === 'string' && paramName) {
        // `kind` genuinely distinguishes a parameter from a later
        // assignment (FR-401's "parameters" vs "assignments" elements) —
        // annotatePrivacyTaint() ignores unknown fields, so this is purely
        // additive for that consumer.
        decls.push({ name: paramName, line: fn.line ?? 0, type: typeAt(fn.line ?? 0, paramName), kind: 'parameter' });
      }
    }
    const nodes = fn.cfg?.nodes || {};
    for (const node of Object.values(nodes)) {
      if (!node) continue;
      if (node.kind === 'assign' && node.target) {
        const line = node.line ?? fn.line ?? 0;
        decls.push({ name: node.target, line, type: typeAt(line, node.target), kind: 'assignment' });
      }
      if (node.kind === 'call') {
        calls.push({
          line: node.line ?? fn.line ?? 0,
          fullPath: _calleeToString(node.callee),
          args: _argsToTextArgs(node.args),
        });
      } else if (node.kind === 'assign' && node.source && node.source.kind === 'call') {
        calls.push({
          line: node.line ?? fn.line ?? 0,
          fullPath: _calleeToString(node.source.callee),
          args: _argsToTextArgs(node.source.args),
        });
      } else if (node.kind === 'return' && node.value) {
        // FR-401's "returns" element: every CFG language parser genuinely
        // emits return-kind nodes (confirmed across parser-js/py/java/go/
        // rb/php/cs/kt/cpp), so this is real IR data, not a stub — surfaced
        // here even though annotatePrivacyTaint() (the shallow walker) does
        // not consume it today, matching the adapter's stated job of
        // supplying what the real IR has, not just what today's one
        // consumer happens to read (see D-0052's evidence for the honest
        // caveat: no current caller reads this field yet).
        const names = [];
        _identifiersIn(node.value, names);
        returns.push({ line: node.line ?? fn.line ?? 0, names });
      }
    }
  }
  return { decls, calls, returns };
}

/**
 * Build the flat, per-file map annotatePrivacyTaint() expects, from the real
 * Layer-1 IR plus the raw file contents (for the `_content` field it uses
 * for snippet extraction — the IR itself carries no raw source text).
 *
 * @param {Record<string,object>} perFileIR - ir/index.js#buildProjectIR's `perFile` (or buildProjectIRAsync's)
 * @param {Record<string,string>} fileContents
 * @param {object|null} [storedRegistry] - engine.js#buildStoredTaintRegistry's
 *   output, for FR-401's "storage" element. Optional and additive: omitted
 *   (or not an object) yields `storage: []` for every file, same
 *   degrade-gracefully convention as every other field here — this is not a
 *   second copy of the registry's own computation, just a per-file view of
 *   the one the engine already builds once per scan.
 * @returns {Map<string, {_content:string, decls:Array, calls:Array, returns:Array, storage:Array}>}
 */
export function adaptIRForPrivacyTaint(perFileIR, fileContents, storedRegistry) {
  const out = new Map();
  const fc = fileContents || {};
  for (const [file, content] of Object.entries(fc)) {
    if (typeof content !== 'string') continue;
    const fileIR = perFileIR ? perFileIR[file] : null;
    // FR-401's "types" element: a real, TypeScript-only signal via a
    // separate parse (see _extractTsTypes's own header) — a no-op Map for
    // every non-.ts/.tsx file, so this costs nothing on the common path.
    const tsTypes = _extractTsTypes(file, content);
    const { decls, calls, returns } = fileIR ? _adaptFile(fileIR, tsTypes) : { decls: [], calls: [], returns: [] };
    const storage = _storageForFile(file, storedRegistry);
    out.set(file, { _content: content, decls, calls, returns, storage });
  }
  return out;
}

export const _internals = {
  _calleeToString, _identifiersIn, _argsToTextArgs, _adaptFile, _storageForFile,
  _tsTypeToString, _qualifiedTypeName, _extractTsTypes,
};
