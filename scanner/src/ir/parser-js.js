// Unified IR — JS/TS frontend.
//
// Walks the Babel AST of one file and emits a structured per-function
// representation that the dataflow engine consumes. The shape is deliberately
// minimal: every statement is a node with a kind, every function has a CFG
// of those nodes, and every call/assignment is exposed as a first-class fact
// rather than buried in AST shape.
//
// Output:
//   {
//     file: '<rel-path>',
//     functions: [{
//       qid:    '<file>::<scope>::<name>',
//       name:   '<name>',
//       line:   <decl line>,
//       params: [<name>...],
//       cfg:    { entry: <nodeId>, exit: <nodeId>, nodes: Map<nodeId, Node> },
//       returns:[<nodeId>...],
//       calls:  [{site: <nodeId>, callee: '<name>', args: [<exprId>...], line}],
//       reads:  Map<varname, [<nodeId>...]>,
//       writes: Map<varname, [{node, source: <exprId>}]>,
//     }],
//     topLevel: <fn-id for module-scope code>,
//   }
//
// Node kinds:
//   'assign'   { target: '<lhs-path>', source: <exprDesc> }
//   'call'     { callee: '<callee-path>', args: [<exprDesc>...] }
//   'return'   { value: <exprDesc> | null }
//   'if'       { cond: <exprDesc>, then: <nodeId>, else: <nodeId> | null }
//   'noop'     (used as join points)
//
// exprDesc is a small JSON value:
//   { kind: 'ident', name }
//   { kind: 'member', object: <exprDesc>, prop }
//   { kind: 'literal', value }
//   { kind: 'call', callee: <exprDesc>, args: [<exprDesc>...] }
//   { kind: 'binary', op, left, right }
//   { kind: 'logical', op, left, right }
//   { kind: 'tpl' }  // template literal — treated as a string concat
//   { kind: 'unknown' }

import { transformSync as babelTransformSync } from '@babel/core';
import presetReact from '@babel/preset-react';
import presetTypescript from '@babel/preset-typescript';

let _nodeIdSeq = 0;
function nextNodeId() { return 'n' + (++_nodeIdSeq); }
/**
 * Reserve `count` consecutive node ids and return the sequence value before them
 * (the first reserved id is `n<base + 1>`). A cached IR is given fresh ids from
 * here, so an id is as unique across the whole process as one the parser made.
 */
export function reserveNodeIds(count) {
  const base = _nodeIdSeq;
  _nodeIdSeq += count;
  return base;
}

// Round-5 lineage-engine finding, generalized in round 6: resolve a Babel
// object-property-shaped node's key (`ObjectProperty` from either an
// `ObjectExpression` or an `ObjectPattern` — both share the same
// `{computed, key}` shape) to either its real, distinct property name, or
// the explicit unknown marker '*' when the key is computed and not itself
// a resolvable literal. A computed key that IS a literal (`{[42]: v}`,
// `{['literal']: v}` — Babel still marks these `computed: true`) still
// resolves to that literal's own string form; a computed key that is an
// arbitrary expression (most commonly an Identifier, e.g. `{[field]: v}`)
// resolves to '*', NEVER to the key expression's own variable name — using
// `p.key.name` unconditionally there would attribute the property to the
// key expression's OWN name as if it were a real, distinct property,
// colliding e.g. `{ field: a, [field]: b }` onto one shared 'field' key.
// Originally fixed only for `ObjectExpression` (round 5); round 6 found the
// identical bug, unfixed, in `lhsPath`'s `ObjectPattern` (destructuring)
// branch and extracted this shared helper so a third instance of the same
// bug can't appear in some future object-key-reading code path. See
// DESIGN_INTRAPROCEDURAL.md §4 and CLAUDE.md's "three hop types" note.
function resolveObjectKey(p) {
  return p.computed
    ? (p.key?.value != null ? String(p.key.value) : '*')
    : (p.key?.name || (p.key?.value != null ? String(p.key.value) : '*'));
}

// Compact a Babel AST node into our exprDesc.
// The simple class name a TypeScript annotation names: `Svc`, `ns.Svc`, `Svc | null`, `Svc | undefined`. Arrays, unions of
// several classes, literals and primitives give null; the class hierarchy honours only a project class, so a library name is inert.
function tsTypeName(ann) {
  let t = ann && ann.type === 'TSTypeAnnotation' ? ann.typeAnnotation : ann;
  if (!t) return null;
  if (t.type === 'TSUnionType') {
    const members = (t.types || []).filter((m) => !/^(?:TSNullKeyword|TSUndefinedKeyword|TSVoidKeyword)$/.test(m.type));
    return members.length === 1 ? tsTypeName(members[0]) : null;
  }
  if (t.type === 'TSTypeReference') {
    const tn = t.typeName;
    if (!tn) return null;
    if (tn.type === 'Identifier') return tn.name;
    if (tn.type === 'TSQualifiedName' && tn.right && tn.right.type === 'Identifier') return tn.right.name;
  }
  return null;
}
// `new Svc(...)` names its class; anything else gives null.
function ctorClassName(init) {
  return init && init.type === 'NewExpression' && init.callee && init.callee.type === 'Identifier' ? init.callee.name : null;
}

function exprOf(n) {
  if (!n) return { kind: 'unknown' };
  switch (n.type) {
    // TypeScript wrappers carry no runtime value of their own: `req.query.name as string`, `x!`, `<T>x`,
    // `x satisfies T`, `f<T>`. They lowered to `unknown`, so a cast on a request value, the ordinary way a typed
    // Express or Fastify handler reads one, cut every flow at the cast. Lower to the wrapped expression.
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'TSTypeAssertion':
    case 'TSSatisfiesExpression':
    case 'TSInstantiationExpression':
    case 'ParenthesizedExpression':
      return exprOf(n.expression);
    case 'Identifier':       return { kind: 'ident', name: n.name };
    case 'NumericLiteral':
    case 'StringLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':       return { kind: 'literal', value: n.value !== undefined ? n.value : null };
    // Next-gen taint capability #2 (string/value abstract domain) — a regex
    // LITERAL (`/^[a-z]+$/`) previously fell through to `{kind:'unknown'}`
    // entirely: no case matched `RegExpLiteral`, so the ENTIRE pattern was
    // lost before any downstream consumer (a guard-narrowing check, the
    // existing `string-domain.js` lattice) ever saw it. This is why a
    // pattern-based validation guard (`if (/^\d+$/.test(x)) sink(x)`) could
    // never be recognized as safety-narrowing at all, regardless of how
    // permissive or restrictive the pattern was — confirmed via a direct IR
    // dump before this fix (the regex literal's own callee-object lowered to
    // `{kind:'unknown'}`, not merely an unrecognized guard shape). Lowered
    // to a `literal` node carrying the ACTUAL RegExp instance (safe here —
    // this parser runs in-process, unlike the five hand-rolled parsers,
    // which have no such runtime and store literal-only VALUES), tagged
    // `isRegex: true` so a consumer can distinguish "this literal's value
    // happens to be a RegExp" from a genuine string/number/boolean literal
    // without doing an `instanceof` check itself. A malformed pattern (rare,
    // Babel would normally reject it upstream) falls back to `unknown`
    // rather than throwing mid-parse.
    case 'RegExpLiteral': {
      try { return { kind: 'literal', value: new RegExp(n.pattern, n.flags || ''), isRegex: true }; }
      catch { return { kind: 'unknown' }; }
    }
    case 'TemplateLiteral':   return { kind: 'tpl', parts: (n.expressions || []).map(exprOf) };
    case 'MemberExpression':  return {
      kind: 'member',
      object: exprOf(n.object),
      prop: n.computed ? (n.property?.value != null ? String(n.property.value) : '*') : (n.property?.name || '*'),
    };
    case 'CallExpression':
    case 'OptionalCallExpression': return {
      kind: 'call',
      callee: exprOf(n.callee),
      args: (n.arguments || []).map(exprOf),
    };
    // `new Foo()` is emitted as a call PLUS an `isNew: true` marker, matching
    // what parser-java.js and parser-cs.js already emit. Without the marker a
    // `new Foo()` is byte-identical in the IR to a plain `Foo()` call, and
    // class-hierarchy.js's typeOfVar walker therefore typed `const x =
    // SomeFactoryFn()` as class `SomeFactoryFn` — a fabricated type that then
    // reaches the dataflow receiver-type gate and can suppress a real finding.
    // Nothing else in the engine reads `isNew`, so this is purely additive.
    case 'NewExpression':     return {
      kind: 'call',
      callee: exprOf(n.callee),
      args: (n.arguments || []).map(exprOf),
      isNew: true,
    };
    case 'BinaryExpression':  return { kind: 'binary', op: n.operator, left: exprOf(n.left), right: exprOf(n.right) };
    case 'LogicalExpression': return { kind: 'logical', op: n.operator, left: exprOf(n.left), right: exprOf(n.right) };
    case 'AssignmentExpression': return { kind: 'assign-expr', target: lhsPath(n.left), source: exprOf(n.right) };
    case 'AwaitExpression':   return exprOf(n.argument);
    case 'YieldExpression':   return exprOf(n.argument);
    case 'ConditionalExpression':
      // Treat as union of consequent + alternate — both may be tainted.
      return { kind: 'union', branches: [exprOf(n.consequent), exprOf(n.alternate)] };
    case 'ObjectExpression':  return {
      kind: 'object',
      // Round-5 lineage-engine finding: for a COMPUTED property
      // (`{[k]: v}`, `p.computed === true`), `p.key` is an arbitrary
      // expression node, not a name — and an Identifier key expression
      // (`k`) HAS a `.name` ('k'), same as a real, non-computed property
      // literally named `k` would. Using `p.key.name` unconditionally
      // therefore attributed a computed property to the key EXPRESSION's
      // own variable name as if it were a real, distinct property name,
      // colliding `{ k: user.ssn, [k]: user.email }` onto one shared 'k'
      // key. A computed key IS still resolvable when it's itself a literal
      // (`{[42]: v}`, `{['literal']: v}` — Babel marks these
      // `computed: true` too, but `p.key.value` gives the real value), so
      // only an Identifier/expression computed key (no `.value`) falls
      // back to the literal string '*' — mirroring the EXISTING computed-
      // MEMBER-access convention (`n.computed` handling just above, and
      // `lhsPath`'s computed-write handling below) rather than inventing a
      // new one. See DESIGN_INTRAPROCEDURAL.md §4 and CLAUDE.md's "three
      // hop types" note.
      //
      // A `SpreadElement` (`{...user}`) previously fell out of the
      // `.filter` entirely — `{...user}` and `{}` were byte-identical in
      // the emitted IR, a real, pre-existing false negative (the identity
      // vanishes, not merged, not flattened — found and documented but
      // not fixed by a final review of an earlier plan). Represented here
      // as a distinct `{spread: true, value: <expr>}` shape (no `key`
      // field) rather than a regular `{key, value}` property, so
      // `scanner/src/lineage/engine.js`'s `resolveExprIdentities` can
      // merge the spread source's OWN field structure directly into this
      // object's structure (see that file for the full mechanism) — a
      // DIFFERENT, more precise handling than a computed-unknown-key
      // property gets (that case folds into one opaque residual bucket; a
      // spread's contents are fully known, just not yet assigned a key in
      // THIS literal, so they can and should stay field-distinguished).
      // Every consumer of `expr.props` outside this package
      // (scanner/src/dataflow/engine.js, higher-order.js,
      // privacy-deep-walker.js — audited before this change) reads only
      // `p.value`, never `p.key`, so this shape is compatible with all of
      // them without any change there — and several gain correct taint/
      // privacy detection through object spread as a direct result, since
      // the spread's value is no longer silently absent from `props`.
      props: (n.properties || []).map(p => {
        if (p.type === 'SpreadElement') return { spread: true, value: exprOf(p.argument) };
        if (p.type !== 'ObjectProperty' || !p.key) return null;
        return { key: resolveObjectKey(p), value: exprOf(p.value) };
      }).filter(Boolean),
    };
    case 'ArrayExpression': {
      // `spreads` is additive and present only when an element is `...x`: the position of every later element is then unknown, which the
      // engine needs in order to treat the literal index by index (E2-03). Consumers that ignore it see the same shape as before.
      const spreads = [];
      (n.elements || []).forEach((el, i) => { if (el && el.type === 'SpreadElement') spreads.push(i); });
      return spreads.length ? { kind: 'array', elements: (n.elements || []).map(exprOf), spreads } : { kind: 'array', elements: (n.elements || []).map(exprOf) };
    }
    case 'SpreadElement':     return exprOf(n.argument);
    case 'ThisExpression':    return { kind: 'ident', name: '_this_' };
    // Taint-recall PRD (80%) Tier 3: JSX had ZERO IR modeling at all — every
    // JSXElement fell through to {kind:'unknown'}, so `return <div
    // dangerouslySetInnerHTML={{__html: html}} />` (React's canonical XSS
    // sink, and the shape of a real corpus miss) silently dropped `html`'s
    // taint entirely. Deliberately narrow: only the `dangerouslySetInnerHTML`
    // attribute is extracted (found on this element or, recursively, any
    // descendant — the attribute can sit on a nested element, not just the
    // one directly returned) and lowered to a synthetic call
    // (`__jsx_dangerously_set_inner_html__`) carrying the `__html` object
    // property's value, so the existing `react-dangerouslySetInnerHTML`
    // member-write sink's SIBLING call-shaped catalog entry can target it.
    // Full JSX modeling (arbitrary attributes, children, expressions) is
    // explicitly out of scope — children are React-auto-escaped by default,
    // so `<div>{unsafeText}</div>` is not itself a vulnerability the way
    // `dangerouslySetInnerHTML` is.
    case 'JSXElement': {
      const found = _findDangerouslySetInnerHTML(n);
      if (found) return { kind: 'call', callee: '__jsx_dangerously_set_inner_html__', args: [exprOf(found)] };
      return { kind: 'unknown' };
    }
    default:                   return { kind: 'unknown' };
  }
}

function _findDangerouslySetInnerHTML(jsxElement) {
  const attrs = jsxElement?.openingElement?.attributes || [];
  for (const attr of attrs) {
    if (attr.type !== 'JSXAttribute' || attr.name?.name !== 'dangerouslySetInnerHTML') continue;
    const val = attr.value;
    if (val?.type !== 'JSXExpressionContainer') continue;
    const obj = val.expression;
    if (obj?.type !== 'ObjectExpression') continue;
    const htmlProp = (obj.properties || []).find(p => p.type === 'ObjectProperty' && (p.key?.name === '__html' || p.key?.value === '__html'));
    if (htmlProp) return htmlProp.value;
  }
  for (const child of jsxElement?.children || []) {
    if (child.type === 'JSXElement') {
      const nested = _findDangerouslySetInnerHTML(child);
      if (nested) return nested;
    }
  }
  return null;
}

// Reduce a Babel LHS node to a string path used as a dataflow variable key.
function lhsPath(n) {
  while (n && (n.type === 'TSAsExpression' || n.type === 'TSNonNullExpression' || n.type === 'TSTypeAssertion' || n.type === 'TSSatisfiesExpression' || n.type === 'ParenthesizedExpression')) n = n.expression;
  if (!n) return null;
  if (n.type === 'Identifier') return n.name;
  if (n.type === 'ThisExpression') return '_this_';
  if (n.type === 'MemberExpression') {
    const base = lhsPath(n.object);
    // Stage 3 correctness audit (detection depth, path-feasibility): a
    // computed WRITE with a literal key (`obj['secret'] = tainted`) used
    // to collapse straight to the wildcard '*' — never trying to extract
    // the literal, unlike exprOf's MemberExpression case just above,
    // which DOES extract it for reads. That asymmetry meant a tainted
    // write via bracket notation with a literal key produced access path
    // "obj.*", while any later read of that same key (`obj.secret` or
    // `obj['secret']`) resolves via exprOf to the specific path
    // "obj.secret" — isCoveredBy has no wildcard semantics (`'*'` is a
    // literal property name here, not a match-anything token), so the two
    // paths never matched and the taint was silently unreachable from any
    // correctly-computed read. Mirrors exprOf's extraction exactly so a
    // write and a read of the same literal key always agree.
    const prop = n.computed
      ? (n.property?.value != null ? String(n.property.value) : '*')
      : (n.property?.name || '*');
    if (!base) return null;
    return base + '.' + prop;
  }
  if (n.type === 'ObjectPattern') {
    // Destructured: return an array of (key, alias) pairs the caller can
    // iterate. Round 6: uses the same `resolveObjectKey` helper
    // `ObjectExpression` uses above, so a non-literal computed key
    // (`const { [field]: value } = user`) resolves to '*' instead of
    // fabricating a colliding key from the key variable's own name — see
    // `resolveObjectKey`'s header comment for the full rationale.
    //
    // A `RestElement` (`const {a, ...rest} = obj`) has its bound identifier
    // at `.argument`, not `.value` (only a real `ObjectProperty` has
    // `.value`) — using `.value` unconditionally here made `lhsPath`
    // resolve to `null` for every rest binding (`lhsPath(undefined)` hits
    // the `if (!n) return null;` guard before ever reaching the
    // `RestElement` case below), so the consumer's `if (!alias) continue;`
    // guard silently skipped it entirely: a real, pre-existing FR-306
    // violation where the rest binding vanished with no trace, not merged,
    // not flattened. `resolveObjectKey(p)` already correctly resolves to
    // '*' for a RestElement (it has no `.key`/`.computed`), which is
    // exactly the right marker: the consumer already treats a `'*'`-keyed
    // destructured binding as a computed-unknown-key selection
    // (`{kind:'member', object: initExpr, prop: '*'}`), and the lineage
    // engine's existing wildcard-selection machinery (built for `obj[k]`)
    // already resolves that correctly — conservatively aggregating the
    // source's full field set, flagged widened. No engine-level change
    // needed for this fix.
    return { kind: 'object-pattern', props: (n.properties || []).map(p => ({
      key: resolveObjectKey(p),
      alias: lhsPath(p.type === 'RestElement' ? p.argument : p.value),
    }))};
  }
  if (n.type === 'ArrayPattern') {
    return { kind: 'array-pattern', elements: (n.elements || []).map(lhsPath) };
  }
  if (n.type === 'AssignmentPattern') return lhsPath(n.left);
  if (n.type === 'RestElement') return lhsPath(n.argument);
  return null;
}

// ── What a module exports (caller-controlled parameters) ─────────────────────
// A library's input arrives as the arguments of the functions it exports, not as `req.body`. collectExports reads the Program body once: ES
// exports (`export function`, `export const f = () =>`, `export default`, `export { a, b }`, exported classes) and CommonJS (`module.exports =
// f | { a, b, c: function () {} }`, `module.exports.a = ...`, `exports.a = ...`). Only the module's own top level is read; a name exported by
// reference marks the top-level function or class of that name. Nothing is inferred from a file name or a package manifest.
const FN_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);
const isModuleExports = (n) => n?.type === 'MemberExpression' && n.object?.type === 'Identifier' && n.object.name === 'module' && !n.computed && n.property?.name === 'exports';
const isExportsTarget = (n) => n?.type === 'MemberExpression' && !n.computed && (isModuleExports(n.object) || (n.object?.type === 'Identifier' && n.object.name === 'exports'));
function collectExports(program, out) {
  const markValue = (v) => {
    if (!v) return;
    if (FN_TYPES.has(v.type)) out.nodes.add(v);
    else if (v.type === 'ClassExpression' || v.type === 'ClassDeclaration') out.classes.add(v);
    else if (v.type === 'Identifier') out.names.add(v.name);
    else if (v.type === 'ObjectExpression') {
      for (const pr of v.properties || []) {
        if (pr.type === 'ObjectMethod') out.nodes.add(pr);
        else if (pr.type === 'ObjectProperty') markValue(pr.value);
      }
    }
  };
  const body = program?.body || [];
  for (const st of body) {
    if (st.type === 'ExportNamedDeclaration') {
      const d = st.declaration;
      if (d?.type === 'FunctionDeclaration') out.nodes.add(d);
      else if (d?.type === 'ClassDeclaration') out.classes.add(d);
      else if (d?.type === 'VariableDeclaration') for (const dc of d.declarations || []) markValue(dc.init);
      if (!st.source) for (const sp of st.specifiers || []) if (sp.local?.type === 'Identifier') out.names.add(sp.local.name);
    } else if (st.type === 'ExportDefaultDeclaration') {
      markValue(st.declaration);
    } else if (st.type === 'ExpressionStatement' && st.expression?.type === 'AssignmentExpression' && st.expression.operator === '=') {
      const { left, right } = st.expression;
      if (isModuleExports(left) || isExportsTarget(left)) markValue(right);
    }
  }
  // names exported by reference resolve to the module's own top-level declarations of that name
  for (const st of body) {
    if (st.type === 'FunctionDeclaration' && st.id && out.names.has(st.id.name)) { st._topLevel = true; out.nodes.add(st); }
    else if (st.type === 'ClassDeclaration' && st.id && out.names.has(st.id.name)) out.classes.add(st);
    else if (st.type === 'VariableDeclaration') {
      for (const dc of st.declarations || []) if (dc.id?.type === 'Identifier' && out.names.has(dc.id.name)) markValue(dc.init?.type === 'Identifier' ? null : dc.init);
    }
  }
}
// A parameter whose declared type cannot carry text (a TypeScript number, boolean, or a function type) is not an injection carrier.
// The same holds for a JSDoc `@param {Function} name` (or `{function(...)}`, an arrow type, `{number}`, `{boolean}`) written on the function, and
// for a TypeScript reference to the global `Function` type or a union every member of which is one of these.
const NON_TEXT_TS = new Set(['TSNumberKeyword', 'TSBooleanKeyword', 'TSFunctionType', 'TSBigIntKeyword', 'TSSymbolKeyword', 'TSVoidKeyword', 'TSNeverKeyword', 'TSConstructorType']);
const nonTextTs = (t) => !!t && (NON_TEXT_TS.has(t.type)
  || (t.type === 'TSTypeReference' && t.typeName?.type === 'Identifier' && /^(?:Function|CallableFunction|NewableFunction)$/.test(t.typeName.name))
  || (t.type === 'TSParenthesizedType' && nonTextTs(t.typeAnnotation))
  || (t.type === 'TSUnionType' && (t.types || []).length > 0 && t.types.every((u) => nonTextTs(u) || u.type === 'TSUndefinedKeyword' || u.type === 'TSNullKeyword') && t.types.some(nonTextTs)));
const NON_TEXT_JSDOC = /^(?:\(?\s*)?(?:Function|function\s*\(.*|\(.*\)\s*=>.*|number|boolean|bigint|symbol|Number|Boolean)(?:\s*\))?$/;
function nonTextJsdoc(type) {
  const parts = String(type || '').replace(/^\s*[?!]/, '').split('|').map((x) => x.trim()).filter((x) => x && !/^(?:null|undefined|void)$/.test(x));
  return parts.length > 0 && parts.every((x) => NON_TEXT_JSDOC.test(x));
}
// `@param {Type} name` tags of the JSDoc block nearest above a function (on the function itself, or on the declaration, export, assignment or
// property that holds it). Returns a Map name -> type text, or null.
function jsdocParamTypes(fnPath) {
  let p = fnPath; let comments = null;
  for (let i = 0; p && i < 4 && !comments; i++, p = p.parentPath) {
    const lc = p.node?.leadingComments;
    if (Array.isArray(lc) && lc.length) { const last = lc[lc.length - 1]; if (last.type === 'CommentBlock' && last.value.startsWith('*')) comments = last.value; }
    if (p.node && /Statement$|Declaration$|^ObjectProperty$|^ObjectMethod$|^ClassMethod$/.test(p.node.type) && p !== fnPath && !comments) break;
  }
  if (!comments) return null;
  const out = new Map();
  // A balanced-brace scan rather than a nested-quantifier pattern: `{function(): {a: string}}` nests.
  for (const tag of comments.matchAll(/@(?:param|arg|argument)\b/g)) {
    let i = tag.index + tag[0].length;
    while (i < comments.length && /\s/.test(comments[i])) i++;
    if (comments[i] !== '{') continue;
    let depth = 0; let j = i;
    for (; j < comments.length; j++) { if (comments[j] === '{') depth++; else if (comments[j] === '}' && --depth === 0) break; }
    if (depth !== 0) continue;
    const name = /^\s+\[?([A-Za-z_$][\w$]*)/.exec(comments.slice(j + 1, j + 200));
    if (name) out.set(name[1], comments.slice(i + 1, j));
  }
  return out.size ? out : null;
}
function callerControllable(ident, jsdocTypes = null) {
  const t = ident.typeAnnotation?.typeAnnotation;
  if (nonTextTs(t)) return false;
  if (jsdocTypes && jsdocTypes.has(ident.name) && nonTextJsdoc(jsdocTypes.get(ident.name))) return false;
  return true;
}

function fnQid(file, scopeName, name, line) {
  // The qualified ID is stable across re-runs of the parser as long as the file
  // path + function scope/name + line don't change.
  return `${file}::${scopeName || 'top'}::${name || 'anon'}@${line}`;
}

// ── Main entry ──────────────────────────────────────────────────────────────
export const JS_MAX_CHARS = 1_500_000;
const _oversize = [];
/** Files parseJsFile refused for size in this process: [{ file, chars }]. */
export function jsOversizeSkips() { return _oversize.slice(); }
export function _resetJsOversizeSkips() { _oversize.length = 0; }
export function parseJsFile(file, code) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) return null;
  // Files above the cap are skipped, and the skip is recorded (`jsOversizeSkips`) so coverage can say so.
  // The cap was 500,000 characters, which silently dropped ordinary application bundles of 0.5 to 1.5 MB
  // (Babel parses a 520 KB editor bundle in about 60 ms); it now matches the module resolver's 1.5 MB.
  if (!code) return null;
  if (code.length > JS_MAX_CHARS) { _oversize.push({ file, chars: code.length }); return null; }
  const functions = [];
  const classes = [];      // one record per class: name, line, bases, fields, fieldTypes (TypeScript annotations and `new X()` in the constructor)

  // Scope stack: each entry is a function being built.
  const stack = [];
  // What the module exports, collected once from the Program body (see collectExports): function and class nodes exported directly, and
  // names exported by reference (`module.exports = { a, b }`, `export { a }`, `exports.a = a`).
  const exportsOf = { nodes: new WeakSet(), names: new Set(), classes: new WeakSet() };
  const isExportedFunction = (node, name) => {
    if (!node || node.type === 'Program') return false;
    if (exportsOf.nodes.has(node)) return true;
    if (node.type === 'ClassMethod') {
      if (node.kind === 'get' || node.kind === 'set' || node.key?.type === 'PrivateName' || node.accessibility === 'private' || node.accessibility === 'protected') return false;
      if (/^_/.test(String(node.key?.name || ''))) return false;
      return exportsOf.classes.has(node._ownerClass);
    }
    return !!name && exportsOf.names.has(name) && node._topLevel === true;
  };
  const enterFn = (name, scopeName, node, params, fnPath = null) => {
    const line = node.loc?.start?.line || 1;
    const exported = isExportedFunction(node, name);
    const jsdocTypes = exported ? jsdocParamTypes(fnPath) : null;
    const serverAction = (exported && exportsOf.useServer === true)
      || ((node?.body?.directives || []).some((d) => d.value?.value === 'use server'));
    const qid = fnQid(file, scopeName, name, line);
    const entryId = nextNodeId();
    const exitId  = nextNodeId();
    const paramAnnotations = [];
    const paramTypes = {};
    // An MCP tool handler: the function literal passed last to `server.tool(name, [description,] schema, handler)` or
    // `server.registerTool(name, config, handler)`. Its first parameter is the tool's arguments, filled by a model acting on untrusted
    // content: the agent-tool trust boundary the catalog already names for `request.params.arguments`. The IR states the fact
    // (`js:mcp-tool-handler`); the catalog decides it is a source. A two-argument `tool(name, handler)` has no schema and its
    // handler receives only the call context, so it is not marked.
    const mcpHandler = (() => {
      const pp = fnPath && fnPath.parentPath;
      const call = pp && pp.node;
      if (!call || call.type !== 'CallExpression' || fnPath.listKey !== 'arguments') return false;
      const callee = call.callee;
      const prop = callee && callee.type === 'MemberExpression' && !callee.computed && callee.property && callee.property.name;
      if (prop !== 'tool' && prop !== 'registerTool') return false;
      const args = call.arguments || [];
      return args.length >= 3 && args[args.length - 1] === node;
    })();
    // tRPC: the resolver handed to .query/.mutation/.subscription on a chain that carries .input(schema) receives { input, ctx }. The IR marks
    // the `input` field of the first parameter (named or destructured); the catalog's js:trpc-procedure-handler source reads it as client input.
    const trpcHandler = (() => {
      const pp = fnPath && fnPath.parentPath;
      const call = pp && pp.node;
      if (!call || call.type !== 'CallExpression' || fnPath.listKey !== 'arguments') return false;
      const callee = call.callee;
      const prop = callee && callee.type === 'MemberExpression' && !callee.computed && callee.property && callee.property.name;
      if (prop !== 'query' && prop !== 'mutation' && prop !== 'subscription') return false;
      if ((call.arguments || []).length !== 1 || call.arguments[0] !== node) return false;
      let cur = callee.object;
      for (let d = 0; cur && d < 12; d++) {
        if (cur.type === 'CallExpression') {
          const c = cur.callee;
          if (c && c.type === 'MemberExpression' && !c.computed && c.property && c.property.name === 'input') return true;
          cur = c && c.type === 'MemberExpression' ? c.object : null;
        } else if (cur.type === 'MemberExpression') cur = cur.object;
        else break;
      }
      return false;
    })();
    const fn = {
      qid, name: name || 'anon', line,
      // Plain strings, per the IR shape contract (ir/CLAUDE.md: "params:
      // ['arg1', 'arg2', ...]") — every other parser (py, cs, rb, cpp, ...)
      // already emits this shape. This one used to emit {name,kind[,props]}
      // objects instead, which every consumer (access-paths.js's
      // isCoveredBy, summaries.js's paramNames.indexOf, entryStateFromCall,
      // the k=2 pass's `new Set(fn.params)`) silently failed to match against
      // — Set/string-equality checks against an object never succeed, so
      // mutated-parameter taint and context-sensitive entry states were both
      // unconditionally inert for every JS/TS function. Nothing in src/
      // reads a param's .kind or .props, so the richer shape bought nothing.
      params: (params || []).map((p, idx) => {
        if (!p) return null;
        // NestJS/Angular-style parameter decorators (@Query(), @Body(), etc.)
        // — Babel attaches these to the raw param node as `p.decorators`
        // (or `p.left.decorators` for a defaulted param, e.g. `@Query() page
        // = 1` — a very common NestJS idiom). This is a real array; every
        // entry must be captured, not just the first, since stacked
        // decorators (@Query() @SomeOtherDecorator() x) are legal and
        // dropping later ones silently loses the source-relevant one.
        //
        // For a defaulted param, `p.type` is 'AssignmentPattern', never
        // 'Identifier' — the identifier that actually carries the decorator
        // and the name lives at `p.left`. The guard below must check THAT
        // resolved node's type, not `p.type` unconditionally, or every
        // defaulted-identifier decorated parameter silently loses its
        // decorator (fix round 1, R14(a) Task 4).
        const resolvedIdent = p.type === 'AssignmentPattern' ? p.left : p;
        const decoratorNodes = p.decorators || (p.left && p.left.decorators) || [];
        for (const d of decoratorNodes) {
          const expr = d.expression;
          const decoratorName = expr?.type === 'CallExpression' ? expr.callee?.name : expr?.name;
          // Only record when the parameter itself resolves to a plain
          // identifier — decorators on destructured params are rare and
          // out of scope for this plan.
          if (decoratorName && resolvedIdent?.type === 'Identifier') {
            paramAnnotations.push({ index: idx, name: resolvedIdent.name, decorator: decoratorName });
          }
        }
        // A parameter of a function the module EXPORTS is supplied by whoever calls the library: the weak caller-controlled source (the same
        // fact the Haskell IR states as `hs:caller-controlled`). The IR states the fact; the catalog decides whether it is a source.
        if (exported && resolvedIdent?.type === 'Identifier' && callerControllable(resolvedIdent, jsdocTypes)) {
          paramAnnotations.push({ index: idx, name: resolvedIdent.name, decorator: 'js:caller-controlled' });
        }
        // Next.js server actions: a function exported from a 'use server' module, or one whose own body starts with the
        // directive, is invoked by the client with arguments it chose (form data, plain values). The IR states the fact;
        // the catalog's `js:server-action` source decides that it is request input.
        if (serverAction && resolvedIdent?.type === 'Identifier' && callerControllable(resolvedIdent)) {
          paramAnnotations.push({ index: idx, name: resolvedIdent.name, decorator: 'js:server-action' });
        }
        if (trpcHandler && idx === 0) {
          const nm = resolvedIdent?.type === 'Identifier' ? resolvedIdent.name : (resolvedIdent?.type === 'ObjectPattern' ? '<obj>' : null);
          if (nm) paramAnnotations.push({ index: idx, name: `${nm}.input`, decorator: 'js:trpc-procedure-handler' });
        }
        if (mcpHandler && idx === 0) {
          // the arguments object, named or destructured (`async ({ city, units }) => ...`: the pattern's bindings read off `<obj>`)
          const mcpName = resolvedIdent?.type === 'Identifier' ? resolvedIdent.name : (resolvedIdent?.type === 'ObjectPattern' ? '<obj>' : null);
          if (mcpName) paramAnnotations.push({ index: idx, name: mcpName, decorator: 'js:mcp-tool-handler' });
        }
        {
          // TypeScript: a parameter's declared class (`svc: ItemService`), for receiver typing (class-hierarchy.js typeOfVar).
          const tIdent = p.type === 'TSParameterProperty' ? p.parameter : resolvedIdent;
          const base = tIdent && tIdent.type === 'AssignmentPattern' ? tIdent.left : tIdent;
          const tname = base && base.type === 'Identifier' ? tsTypeName(base.typeAnnotation) : null;
          if (tname) paramTypes[base.name] = tname;
        }
        if (p.type === 'TSParameterProperty' && p.parameter) { const b = p.parameter.type === 'AssignmentPattern' ? p.parameter.left : p.parameter; if (b && b.type === 'Identifier') return b.name; }
        if (p.type === 'Identifier') return p.name;
        if (p.type === 'ObjectPattern') return '<obj>';
        if (p.type === 'ArrayPattern') return '<arr>';
        if (p.type === 'AssignmentPattern' && p.left?.type === 'Identifier') return p.left.name;
        if (p.type === 'AssignmentPattern' && p.left?.type === 'ObjectPattern') return '<obj>';
        if (p.type === 'AssignmentPattern' && p.left?.type === 'ArrayPattern') return '<arr>';
        if (p.type === 'RestElement' && p.argument?.type === 'Identifier') return p.argument.name;
        return null;
      }).filter(Boolean),
      cfg: { entry: entryId, exit: exitId, nodes: new Map() },
      returns: [],
      calls: [],
      reads: new Map(),
      writes: new Map(),
      file,
      _cursor: entryId, // current node ID — next addNode() links from here
      ...(paramAnnotations.length ? { paramAnnotations } : {}),
      ...(Object.keys(paramTypes).length ? { paramTypes } : {}),
    };
    fn.cfg.nodes.set(entryId, { id: entryId, kind: 'entry', succ: [], pred: [], line });
    fn.cfg.nodes.set(exitId,  { id: exitId,  kind: 'exit',  succ: [], pred: [], line });
    stack.push(fn);
    // A destructured parameter (`async ({ city, units }) => ...`) binds its names off the `<obj>` placeholder the params list carries:
    // `city = <obj>.city`, `{ a: b }` gives `b = <obj>.a`, a rest element takes the whole object. Without these the names were unbound,
    // so a source marked on the parameter (an MCP tool handler's arguments) never reached a use of a field.
    (params || []).forEach((p, idx) => {
      const pat = p && p.type === 'ObjectPattern' ? p : (p && p.type === 'AssignmentPattern' && p.left && p.left.type === 'ObjectPattern' ? p.left : null);
      if (!pat) return;
      const holder = fn.params[idx] === '<obj>' ? '<obj>' : null;
      if (!holder) return;
      for (const prop of pat.properties || []) {
        let target = null, source = null;
        if (prop.type === 'RestElement' && prop.argument && prop.argument.type === 'Identifier') { target = prop.argument.name; source = { kind: 'ident', name: holder }; }
        else if (prop.type === 'ObjectProperty' && prop.key && prop.key.type === 'Identifier') {
          const v = prop.value && prop.value.type === 'AssignmentPattern' ? prop.value.left : prop.value;
          if (v && v.type === 'Identifier') { target = v.name; source = { kind: 'member', object: { kind: 'ident', name: holder }, prop: prop.key.name }; }
        }
        if (!target) continue;
        const nid = nextNodeId();
        addNode(fn, { id: nid, kind: 'assign', target, source, line, succ: [], pred: [] });
      }
    });
    return fn;
  };
  const exitFn = () => {
    const fn = stack.pop();
    if (!fn) return null;
    // Connect cursor → exit.
    linkCfg(fn, fn._cursor, fn.cfg.exit);
    delete fn._cursor;
    functions.push(fn);
    return fn;
  };

  const currentFn = () => stack[stack.length - 1];
  const linkCfg = (fn, from, to) => {
    if (!from || !to || from === to) return;
    const f = fn.cfg.nodes.get(from); const t = fn.cfg.nodes.get(to);
    if (!f || !t) return;
    if (!f.succ.includes(to)) f.succ.push(to);
    if (!t.pred.includes(from)) t.pred.push(from);
  };
  const addNode = (fn, node) => {
    if (!fn) return null;
    fn.cfg.nodes.set(node.id, node);
    linkCfg(fn, fn._cursor, node.id);
    fn._cursor = node.id;
    return node.id;
  };

  // Babel visits an IfStatement's consequent then its alternate as ordinary
  // children of the same enter/exit pair, with no boundary hook between
  // them — so fn._cursor was never reset before the alternate was
  // traversed: the alternate's first node was linked as a successor of the
  // CONSEQUENT's tail (a false predecessor edge corrupting any taint-state
  // reasoning across the join) rather than a true second branch off the
  // condition (also silently dropping the condition's "false" outgoing
  // edge, which made applyPathFeasibility's constant-condition pruning
  // treat the `if` as unconditional and delete its only edge).
  //
  // Called from the generic `Statement` visitor below AND from the top of
  // every handler whose node type can itself be the direct (unbraced) root
  // of an if's alternate (ReturnStatement, ThrowStatement, IfStatement for
  // else-if chains, the loop statements, TryStatement) — Babel merges
  // alias-derived and type-specific visitors for the same node but runs the
  // type-specific one FIRST, so relying on the `Statement` alias alone
  // misses every alternate root that also has its own specific handler.
  // The one-shot flag makes the (redundant, second) `Statement` firing a
  // safe no-op once the type-specific handler already did the reset.
  const maybeResetAtAlternateBoundary = (fn, path) => {
    const parent = path.parentPath && path.parentPath.node;
    if (!parent || parent.type !== 'IfStatement' || parent.alternate !== path.node) return;
    if (path.node._alternateBoundaryHandled) return;
    path.node._alternateBoundaryHandled = true;
    // fn._cursor is still the consequent's tail (or the condition node
    // itself, if the consequent added none) — converge it into the join
    // before abandoning it, then start the alternate from the condition,
    // exactly like the consequent did.
    linkCfg(fn, fn._cursor, parent._asJoin);
    fn._cursor = parent._asCond;
  };

  const recordWrite = (fn, target, source, nodeId) => {
    if (!target || typeof target !== 'string') return;
    if (!fn.writes.has(target)) fn.writes.set(target, []);
    fn.writes.get(target).push({ node: nodeId, source });
  };
  const recordRead = (fn, name, nodeId) => {
    if (!name) return;
    if (!fn.reads.has(name)) fn.reads.set(name, []);
    fn.reads.get(name).push(nodeId);
  };

  // Visitor — Babel plugin shape.
  const plugin = function () {
    return {
      visitor: {
        Program: {
          enter(path) { collectExports(path.node, exportsOf); exportsOf.useServer = (path.node.directives || []).some((d) => d.value?.value === 'use server'); enterFn('<module>', '', path.node, []); },
          exit() { exitFn(); },
        },
        FunctionDeclaration: {
          enter(path) {
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(path.node.id?.name || 'anon', parentName, path.node, path.node.params || [], path);
          },
          exit() { exitFn(); },
        },
        FunctionExpression: {
          enter(path) {
            const parent = path.parent;
            let name = path.node.id?.name;
            if (!name && parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') name = parent.id.name;
            if (!name && parent?.type === 'AssignmentExpression' && parent.left?.type === 'MemberExpression') {
              name = parent.left.property?.name;
            }
            if (!name && parent?.type === 'ObjectProperty' && parent.key) name = parent.key.name || String(parent.key.value);
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(name || 'anon', parentName, path.node, path.node.params || [], path);
          },
          exit() { exitFn(); },
        },
        ArrowFunctionExpression: {
          enter(path) {
            const parent = path.parent;
            let name = null;
            if (parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') name = parent.id.name;
            if (!name && parent?.type === 'AssignmentExpression' && parent.left?.type === 'MemberExpression') {
              name = parent.left.property?.name;
            }
            if (!name && parent?.type === 'ObjectProperty' && parent.key) name = parent.key.name || String(parent.key.value);
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(name || 'anon', parentName, path.node, path.node.params || [], path);
          },
          exit(path) {
            // An arrow with an EXPRESSION body (`(req) => req.query.c`) returns that expression. It has no ReturnStatement, so the function used to
            // record no return at all and every helper written this way was invisible to return-taint summaries. The return node is added on exit so
            // it follows any call nodes the expression contained.
            const fn = currentFn();
            const body = path.node.body;
            if (fn && body && body.type !== 'BlockStatement') {
              const nodeId = nextNodeId();
              addNode(fn, { id: nodeId, kind: 'return', value: exprOf(body), line: body.loc?.start?.line || path.node.loc?.start?.line || 0, succ: [], pred: [] });
              fn.returns.push(nodeId);
              linkCfg(fn, nodeId, fn.cfg.exit);
            }
            exitFn();
          },
        },
        ClassMethod: {
          enter(path) {
            const cls = path.findParent(p => p.isClassDeclaration() || p.isClassExpression())?.node;
            path.node._ownerClass = cls;
            const className = cls?.id?.name || 'anon';
            const methodName = path.node.key?.name || 'anon';
            enterFn(methodName, className, path.node, path.node.params || [], path);
          },
          exit() { exitFn(); },
        },
        ObjectMethod: {
          enter(path) {
            const methodName = path.node.key?.name || 'anon';
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(methodName, parentName, path.node, path.node.params || [], path);
          },
          exit() { exitFn(); },
        },

        // One record per class, read before the TypeScript preset strips the annotations: the class's name and base, its
        // declared fields with their types, constructor parameter properties (`constructor(private readonly svc: Svc)`), and
        // fields the constructor assigns from a typed parameter or a `new X()`. The IR states the facts; class-hierarchy.js
        // types `this.svc` from them. Every class is listed, so callgraph.js's known-class set for the file is complete.
        'ClassDeclaration|ClassExpression'(path) {
          const node = path.node;
          let cname = node.id && node.id.name;
          if (!cname && path.parent && path.parent.type === 'VariableDeclarator' && path.parent.id && path.parent.id.type === 'Identifier') cname = path.parent.id.name;
          if (!cname) return;
          const bases = node.superClass && node.superClass.type === 'Identifier' ? [node.superClass.name] : [];
          const fields = []; const fieldTypes = {};
          const note = (n, t) => { if (!n) return; if (!fields.includes(n)) fields.push(n); if (t && !fieldTypes[n]) fieldTypes[n] = t; };
          for (const m of (node.body && node.body.body) || []) {
            if ((m.type === 'ClassProperty' || m.type === 'ClassPrivateProperty' || m.type === 'PropertyDefinition') && m.key) {
              const n = m.key.type === 'Identifier' ? m.key.name : (m.key.type === 'PrivateName' && m.key.id ? m.key.id.name : null);
              note(n, tsTypeName(m.typeAnnotation) || ctorClassName(m.value));
            }
            if (m.type === 'ClassMethod' && m.kind === 'constructor') {
              const ptypes = {};
              for (const p of m.params || []) {
                const inner = p.type === 'TSParameterProperty' ? p.parameter : p;
                const b = inner && inner.type === 'AssignmentPattern' ? inner.left : inner;
                if (!b || b.type !== 'Identifier') continue;
                const t = tsTypeName(b.typeAnnotation);
                if (t) ptypes[b.name] = t;
                if (p.type === 'TSParameterProperty') note(b.name, t);
              }
              for (const st of (m.body && m.body.body) || []) {
                const e = st.type === 'ExpressionStatement' ? st.expression : null;
                if (!e || e.type !== 'AssignmentExpression' || e.operator !== '=' || !e.left || e.left.type !== 'MemberExpression' || e.left.computed) continue;
                if (!e.left.object || e.left.object.type !== 'ThisExpression' || !e.left.property || e.left.property.type !== 'Identifier') continue;
                const t = ctorClassName(e.right) || (e.right && e.right.type === 'Identifier' ? ptypes[e.right.name] : null) || null;
                note(e.left.property.name, t);
              }
            }
          }
          classes.push({ name: cname, line: node.loc ? node.loc.start.line : 0, bases, fields, ...(Object.keys(fieldTypes).length ? { fieldTypes } : {}) });
        },
        VariableDeclarator(path) {
          const fn = currentFn(); if (!fn) return;
          // PRD R13(b): `for (const item of tainted)` is, structurally, also
          // an ordinary VariableDeclarator (`item`, no `init`) — Babel visits
          // it as a normal child of the ForOfStatement's `left` on the way
          // into the loop body. Left to the general case below, this generic
          // visit fires AFTER the loop visitor's enter() hook synthesizes
          // `item = <iterated expr>`, re-assigning `item` from an absent
          // `init` (source: unknown) and silently erasing the taint just
          // synthesized. Skip it here ONLY for the simple-identifier shape
          // the loop visitor actually owns and synthesizes for — a bare
          // `for (const item of ...)` binding.
          //
          // A destructuring for-of binding (`for (const {a,b} of ...)` /
          // `for (const [a,b] of ...)`) is explicitly NOT covered by the
          // loop visitor's synthesis (see the ForOfStatement branch below —
          // `loopVar` stays null and nothing is emitted for it), so it MUST
          // fall through to the general destructuring handling further down
          // in this same visitor. That handling was already here before this
          // task and does something this guard must not break: it emits real
          // taint-KILL assign nodes for each destructured name, which is what
          // makes `let cmd = tainted; for (const {cmd} of SAFE) sink(cmd)`
          // correctly clear cmd's stale outer taint. An earlier version of
          // this guard matched on the ForOfStatement `left` alone (no
          // Identifier check) and silently deleted those taint-kill nodes,
          // producing a false positive on exactly that shadowing shape — see
          // the regression test below.
          const gpDecl = path.parentPath && path.parentPath.node;
          const gpLoop = path.parentPath && path.parentPath.parentPath && path.parentPath.parentPath.node;
          if (gpLoop && gpLoop.type === 'ForOfStatement' && gpLoop.left === gpDecl
              && path.node.id?.type === 'Identifier') return;
          const id = lhsPath(path.node.id);
          if (!id) return;
          const initExpr = exprOf(path.node.init);
          const line = path.node.loc?.start?.line || 0;
          if (typeof id === 'string') {
            const nodeId = nextNodeId();
            // the declared (`const s: Svc = ...`) or constructed (`const s = new Svc()`) class, for receiver typing
            const dt = (path.node.id && path.node.id.type === 'Identifier' ? tsTypeName(path.node.id.typeAnnotation) : null) || ctorClassName(path.node.init);
            addNode(fn, { id: nodeId, kind: 'assign', target: id, source: initExpr, line, succ: [], pred: [], ...(dt ? { declaredType: dt } : {}) });
            recordWrite(fn, id, initExpr, nodeId);
            return;
          }
          // Destructuring: `const {a, b: renamed} = obj;` / `const [a, b] = arr;`.
          // Emit one REAL 'assign' CFG node per bound name — not just a
          // recordWrite() bookkeeping entry — because the taint engine's
          // step() 'assign' case reads `node.target` directly and requires
          // a plain string (`typeof node.target === 'string'`); the single
          // node this used to emit had target=the whole {kind:'object-
          // pattern'|'array-pattern', ...} OBJECT, which step() always
          // treated as `target=null` — so taint from `obj`/`arr` never
          // reached ANY destructured binding, for every project that uses
          // this extremely common pattern. fn.writes/recordWrite (used
          // below too) is bookkeeping nothing in dataflow/ ever reads;
          // only real CFG nodes matter to the walk.
          if (id && typeof id === 'object' && id.kind === 'object-pattern') {
            for (const p of id.props) {
              const alias = typeof p.alias === 'string' ? p.alias : null;
              if (!alias) continue;
              const memberSrc = { kind: 'member', object: initExpr, prop: p.key };
              const nodeId = nextNodeId();
              addNode(fn, { id: nodeId, kind: 'assign', target: alias, source: memberSrc, line, succ: [], pred: [] });
              recordWrite(fn, alias, memberSrc, nodeId);
            }
            return;
          }
          if (id && typeof id === 'object' && id.kind === 'array-pattern') {
            id.elements.forEach((el, i) => {
              const alias = typeof el === 'string' ? el : null;
              if (!alias) return; // elision (`const [, b] = arr`) or nested pattern — not modeled
              const memberSrc = { kind: 'member', object: initExpr, prop: String(i) };
              const nodeId = nextNodeId();
              addNode(fn, { id: nodeId, kind: 'assign', target: alias, source: memberSrc, line, succ: [], pred: [] });
              recordWrite(fn, alias, memberSrc, nodeId);
            });
          }
        },

        AssignmentExpression(path) {
          const fn = currentFn(); if (!fn) return;
          const id = lhsPath(path.node.left);
          if (!id) return;
          const rhsExpr = exprOf(path.node.right);
          const nodeId = nextNodeId();
          const line = path.node.loc?.start?.line || 0;
          addNode(fn, { id: nodeId, kind: 'assign', target: id, source: rhsExpr, line, succ: [], pred: [] });
          if (typeof id === 'string') recordWrite(fn, id, rhsExpr, nodeId);
        },

        CallExpression(path) {
          const fn = currentFn(); if (!fn) return;
          // Skip if this call is itself the RHS of an assignment we just emitted
          // (the assignment node already references it via its source.kind=='call').
          const parent = path.parent;
          if (parent && (parent.type === 'VariableDeclarator' || parent.type === 'AssignmentExpression')) return;
          const calleeExpr = exprOf(path.node.callee);
          // An inline arrow/function-expression argument (`arr.map(x => ...)`)
          // becomes {kind:'function-value', qid} instead of exprOf's generic
          // {kind:'unknown'} fallback (exprOf has no case for either node
          // type) — dataflow/higher-order.js's calleeIsResolvableCallback and
          // engine.js's higher-order-invocation push site both special-case
          // 'function-value', but nothing ever produced one for JS/TS, so
          // higher-order taint flow only ever worked for a by-reference
          // callback (`arr.map(processItem)`), never the far more common
          // inline-callback shape. The qid is computed to match EXACTLY what
          // this same node's own ArrowFunctionExpression/FunctionExpression
          // visitor (below) will independently compute when Babel's
          // traversal reaches it: for a function literal passed directly as
          // a call argument, none of that visitor's naming heuristics
          // (VariableDeclarator/AssignmentExpression/ObjectProperty parent)
          // match, so it always resolves to name 'anon' scoped under the
          // CURRENT function — exactly what's available here.
          const args = (path.node.arguments || []).map(a => {
            if (a && (a.type === 'ArrowFunctionExpression' || a.type === 'FunctionExpression')) {
              const argLine = a.loc?.start?.line || 1; // matches enterFn's own fallback
              return { kind: 'function-value', qid: fnQid(file, fn.name, 'anon', argLine) };
            }
            return exprOf(a);
          });
          const line = path.node.loc?.start?.line || 0;
          const nodeId = nextNodeId();
          addNode(fn, { id: nodeId, kind: 'call', callee: calleeExpr, args, line, succ: [], pred: [] });
          // Resolve a flat callee name from the expression — used by the cross-file
          // call graph join later.
          const calleeName =
            (calleeExpr.kind === 'ident' && calleeExpr.name) ||
            (calleeExpr.kind === 'member' && calleeExpr.prop && (calleeExpr.object.kind === 'ident' ? `${calleeExpr.object.name}.${calleeExpr.prop}` : calleeExpr.prop)) ||
            null;
          fn.calls.push({ site: nodeId, callee: calleeName, args, line });
        },

        ReturnStatement(path) {
          const fn = currentFn(); if (!fn) return;
          maybeResetAtAlternateBoundary(fn, path);
          const expr = path.node.argument ? exprOf(path.node.argument) : null;
          const nodeId = nextNodeId();
          const line = path.node.loc?.start?.line || 0;
          addNode(fn, { id: nodeId, kind: 'return', value: expr, line, succ: [], pred: [] });
          fn.returns.push(nodeId);
          // Link to exit; subsequent code is unreachable from this branch.
          linkCfg(fn, nodeId, fn.cfg.exit);
        },

        // Fires for every statement node, via Babel's built-in "Statement"
        // alias — the fallback path for whichever concrete type an if's
        // `alternate` turns out to be when that type has no specific
        // handler of its own (BlockStatement, ExpressionStatement,
        // VariableDeclaration, ...). Types that DO have a specific handler
        // below (ReturnStatement, IfStatement, the loop statements,
        // TryStatement) call `maybeResetAtAlternateBoundary` themselves,
        // since Babel runs a node's type-specific visitor BEFORE its
        // alias-derived one for the same node — relying on this alone would
        // miss those cases entirely.
        Statement: {
          enter(path) {
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
          },
        },

        IfStatement: {
          enter(path) {
            // We model branches by inserting a noop "join" after the if; both
            // branches link to it. Without this, the linear cursor model would
            // miss that statements after the if are reachable from either branch.
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
            const condNodeId = nextNodeId();
            const joinId = nextNodeId();
            const line = path.node.loc?.start?.line || 0;
            addNode(fn, { id: condNodeId, kind: 'if', cond: exprOf(path.node.test), line, succ: [], pred: [] });
            fn.cfg.nodes.set(joinId, { id: joinId, kind: 'noop', succ: [], pred: [], line });
            path.node._asJoin = joinId;
            path.node._asCond = condNodeId;
          },
          exit(path) {
            const fn = currentFn(); if (!fn) return;
            const joinId = path.node._asJoin;
            const condId = path.node._asCond;
            if (!joinId || !condId) return;
            // The visitor visited the body of the if — Babel's body visit ran
            // *after* the enter(), so fn._cursor now points to the tail of the
            // consequent (or, thanks to maybeResetAtAlternateBoundary, of the
            // alternate when one exists). Connect it to the join, then if no
            // else branch existed, connect the cond directly to the join
            // (representing the "false" edge).
            linkCfg(fn, fn._cursor, joinId);
            if (!path.node.alternate) linkCfg(fn, condId, joinId);
            fn._cursor = joinId;
          },
        },

        // We don't deeply model loops; treat the body as a sequence and link
        // its tail back to the loop header. For taint, this gives "any
        // iteration could taint X" which is the conservative answer we want.
        'WhileStatement|ForStatement|DoWhileStatement|ForInStatement|ForOfStatement': {
          enter(path) {
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
            const headerId = nextNodeId();
            const exitId = nextNodeId();
            const line = path.node.loc?.start?.line || 0;
            addNode(fn, { id: headerId, kind: 'loop-header', line, succ: [], pred: [] });
            fn.cfg.nodes.set(exitId, { id: exitId, kind: 'noop', succ: [], pred: [], line });
            path.node._loopHeader = headerId;
            path.node._loopExit = exitId;
            // PRD R13(b): for-of's binding variable is never connected to the
            // iterated expression, so `for (const x of tainted) sink(x)` reads
            // x as {kind:'unknown'} — clean. Synthesize an assign binding the
            // loop variable to the iterated expression, exactly as the
            // Python-CST/Go/PHP parsers already do for their own for-each
            // constructs (parser-py.helper.py, parser-go.js, parser-php.js).
            // Conservative, matching this file's own stated doctrine for
            // loops in general ("any iteration could taint X"): the WHOLE
            // loop variable is tainted if the iterable is tainted, not a
            // specific element — element-level precision isn't modeled here
            // any more than it is for the rest of this file's loop handling.
            // Scoped to ForOfStatement only — While/For/DoWhile/ForIn have no
            // "loop variable bound to an iterated collection" shape and must
            // see zero behavior change from this addition.
            if (path.node.type === 'ForOfStatement') {
              const leftNode = path.node.left;
              const declId = leftNode && leftNode.type === 'VariableDeclaration'
                ? leftNode.declarations[0]?.id
                : leftNode;
              // Only the simple `for (const x of ...)` / `for (x of ...)`
              // shape is synthesized. A destructuring binding
              // (`for (const {a,b} of ...)`) has no single flat target name
              // lhsPath-style logic could bind to — left unsynthesized rather
              // than guessed at, matching this codebase's "refuse rather than
              // invent an edge" doctrine elsewhere (see _resolvableCalleeName
              // in dataflow/engine.js for the same principle applied to call
              // resolution).
              const loopVar = declId && declId.type === 'Identifier' ? declId.name : null;
              if (loopVar) {
                const iterExpr = exprOf(path.node.right);
                const bindId = nextNodeId();
                addNode(fn, { id: bindId, kind: 'assign', target: loopVar, source: iterExpr, line, succ: [], pred: [] });
                // `for (const x of ...)` / `for (let x of ...)` declares a
                // BLOCK-SCOPED binding: a same-named `x` outside the loop is a
                // different variable and must be completely unaffected by
                // whatever the loop's `x` held. This engine's taint model has
                // no block scoping, so the synthesized binding above would
                // otherwise flow past the loop's exit and over-taint an outer
                // `x` (proven: `let item='safe'; for (const item of req.body
                // .items){} eval(item)` reported a Code Injection finding that
                // pre-R13(b) code correctly reported as clean — the generic
                // VariableDeclarator visitor used to emit `assign x <-
                // {kind:'unknown'}` here, a taint KILL, and the guard above now
                // suppresses it for exactly this shape). Record the name so
                // exit() can re-emit that kill AFTER the loop, restoring the
                // pre-existing behavior for post-loop reads while keeping the
                // new in-loop taint flow.
                //
                // Deliberately NOT done for the bare-assignment form
                // (`for (x of ...)`, leftNode is not a VariableDeclaration):
                // that binding is not block-scoped, it reuses an existing
                // outer `x`, and its value legitimately survives the loop —
                // killing it there would itself be a regression.
                if (leftNode && leftNode.type === 'VariableDeclaration') {
                  path.node._loopBindVar = loopVar;
                }
              }
            }
          },
          exit(path) {
            const fn = currentFn(); if (!fn) return;
            const headerId = path.node._loopHeader;
            const exitId = path.node._loopExit;
            if (!headerId || !exitId) return;
            linkCfg(fn, fn._cursor, headerId); // back-edge
            linkCfg(fn, headerId, exitId);     // exit edge
            fn._cursor = exitId;
            // See the _loopBindVar comment in enter(): restore the taint KILL
            // that the ForOfStatement VariableDeclarator guard suppresses, so
            // a block-scoped for-of binding's synthesized taint cannot leak
            // past the loop onto a same-named outer variable. Emitted AFTER
            // `fn._cursor = exitId` so it sits on the loop's normal exit path
            // (header -> exit-noop -> kill -> whatever follows the loop) and
            // therefore runs once on the way out — never inside the body, so
            // in-loop taint reachability is unchanged.
            if (path.node._loopBindVar) {
              const killId = nextNodeId();
              addNode(fn, {
                id: killId,
                kind: 'assign',
                target: path.node._loopBindVar,
                source: { kind: 'unknown' },
                line: path.node.loc?.start?.line || 0,
                succ: [],
                pred: [],
              });
            }
          },
        },

        TryStatement: {
          enter(path) {
            const fn = currentFn(); if (!fn) return;
            maybeResetAtAlternateBoundary(fn, path);
            /* approximate try/catch as sequential — taint flows through both */
          },
        },

        ThrowStatement(path) {
          const fn = currentFn(); if (!fn) return;
          maybeResetAtAlternateBoundary(fn, path);
          const expr = exprOf(path.node.argument);
          const nodeId = nextNodeId();
          const line = path.node.loc?.start?.line || 0;
          addNode(fn, { id: nodeId, kind: 'throw', value: expr, line, succ: [], pred: [] });
          linkCfg(fn, nodeId, fn.cfg.exit);
        },
      },
    };
  };

  try {
    babelTransformSync(code, {
      filename: file,
      // Babel 8 removed preset-typescript's .isTSX/.allExtensions. ignoreExtensions
      // is the documented replacement: parse every file with the same TS grammar
      // regardless of extension. JSX stays enabled via preset-react, so .js files
      // containing JSX still parse — which .isTSX/.allExtensions guaranteed before.
      // JSX is not legal in a .ts file, where `<T>expr` is a type assertion; with the React preset on, the angle
      // cast parsed as a JSX element and the whole expression lowered to `unknown`. .js/.jsx/.tsx keep JSX.
      presets: /\.ts$/i.test(file) ? [[presetTypescript, { ignoreExtensions: true }]] : [presetReact, [presetTypescript, { ignoreExtensions: true }]],
      // Decorators are SYNTAX we must accept, never transform — without them the
      // parser rejects the whole file and every finding in it silently disappears.
      // Measured on one real target: 201 JS files unparseable, all decorator-using
      // framework code. 'decorators-legacy' covers the framework and TypeScript
      // parameter forms; 'decoratorAutoAccessors' adds the modern `accessor` field.
      // The modern 'decorators' variant was rejected: it cannot parse TS parameter
      // decorators, so it would trade one blind spot for another.
      parserOpts: { plugins: ['decorators-legacy', 'decoratorAutoAccessors'] },
      plugins: [plugin],
      ast: false, code: false, babelrc: false, configFile: false,
    });
  } catch {
    return null;
  }

  // Convert reads/writes Maps to plain objects for downstream JSON serializability.
  for (const fn of functions) {
    fn.reads = Object.fromEntries(fn.reads);
    fn.writes = Object.fromEntries(fn.writes);
    fn.cfg.nodes = Object.fromEntries(fn.cfg.nodes);
  }
  return { file, functions, ...(classes.length ? { classes } : {}), topLevel: functions.find(f => f.name === '<module>')?.qid || null };
}
