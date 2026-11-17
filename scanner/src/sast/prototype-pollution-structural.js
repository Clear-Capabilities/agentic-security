// Prototype pollution in a key-walking function, independent of where the keys come from (CWE-1321).
//
// prototype-pollution.js needs request input next to a merge or set call, so a LIBRARY's deep-extend or set-by-path utility, whose keys
// arrive as its caller's arguments, never qualifies. Those utilities are where this class is actually published (a deep extend, a
// setValueAtPath, a form-data objectizer). This rule reads the function's syntax tree instead:
//
//   key variable   the loop variable of `for (k in o)`, of `for (k of Object.keys(o) | Object.entries(o) | s.split(..) | parts)`, the key
//                  parameter of `Object.keys(o).forEach(k => ..)` / `parts.forEach(k => ..)` / `parts.reduce((acc, k) => ..)`, or the last
//                  segment `parts[parts.length - 1]` / `parts.pop()` of a split path (`parts` is a variable assigned from `.split(..)`).
//   walk           the function descends with that key (`cur = cur[k]`, or a reduce callback returning `acc[k]`), or calls itself with a
//                  value indexed by it (`extend(deep, clone, copy)` after `copy = options[k]`, or `merge(t[k], s[k])`).
//   write          `x[k] = value` with a key variable.
//
// A function with a walk and a write is reported at the write, unless the function guards the keys: it names `__proto__`, `constructor`
// or `prototype` as a string, checks own properties (`hasOwnProperty`, `Object.hasOwn`, `hasOwn.call`), builds with
// `Object.create(null)` or a `Map`, or freezes the prototype. Those are the fixes the real advisories shipped, so a fixed function is
// silent. The rule says nothing about whether a caller can reach the function with an attacker's keys; the finding states that.
import { parseSync } from '@babel/core';
import presetReact from '@babel/preset-react';
import presetTypescript from '@babel/preset-typescript';

const FILE_RE = /\.(?:m?[jt]sx?|cjs)$/i;
// a key compared with a prototype key, or a list or set of them (`k === '__proto__'`, `['__proto__', 'constructor'].includes(k)`)
const PROTO_KEY_TEST = /(?:[!=]==?\s*['"`](?:__proto__|constructor|prototype)['"`])|(?:['"`](?:__proto__|constructor|prototype)['"`]\s*[!=]==?)|(?:\[\s*['"`](?:__proto__|constructor|prototype)['"`]\s*,)/;
const GUARD_RE = /(?:[!=]==?\s*['"`](?:__proto__|constructor|prototype)['"`])|(?:['"`](?:__proto__|constructor|prototype)['"`]\s*[!=]==?)|(?:\[\s*['"`](?:__proto__|constructor|prototype)['"`]\s*,)|\bhasOwnProperty\b|\bObject\.hasOwn\b|\bhasOwn\.call\b|\bObject\.create\(\s*null\s*\)|\bnew\s+Map\b|Object\.freeze\(\s*Object\.prototype|\bisSafeKey\b|\bisUnsafeKey\b/;
const FN_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod']);

function parse(file, code) {
  try {
    return parseSync(code, {
      filename: file, sourceType: 'unambiguous', babelrc: false, configFile: false,
      presets: [presetReact, [presetTypescript, { ignoreExtensions: true }]],
      parserOpts: { plugins: ['decorators-legacy', 'decoratorAutoAccessors'], errorRecovery: true },
    });
  } catch { return null; }
}

/** Visit every node under `node`, not descending into nested functions when `stopAtFunctions`. */
function walk(node, visit, stopAtFunctions, root = node) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const n of node) walk(n, visit, stopAtFunctions, root); return; }
  if (typeof node.type !== 'string') return;
  if (node !== root && stopAtFunctions && FN_TYPES.has(node.type) && !node._inlineCallback) return;
  visit(node);
  for (const k of Object.keys(node)) {
    if (k === 'loc' || k === 'start' || k === 'end' || k === 'leadingComments' || k === 'trailingComments' || k === 'innerComments' || k === 'extra') continue;
    const v = node[k];
    if (v && typeof v === 'object') walk(v, visit, stopAtFunctions, root);
  }
}

const isCall = (n, name) => n?.type === 'CallExpression' && n.callee?.type === 'MemberExpression' && !n.callee.computed && n.callee.property?.name === name;
const isObjectKeys = (n) => n?.type === 'CallExpression' && n.callee?.type === 'MemberExpression' && n.callee.object?.type === 'Identifier' && n.callee.object.name === 'Object' && ['keys', 'entries', 'getOwnPropertyNames'].includes(n.callee.property?.name);
const idName = (n) => (n?.type === 'Identifier' ? n.name : null);
const fnName = (fn, parent) => fn.id?.name || (parent?.type === 'VariableDeclarator' ? idName(parent.id) : null) || (fn.key ? idName(fn.key) : null);

/** The key variables of one function body (callbacks passed to forEach/reduce on a key list are treated as part of it). */
function keyVariables(fn) {
  const keys = new Set(); const splitVars = new Set(); const listVars = new Set();
  const iterates = new Map(); // key variable -> the object whose own keys it walks (for..in o, Object.keys(o))
  const boundAt = new Map(); // key variable -> the line where it enters (the loop header, the callback, the split or pop)
  const iteratedOf = (n) => (isObjectKeys(n) ? idName(n.arguments[0]) : null);
  const listish = (n) => isObjectKeys(n) || isCall(n, 'split') || (n?.type === 'Identifier' && (splitVars.has(n.name) || listVars.has(n.name)))
    || (isCall(n, 'slice') && listish(n.callee.object)) || (isCall(n, 'filter') && listish(n.callee.object)) || (isCall(n, 'map') && listish(n.callee.object));
  const bindLeft = (left, over, line) => {
    const decl = left?.type === 'VariableDeclaration' ? left.declarations[0]?.id : left;
    const name = decl?.type === 'Identifier' ? decl.name : decl?.type === 'ArrayPattern' && decl.elements[0]?.type === 'Identifier' ? decl.elements[0].name : null;
    if (!name) return;
    keys.add(name);
    if (over) iterates.set(name, over);
    if (line && !boundAt.has(name)) boundAt.set(name, line);
  };
  // two passes, so a list variable declared after its first use in source order is still known
  for (let pass = 0; pass < 2; pass++) {
    walk(fn.body, (n) => {
      if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier') {
        if (isCall(n.init, 'split') || (n.init?.type === 'TSAsExpression' && isCall(n.init.expression, 'split'))) { splitVars.add(n.id.name); if (!boundAt.has(n.id.name)) boundAt.set(n.id.name, n.loc?.start?.line); }
        else if (isObjectKeys(n.init) || (n.init && listish(n.init))) listVars.add(n.id.name);
        // the last segment of a split path
        const i = n.init;
        // the last segment enters with the split it came from
        if (i?.type === 'MemberExpression' && i.computed && idName(i.object) && splitVars.has(i.object.name)) { keys.add(n.id.name); boundAt.set(n.id.name, boundAt.get(i.object.name) || n.loc?.start?.line); }
        if (isCall(i, 'pop') && idName(i.callee.object) && splitVars.has(i.callee.object.name)) { keys.add(n.id.name); boundAt.set(n.id.name, boundAt.get(i.callee.object.name) || n.loc?.start?.line); }
      }
      if (n.type === 'ForInStatement') bindLeft(n.left, idName(n.right), n.loc?.start?.line);
      if (n.type === 'ForOfStatement' && listish(n.right)) bindLeft(n.left, iteratedOf(n.right), n.loc?.start?.line);
      if (n.type === 'CallExpression' && n.callee?.type === 'MemberExpression' && ['forEach', 'reduce', 'some', 'every', 'map'].includes(n.callee.property?.name) && listish(n.callee.object)) {
        const cb = n.arguments[0];
        if (cb && FN_TYPES.has(cb.type)) {
          cb._inlineCallback = true;
          const p = cb.params[n.callee.property.name === 'reduce' ? 1 : 0];
          bindLeft(p, iteratedOf(n.callee.object), n.loc?.start?.line);
        }
      }
    }, true);
  }
  keys.iterates = iterates; keys.boundAt = boundAt; keys.splitVars = splitVars;
  return keys;
}

function analyseFunction(fn, parent, code, guardNames) {
  const text = code.slice(fn.start, fn.end);
  if (GUARD_RE.test(text)) return null;
  // a module-level helper or constant that names the prototype keys (`UNSAFE_KEYS.has(k)`, `check_prototype_pollution(k)`) guards too
  for (const g of guardNames) if (new RegExp(`\\b${g.replace(/\$/g, '\\$')}\\b`).test(text)) return null;
  const keys = keyVariables(fn);
  if (!keys.size) return null;
  const self = fnName(fn, parent);
  const splitVars = new Set();
  walk(fn.body, (n) => { if (n.type === 'VariableDeclarator' && idName(n.id) && (isCall(n.init, 'split') || (n.init?.type === 'TSAsExpression' && isCall(n.init.expression, 'split')))) splitVars.add(n.id.name); }, true);
  // a key is a key variable, or the last segment of a split path written inline (`parts[parts.length - 1]`)
  const isKey = (p) => (p?.type === 'Identifier' && keys.has(p.name)) || (p?.type === 'MemberExpression' && p.computed && idName(p.object) && splitVars.has(p.object.name));
  const keyed = (m) => m?.type === 'MemberExpression' && m.computed && isKey(m.property);
  // a variable initialised to a fresh object or array literal and never reassigned: writing into it changes that object only
  const fresh = new Set(); const reassigned = new Set();
  walk(fn.body, (n) => {
    if (n.type === 'VariableDeclarator' && idName(n.id) && ['ObjectExpression', 'ArrayExpression'].includes(n.init?.type)) fresh.add(n.id.name);
    if (n.type === 'AssignmentExpression' && idName(n.left)) reassigned.add(n.left.name);
  }, true);
  const intoFresh = (m) => idName(m.object) && fresh.has(m.object.name) && !reassigned.has(m.object.name);
  // writing an object back under one of its OWN keys (for k of Object.keys(o): o[k] = ..) changes no prototype
  const inPlace = (m) => idName(m.object) && m.property?.type === 'Identifier' && keys.iterates.get(m.property.name) === m.object.name;
  const indexedByKey = new Set(); // variables assigned `x = o[k]`
  let walkFound = false; let write = null;
  walk(fn.body, (n) => {
    if (n.type === 'AssignmentExpression' && n.operator === '=') {
      if (keyed(n.left) && !intoFresh(n.left) && !inPlace(n.left) && !write) write = n;
      // descend: cur = cur[k]
      if (n.left.type === 'Identifier' && keyed(n.right) && idName(n.right.object) === n.left.name) walkFound = true;
      if (n.left.type === 'Identifier' && keyed(n.right)) indexedByKey.add(n.left.name);
    }
    if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier' && keyed(n.init)) indexedByKey.add(n.id.name);
    // reduce((acc, k) => acc[k] ...) returning the indexed value descends too
    if (n.type === 'ReturnStatement' && keyed(n.argument)) walkFound = true;
    if (n.type === 'ArrowFunctionExpression' && n._inlineCallback && (keyed(n.body) || (n.body?.type === 'LogicalExpression' && keyed(n.body.left)) || (n.body?.type === 'AssignmentExpression' && keyed(n.body.left)))) walkFound = true;
  }, true);
  // recursion with a key-indexed value: merge(t[k], s[k]) or extend(deep, clone, copy) where copy = options[k]
  if (!walkFound && self) {
    walk(fn.body, (n) => {
      if (n.type === 'CallExpression' && idName(n.callee) === self && n.arguments.some((a) => keyed(a) || (a.type === 'Identifier' && indexedByKey.has(a.name)))) walkFound = true;
    }, true);
  }
  if (!walkFound || !write) return null;
  // reported where the key ENTERS (the loop header, the callback, the split): that is where the guard belongs; the write is named
  const k = write.left.property;
  const enters = k.type === 'Identifier' ? keys.boundAt.get(k.name) : keys.boundAt.get(k.object?.name);
  const writeLine = write.loc?.start?.line || fn.loc?.start?.line || 1;
  return { line: enters || writeLine, writeLine, name: self || 'anonymous function' };
}

export function scanPrototypePollutionStructural(file, code) {
  if (!FILE_RE.test(file) || !code || code.length > 400_000) return [];
  // cheap gate: a computed write with an identifier key must appear somewhere
  if (!/\]\s*=[^=]/.test(code) || !/\bfor\s*\(|\.forEach\(|\.reduce\(|\.split\(/.test(code)) return [];
  const ast = parse(file, code);
  if (!ast) return [];
  const out = []; const seen = new Set();
  // module-level functions and constants whose text names a prototype key: a function that uses one is guarded
  const guardNames = [];
  for (const st of ast.program.body) {
    const d = st.type === 'ExportNamedDeclaration' ? st.declaration : st;
    if (d?.type === 'FunctionDeclaration' && d.id && PROTO_KEY_TEST.test(code.slice(d.start, d.end))) guardNames.push(d.id.name);
    if (d?.type === 'VariableDeclaration') for (const dc of d.declarations) if (idName(dc.id) && dc.init && PROTO_KEY_TEST.test(code.slice(dc.init.start, dc.init.end))) guardNames.push(dc.id.name);
  }
  const visitFns = (node, parent) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { for (const n of node) visitFns(n, parent); return; }
    if (typeof node.type !== 'string') return;
    if (FN_TYPES.has(node.type) && !node._inlineCallback) {
      const r = analyseFunction(node, parent, code, guardNames);
      if (r && !seen.has(r.line)) {
        seen.add(r.line);
        out.push({
          id: `prototype-pollution-walk:${file}:${r.line}`,
          file, line: r.line,
          vuln: 'Prototype Pollution: key walk with no prototype-key guard',
          severity: 'high',
          cwe: 'CWE-1321',
          family: 'prototype-pollution',
          stride: 'Tampering',
          description: `${r.name} walks into an object by keys it is given (a key loop, a split path, or recursion) and writes with one of those keys at line ${r.writeLine}, without refusing \`__proto__\`, \`constructor\` or \`prototype\`. Reported where the key enters, which is where the refusal belongs. A caller that passes such a key changes Object.prototype for the whole process. Whether an attacker can reach this function with their keys is not checked here.`,
          remediation: 'Refuse the three prototype keys before writing (`if (key === "__proto__" || key === "constructor" || key === "prototype") continue;`), or only walk own properties (`Object.hasOwn`), or build the result on `Object.create(null)` or a `Map`.',
          snippet: (code.split('\n')[r.line - 1] || '').trim().slice(0, 200),
          parser: 'PROTO-POLLUTION',
          confidence: 0.6,
        });
      }
    }
    for (const k of Object.keys(node)) {
      if (k === 'loc' || k === 'start' || k === 'end' || k.endsWith('Comments') || k === 'extra') continue;
      const v = node[k];
      if (v && typeof v === 'object') visitFns(v, node);
    }
  };
  visitFns(ast.program, null);
  return out;
}
