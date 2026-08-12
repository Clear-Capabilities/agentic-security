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

// Compact a Babel AST node into our exprDesc.
function exprOf(n) {
  if (!n) return { kind: 'unknown' };
  switch (n.type) {
    case 'Identifier':       return { kind: 'ident', name: n.name };
    case 'NumericLiteral':
    case 'StringLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':       return { kind: 'literal', value: n.value !== undefined ? n.value : null };
    case 'TemplateLiteral':   return { kind: 'tpl', parts: (n.expressions || []).map(exprOf) };
    case 'MemberExpression':  return {
      kind: 'member',
      object: exprOf(n.object),
      prop: n.computed ? (n.property?.value != null ? String(n.property.value) : '*') : (n.property?.name || '*'),
    };
    case 'CallExpression':
    case 'OptionalCallExpression':
    case 'NewExpression':     return {
      kind: 'call',
      callee: exprOf(n.callee),
      args: (n.arguments || []).map(exprOf),
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
      props: (n.properties || []).filter(p => p.type === 'ObjectProperty' && p.key).map(p => ({
        key: p.key.name || (p.key.value != null ? String(p.key.value) : '*'),
        value: exprOf(p.value),
      })),
    };
    case 'ArrayExpression':   return { kind: 'array', elements: (n.elements || []).map(exprOf) };
    case 'SpreadElement':     return exprOf(n.argument);
    case 'ThisExpression':    return { kind: 'ident', name: '_this_' };
    default:                   return { kind: 'unknown' };
  }
}

// Reduce a Babel LHS node to a string path used as a dataflow variable key.
function lhsPath(n) {
  if (!n) return null;
  if (n.type === 'Identifier') return n.name;
  if (n.type === 'ThisExpression') return '_this_';
  if (n.type === 'MemberExpression') {
    const base = lhsPath(n.object);
    const prop = n.computed ? '*' : (n.property?.name || '*');
    if (!base) return null;
    return base + '.' + prop;
  }
  if (n.type === 'ObjectPattern') {
    // Destructured: return an array of (key, alias) pairs the caller can iterate.
    return { kind: 'object-pattern', props: (n.properties || []).map(p => ({
      key: p.key?.name || (p.key?.value != null ? String(p.key.value) : '*'),
      alias: lhsPath(p.value),
    }))};
  }
  if (n.type === 'ArrayPattern') {
    return { kind: 'array-pattern', elements: (n.elements || []).map(lhsPath) };
  }
  if (n.type === 'AssignmentPattern') return lhsPath(n.left);
  if (n.type === 'RestElement') return lhsPath(n.argument);
  return null;
}

function fnQid(file, scopeName, name, line) {
  // The qualified ID is stable across re-runs of the parser as long as the file
  // path + function scope/name + line don't change.
  return `${file}::${scopeName || 'top'}::${name || 'anon'}@${line}`;
}

// ── Main entry ──────────────────────────────────────────────────────────────
export function parseJsFile(file, code) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) return null;
  if (!code || code.length > 500_000) return null;
  const functions = [];

  // Scope stack: each entry is a function being built.
  const stack = [];
  const enterFn = (name, scopeName, node, params) => {
    const line = node.loc?.start?.line || 1;
    const qid = fnQid(file, scopeName, name, line);
    const entryId = nextNodeId();
    const exitId  = nextNodeId();
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
      params: (params || []).map(p => {
        if (!p) return null;
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
    };
    fn.cfg.nodes.set(entryId, { id: entryId, kind: 'entry', succ: [], pred: [], line });
    fn.cfg.nodes.set(exitId,  { id: exitId,  kind: 'exit',  succ: [], pred: [], line });
    stack.push(fn);
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
          enter(path) { enterFn('<module>', '', path.node, []); },
          exit() { exitFn(); },
        },
        FunctionDeclaration: {
          enter(path) {
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(path.node.id?.name || 'anon', parentName, path.node, path.node.params || []);
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
            enterFn(name || 'anon', parentName, path.node, path.node.params || []);
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
            enterFn(name || 'anon', parentName, path.node, path.node.params || []);
          },
          exit() { exitFn(); },
        },
        ClassMethod: {
          enter(path) {
            const cls = path.findParent(p => p.isClassDeclaration() || p.isClassExpression())?.node;
            const className = cls?.id?.name || 'anon';
            const methodName = path.node.key?.name || 'anon';
            enterFn(methodName, className, path.node, path.node.params || []);
          },
          exit() { exitFn(); },
        },
        ObjectMethod: {
          enter(path) {
            const methodName = path.node.key?.name || 'anon';
            const parentName = stack[stack.length - 1]?.name || '';
            enterFn(methodName, parentName, path.node, path.node.params || []);
          },
          exit() { exitFn(); },
        },

        VariableDeclarator(path) {
          const fn = currentFn(); if (!fn) return;
          const id = lhsPath(path.node.id);
          if (!id) return;
          const initExpr = exprOf(path.node.init);
          const nodeId = nextNodeId();
          const line = path.node.loc?.start?.line || 0;
          addNode(fn, { id: nodeId, kind: 'assign', target: id, source: initExpr, line, succ: [], pred: [] });
          if (typeof id === 'string') recordWrite(fn, id, initExpr, nodeId);
          if (id && typeof id === 'object' && id.kind === 'object-pattern') {
            // x = { foo: a, bar: b } — emit one write per property.
            for (const p of id.props) {
              const alias = typeof p.alias === 'string' ? p.alias : null;
              if (!alias) continue;
              recordWrite(fn, alias, { kind: 'member', object: initExpr, prop: p.key }, nodeId);
            }
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
          },
          exit(path) {
            const fn = currentFn(); if (!fn) return;
            const headerId = path.node._loopHeader;
            const exitId = path.node._loopExit;
            if (!headerId || !exitId) return;
            linkCfg(fn, fn._cursor, headerId); // back-edge
            linkCfg(fn, headerId, exitId);     // exit edge
            fn._cursor = exitId;
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
      presets: [presetReact, [presetTypescript, { ignoreExtensions: true }]],
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
  return { file, functions, topLevel: functions.find(f => f.name === '<module>')?.qid || null };
}
