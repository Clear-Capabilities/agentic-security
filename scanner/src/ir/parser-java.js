// Java IR frontend (P2.3).
//
// Converts the java-parser AST into our unified IR shape. The dataflow
// engine consumes the same node kinds as the JS frontend (assign / call /
// return / if / loop-header / throw / entry / exit / noop).
//
// v1 scope:
//   - Method declarations → IR functions with CFG
//   - Field declarations → top-level assigns
//   - Local variable declarations + assignments → assign nodes
//   - Method invocations → call nodes
//   - Return / throw / if-else / while / for → corresponding IR nodes
//   - Try / catch → exception-flow scaffolding (P3.4 will model)
//   - Lambdas → captured as function-value (P1.3 helpers consume)
//
// Out of scope for v1: generics resolution, annotation introspection beyond
// shallow name capture, varargs unpacking, switch expressions.
//
// The implementation is line-aware: java-parser produces an exhaustive CST,
// which we walk to extract just the dataflow-relevant nodes. v1 is
// conservative — we recover what we can, and fall back to a single noop
// when the shape is unfamiliar.

import { blankComments } from '../sast/_comment-strip.js';

let _nodeIdSeq = 0;
function nextNodeId() { return 'jn' + (++_nodeIdSeq); }

let _javaParser = null;
async function _loadJavaParser() {
  if (_javaParser) return _javaParser;
  try {
    const mod = await import('java-parser');
    _javaParser = mod.parse || mod.default;
    return _javaParser;
  } catch {
    return null;
  }
}

/**
 * Walk a java-parser CST node and emit our exprDesc shape.
 */
function exprFromCst(node) {
  if (!node) return { kind: 'unknown' };
  if (Array.isArray(node)) {
    return node.length === 1 ? exprFromCst(node[0]) : { kind: 'unknown' };
  }
  if (node.image) {
    // Token leaf — number, string, ident.
    const img = node.image;
    if (/^['"]/.test(img)) return { kind: 'literal', value: img };
    if (/^-?\d/.test(img)) return { kind: 'literal', value: Number(img) || img };
    if (/^(?:true|false|null)$/.test(img)) return { kind: 'literal', value: img };
    return { kind: 'ident', name: img };
  }
  if (node.children) {
    // CST node with named children — recurse into the most informative one.
    // Method invocation
    if (node.children.methodInvocation) return _methodInvocation(node.children.methodInvocation[0]);
    // `primary` is how java-parser actually models a call: the name lives in
    // primaryPrefix (an fqnOrRefType) and the invocation itself in
    // primarySuffix.methodInvocationSuffix. Without this branch the fall-through
    // below recursed into the prefix and returned the NAME — so
    // `req.getParameter("q")` lowered to a member access, never a call, and no
    // source or sink in the Java catalog could ever match.
    if (node.children.primaryPrefix) {
      const prefix = node.children.primaryPrefix[0];
      const suffixes = node.children.primarySuffix || [];
      const invocation = suffixes
        .map(s => s.children?.methodInvocationSuffix?.[0])
        .find(Boolean);
      if (invocation) {
        const fqn = prefix?.children?.fqnOrRefType?.[0];
        const callee = fqn ? _flattenFqnToString(fqn) : 'unknown';
        const args = (invocation.children?.argumentList?.[0]?.children?.expression || [])
          .map(exprFromCst);
        return { kind: 'call', callee, args };
      }
      return exprFromCst(prefix);
    }
    // FQN ref
    if (node.children.fqnOrRefType) return _fqnExpr(node.children.fqnOrRefType[0]);
    if (node.children.unqualifiedClassInstanceCreationExpression) {
      const ci = node.children.unqualifiedClassInstanceCreationExpression[0];
      const callee = (ci.children?.classOrInterfaceTypeToInstantiate?.[0]?.children?.Identifier?.[0]?.image) || 'new';
      return { kind: 'call', callee, isNew: true, args: [] };
    }
    if (node.children.literal) return exprFromCst(node.children.literal[0]);
    if (node.children.Identifier) return { kind: 'ident', name: node.children.Identifier[0].image };
    // Binary expression
    if (node.children.BinaryOperator || node.children.binaryExpression) {
      // Best-effort: take the two operands.
      const kids = node.children.unaryExpression || node.children.expression || [];
      if (kids.length >= 2) {
        return {
          kind: 'binary',
          op: '?',
          left: exprFromCst(kids[0]),
          right: exprFromCst(kids[1]),
        };
      }
    }
    // Fall through: recurse the first child
    for (const k of Object.keys(node.children)) {
      const arr = node.children[k];
      if (Array.isArray(arr) && arr.length) return exprFromCst(arr[0]);
    }
  }
  return { kind: 'unknown' };
}

/**
 * The identifier images of an `fqnOrRefType`, in order.
 *
 * java-parser does NOT put `Identifier` directly on `fqnOrRefType`. The real
 * shape is fqnOrRefTypePartFirst / fqnOrRefTypePartRest → fqnOrRefTypePartCommon
 * → Identifier, so reading `children.Identifier` returned nothing for every
 * real-world expression and both callers below degraded to 'unknown'. The
 * direct-Identifier form is still accepted as a fallback.
 */
function _fqnIdents(node) {
  if (!node || !node.children) return [];
  const direct = node.children.Identifier;
  if (Array.isArray(direct) && direct.length) return direct.map(t => t.image);
  const out = [];
  const parts = [
    ...(node.children.fqnOrRefTypePartFirst || []),
    ...(node.children.fqnOrRefTypePartRest || []),
  ];
  for (const p of parts) {
    const common = p.children?.fqnOrRefTypePartCommon?.[0];
    const id = common?.children?.Identifier?.[0]?.image;
    if (id) out.push(id);
  }
  return out;
}

function _fqnExpr(node) {
  if (!node || !node.children) return { kind: 'unknown' };
  const idImages = _fqnIdents(node);
  if (!idImages.length) return { kind: 'unknown' };
  const ids = idImages.map(image => ({ image }));
  let cur = { kind: 'ident', name: ids[0].image };
  for (let i = 1; i < ids.length; i++) {
    cur = { kind: 'member', object: cur, prop: ids[i].image };
  }
  return cur;
}

function _methodInvocation(node) {
  // node.children typically: fqnOrRefType (callee) + argumentList (args).
  const callee = node.children?.fqnOrRefType
    ? _flattenFqnToString(node.children.fqnOrRefType[0])
    : (node.children?.Identifier?.[0]?.image || 'unknown');
  const args = [];
  if (node.children?.argumentList) {
    const al = node.children.argumentList[0];
    if (al && al.children?.expression) {
      for (const e of al.children.expression) args.push(exprFromCst(e));
    }
  }
  return { kind: 'call', callee, args };
}

function _flattenFqnToString(node) {
  const ids = _fqnIdents(node);
  return ids.length ? ids.join('.') : 'unknown';
}

// Descend to the first leaf token in a CST subtree and return its
// startLine. java-parser (chevrotain) leaf tokens carry startLine directly;
// rule nodes only carry `children`. Returns 0 when nothing is found (e.g.
// an empty node), which callers already treat as "unknown".
function _lineOf(node) {
  if (!node) return 0;
  if (Array.isArray(node)) {
    for (const n of node) { const l = _lineOf(n); if (l) return l; }
    return 0;
  }
  if (typeof node.startLine === 'number') return node.startLine;
  if (node.children) {
    for (const k of Object.keys(node.children)) {
      const l = _lineOf(node.children[k]);
      if (l) return l;
    }
  }
  return 0;
}

/**
 * Build a function's CFG from its method-body CST.
 *
 * v1: a simple sequential walk — every statement becomes one IR node,
 * connected linearly. Branches (`if/else`, `while`, `for`) emit an
 * `if` / `loop-header` node and the body falls through linearly. This is
 * coarser than the JS frontend; v2 will branch the succ array.
 */
function buildCfgFromBody(bodyNode) {
  const nodes = {};
  const entry = nextNodeId();
  const exit = nextNodeId();
  nodes[entry] = { id: entry, kind: 'entry', succ: [] };
  nodes[exit] = { id: exit, kind: 'exit', succ: [] };
  let prev = entry;

  function emit(node) {
    const id = nextNodeId();
    node.id = id;
    nodes[id] = node;
    if (nodes[prev]) {
      nodes[prev].succ = nodes[prev].succ || [];
      nodes[prev].succ.push(id);
    }
    prev = id;
    return id;
  }

  walkStmts(bodyNode);

  function walkStmts(stmtNode) {
    if (!stmtNode || !stmtNode.children) return;
    const kids = stmtNode.children;
    // java-parser nests a `block` as block → blockStatements (PLURAL, an
    // intermediate rule node) → blockStatement. Walking only `blockStatement`
    // from the block node therefore descended into nothing and every method
    // body lowered to an empty CFG — which is why Java had IR functions with
    // entry/exit and no statements, and taint could never fire.
    if (kids.blockStatements) {
      for (const bss of kids.blockStatements) walkStmts(bss);
    }
    // Block statement children
    if (kids.blockStatement) {
      for (const bs of kids.blockStatement) walkStmts(bs);
    }
    if (kids.localVariableDeclarationStatement) {
      for (const lv of kids.localVariableDeclarationStatement) {
        const vdecl = lv.children?.localVariableDeclaration?.[0];
        const declarators = vdecl?.children?.variableDeclaratorList?.[0]?.children?.variableDeclarator;
        if (declarators) {
          for (const d of declarators) {
            const target = d.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
            const initExpr = d.children?.variableInitializer?.[0]?.children?.expression?.[0];
            if (target) {
              emit({ kind: 'assign', target, source: initExpr ? exprFromCst(initExpr) : { kind: 'unknown' }, line: _lineOf(lv), succ: [] });
            }
          }
        }
      }
    }
    if (kids.statement) {
      for (const s of kids.statement) walkStmts(s);
    }
    if (kids.statementWithoutTrailingSubstatement) {
      for (const s of kids.statementWithoutTrailingSubstatement) walkStmts(s);
    }
    if (kids.expressionStatement) {
      const e = kids.expressionStatement[0]?.children?.statementExpression?.[0]?.children?.expression?.[0];
      if (e) {
        const expr = exprFromCst(e);
        if (expr.kind === 'call') emit({ ...expr, line: _lineOf(kids.expressionStatement[0]), succ: [] });
        else if (expr.kind === 'binary' && expr.op === '=') {
          // assignment expr `x = y;`
          emit({ kind: 'assign', target: expr.left?.name || null, source: expr.right, line: _lineOf(kids.expressionStatement[0]), succ: [] });
        }
      }
    }
    if (kids.returnStatement) {
      const r = kids.returnStatement[0];
      const expr = r.children?.expression?.[0];
      emit({ kind: 'return', value: expr ? exprFromCst(expr) : null, line: _lineOf(r), succ: [] });
    }
    if (kids.throwStatement) {
      const t = kids.throwStatement[0];
      const expr = t.children?.expression?.[0];
      emit({ kind: 'throw', value: expr ? exprFromCst(expr) : null, line: _lineOf(t), succ: [] });
    }
    if (kids.ifStatement) {
      const i = kids.ifStatement[0];
      const cond = i.children?.expression?.[0];
      emit({ kind: 'if', cond: cond ? exprFromCst(cond) : null, line: _lineOf(i), succ: [] });
      // Then branch body falls through linearly; v1 simplification.
      for (const sub of (i.children?.statement || [])) walkStmts(sub);
    }
    if (kids.whileStatement) {
      const w = kids.whileStatement[0];
      const cond = w.children?.expression?.[0];
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(w), succ: [] });
      for (const sub of (w.children?.statement || [])) walkStmts(sub);
    }
  }

  if (nodes[prev]) {
    nodes[prev].succ = nodes[prev].succ || [];
    nodes[prev].succ.push(exit);
  }
  return { entry, exit, nodes };
}

/**
 * Top-level: parse one .java file. Returns the perFileIR shape (same as
 * parser-js.js). Returns null when java-parser is unavailable OR the
 * file fails to parse.
 *
 * Async because we lazy-import java-parser.
 */
export async function parseJavaFile(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return null;
  if (!/\.java$/i.test(file)) return null;
  if (raw.length > 1_000_000) return null;
  const parser = await _loadJavaParser();
  if (!parser) return null;

  let cst;
  try { cst = parser(raw); } catch { return null; }
  if (!cst) return null;

  const functions = [];
  // Walk the CST for methodDeclaration nodes.
  function walkForMethods(node, className) {
    if (!node || !node.children) return;
    for (const k of Object.keys(node.children)) {
      const arr = node.children[k];
      if (!Array.isArray(arr)) continue;
      for (const child of arr) {
        if (k === 'classDeclaration' || k === 'normalClassDeclaration') {
          const newClassName = child.children?.typeIdentifier?.[0]?.children?.Identifier?.[0]?.image
            || child.children?.Identifier?.[0]?.image
            || className;
          walkForMethods(child, newClassName);
          continue;
        }
        if (k === 'methodDeclaration' || k === 'methodHeader') {
          const md = child;
          const name = md.children?.methodHeader?.[0]?.children?.methodDeclarator?.[0]?.children?.Identifier?.[0]?.image
            || md.children?.methodDeclarator?.[0]?.children?.Identifier?.[0]?.image
            || 'anonymous';
          const params = []; // params extraction deferred
          const body = md.children?.methodBody?.[0]?.children?.block?.[0];
          if (body) {
            const methodLine = _lineOf(md);
            functions.push({
              // Sibling frontends (parser-js.js) suffix the qid with `@line`
              // so overloaded/same-named methods don't collide — without it,
              // callgraph.js's `functions.set(fn.qid, fn)` silently drops
              // every overload but the last one declared.
              qid: `${file}::${className || 'class'}::${name}@${methodLine}`,
              name: className ? `${className}.${name}` : name,
              line: methodLine,
              params,
              cfg: buildCfgFromBody(body),
              file,
            });
          }
        }
        walkForMethods(child, className);
      }
    }
  }
  walkForMethods(cst, null);

  return { file, functions, topLevel: null };
}
