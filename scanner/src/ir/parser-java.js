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
import { callSitesFromCfg } from './call-sites.js';

let _nodeIdSeq = 0;
function nextNodeId() { return 'jn' + (++_nodeIdSeq); }

let _javaParser = null;
async function _loadJavaParser() {
  if (_javaParser) return _javaParser;
  try {
    const mod = await import('#java-parser');
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
    // Assignment: java-parser models `x = y` (and `x += y`) as a
    // binaryExpression whose children are {unaryExpression (LHS),
    // AssignmentOperator, expression (RHS)}. There is no BinaryOperator
    // token, so this shape previously fell through to the generic
    // "recurse the first child" branch and lowered to the LHS alone: every
    // expression-statement assignment in a method body vanished from the CFG.
    if (node.children.AssignmentOperator) {
      const op = node.children.AssignmentOperator[0]?.image || '=';
      const lhs = node.children.unaryExpression?.[0];
      const rhs = node.children.expression?.[0];
      return { kind: 'binary', op, left: exprFromCst(lhs), right: exprFromCst(rhs) };
    }
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
      // Taint-recall PRD (80%): java-parser models a CHAIN
      // (`X().Y().Z(tainted)`) as ONE primary node with a FLAT array of
      // primarySuffix entries — each is EITHER a methodInvocationSuffix
      // (a `(...)` call) OR a {Dot, Identifier} member-access pair, in
      // source order. The old code used `.find(Boolean)` to grab the
      // FIRST methodInvocationSuffix in the whole array and stopped there
      // — for `DocumentBuilderFactory.newInstance().newDocumentBuilder()
      // .parse(s)` this returned just the `newInstance()` call with
      // args: [], silently dropping `.newDocumentBuilder().parse(s)`
      // entirely (confirmed via a real corpus fixture; the same shape
      // also explains the earlier-documented, never-fixed
      // `Runtime.getRuntime().exec(...)` gap). Now walks every suffix in
      // order, building the callee name from member-access suffixes and,
      // at each invocation suffix, folding that call's args into the
      // running result — outermost-first (the LATEST call's own args are
      // prepended), same convention as _followChain in the other 5
      // hand-rolled parsers, so an existing `argIndex: 0` catalog entry
      // keyed to the outermost call is unaffected while `argIndex: 'all'`
      // can still find taint an inner call in the chain carried.
      let chainCallee = '';
      let chainArgs = null;
      const fqn = prefix?.children?.fqnOrRefType?.[0];
      // Taint-recall PRD (80%): a `new X(args)` CONSTRUCTOR starting the
      // chain (`new URL(url).openStream()`) is a DIFFERENT CST shape than
      // an fqnOrRefType prefix — `prefix.children.fqnOrRefType` is absent,
      // so `fqn` above is undefined and, before this fix, BOTH the
      // constructor's own class name AND its own arguments were silently
      // dropped: `chainCallee` stayed empty and the suffix walk below only
      // ever contributes the CHAINED method's name, producing a callee
      // like bare "openStream" with the constructor's tainted argument
      // nowhere in the IR at all — not misattributed, genuinely absent, a
      // strictly worse failure than the terminal-segment-shift class this
      // PRD fixes elsewhere with a receiver-scoped catalog entry (there is
      // no catalog fix possible for taint the IR never represents).
      // Confirmed via a real corpus fixture (CVE-2019-3799-spring-ssrf-
      // shape). The actual CST path is one level deeper than the analogous
      // fqnOrRefType check above: `primaryPrefix.children.newExpression[0]
      // .children.unqualifiedClassInstanceCreationExpression[0]` — found by
      // dumping `prefix.children` directly rather than guessing (the
      // standalone, NON-chained `new X(args)` branch further below reaches
      // `unqualifiedClassInstanceCreationExpression` straight off `node`,
      // one level shallower, which is what made the wrapping `newExpression`
      // layer easy to miss here). Seeds `chainCallee` with the class name
      // and `chainArgs` with the constructor's OWN args (same
      // argumentList.expression shape that standalone branch already
      // extracts) — the suffix loop's existing `chainArgs === null ? args :
      // args.concat(chainArgs)` then correctly prepends each chained call's
      // own args ahead of the constructor's, preserving the outermost-first
      // convention.
      const ctorPrefix = prefix?.children?.newExpression?.[0]?.children?.unqualifiedClassInstanceCreationExpression?.[0];
      // `(new X(args)).m(a)`: the parenthesized-constructor form Juliet's
      // multi-file flow variants use for every cross-class sink call. The
      // prefix is a parenthesisExpression wrapping the constructor, so
      // neither the fqn nor the ctorPrefix branch below sees it and the
      // chain used to lower to a bare `m` with the class name dropped.
      // Seed the chain from the inner lowered constructor exactly like the
      // direct `new X().m()` form so callgraph.js's `Class.method` index
      // can resolve it.
      const parenInner = prefix?.children?.parenthesisExpression?.[0]?.children?.expression?.[0];
      let parenExpr = null;
      // Tracks whether the chain so far is STILL exactly the bare
      // constructor call with no method invoked on the result yet — cleared
      // the moment the suffix loop below consumes a real
      // methodInvocationSuffix. Only in that still-true state does the
      // eventual return carry `isNew: true`, matching class-hierarchy.js's
      // `typeOfVar` contract (`b.action(data)` for `A_81_base b = new
      // A_81_bad();` needs the RHS lowered with isNew so allocation-typed
      // dispatch can resolve `b`'s declared type); `(new B()).badSink(x)`
      // must NOT carry it, since the resulting call IS `B.badSink`, not a
      // constructor.
      let isCtorSeed = false;
      if (fqn) {
        chainCallee = _flattenFqnToString(fqn);
      } else if (ctorPrefix) {
        chainCallee = _ctorClassName(ctorPrefix);
        chainArgs = (ctorPrefix.children?.argumentList?.[0]?.children?.expression || []).map(exprFromCst);
        isCtorSeed = true;
      } else if (parenInner) {
        parenExpr = exprFromCst(parenInner);
        if (parenExpr.kind === 'call' && parenExpr.isNew) {
          chainCallee = parenExpr.callee;
          chainArgs = parenExpr.args || [];
          isCtorSeed = true;
        } else if (!suffixes.length) {
          return parenExpr;
        } else {
          // `(a + b).toString()`: no textual receiver name exists. Carry the
          // inner expression as an extra argument so its taint still reaches
          // the chained call (recall-preserving, mirrors receiver-taint).
          chainArgs = [parenExpr];
        }
      }
      // No FQN/constructor prefix — e.g. `this.foo(x)`, `super.foo(x)`
      // (prefix is a keyword expression). chainCallee starts empty; the
      // walk below supplies the real name from the first member-access
      // suffix.
      let pendingName = [];
      const appendPending = () => {
        if (!pendingName.length) return;
        chainCallee = chainCallee ? `${chainCallee}.${pendingName.join('.')}` : pendingName.join('.');
        pendingName = [];
      };
      for (const suf of suffixes) {
        const inv = suf.children?.methodInvocationSuffix?.[0];
        if (inv) {
          appendPending();
          const args = (inv.children?.argumentList?.[0]?.children?.expression || []).map(exprFromCst);
          chainArgs = chainArgs === null ? args : args.concat(chainArgs);
          isCtorSeed = false; // a real method is now being invoked on the constructed object
          continue;
        }
        const ident = suf.children?.Identifier?.[0]?.image;
        if (ident) { pendingName.push(ident); isCtorSeed = false; }
      }
      if (chainArgs !== null) {
        appendPending(); // a trailing member access after the last call (e.g. a field read)
        return { kind: 'call', callee: chainCallee || 'unknown', args: chainArgs, ...(isCtorSeed ? { isNew: true } : {}) };
      }
      // No call anywhere in the chain: a plain member read such as
      // `this.inst` or `obj.field` (an fqn prefix already lowers to a member
      // chain on its own; this covers the `this`/`super`/parenthesized
      // prefix shapes whose member suffixes were previously discarded).
      if (pendingName.length) {
        let cur = parenExpr || exprFromCst(prefix);
        for (const p of pendingName) cur = { kind: 'member', object: cur, prop: p };
        return cur;
      }
      return parenExpr || exprFromCst(prefix);
    }
    if (node.children.parenthesisExpression) {
      const inner = node.children.parenthesisExpression[0]?.children?.expression?.[0];
      if (inner) return exprFromCst(inner);
    }
    // Taint-recall PRD (80%): a cast expression — `(String) xp.evaluate(...)`,
    // `(int) computeVal(x)` — was falling through to the generic "recurse the
    // first child" branch below, which for a castExpression's shape hits its
    // own `primaryPrefix.children.castExpression` sub-node with no dedicated
    // branch, and beneath THAT the raw `LBrace`/`LParen` token sorts first in
    // key order — silently corrupting the parse into `{kind:'ident',
    // name:'('}` and losing the entire operand (the actual call, and
    // whatever tainted argument it carried). Confirmed via a real corpus
    // fixture (CVE-2018-1320-xpath-injection). Casts are semantically
    // transparent for taint purposes — unwrap to the operand, reference-type
    // (`(String) x` → unaryExpressionNotPlusMinus) or primitive
    // (`(int) x` → unaryExpression) shaped.
    if (node.children.castExpression) {
      const ce = node.children.castExpression[0];
      const rtc = ce.children?.referenceTypeCastExpression?.[0];
      const pc = ce.children?.primitiveCastExpression?.[0];
      const operand = rtc?.children?.unaryExpressionNotPlusMinus?.[0]
        || pc?.children?.unaryExpression?.[0];
      if (operand) return exprFromCst(operand);
    }
    // FQN ref
    if (node.children.fqnOrRefType) return _fqnExpr(node.children.fqnOrRefType[0]);
    if (node.children.unqualifiedClassInstanceCreationExpression) {
      const ci = node.children.unqualifiedClassInstanceCreationExpression[0];
      const callee = _ctorClassName(ci) || 'new';
      // Taint-recall PRD (80%): args was hardcoded to [] — every
      // `new X(arg1, arg2)` constructor call lowered with its arguments
      // silently discarded, so a sink modeled as a constructor call
      // (argIndex-based) could never see a tainted constructor argument
      // regardless of catalog correctness. Same argumentList.expression
      // shape the methodInvocationSuffix branch above already extracts
      // from. Confirmed via a real corpus fixture
      // (`new ByteArrayInputStream(xml)` feeding `b.parse(...)`).
      const args = (ci.children?.argumentList?.[0]?.children?.expression || [])
        .map(exprFromCst);
      return { kind: 'call', callee, isNew: true, args };
    }
    if (node.children.literal) return exprFromCst(node.children.literal[0]);
    if (node.children.Identifier) return { kind: 'ident', name: node.children.Identifier[0].image };
    // Binary expression
    if (node.children.BinaryOperator || node.children.binaryExpression) {
      // Found via the independent-holdout fixture microledger (SARD_80_F1_
      // SCANNER_PRD.md P1 item 6): this branch hardcoded `op: '?'` for EVERY
      // binary expression, regardless of the real operator, and only ever
      // took the first two operands — chevrotain's `binaryExpression`
      // production for a chain like `"a" + query + "b"` is FLAT (one node
      // listing all 3 operands and both `+` tokens), not a nested binary
      // tree, so a 3+-operand chain silently dropped every operand past the
      // second AND mislabeled the operator on top of that.
      //
      // Neither defect was independently harmless: a taint value sitting in
      // the THIRD (or later) operand of a concatenation was invisible to the
      // taint walker regardless of the operator bug, and a real corpus
      // fixture with exactly this shape (`"<div>..." + query + "</div>"`,
      // one `sink(a + tainted + b)` call) lost its finding entirely — not
      // merely mislabeled. `node.children.BinaryOperator` is chevrotain's own
      // token array for this production; `.image` is the literal operator
      // text (confirmed via direct CST inspection this session — `+`, not a
      // synthesized value). Left-folds all operands with their real
      // operators, matching left-to-right evaluation order; the `|| '+'`
      // fallback only matters if a future java-parser version ever changes
      // this shape so operator/operand counts disagree, and `+` is the
      // overwhelmingly dominant real-world case for this production
      // (string concatenation), so it is the safer of two bad guesses.
      const kids = node.children.unaryExpression || node.children.expression || [];
      const ops = (node.children.BinaryOperator || []).map(t => t.image);
      if (kids.length >= 2) {
        let result = exprFromCst(kids[0]);
        for (let i = 1; i < kids.length; i++) {
          result = { kind: 'binary', op: ops[i - 1] || '+', left: result, right: exprFromCst(kids[i]) };
        }
        return result;
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

const _ASSIGN_OPS = new Set(['=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '>>>=']);
function _isAssignment(expr) {
  return !!expr && expr.kind === 'binary' && _ASSIGN_OPS.has(expr.op);
}

// Dotted access-path string for a member chain rooted at an identifier or
// `this`; null when the chain is rooted at something with no name (a call
// result, a literal).
function _memberPath(expr) {
  if (!expr) return null;
  if (expr.kind === 'ident') return expr.name;
  if (expr.kind === 'member') {
    const base = _memberPath(expr.object);
    return base ? `${base}.${expr.prop}` : null;
  }
  return null;
}

// Targets for one lowered assignment LHS. See emitAssignment for why a
// field write yields a bare alias alongside its qualified path.
function _assignTargets(left) {
  const path = _memberPath(left);
  if (!path) return [];
  if (!path.includes('.')) return [path];
  const segs = path.split('.');
  const out = [path];
  if (segs.length === 2 && (segs[0] === 'this' || /^[A-Z]/.test(segs[0]))) out.push(segs[1]);
  return out;
}

// { name, line, bases, fields } for one class/interface declaration node.
// `classType` (extends) and each `interfaceType` (implements) both bottom
// out at a plain `Identifier` array — a fully-qualified supertype
// (`extends java.util.AbstractList`) yields multiple Identifier tokens, of
// which only the LAST is the actual type name, matching `_ctorClassName`'s
// same convention. Field names come from every `fieldDeclaration`'s
// `variableDeclaratorList` directly under `classBody` — one declaration can
// name several comma-separated fields (`private String inst, other;`).
function _classRecord(node, name) {
  const bases = [];
  const extendsIds = node.children?.classExtends?.[0]?.children?.classType?.[0]?.children?.Identifier;
  if (Array.isArray(extendsIds) && extendsIds.length) bases.push(extendsIds[extendsIds.length - 1].image);
  const interfaceTypes = node.children?.classImplements?.[0]?.children?.interfaceTypeList?.[0]?.children?.interfaceType || [];
  for (const it of interfaceTypes) {
    const ids = it.children?.classType?.[0]?.children?.Identifier;
    if (Array.isArray(ids) && ids.length) bases.push(ids[ids.length - 1].image);
  }
  const fields = [];
  const classBody = node.children?.classBody?.[0];
  for (const cbd of classBody?.children?.classBodyDeclaration || []) {
    const fd = cbd.children?.classMemberDeclaration?.[0]?.children?.fieldDeclaration?.[0];
    const declarators = fd?.children?.variableDeclaratorList?.[0]?.children?.variableDeclarator || [];
    for (const d of declarators) {
      const fname = d.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
      if (fname) fields.push(fname);
    }
  }
  return { name, line: _lineOf(node), bases, fields };
}

// The simple class name of a `new X(...)` expression. A fully-qualified
// instantiation (`new java.util.LinkedList<String>()`) carries one Identifier
// token per package segment plus the class, so taking the FIRST token
// yielded "java"; the class is always the LAST segment, and type arguments
// live under a separate typeArgumentsOrDiamond child that is simply not
// consulted.
// Ported from parser-cs.js's identical mechanism (see its own header comment
// for the full rationale). Closes Juliet's dominant abstract/interface
// dispatch idiom (flow variants 81/82): `A_81_base b = new A_81_bad();
// b.action(data);` lowers `b.action`'s callee to the local-variable-named
// string `"b.action"`, which `callgraph.js`'s `classMethods` index (keyed by
// real class name, `"A_81_bad.action"`) can never match. Since a variable's
// constructed type is unambiguous within one function (once assigned via a
// `{kind:'call', isNew:true}` source — see emitAssignment/isCtorSeed above),
// rewriting `b.action` to `A_81_bad.action` in place lets the EXISTING
// project-wide `classMethods` index resolve it with no engine changes.
// Refuses to guess when a variable is (re)assigned two distinct constructed
// types in the same function, matching this file's own `bareTailInFile`
// ambiguity-refusal convention elsewhere.
function _localVarConstructedTypes(nodes) {
  const varTypes = new Map(); // varName -> className | null (ambiguous)
  for (const node of Object.values(nodes)) {
    if (node.kind !== 'assign') continue;
    const src = node.source;
    if (!src || src.kind !== 'call' || !src.isNew || typeof src.callee !== 'string') continue;
    const varName = node.target;
    if (!varName || varName.includes('.')) continue; // only a bare local, never a field-write target
    if (varTypes.has(varName)) {
      if (varTypes.get(varName) !== src.callee) varTypes.set(varName, null);
    } else {
      varTypes.set(varName, src.callee);
    }
  }
  return varTypes;
}

function _rewriteVarTypeCallees(expr, varTypes) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    if (typeof expr.callee === 'string') {
      const dot = expr.callee.indexOf('.');
      if (dot > 0) {
        const varName = expr.callee.slice(0, dot);
        const cls = varTypes.get(varName);
        if (cls) expr.callee = `${cls}${expr.callee.slice(dot)}`;
      }
    }
    if (Array.isArray(expr.args)) for (const a of expr.args) _rewriteVarTypeCallees(a, varTypes);
    return;
  }
  if (expr.kind === 'member') { _rewriteVarTypeCallees(expr.object, varTypes); return; }
  if (expr.kind === 'binary' || expr.kind === 'logical') {
    _rewriteVarTypeCallees(expr.left, varTypes); _rewriteVarTypeCallees(expr.right, varTypes); return;
  }
  if (expr.kind === 'tpl' && Array.isArray(expr.parts)) { for (const p of expr.parts) _rewriteVarTypeCallees(p, varTypes); return; }
  if (expr.kind === 'union' && Array.isArray(expr.branches)) { for (const b of expr.branches) _rewriteVarTypeCallees(b, varTypes); return; }
  if (expr.kind === 'array' && Array.isArray(expr.elements)) { for (const e of expr.elements) _rewriteVarTypeCallees(e, varTypes); return; }
}

function _applyVarTypeRewrite(nodes) {
  const varTypes = _localVarConstructedTypes(nodes);
  let any = false;
  for (const t of varTypes.values()) if (t) { any = true; break; }
  if (!any) return;
  for (const node of Object.values(nodes)) {
    if (node.kind === 'call') _rewriteVarTypeCallees(node, varTypes);
    else if (node.kind === 'assign') _rewriteVarTypeCallees(node.source, varTypes);
    else if (node.kind === 'return' || node.kind === 'throw') _rewriteVarTypeCallees(node.value, varTypes);
    else if (node.kind === 'if') _rewriteVarTypeCallees(node.cond, varTypes);
  }
}

// The simple class name of a `new X(...)` expression.
function _ctorClassName(ci) {
  const ids = ci?.children?.classOrInterfaceTypeToInstantiate?.[0]?.children?.Identifier;
  if (!Array.isArray(ids) || !ids.length) return '';
  return ids[ids.length - 1].image || '';
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

  // Lower one assignment expression (already through exprFromCst) to CFG
  // assign node(s). A compound operator (`+=`) reads the target too, so its
  // source is a tpl of [target, rhs], the same shape string interpolation
  // lowers to. Field writes emit a bare alias next to the qualified target:
  // `this.f = v` is read back as `f` elsewhere in the class, and a
  // class-qualified static (`A.sf = v`) is read back as `sf`. An array
  // element write taints the whole array (its read lowers to the array
  // identifier, so the element-level path would never match).
  function emitAssignment(expr, line) {
    const targets = _assignTargets(expr.left);
    if (!targets.length) return;
    const source = expr.op === '='
      ? expr.right
      : { kind: 'tpl', parts: [expr.left, expr.right] };
    for (const target of targets) emit({ kind: 'assign', target, source, line, succ: [] });
  }

  // `while ((line = r.readLine()) != null)` and the if-form: the assignment
  // lives inside the condition expression, not in a statement of its own.
  // Emit every assignment nested in the condition subtree ahead of the
  // header node so the bound variable carries the call's taint into the
  // body.
  function emitCondAssignments(condCst, line) {
    if (!condCst || typeof condCst !== 'object') return;
    if (condCst.children?.AssignmentOperator) {
      const expr = exprFromCst(condCst);
      if (_isAssignment(expr)) emitAssignment(expr, line);
      return;
    }
    for (const k of Object.keys(condCst.children || {})) {
      for (const c of condCst.children[k]) emitCondAssignments(c, line);
    }
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
              emit({ kind: 'assign', target, source: initExpr ? exprFromCst(initExpr) : { kind: 'unknown' }, line: _lineOf(lv), succ: [], decl: true });
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
        const line = _lineOf(kids.expressionStatement[0]);
        if (expr.kind === 'call') emit({ ...expr, line, succ: [] });
        else if (_isAssignment(expr)) emitAssignment(expr, line);
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
      emitCondAssignments(cond, _lineOf(i));
      emit({ kind: 'if', cond: cond ? exprFromCst(cond) : null, line: _lineOf(i), succ: [] });
      // Then branch body falls through linearly; v1 simplification.
      for (const sub of (i.children?.statement || [])) walkStmts(sub);
    }
    if (kids.whileStatement) {
      const w = kids.whileStatement[0];
      const cond = w.children?.expression?.[0];
      emitCondAssignments(cond, _lineOf(w));
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(w), succ: [] });
      for (const sub of (w.children?.statement || [])) walkStmts(sub);
    }
    if (kids.forStatement) {
      const f = kids.forStatement[0];
      // Both basicForStatement (`for(init;test;step)`) and
      // enhancedForStatement (`for(T x : xs)`) wrap a `statement` child for
      // the loop body — same shape whileStatement already walks. Confirmed
      // via direct java-parser CST inspection (java-parser@3.0.1): each
      // forStatement's `children` has exactly one of these two keys, never
      // both, and each carries `statement` directly.
      const basic = f.children?.basicForStatement?.[0];
      const enhanced = f.children?.enhancedForStatement?.[0];
      const inner = basic || enhanced;
      const cond = basic?.children?.expression?.[0];
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(f), succ: [] });
      // R8 Task 1 fix round 1: `for (T x : xs)` never bound `x` to `xs` —
      // the loop body was reachable (the fix above) but the loop variable
      // itself carried no taint provenance, so a genuinely tainted
      // collection reaching a sink through the loop variable still
      // couldn't fire. Confirmed via direct CST inspection:
      // enhancedForStatement.children = {..., localVariableDeclaration,
      // Colon, expression, ..., statement} — `localVariableDeclaration` is
      // the loop var's declaration (same variableDeclaratorList shape used
      // elsewhere in this file) and `expression` is the iterated
      // collection. Mirrors the established pattern in parser-js.js's
      // ForOfStatement handling (PRD R13(b)): synthesize
      // `{kind:'assign', target: loopVar, source: iterExpr}` BEFORE
      // recursing into the body, so any body statement reading the loop
      // variable sees its taint provenance already established. Java's
      // for-each always declares a fresh block-scoped variable (there is
      // no bare-assignment form the way JS's `for (x of xs)` has), so —
      // unlike parser-js.js — there is no pre-existing outer variable of
      // the same name to protect with a post-loop kill; the Java CFG
      // builder does not model block scoping elsewhere either, so adding
      // one only for this binding would be new, inconsistent behavior
      // rather than a fix for this gap.
      if (enhanced) {
        const lvd = enhanced.children?.localVariableDeclaration?.[0];
        const declarator = lvd?.children?.variableDeclaratorList?.[0]?.children?.variableDeclarator?.[0];
        const loopVar = declarator?.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
        const iterExpr = enhanced.children?.expression?.[0];
        if (loopVar) {
          emit({ kind: 'assign', target: loopVar, source: iterExpr ? exprFromCst(iterExpr) : { kind: 'unknown' }, line: _lineOf(enhanced), succ: [] });
        }
      }
      for (const sub of (inner?.children?.statement || [])) walkStmts(sub);
    }
    if (kids.doStatement) {
      const d = kids.doStatement[0];
      const cond = d.children?.expression?.[0];
      emitCondAssignments(cond, _lineOf(d));
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(d), succ: [] });
      for (const sub of (d.children?.statement || [])) walkStmts(sub);
    }
    if (kids.tryStatement) {
      const t = kids.tryStatement[0];
      emit({ kind: 'noop', line: _lineOf(t), succ: [] });
      // Plain `try { ... }` has direct `block`/`catches`/`finally` children.
      // Try-with-resources (`try (Resource r = ...) { ... }` — the idiomatic
      // JDBC shape) wraps in a distinct `tryWithResourcesStatement`
      // intermediate node, and — confirmed via direct CST inspection, this
      // is the one place the plan's illustrative code was wrong — that
      // intermediate node carries its OWN `block`/`catches`/`finally`
      // children; a plain tryStatement's outer `children` is just
      // `{ tryWithResourcesStatement: [...] }` with nothing else, so
      // reading `catches`/`finally` off the outer `t` (as the plan's draft
      // did) silently drops the catch/finally bodies of every
      // try-with-resources block. `container` below picks the node that
      // actually owns them.
      const twr = t.children?.tryWithResourcesStatement?.[0];
      const container = twr || t;
      if (twr) {
        const resSpec = twr.children?.resourceSpecification?.[0];
        // resourceSpecification -> resourceList -> resource[] -> each a
        // localVariableDeclaration-shaped resource; reuse the existing
        // localVariableDeclarationStatement lowering shape directly rather
        // than duplicating it, by walking each resource as if it were one.
        const resources = resSpec?.children?.resourceList?.[0]?.children?.resource || [];
        for (const r of resources) {
          const vdecl = r.children?.localVariableDeclaration?.[0] || r;
          const declarators = vdecl?.children?.variableDeclaratorList?.[0]?.children?.variableDeclarator || [];
          for (const d of declarators) {
            const target = d.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
            const initExpr = d.children?.variableInitializer?.[0]?.children?.expression?.[0] || d.children?.expression?.[0];
            if (target) emit({ kind: 'assign', target, source: initExpr ? exprFromCst(initExpr) : { kind: 'unknown' }, line: _lineOf(r), succ: [] });
          }
        }
      }
      const bodyBlock = container.children?.block?.[0];
      if (bodyBlock) walkStmts(bodyBlock);
      const catches = container.children?.catches?.[0]?.children?.catchClause || [];
      for (const cc of catches) {
        const cblock = cc.children?.block?.[0];
        if (cblock) walkStmts(cblock);
      }
      // Confirmed via direct CST inspection: the key is `finally`, no
      // trailing underscore, in both the plain and try-with-resources
      // shapes (java-parser@3.0.1).
      const fin = container.children?.finally?.[0];
      const finBlock = fin?.children?.block?.[0];
      if (finBlock) walkStmts(finBlock);
    }
    if (kids.switchStatement) {
      const sw = kids.switchStatement[0];
      const cond = sw.children?.expression?.[0];
      emit({ kind: 'if', cond: cond ? exprFromCst(cond) : null, line: _lineOf(sw), succ: [] });
      const swBlock = sw.children?.switchBlock?.[0];
      // Classic colon-form (`case 1: ...; break;`).
      const groups = swBlock?.children?.switchBlockStatementGroup || [];
      for (const g of groups) {
        const bss = g.children?.blockStatements?.[0];
        if (bss) walkStmts(bss);
      }
      // R8 Task 1 fix round 1: arrow-form (`case 1 -> ...;`, Java 14+) is a
      // structurally distinct grammar rule — confirmed via direct CST
      // inspection (java-parser@3.0.1) — not an alternate reading of
      // switchBlockStatementGroup. A switchBlock's children carry EITHER
      // switchBlockStatementGroup (colon-form) OR switchRule (arrow-form),
      // never both (Java's grammar forbids mixing them in one switch
      // block), so this is a separate, independent branch rather than a
      // fallback path. Each switchRule carries exactly one body-shape key:
      // `expression` (`case 1 -> sink(x);`), `block`
      // (`case 1 -> { ...; }`), or `throwStatement`
      // (`case 1 -> throw new X();`). Before this fix arrow-form switches
      // fell through this whole branch producing zero walked statements —
      // confirmed 0 IR-TAINT findings for the idiomatic modern-Java shape.
      const rules = swBlock?.children?.switchRule || [];
      for (const r of rules) {
        const rblock = r.children?.block?.[0];
        if (rblock) { walkStmts(rblock); continue; }
        const rthrow = r.children?.throwStatement?.[0];
        if (rthrow) {
          const texpr = rthrow.children?.expression?.[0];
          emit({ kind: 'throw', value: texpr ? exprFromCst(texpr) : null, line: _lineOf(rthrow), succ: [] });
          continue;
        }
        const rexpr = r.children?.expression?.[0];
        if (rexpr) {
          const expr = exprFromCst(rexpr);
          if (expr.kind === 'call') emit({ ...expr, line: _lineOf(r), succ: [] });
          else if (expr.kind === 'binary' && expr.op === '=') {
            emit({ kind: 'assign', target: expr.left?.name || null, source: expr.right, line: _lineOf(r), succ: [] });
          }
        }
      }
    }
    // Bare nested block `{ ... }` with no leading keyword. The
    // `statementWithoutTrailingSubstatement` branch above already recurses
    // into each such node via walkStmts; confirmed via direct CST
    // inspection that a bare block lands as
    // `statementWithoutTrailingSubstatement[0].children.block[0]`, so this
    // branch — which fires for any node with a `block` child, not just
    // this one — picks it up on the recursive call without a dedicated
    // bare-block branch.
    if (kids.block) {
      for (const b of kids.block) walkStmts(b);
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
  // Class records for class-hierarchy analysis: `bases` (extends + all
  // implements names) feeds abstract/interface-receiver dispatch (Juliet
  // flow variants 81/82 — `A_81_base b = new A_81_bad(); b.action(data)`
  // needs to know A_81_bad extends A_81_base to resolve the call), `fields`
  // (instance and static declared names) lets cross-method taint tell a
  // field write (`sf = data;`, live across the whole class) apart from an
  // unrelated local variable of the same name in another method. Same
  // optional per-file shape `parser-cpp.js` already attaches.
  const classes = [];
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
          if (newClassName) classes.push(_classRecord(child, newClassName));
          walkForMethods(child, newClassName);
          continue;
        }
        if (k === 'methodDeclaration' || k === 'methodHeader') {
          const md = child;
          const name = md.children?.methodHeader?.[0]?.children?.methodDeclarator?.[0]?.children?.Identifier?.[0]?.image
            || md.children?.methodDeclarator?.[0]?.children?.Identifier?.[0]?.image
            || 'anonymous';
          // Parameter list + annotations live in the same CST subtree, so
          // both are extracted in one walk (PRD R14(a) Task 5). Mirrors the
          // dual-path fallback pattern used above for `name`: depending on
          // which `k` matched in the outer loop, the params live nested
          // under a `methodHeader` node OR directly under `methodDeclarator`.
          const fpl = md.children?.methodHeader?.[0]?.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0]
            || md.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0];
          const paramAnnotations = [];
          const params = (fpl?.children?.formalParameter || []).map((fp, idx) => {
            // Regular parameters nest under `variableParaRegularParameter`.
            // Varargs (`String... args`) instead use a distinct
            // `variableArityParameter` node that this walk doesn't extract
            // from — `vp` is undefined, so this degrades gracefully to a
            // dropped (not corrupted/crashed) parameter, matching the
            // codebase's existing "degrade gracefully rather than throw"
            // convention for shapes that aren't cleanly extractable. Array
            // types (`String[] args`) are unaffected — the `[]` lives in
            // `unannType`, not the identifier, so `variableDeclaratorId`
            // still yields a clean name.
            const vp = fp.children?.variableParaRegularParameter?.[0];
            const paramName = vp?.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image || null;
            // Java allows multiple stacked annotations on one parameter
            // (`@NotNull @RequestParam String q`), each its own
            // `variableModifier` entry — loop over all of them, not just
            // the first, or a stacked annotation is silently dropped (the
            // same class of bug Task 3's C# regex needed a fix round for).
            const variableModifiers = vp?.children?.variableModifier || [];
            for (const vm of variableModifiers) {
              const ann = vm.children?.annotation?.[0];
              // `typeName.children.Identifier` is an array of ALL
              // dot-separated segments for a fully-qualified annotation
              // (`@org.springframework.web.bind.annotation.RequestParam`
              // yields ['org','springframework','web','bind','annotation',
              // 'RequestParam']) — the simple annotation name is the LAST
              // segment, not the first. Taking [0] previously recorded the
              // package root ("org") as the decorator name, a silent wrong
              // value rather than the honest drop the C#/JS sibling parsers
              // produce for the same shape (fix round 1, R14(a) Task 5).
              const identifiers = ann?.children?.typeName?.[0]?.children?.Identifier;
              const decoratorName = identifiers?.length ? identifiers[identifiers.length - 1]?.image : undefined;
              if (decoratorName && paramName) {
                paramAnnotations.push({ index: idx, name: paramName, decorator: decoratorName });
              }
            }
            return paramName;
          }).filter(Boolean);
          const body = md.children?.methodBody?.[0]?.children?.block?.[0];
          if (body) {
            const methodLine = _lineOf(md);
            const cfg = buildCfgFromBody(body);
            _applyVarTypeRewrite(cfg.nodes);
            functions.push({
              // Sibling frontends (parser-js.js) suffix the qid with `@line`
              // so overloaded/same-named methods don't collide — without it,
              // callgraph.js's `functions.set(fn.qid, fn)` silently drops
              // every overload but the last one declared.
              qid: `${file}::${className || 'class'}::${name}@${methodLine}`,
              name: className ? `${className}.${name}` : name,
              line: methodLine,
              params,
              cfg,
              file,
              calls: callSitesFromCfg(cfg),
              ...(paramAnnotations.length ? { paramAnnotations } : {}),
            });
          }
        }
        walkForMethods(child, className);
      }
    }
  }
  walkForMethods(cst, null);

  return { file, functions, topLevel: null, ...(classes.length ? { classes } : {}) };
}
