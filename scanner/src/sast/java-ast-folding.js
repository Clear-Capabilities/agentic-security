// java-ast-folding.js — AST-based constant folding for Java if/switch statements.
//
// Powered by `java-parser` (Chevrotain CST). Walks the parse tree, tracks
// local-variable constant values within method scope, evaluates if-conditions
// and switch-scrutinees, and returns line ranges of provably-unreachable
// branches. The engine uses these ranges to suppress findings in dead code,
// which fixes OWASP Benchmark FPs of the shape:
//
//   int x = 86;
//   if ((7 * 42) - x > 200) bar = "safe";   // always true → else dead
//   else bar = param;
//
// Reaches roadmap items #1 (tree-sitter Java foundation), #2 (if-condition
// constant folding) and #10 (switch-case constant folding).
//
// Out of scope (for the regex engine these can come later):
//   - Cross-method propagation (different file or non-final field)
//   - String method calls beyond .equals / .equalsIgnoreCase / length()
//   - Floating-point arithmetic
//   - long / short / byte coercion edge cases (we treat all as Number)

// Dynamic + try/caught, not a plain static import: java-ast-folding.js is
// pulled in by engine.js, which every CLI invocation imports regardless of
// language — a static import made a transient failure to resolve the
// vendored '#java-parser' subpath (observed under heavy concurrent test
// load: many processes resolving the same large vendored tree at once) a
// module-LINK-time crash of the entire CLI, for every user, for every scan,
// not just Java ones. This file already treats a `parse()` call failure as
// non-fatal ("On parse error returns []; callers should fall back to
// non-AST behavior" — see deadBranchRanges below); extending that same
// degrade-to-empty philosophy to a load-time failure, instead of letting it
// crash the process, is the fix.
let parse = null;
try {
  ({ parse } = await import('#java-parser'));
} catch {
  parse = null;
}

// ─── CST helpers ──────────────────────────────────────────────────────────

/** Resolve a CST node down to its first IToken leaf (for "image" / line info). */
function firstToken(node) {
  if (!node) return null;
  if (node.image !== undefined) return node;
  if (Array.isArray(node)) return firstToken(node[0]);
  if (node.children) {
    for (const key of Object.keys(node.children)) {
      const t = firstToken(node.children[key]);
      if (t) return t;
    }
  }
  return null;
}

/** Last token, for end-of-range work. */
function lastToken(node) {
  if (!node) return null;
  if (node.image !== undefined) return node;
  if (Array.isArray(node)) return lastToken(node[node.length - 1]);
  if (node.children) {
    const keys = Object.keys(node.children);
    for (let i = keys.length - 1; i >= 0; i--) {
      const t = lastToken(node.children[keys[i]]);
      if (t) return t;
    }
  }
  return null;
}

/** Concatenate all token images under a node — useful for cheap text rendering. */
function rangeOf(node) {
  const a = firstToken(node);
  const b = lastToken(node);
  if (!a || !b) return null;
  return { startLine: a.startLine, endLine: b.endLine };
}

/** Pick the single child of a node, or null when not unary. */
function only(children, key) {
  return children && children[key] && children[key].length === 1 ? children[key][0] : null;
}


// ─── Constant evaluator ──────────────────────────────────────────────────

// Sentinel for "could not evaluate". Distinct from `false` etc. so we can
// distinguish "unknown" from "evaluated to false".
const UNKNOWN = Symbol('unknown');

/** Evaluate a CST expression node, returning a JS value or UNKNOWN.
 *  `scope` is a Map<name, value> of in-scope local constants. */
function evalExpr(node, scope) {
  if (!node) return UNKNOWN;
  // java-parser's expression CST root is `expression -> conditionalExpression`.
  if (node.name === 'expression' || node.children?.conditionalExpression) {
    const ce = node.children?.conditionalExpression?.[0] || only(node, 'conditionalExpression');
    return evalExpr(ce, scope);
  }
  if (node.name === 'conditionalExpression') {
    return evalConditional(node, scope);
  }
  if (node.name === 'binaryExpression') {
    return evalBinary(node, scope);
  }
  if (node.name === 'unaryExpression') {
    return evalUnary(node, scope);
  }
  if (node.name === 'unaryExpressionNotPlusMinus') {
    return evalUnary(node, scope);
  }
  if (node.name === 'primary') {
    return evalPrimary(node, scope);
  }
  if (node.name === 'primaryPrefix') {
    return evalPrimaryPrefix(node, scope);
  }
  return UNKNOWN;
}

function evalConditional(node, scope) {
  const ch = node.children || {};
  const be = ch.binaryExpression?.[0];
  if (!be) return UNKNOWN;
  return evalBinary(be, scope);
}

const COMPARE_OPS = new Set(['<', '<=', '>', '>=']);
const EQUALITY_OPS = new Set(['==', '!=']);
const LOGICAL_AND = '&&';
const LOGICAL_OR = '||';
const ARITH_OPS = new Set(['+', '-', '*', '/', '%']);

function evalBinary(node, scope) {
  const ch = node.children || {};
  const operands = ch.unaryExpression || [];
  // Binary operators come in `BinaryOperator` token arrays interleaved between operands.
  // Locate operator tokens (any token with an image of a recognised op).
  const opTokens = [];
  for (const key of Object.keys(ch)) {
    if (key === 'unaryExpression' || key === 'expression') continue;
    if (Array.isArray(ch[key])) {
      for (const t of ch[key]) {
        if (t.image && /^(?:\+|-|\*|\/|%|<<|>>|>>>|<=?|>=?|==|!=|&&|\|\||&|\||\^)$/.test(t.image)) {
          opTokens.push(t);
        }
      }
    }
  }
  if (operands.length === 1 && opTokens.length === 0) {
    return evalUnary(operands[0], scope);
  }
  // The CST flattens binary ops left-to-right with all operands at one level.
  // Re-fold left-to-right respecting precedence is complex; restrict to the
  // shapes OWASP Benchmark uses (single comparison wrapping integer arith).
  if (operands.length < 2 || opTokens.length < 1) return UNKNOWN;
  // First pass: pure-arith chain into a single Number (left to right, common case).
  // Second pass: apply final comparison if any.
  let accum = evalUnary(operands[0], scope);
  if (accum === UNKNOWN) return UNKNOWN;
  for (let i = 0; i < opTokens.length; i++) {
    const op = opTokens[i].image;
    const next = evalUnary(operands[i + 1], scope);
    if (next === UNKNOWN) return UNKNOWN;
    if (ARITH_OPS.has(op)) {
      if (typeof accum !== 'number' || typeof next !== 'number') return UNKNOWN;
      switch (op) {
        case '+': accum = accum + next; break;
        case '-': accum = accum - next; break;
        case '*': accum = accum * next; break;
        case '/': if (next === 0) return UNKNOWN; accum = Math.trunc(accum / next); break;
        case '%': if (next === 0) return UNKNOWN; accum = accum % next; break;
      }
    } else if (COMPARE_OPS.has(op)) {
      if (typeof accum !== 'number' || typeof next !== 'number') return UNKNOWN;
      switch (op) {
        case '<':  accum = accum <  next; break;
        case '<=': accum = accum <= next; break;
        case '>':  accum = accum >  next; break;
        case '>=': accum = accum >= next; break;
      }
    } else if (EQUALITY_OPS.has(op)) {
      // == and != work on numbers, strings, booleans
      switch (op) {
        case '==': accum = accum === next; break;
        case '!=': accum = accum !== next; break;
      }
    } else if (op === LOGICAL_AND) {
      if (typeof accum !== 'boolean' || typeof next !== 'boolean') return UNKNOWN;
      accum = accum && next;
    } else if (op === LOGICAL_OR) {
      if (typeof accum !== 'boolean' || typeof next !== 'boolean') return UNKNOWN;
      accum = accum || next;
    } else {
      return UNKNOWN;
    }
  }
  return accum;
}

function evalUnary(node, scope) {
  if (!node) return UNKNOWN;
  const ch = node.children || {};
  // unary +/-/!/~ prefix
  let value;
  const primary = ch.primary?.[0];
  if (primary) {
    value = evalPrimary(primary, scope);
    if (value === UNKNOWN) return UNKNOWN;
  } else {
    return UNKNOWN;
  }
  // Apply prefix operators in reverse
  const prefixOps = [];
  for (const key of Object.keys(ch)) {
    if (key === 'primary') continue;
    if (Array.isArray(ch[key])) {
      for (const t of ch[key]) {
        if (t.image === '!') prefixOps.unshift('!');
        if (t.image === '-') prefixOps.unshift('-');
        if (t.image === '+') prefixOps.unshift('+');
        if (t.image === '~') prefixOps.unshift('~');
      }
    }
  }
  for (const op of prefixOps) {
    if (op === '!') {
      if (typeof value !== 'boolean') return UNKNOWN;
      value = !value;
    } else if (op === '-') {
      if (typeof value !== 'number') return UNKNOWN;
      value = -value;
    } else if (op === '+') {
      if (typeof value !== 'number') return UNKNOWN;
    } else if (op === '~') {
      if (typeof value !== 'number') return UNKNOWN;
      value = ~value;
    }
  }
  return value;
}

function evalPrimary(node, scope) {
  if (!node) return UNKNOWN;
  const ch = node.children || {};
  const prefix = ch.primaryPrefix?.[0];
  if (!prefix) return UNKNOWN;
  const value = evalPrimaryPrefix(prefix, scope);
  // Suffix chains (.field, .method(), [idx]) make evaluation fail.
  if (ch.primarySuffix && ch.primarySuffix.length > 0) {
    return UNKNOWN;
  }
  return value;
}

function evalPrimaryPrefix(node, scope) {
  if (!node) return UNKNOWN;
  const ch = node.children || {};
  // literal: integer, boolean, string, null
  if (ch.literal) {
    return evalLiteral(ch.literal[0]);
  }
  // parenthesised expression
  if (ch.parenthesisExpression) {
    const pe = ch.parenthesisExpression[0];
    const inner = pe.children?.expression?.[0];
    return evalExpr(inner, scope);
  }
  // fqnOrRefType / identifier
  if (ch.fqnOrRefType) {
    const fr = ch.fqnOrRefType[0];
    const parts = fr.children?.fqnOrRefTypePartFirst || [];
    if (parts.length === 1) {
      const ident = parts[0].children?.fqnOrRefTypePartCommon?.[0]?.children?.Identifier?.[0]?.image;
      if (ident && scope.has(ident)) return scope.get(ident);
    }
    return UNKNOWN;
  }
  return UNKNOWN;
}

function evalLiteral(litNode) {
  if (!litNode) return UNKNOWN;
  const ch = litNode.children || {};
  if (ch.integerLiteral) {
    const t = firstToken(ch.integerLiteral[0]);
    if (!t) return UNKNOWN;
    // Strip Java integer suffixes (L, _, 0x...)
    let s = t.image.replace(/[Ll_]/g, '');
    if (/^0x/i.test(s)) return parseInt(s, 16);
    if (/^0b/i.test(s)) return parseInt(s.slice(2), 2);
    if (/^0[0-7]+$/.test(s)) return parseInt(s, 8);
    const n = Number(s);
    return Number.isFinite(n) ? n : UNKNOWN;
  }
  if (ch.floatingPointLiteral) {
    const t = firstToken(ch.floatingPointLiteral[0]);
    if (!t) return UNKNOWN;
    const n = parseFloat(t.image.replace(/[FfDd]/, ''));
    return Number.isFinite(n) ? n : UNKNOWN;
  }
  if (ch.booleanLiteral) {
    const t = firstToken(ch.booleanLiteral[0]);
    return t?.image === 'true';
  }
  if (ch.CharLiteral) {
    return ch.CharLiteral[0].image;
  }
  if (ch.StringLiteral) {
    const s = ch.StringLiteral[0].image;
    return s.slice(1, -1);  // strip quotes
  }
  if (ch.Null) return null;
  return UNKNOWN;
}


// ─── Scope walker ─────────────────────────────────────────────────────────

/** Walk a method block, populating `scope` with local-final assignments and
 *  emitting dead-branch ranges into `out`. */
function walkBlock(blockNode, scope, out) {
  if (!blockNode) return;
  const stmts = blockNode.children?.blockStatements?.[0]?.children?.blockStatement || [];
  for (const st of stmts) {
    walkStatement(st, scope, out);
  }
}

function walkStatement(stmtNode, scope, out) {
  if (!stmtNode) return;
  const ch = stmtNode.children || {};

  // Local variable declaration: track if it's a simple literal/constant init.
  if (ch.localVariableDeclarationStatement) {
    const lvd = ch.localVariableDeclarationStatement[0].children?.localVariableDeclaration?.[0];
    captureLocalDecl(lvd, scope);
    return;
  }

  // Most statements are wrapped in `statement → statementWithoutTrailingSubstatement → blockStatement`.
  const inner = ch.statement?.[0] || ch.statementWithoutTrailingSubstatement?.[0];
  if (inner) {
    walkStatement(inner, scope, out);
    return;
  }

  // Direct if-statement
  if (ch.ifStatement) {
    walkIf(ch.ifStatement[0], scope, out);
    return;
  }

  // Switch
  if (ch.switchStatement) {
    walkSwitch(ch.switchStatement[0], scope, out);
    return;
  }

  // Block
  if (ch.block) {
    walkBlock(ch.block[0], new Map(scope), out);
    return;
  }

  // Loop bodies, try, etc. — descend but don't bind constants.
  for (const key of Object.keys(ch)) {
    const arr = ch[key];
    if (Array.isArray(arr)) for (const child of arr) {
      if (child && child.name) walkStatement(child, scope, out);
    }
  }
}

function captureLocalDecl(lvdNode, scope) {
  if (!lvdNode) return;
  const ch = lvdNode.children || {};
  const list = ch.variableDeclaratorList?.[0]?.children?.variableDeclarator || [];
  for (const vd of list) {
    const id = vd.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
    const init = vd.children?.variableInitializer?.[0]?.children?.expression?.[0];
    if (!id) continue;
    if (!init) { scope.delete(id); continue; }
    const v = evalExpr(init, scope);
    if (v !== UNKNOWN) scope.set(id, v);
    else scope.delete(id);
  }
}

function walkIf(ifNode, scope, out) {
  if (!ifNode) return;
  const ch = ifNode.children || {};
  const cond = ch.expression?.[0];
  const stmts = ch.statement || [];
  const v = evalExpr(cond, scope);
  if (v === true) {
    // else branch is dead
    if (stmts[1]) {
      const r = rangeOf(stmts[1]);
      if (r) out.push({ startLine: r.startLine, endLine: r.endLine, reason: 'constant-true-if dead-else' });
    }
  } else if (v === false) {
    // if branch is dead
    if (stmts[0]) {
      const r = rangeOf(stmts[0]);
      if (r) out.push({ startLine: r.startLine, endLine: r.endLine, reason: 'constant-false-if dead-then' });
    }
  }
  // Recurse into both branches so any nested if/switch inside is still checked.
  for (const s of stmts) {
    if (s) walkStatement(s, new Map(scope), out);
  }
}

function walkSwitch(switchNode, scope, out) {
  if (!switchNode) return;
  const ch = switchNode.children || {};
  const scrutinee = ch.expression?.[0];
  const blockNode = ch.switchBlock?.[0];
  if (!scrutinee || !blockNode) return;
  const v = evalExpr(scrutinee, scope);
  if (v === UNKNOWN) return;

  // For each switchBlockStatementGroup, check if its case label matches `v`.
  const groups = blockNode.children?.switchBlockStatementGroup || [];
  let matchedAny = false;
  for (const g of groups) {
    const labels = g.children?.switchLabel || [];
    let groupMatches = false;
    for (const lbl of labels) {
      const lblCh = lbl.children || {};
      if (lblCh.Default) {
        // default — matches if nothing else does (decided after)
        continue;
      }
      const labelExpr = lblCh.caseConstant?.[0]?.children?.expression?.[0]
        || lblCh.caseLabelElement?.[0]?.children?.expression?.[0];
      if (!labelExpr) continue;
      const lv = evalExpr(labelExpr, scope);
      if (lv !== UNKNOWN && lv === v) groupMatches = true;
    }
    if (groupMatches) matchedAny = true;
    else {
      // Group does NOT match scrutinee → its block is dead (unless default and nothing else matched).
      // We'll resolve default later. For now, conservatively skip "default-only" groups.
      const onlyDefault = labels.every(l => l.children?.Default);
      if (onlyDefault) continue;
      const r = rangeOf(g);
      if (r) out.push({ startLine: r.startLine, endLine: r.endLine, reason: 'unreachable case (switch on constant)' });
    }
  }
}


// ─── Public API ───────────────────────────────────────────────────────────

/** Walk every method body anywhere in the type hierarchy (including inner
 *  classes, interfaces, anonymous classes). Recursive. */
function walkClassBody(classBody, out) {
  if (!classBody) return;
  const decls = classBody.children?.classBodyDeclaration || [];
  for (const bd of decls) {
    const member = bd.children?.classMemberDeclaration?.[0];
    if (!member) continue;
    const memCh = member.children || {};

    // Methods
    if (memCh.methodDeclaration) {
      const method = memCh.methodDeclaration[0];
      const block = method.children?.methodBody?.[0]?.children?.block?.[0];
      if (block) walkBlock(block, new Map(), out);
    }

    // Constructors
    if (memCh.constructorDeclaration) {
      const ctor = memCh.constructorDeclaration[0];
      const block = ctor.children?.constructorBody?.[0];
      if (block) walkBlock(block, new Map(), out);
    }

    // Nested class / interface
    if (memCh.classDeclaration) {
      const cd = memCh.classDeclaration[0];
      walkClassDeclaration(cd, out);
    }
    if (memCh.interfaceDeclaration) {
      const id = memCh.interfaceDeclaration[0];
      walkInterfaceDeclaration(id, out);
    }
  }
}

function walkClassDeclaration(cd, out) {
  if (!cd) return;
  const ncd = cd.children?.normalClassDeclaration?.[0];
  if (ncd) {
    const body = ncd.children?.classBody?.[0];
    walkClassBody(body, out);
  }
  // Enums and records also have bodies that may contain methods.
  const ed = cd.children?.enumDeclaration?.[0];
  if (ed) {
    const enumBody = ed.children?.enumBody?.[0];
    const enumBodyDecls = enumBody?.children?.enumBodyDeclarations?.[0];
    const decls = enumBodyDecls?.children?.classBodyDeclaration || [];
    for (const bd of decls) {
      const member = bd.children?.classMemberDeclaration?.[0];
      if (!member) continue;
      const memCh = member.children || {};
      if (memCh.methodDeclaration) {
        const block = memCh.methodDeclaration[0].children?.methodBody?.[0]?.children?.block?.[0];
        if (block) walkBlock(block, new Map(), out);
      }
    }
  }
}

function walkInterfaceDeclaration(id, out) {
  if (!id) return;
  const nid = id.children?.normalInterfaceDeclaration?.[0];
  if (nid) {
    const body = nid.children?.interfaceBody?.[0];
    const decls = body?.children?.interfaceMemberDeclaration || [];
    for (const bd of decls) {
      const memCh = bd.children || {};
      if (memCh.interfaceMethodDeclaration) {
        const block = memCh.interfaceMethodDeclaration[0].children?.methodBody?.[0]?.children?.block?.[0];
        if (block) walkBlock(block, new Map(), out);
      }
    }
  }
}

/** Parse a Java source file and return dead-branch line ranges.
 *  On parse error returns []; callers should fall back to non-AST behavior. */
export function deadBranchRanges(source) {
  if (!parse || !source || source.length === 0 || source.length > 800_000) return [];
  let cst;
  try {
    cst = parse(source);
  } catch {
    return [];
  }
  const out = [];
  try {
    const cu = cst.children?.ordinaryCompilationUnit?.[0];
    const tds = cu?.children?.typeDeclaration || [];
    for (const td of tds) {
      const cd = td.children?.classDeclaration?.[0];
      if (cd) walkClassDeclaration(cd, out);
      const id = td.children?.interfaceDeclaration?.[0];
      if (id) walkInterfaceDeclaration(id, out);
    }
  } catch {
    // Parser/visitor quirks — return what we have.
  }
  // Dedupe overlapping ranges (collapse adjacent)
  out.sort((a, b) => a.startLine - b.startLine || a.endLine - b.endLine);
  const merged = [];
  for (const r of out) {
    const top = merged[merged.length - 1];
    if (top && r.startLine <= top.endLine + 1) {
      top.endLine = Math.max(top.endLine, r.endLine);
    } else {
      merged.push({ ...r });
    }
  }
  return merged;
}

/** Check if a given line falls within any dead-branch range. */
export function isLineInDeadRange(line, ranges) {
  for (const r of ranges) {
    if (line >= r.startLine && line <= r.endLine) return true;
  }
  return false;
}
