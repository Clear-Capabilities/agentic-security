// Python IR frontend (P2.2).
//
// Emits the same IR node shape as parser-js.js so the existing dataflow
// engine consumes both transparently.
//
// v1: a pragmatic indentation-aware parser. We avoid bundling tree-sitter
// (a 4–10MB WASM blob) and instead recognize the core Python shapes we
// actually need for taint analysis:
//
//   def f(args):           → function header (new fn, CFG)
//   x = expr               → assign node
//   call(args)             → call node
//   return expr            → return node
//   if cond:               → if node
//   while cond:            → loop-header node
//   for v in expr:         → loop-header node + implicit assign
//   raise expr             → throw node
//   try / except / finally → exception-flow scaffolding (P3.4 will model)
//
// Out of scope for v1: comprehensions (treated as opaque), decorators
// (parsed but not used for taint), match statements, async / await
// modeled as transparent unwrap. lambda bodies collapsed to expr.
//
// The output matches the parser-js.js shape:
//
//   {
//     file, functions: [{
//       qid, name, line, params, cfg: { entry, exit, nodes }
//     }],
//     topLevel
//   }

import { blankComments } from '../sast/_comment-strip.js';

let _nodeIdSeq = 0;
function nextNodeId() { return 'pyn' + (++_nodeIdSeq); }

// ── Lightweight expression parser ───────────────────────────────────────

const _IDENT = /^[A-Za-z_][A-Za-z_0-9]*/;

function parseExpr(text) {
  if (!text) return { kind: 'unknown' };
  text = text.trim();
  if (!text) return { kind: 'unknown' };
  // String literal
  if (/^['"]/.test(text)) {
    return { kind: 'literal', value: text };
  }
  // Number literal
  if (/^-?\d/.test(text)) {
    return { kind: 'literal', value: Number(text) || text };
  }
  // True / False / None
  if (/^(?:True|False|None)$/.test(text)) {
    return { kind: 'literal', value: text };
  }
  // F-string (template literal)
  if (/^f['"]/.test(text)) {
    const inner = text.slice(2, -1);
    const parts = [];
    let m;
    const fre = /\{([^{}]+)\}/g;
    while ((m = fre.exec(inner))) {
      parts.push(parseExpr(m[1]));
    }
    return { kind: 'tpl', parts };
  }
  // Call: name(args) or name.method(args) — premortem #14: accept arbitrary
  // nesting of parens/brackets/braces in args, not just one level. The old
  // regex `[^()]*` rejected anything with a nested paren, silently dropping
  // most idiomatic Python (`db.execute(sanitize(x))`, `f(g(y))`).
  const calleeMatch = /^([A-Za-z_][\w.]*)\s*\(/.exec(text);
  if (calleeMatch) {
    const callee = calleeMatch[1];
    const openIdx = calleeMatch[0].length - 1;
    // Walk forward from openIdx, tracking balanced (), [], {}, with quote
    // awareness so a `)` inside a string doesn't close the call.
    let depth = 1, i = openIdx + 1, inStr = false, q = '';
    for (; i < text.length; i++) {
      const c = text[i];
      if (inStr) {
        if (c === '\\') { i++; continue; }
        if (c === q) { inStr = false; }
        continue;
      }
      if (c === '"' || c === "'") { inStr = true; q = c; continue; }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') {
        depth--;
        if (depth === 0) break;
      }
    }
    // Whole text must end right at the matching close-paren for this to
    // be a plain call expression; otherwise it's a sub-expression.
    if (depth === 0 && i === text.length - 1) {
      const argsText = text.slice(openIdx + 1, i);
      const args = _splitArgs(argsText).map(a => parseExpr(a));
      return { kind: 'call', callee, args };
    }
  }
  // Binary op
  for (const op of [' or ', ' and ', '==', '!=', '<=', '>=', '<', '>', '+', '-', '*', '/', '%']) {
    const idx = _findTopLevel(text, op);
    if (idx > 0) {
      const left = parseExpr(text.slice(0, idx));
      const right = parseExpr(text.slice(idx + op.length));
      return { kind: op === ' or ' || op === ' and ' ? 'logical' : 'binary', op: op.trim(), left, right };
    }
  }
  // Member access x.y.z
  if (/\./.test(text) && _IDENT.test(text.split('.')[0])) {
    const parts = text.split('.');
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) {
      cur = { kind: 'member', object: cur, prop: parts[i].replace(/\(.*\)$/, '') };
    }
    return cur;
  }
  // Plain ident
  if (_IDENT.test(text)) {
    return { kind: 'ident', name: text.match(_IDENT)[0] };
  }
  // List / dict literal
  if (/^\[/.test(text)) {
    const inner = text.slice(1, -1);
    const elements = _splitArgs(inner).map(parseExpr);
    return { kind: 'array', elements };
  }
  if (/^\{/.test(text)) {
    const inner = text.slice(1, -1);
    const pairs = _splitArgs(inner).map(p => {
      const colon = _findTopLevel(p, ':');
      if (colon < 0) return null;
      return { value: parseExpr(p.slice(colon + 1)) };
    }).filter(Boolean);
    return { kind: 'object', props: pairs };
  }
  return { kind: 'unknown' };
}

function _splitArgs(s) {
  if (!s) return [];
  const out = [];
  let depth = 0, last = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { out.push(s.slice(last, i).trim()); last = i + 1; }
  }
  const tail = s.slice(last).trim();
  if (tail) out.push(tail);
  return out;
}

function _findTopLevel(s, sep) {
  let depth = 0;
  for (let i = 0; i < s.length - sep.length + 1; i++) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (depth === 0 && s.startsWith(sep, i)) return i;
  }
  return -1;
}

// ── Indentation-aware function extraction ───────────────────────────────

function extractFunctions(text, file) {
  const lines = blankComments(text, 'py').split('\n');
  const fns = [];
  const consumed = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Premortem #14: balanced-paren signature parse to handle default values
    // that contain parens (e.g. `def f(x=Foo(1, 2)) -> None:`). The old regex
    // `\(([^)]*)\)` couldn't see past the first ')' and would either miss the
    // function entirely or capture only the leading args.
    const head = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/.exec(line);
    if (!head) continue;
    const indent = head[1].length;
    const name = head[2];
    let p = head[0].length, depth = 1, inStr = false, q = '';
    for (; p < line.length; p++) {
      const c = line[p];
      if (inStr) { if (c === '\\') { p++; continue; } if (c === q) inStr = false; continue; }
      if (c === '"' || c === "'") { inStr = true; q = c; continue; }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) break; }
    }
    if (depth !== 0) continue;
    const paramsText = line.slice(head[0].length, p);
    // After the close paren, require a `:` (possibly via `-> X:`)
    const after = line.slice(p + 1);
    if (!/^\s*(?:->\s*[^:]+)?:\s*(?:#.*)?$/.test(after)) continue;
    const params = _splitArgs(paramsText).map(s => s.trim().split(/[:=]/)[0].trim()).filter(Boolean);
    consumed.add(i + 1);
    // Collect body lines: anything indented strictly more than `indent`
    // until we hit a line with same-or-less indent.
    const body = [];
    let j = i + 1;
    while (j < lines.length) {
      const l = lines[j];
      if (l.trim() === '') { body.push({ line: j + 1, text: '' }); consumed.add(j + 1); j++; continue; }
      const li = l.match(/^(\s*)/)[1].length;
      if (li <= indent) break;
      body.push({ line: j + 1, text: l.slice(indent + 4) });   // strip one indent
      consumed.add(j + 1);
      j++;
    }
    fns.push({
      qid: `${file}::module::${name}`,
      name,
      line: i + 1,
      params,
      body,
    });
  }
  return { fns, consumed, lines };
}

// R14(b): the complement of extractFunctions' consumed lines is the
// module-level (top-level) statement text, lowered through the same
// buildCfg() every real function body already uses. Only line text is
// needed — buildCfg/_classifyLine already trim() before matching, so
// leading indentation on a stray line is harmless.
function _moduleLevelBody(lines, consumed) {
  const body = [];
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    if (consumed.has(lineNo)) continue;
    body.push({ line: lineNo, text: lines[i] });
  }
  return body;
}

// ── Build CFG from a function's body lines ──────────────────────────────

function buildCfg(fn) {
  const nodes = {};
  const entry = nextNodeId();
  const exit = nextNodeId();
  nodes[entry] = { id: entry, kind: 'entry', succ: [] };
  nodes[exit] = { id: exit, kind: 'exit', succ: [] };

  let prev = entry;
  for (const { line, text } of fn.body) {
    if (!text.trim()) continue;
    const node = _classifyLine(text, line);
    if (!node) continue;
    const id = nextNodeId();
    node.id = id;
    nodes[id] = node;
    if (nodes[prev]) {
      nodes[prev].succ = nodes[prev].succ || [];
      nodes[prev].succ.push(id);
    }
    prev = id;
  }
  if (nodes[prev]) {
    nodes[prev].succ = nodes[prev].succ || [];
    nodes[prev].succ.push(exit);
  }
  return { entry, exit, nodes };
}

function _classifyLine(text, line) {
  text = text.trim();
  if (!text) return null;
  // return expr
  let m;
  if ((m = /^return\s*(.*)$/.exec(text))) {
    return { kind: 'return', value: m[1] ? parseExpr(m[1]) : null, line, succ: [] };
  }
  // raise expr
  if ((m = /^raise\s*(.*)$/.exec(text))) {
    return { kind: 'throw', value: m[1] ? parseExpr(m[1]) : null, line, succ: [] };
  }
  // if cond:
  if ((m = /^(?:el)?if\s+(.+):\s*$/.exec(text))) {
    return { kind: 'if', cond: parseExpr(m[1]), line, succ: [] };
  }
  // for v in expr:
  if ((m = /^for\s+(\w+)\s+in\s+(.+):\s*$/.exec(text))) {
    return { kind: 'assign', target: m[1], source: parseExpr(m[2]), line, succ: [] };
  }
  // while cond:
  if ((m = /^while\s+(.+):\s*$/.exec(text))) {
    return { kind: 'loop-header', cond: parseExpr(m[1]), line, succ: [] };
  }
  // x = expr  (avoid matching `==`)
  if ((m = /^([A-Za-z_][\w.]*)\s*=(?!=)\s*(.+)$/.exec(text))) {
    const target = m[1];
    const source = parseExpr(m[2]);
    return { kind: 'assign', target, source, line, succ: [] };
  }
  // bare call: func(args)
  if ((m = /^([A-Za-z_][\w.]*)\s*\(([^()]*)\)\s*$/.exec(text))) {
    return { kind: 'call', callee: m[1], args: _splitArgs(m[2]).map(parseExpr), line, succ: [] };
  }
  // unhandled: noop
  return { kind: 'noop', line, succ: [] };
}

/**
 * Public entry point — produces the same shape as parser-js.js's output.
 *
 *   file: repo-relative .py path
 *   raw:  file contents
 */
export function parsePythonFile(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return null;
  if (!/\.py$/i.test(file)) return null;
  if (raw.length > 1_000_000) return null;
  const { fns: fnRecs, consumed, lines } = extractFunctions(raw, file);
  const functions = fnRecs.map(fn => ({
    qid: fn.qid,
    name: fn.name,
    line: fn.line,
    params: fn.params,
    cfg: buildCfg(fn),
    file,
  }));
  const modBody = _moduleLevelBody(lines, consumed);
  const modCfg = buildCfg({ body: modBody });
  const modHasContent = Object.values(modCfg.nodes).some(n => n.kind !== 'entry' && n.kind !== 'exit' && n.kind !== 'noop');
  let topLevel = null;
  if (modHasContent) {
    const modQid = `${file}::module::<module>`;
    functions.push({ qid: modQid, name: '<module>', line: 1, params: [], cfg: modCfg, file });
    topLevel = modQid;
  }
  return {
    file,
    functions,
    topLevel,
  };
}
